import hashlib
import json
import shutil
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Barrier, Lock

import pytest

from tempesttrace import backup
from tempesttrace.backup import BackupCancelled, create_backup


def fixture(root: Path) -> Path:
    (root / "basic/profiles/default").mkdir(parents=True)
    (root / "basic/scenes").mkdir(parents=True)
    (root / "logs").mkdir()
    (root / "basic/profiles/default/service.json").write_text(
        '{"key":"TOP_SECRET","server":"rtmp://x"}', encoding="utf-8"
    )
    (root / "basic/profiles/default/basic.ini").write_text(
        "[Output]\nMode=Advanced\nkey=INI_PROFILE_SECRET\n", encoding="utf-8"
    )
    (root / "basic/scenes/main.json").write_text('{"sources":[]}', encoding="utf-8")
    (root / "basic/scenes/ignored.txt").write_text("ignore", encoding="utf-8")
    (root / "basic/profiles/default/plugin.yaml").write_text(
        "token: SHOULD_NOT_BE_COPIED", encoding="utf-8"
    )
    (root / "global.ini").write_text("[General]\nName=OBS\n", encoding="utf-8")
    (root / "logs/2026-01-01.txt").write_text("key=LOG_SECRET", encoding="utf-8")
    return root


def test_backup_packages_allowlisted_redacted_snapshot_without_source_changes(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "Dropbox/Jasmeralia and Rin/obs logs"
    destination.mkdir(parents=True)
    before = {
        p.relative_to(source): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in source.rglob("*")
        if p.is_file()
    }
    result = create_backup(
        source, destination, now=__import__("datetime").datetime(2026, 9, 28, 11, 0, 0)
    )
    after = {
        p.relative_to(source): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in source.rglob("*")
        if p.is_file()
    }
    assert before == after
    assert result.archive.name == "TempestTrace-2026-09-28_11-00-00.zip"
    with zipfile.ZipFile(result.archive) as archive:
        names = set(archive.namelist())
        assert "basic/profiles/default/service.json" in names
        assert "basic/scenes/main.json" in names
        assert "basic/scenes/ignored.txt" not in names
        assert "README.txt" in names and "manifest.json" in names
        contents = b"".join(archive.read(name) for name in names)
        assert b"TOP_SECRET" not in contents and b"LOG_SECRET" not in contents
        assert b"INI_PROFILE_SECRET" not in contents
        assert b"<REDACTED>" in archive.read("basic/profiles/default/basic.ini")
        assert "basic/profiles/default/plugin.yaml" not in names
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["complete"] is True
        assert manifest["copied_count"] >= 4


def test_backup_refuses_destination_inside_source(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    with pytest.raises(ValueError, match="inside"):
        create_backup(source, source / "basic")


def test_raw_source_bytes_never_enter_destination_staging(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "Dropbox/out"
    destination.mkdir(parents=True)

    def check_destination(phase: str, current: int, total: int) -> None:
        if phase == "redacting":
            assert all(
                b"INI_PROFILE_SECRET" not in item.read_bytes()
                for item in destination.rglob("*")
                if item.is_file()
            )

    create_backup(source, destination, progress=check_destination)


def test_cancel_leaves_marked_incomplete_stage(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(BackupCancelled, match="cancelled"):
        create_backup(source, destination, cancelled=lambda: True)
    assert list(destination.glob(".TempestTrace-*.incomplete-*"))
    assert not list(destination.glob("*.zip"))


def test_staging_cleanup_failure_keeps_created_backup_successful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()
    original_rmtree = shutil.rmtree

    def fail_staging_removal(path: str | Path, *args: object, **kwargs: object) -> None:
        if Path(path).parent == destination and Path(path).name.startswith(".TempestTrace-"):
            raise OSError("synthetic cleanup failure")
        original_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(backup.shutil, "rmtree", fail_staging_removal)

    result = create_backup(source, destination)

    assert result.archive.is_file()
    assert any("temporary sanitized snapshot" in warning for warning in result.warnings)
    assert list(destination.glob(".TempestTrace-*.incomplete-*"))


@pytest.mark.parametrize(
    "line",
    [
        "token=LOG_TOKEN_SECRET",
        "api_key=LOG_API_KEY_SECRET",
        'secret="LOG_QUOTED_SECRET"',
    ],
)
def test_private_verifier_detects_plain_and_quoted_log_credentials(
    tmp_path: Path, line: str
) -> None:
    path = tmp_path / "log.txt"
    path.write_text(line, encoding="utf-8")

    assert backup._secret_scan(path)


def test_backup_verifier_preserves_hotkey_log_lines(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    hotkey_line = "hotkey binding key=F9\n"
    (source / "logs/2026-01-01.txt").write_text(hotkey_line, encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    with zipfile.ZipFile(result.archive) as archive:
        assert archive.read("logs/2026-01-01.txt").decode("utf-8") == hotkey_line


@pytest.mark.parametrize(
    "property_name",
    ["key", '"key"'],
    ids=["top-level-key", "quoted-property-name"],
)
def test_json_private_verifier_uses_filename_context_for_key_properties(
    tmp_path: Path, property_name: str
) -> None:
    path = tmp_path / "service.json"
    path.write_text(json.dumps({property_name: "LEAKED_STREAM_KEY"}), encoding="utf-8")

    assert backup._secret_scan(path)


def test_short_credentials_do_not_reject_unrelated_substrings_in_backup(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    (source / "logs/2026-01-02.txt").write_text("token=x description=texture\n", encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    with zipfile.ZipFile(result.archive) as archive:
        log = archive.read("logs/2026-01-02.txt").decode("utf-8")
    assert log == "token=<REDACTED> description=texture\n"


def test_bad_json_is_omitted_and_symlinks_are_not_followed(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    bad = source / "basic/profiles/default/bad.json"
    bad.write_text('{"token":', encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text('{"key":"OUTSIDE_SECRET"}', encoding="utf-8")
    link = source / "basic/profiles/default/linked.json"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        assert "basic/profiles/default/bad.json" not in archive.namelist()
        assert "basic/profiles/default/linked.json" not in archive.namelist()
        manifest = json.loads(archive.read("manifest.json"))
        reasons = {item["reason"] for item in manifest["skipped"]}
        assert "unreadable_or_unsanitizable" in reasons
        assert "link_or_reparse_point" in reasons


def test_symlinked_obs_subtree_is_never_traversed(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.json").write_text('{"key":"OUTSIDE_SECRET"}', encoding="utf-8")
    shutil.rmtree(source / "basic/profiles")
    try:
        (source / "basic/profiles").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        assert not any(name.startswith("basic/profiles/") for name in archive.namelist())
        assert b"OUTSIDE_SECRET" not in b"".join(archive.read(name) for name in archive.namelist())


def test_empty_obs_tree_is_not_reported_as_success(tmp_path: Path) -> None:
    source = tmp_path / "obs"
    (source / "basic/profiles").mkdir(parents=True)
    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(ValueError, match="No supported OBS files"):
        create_backup(source, destination)


def test_quoted_log_credential_fails_backup_verification_if_not_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = fixture(tmp_path / "obs")
    (source / "logs/2026-01-01.txt").write_text('key="LEAK_IF_UNVERIFIED"', encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    original_redact_file = backup.redact_file_with_secrets

    def leave_quoted_secret(path: Path):
        if path.suffix == ".txt":
            return {}, 0, set()
        return original_redact_file(path)

    monkeypatch.setattr(backup, "redact_file_with_secrets", leave_quoted_secret)
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        contents = b"".join(archive.read(name) for name in archive.namelist())
        assert b"LEAK_IF_UNVERIFIED" not in contents
        manifest = json.loads(archive.read("manifest.json"))
        assert any(item["reason"] == "verification_secret_found" for item in manifest["skipped"])


def test_cancel_during_zip_packaging_keeps_final_archive_unpromoted(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()
    packaging_started = False

    def progress(phase: str, current: int, total: int) -> None:
        nonlocal packaging_started
        if phase == "packaging" and current >= 1:
            packaging_started = True

    with pytest.raises(BackupCancelled, match="cancelled"):
        create_backup(source, destination, progress=progress, cancelled=lambda: packaging_started)
    final_archives = [
        path for path in destination.glob("TempestTrace-*.zip") if ".incomplete" not in path.name
    ]
    assert not final_archives
    assert list(destination.glob("TempestTrace-*.incomplete.zip"))


def test_cancel_after_zip_verification_prevents_final_promotion(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()
    promoting = False

    def progress(phase: str, current: int, total: int) -> None:
        nonlocal promoting
        if phase == "promoting":
            promoting = True

    with pytest.raises(BackupCancelled, match="cancelled"):
        create_backup(source, destination, progress=progress, cancelled=lambda: promoting)
    final_archives = [
        path for path in destination.glob("TempestTrace-*.zip") if ".incomplete" not in path.name
    ]
    assert not final_archives
    assert list(destination.glob("TempestTrace-*.incomplete.zip"))


@pytest.mark.parametrize("race_at", ["stat", "read"])
def test_log_disappearing_during_inventory_or_read_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, race_at: str
) -> None:
    source = fixture(tmp_path / "obs")
    disappearing_log = source / "logs/2026-01-01.txt"
    destination = tmp_path / "out"
    destination.mkdir()

    if race_at == "stat":
        original_stat = Path.stat
        stat_calls = 0

        def race_stat(path: Path, *args: object, **kwargs: object):
            nonlocal stat_calls
            if path == disappearing_log:
                stat_calls += 1
                if stat_calls > 1:
                    raise FileNotFoundError(path)
            return original_stat(path, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", race_stat)
    else:
        original_read = backup._read_consistent

        def race_read(path: Path, target: Path, max_bytes: int):
            if path == disappearing_log:
                raise FileNotFoundError(path)
            return original_read(path, target, max_bytes)

        monkeypatch.setattr(backup, "_read_consistent", race_read)

    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert any(
        item["path"] == "logs/2026-01-01.txt" and item["reason"] == "unreadable"
        for item in manifest["skipped"]
    )


def test_credential_duplicated_under_nonsensitive_json_key_is_removed_without_manifest_leak(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    duplicated_secret = "DUPLICATED_STREAM_SECRET"
    service = source / "basic/profiles/default/service.json"
    service.write_text(
        json.dumps({"key": duplicated_secret, "plugin_metadata": duplicated_secret}),
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        contents = b"".join(archive.read(name) for name in archive.namelist())
        assert duplicated_secret.encode() not in contents
        manifest_bytes = archive.read("manifest.json")
        assert duplicated_secret.encode() not in manifest_bytes


def test_nested_credential_duplicate_under_nonsensitive_key_does_not_leak(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    duplicated_secret = "NESTED_DUPLICATED_SECRET"
    service = source / "basic/profiles/default/service.json"
    service.write_text(
        json.dumps({"token": {"value": duplicated_secret}, "plugin_metadata": duplicated_secret}),
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        contents = b"".join(archive.read(name) for name in archive.namelist())
    assert duplicated_secret.encode() not in contents


def test_same_timestamp_concurrent_backups_reserve_distinct_complete_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()
    same_time = datetime(2026, 9, 28, 12, 0, 0)
    original_reserve = backup._reserve_archive_name
    both_ready = Barrier(2)
    call_lock = Lock()
    initial_calls = 0

    def synchronized_reserve(target_dir: Path, base: str, start_suffix: int = 0):
        nonlocal initial_calls
        with call_lock:
            initial_calls += 1
            wait_for_peer = initial_calls <= 2
        if wait_for_peer:
            both_ready.wait(timeout=5)
        return original_reserve(target_dir, base, start_suffix)

    monkeypatch.setattr(backup, "_reserve_archive_name", synchronized_reserve)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _index: create_backup(source, destination, now=same_time), range(2))
        )

    assert len({result.archive for result in results}) == 2
    assert {result.archive.name for result in results} == {
        "TempestTrace-2026-09-28_12-00-00.zip",
        "TempestTrace-2026-09-28_12-00-00-1.zip",
    }
    for result in results:
        with zipfile.ZipFile(result.archive) as archive:
            assert archive.testzip() is None
            assert "manifest.json" in archive.namelist()
    assert not list(destination.glob(".*.reserve"))


def test_late_final_name_collision_is_preserved_and_backup_uses_suffix(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()
    same_time = datetime(2026, 9, 28, 12, 0, 0)
    conflicting_final = destination / "TempestTrace-2026-09-28_12-00-00.zip"

    def create_late_collision(phase: str, current: int, total: int) -> None:
        if phase == "promoting":
            conflicting_final.write_bytes(b"preexisting archive")

    result = create_backup(source, destination, now=same_time, progress=create_late_collision)

    assert conflicting_final.read_bytes() == b"preexisting archive"
    assert result.archive.name == "TempestTrace-2026-09-28_12-00-00-1.zip"
    with zipfile.ZipFile(result.archive) as archive:
        assert archive.testzip() is None
        assert "manifest.json" in archive.namelist()
    assert not list(destination.glob(".*.reserve"))
