import hashlib
import json
import shutil
import zipfile
from pathlib import Path

import pytest

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


def test_cancel_leaves_marked_incomplete_stage(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(BackupCancelled, match="cancelled"):
        create_backup(source, destination, cancelled=lambda: True)
    assert list(destination.glob(".TempestTrace-*.incomplete-*"))
    assert not list(destination.glob("*.zip"))


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
