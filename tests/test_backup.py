import hashlib
import json
import os
import shutil
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Barrier, Lock, Thread

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
        assert manifest["redaction_rules_version"] == backup.RULE_VERSION
        assert manifest["copied_count"] >= 4


def test_backup_refuses_destination_inside_source(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    with pytest.raises(ValueError, match="inside"):
        create_backup(source, source / "basic")


def test_backup_scrubs_authorization_fragments_and_rtmp_duplicate_keys(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "Dropbox/out"
    destination.mkdir(parents=True)
    (source / "basic/profiles/default/service.json").write_text(
        '{"key":"deadbeefcafe","server":"rtmp://live.example.com/app/deadbeefcafe"}',
        encoding="utf-8",
    )
    (source / "logs/2026-01-01.txt").write_text(
        'info: {"authorization": "Bearer SUPERAUTHSECRET99",}\n'
        "publish failed for deadbeefcafe and test123\n"
        "rtmp://live.example.com/app/test123\n",
        encoding="utf-8",
    )
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        payload = b"".join(archive.read(name) for name in archive.namelist())
    assert b"SUPERAUTHSECRET99" not in payload
    assert b"deadbeefcafe" not in payload
    assert b"test123" not in payload


def test_percent_and_plus_encoded_private_literals_are_scrubbed_in_logs(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "Dropbox/out"
    destination.mkdir(parents=True)
    (source / "basic/profiles/default/service.json").write_text(
        '{"password":"p@ss w0rd!"}', encoding="utf-8"
    )
    (source / "logs/2026-01-01.txt").write_text(
        "seen p%40ss%20w0rd%21 and p@ss+w0rd! and p%40ss w0rd! "
        "and p%2540ss%2520w0rd%2521; unrelated=%2F and path=%20\n",
        encoding="utf-8",
    )
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        cleaned = archive.read("logs/2026-01-01.txt").decode("utf-8")
    assert "p%40ss" not in cleaned and "p@ss" not in cleaned
    assert "p%2540ss" not in cleaned and "unrelated=%2F" in cleaned and "path=%20" in cleaned


@pytest.mark.parametrize("secret", ["deadbeefcafe", "test123"])
def test_rtmp_weak_key_literals_are_scrubbed_in_same_log(secret: str, tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "Dropbox/out"
    destination.mkdir(parents=True)
    (source / "logs/2026-01-01.txt").write_text(
        f"url rtmp://live.example.com/app/{secret} publish failed for {secret}\n",
        encoding="utf-8",
    )
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        cleaned = archive.read("logs/2026-01-01.txt").decode("utf-8")
    assert secret not in cleaned


def test_rtmp_application_names_are_not_harvested(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "Dropbox/out"
    destination.mkdir(parents=True)
    (source / "logs/2026-01-01.txt").write_text(
        "rtmp://ingest.example.com/app/live go live now live.twitch.tv live2\n",
        encoding="utf-8",
    )
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        cleaned = archive.read("logs/2026-01-01.txt").decode("utf-8")
    assert cleaned == "rtmp://ingest.example.com/app/live go live now live.twitch.tv live2\n"


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


def test_backup_redacts_bare_keys_and_keeps_ini_words_and_hotkeys(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    service = {"settings": {"key": "BAK_STREAM_SECRET"}}
    (source / "basic/profiles/default/service.json.bak").write_text(
        json.dumps(service), encoding="utf-8"
    )
    (source / "basic/scenes/main.json").write_text(
        json.dumps(
            {
                "sources": [{"name": "Camera", "settings": {"key": "SCENE_STREAM_SECRET"}}],
                "hotkeys": [{"key": "OBS_KEY_F9"}],
            }
        ),
        encoding="utf-8",
    )
    (source / "basic/scenes/Streaming Hotkeys.json").write_text(
        json.dumps({"settings": {"key": "FILENAME_HOTKEY_SECRET"}}), encoding="utf-8"
    )
    notes = source / "basic/profiles/default/notes.ini"
    notes.write_text(
        "[Video]\nmonkey=keep-me\nhotkey=F9\n"
        "[Hotkeys]\nkey=HOTKEY_SECTION_SECRET\n"
        'OBSBasic.StartStreaming={"key":"OBS_KEY_F9"}\n',
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    with zipfile.ZipFile(result.archive) as archive:
        names = set(archive.namelist())
        assert "basic/profiles/default/service.json.bak" in names
        assert "basic/profiles/default/notes.ini" in names
        service_text = archive.read("basic/profiles/default/service.json.bak").decode()
        scene_text = archive.read("basic/scenes/main.json").decode()
        ini_text = archive.read("basic/profiles/default/notes.ini").decode()
        all_content = b"".join(archive.read(name) for name in names)

    assert "BAK_STREAM_SECRET" not in all_content.decode()
    assert "SCENE_STREAM_SECRET" not in all_content.decode()
    assert "FILENAME_HOTKEY_SECRET" not in all_content.decode()
    assert "HOTKEY_SECTION_SECRET" not in all_content.decode()
    assert json.loads(service_text)["settings"]["key"] == "<REDACTED>"
    scene = json.loads(scene_text)
    assert scene["sources"][0]["settings"]["key"] == "<REDACTED>"
    assert scene["hotkeys"][0]["key"] == "OBS_KEY_F9"
    assert ini_text == (
        "[Video]\nmonkey=keep-me\nhotkey=F9\n"
        "[Hotkeys]\nkey=<REDACTED>\n"
        'OBSBasic.StartStreaming={"key":"OBS_KEY_F9"}\n'
    )


def test_backup_redacts_credentials_nested_in_json_text_containers(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    (source / "basic/profiles/default/basic.ini").write_text(
        '[Output]\nOBSBasic.StartStreaming={"key":"OBS_KEY_F9","token":"INI_JSON_SECRET"}\n',
        encoding="utf-8",
    )
    (source / "logs/2026-01-01.txt").write_text(
        '{"settings":{"key":"LOG_JSON_SECRET","token":"LOG_TOKEN_SECRET"}}\n'
        "key=LOG_SECOND_SECRET\n",
        encoding="utf-8",
    )
    (source / "basic/scenes/main.json").write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "name": "Camera",
                        "settings": {
                            "payload": '{"key": "SCENE_JSON_SECRET", "token": "SCENE_TOKEN_SECRET"}'
                        },
                    }
                ],
                "hotkeys": {"libobs.mute": {"key": "OBS_KEY_F9"}},
            }
        ),
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        contents = {name: archive.read(name).decode("utf-8") for name in archive.namelist()}
    combined = "\n".join(contents.values())
    for secret in (
        "INI_JSON_SECRET",
        "LOG_JSON_SECRET",
        "LOG_TOKEN_SECRET",
        "LOG_SECOND_SECRET",
        "SCENE_JSON_SECRET",
        "SCENE_TOKEN_SECRET",
    ):
        assert secret not in combined
    assert '"key":"OBS_KEY_F9"' in contents["basic/profiles/default/basic.ini"]
    scene = json.loads(contents["basic/scenes/main.json"])
    assert json.loads(scene["sources"][0]["settings"]["payload"]) == {
        "key": "<REDACTED>",
        "token": "<REDACTED>",
    }
    assert scene["hotkeys"]["libobs.mute"]["key"] == "OBS_KEY_F9"


def test_cross_file_secret_scrub_is_order_independent_and_covers_scenes(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    secret = "Nk8sQ7wL91"
    (source / "basic/profiles/default/basic.ini").write_text(
        f"[General]\nNote=remember {secret}\n", encoding="utf-8"
    )
    (source / "basic/profiles/default/service.json").write_text(
        json.dumps({"settings": {"key": secret}}), encoding="utf-8"
    )
    (source / "basic/scenes/main.json").write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "settings": {
                            "note": f"paste {secret} here",
                            "url": f"https://x/cb?code={secret}&x=1",
                            "encoded": "?code=%4E%6B%38%73%51%37%77%4C%39%31",
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (source / "logs/2026-01-01.txt").write_text(
        f"password={secret} https://example.com/cb?code=%4E%6B%38%73%51%37%77%4C%39%31 "
        "keyint: 250 74% %PATH% %APPDATA% printf %s\n",
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        content = "\n".join(archive.read(name).decode() for name in archive.namelist())
    assert secret not in content
    assert "%PATH%" in content and "%APPDATA%" in content and "printf %s" in content
    assert "keyint: 250" in content and "74%" in content


def test_backup_promotes_without_hard_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()

    def unsupported_link(*args: object, **kwargs: object) -> None:
        raise OSError(95, "Operation not supported")

    monkeypatch.setattr(backup.os, "link", unsupported_link)

    result = create_backup(source, destination)

    assert result.archive.is_file()
    assert not list(destination.glob("*.incomplete.zip"))


def test_private_staging_falls_back_outside_destination_when_tempdir_is_inside(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()
    monkeypatch.setattr(backup.tempfile, "gettempdir", lambda: str(destination))

    create_backup(source, destination)

    assert not list(destination.glob(".*.private-*"))


def test_racing_final_file_is_not_replaced_during_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()
    same_time = datetime(2026, 9, 28, 12, 0, 0)
    conflicting_final = destination / "TempestTrace-2026-09-28_12-00-00.zip"
    original_rename = backup._rename_noreplace

    def create_late_collision(source_path: Path, destination_path: Path) -> None:
        if destination_path == conflicting_final and not conflicting_final.exists():
            conflicting_final.write_bytes(b"preexisting archive")
        original_rename(source_path, destination_path)

    monkeypatch.setattr(backup, "_rename_noreplace", create_late_collision)

    result = create_backup(source, destination, now=same_time)

    assert conflicting_final.read_bytes() == b"preexisting archive"
    assert result.archive.name == "TempestTrace-2026-09-28_12-00-00-1.zip"
    with zipfile.ZipFile(result.archive) as archive:
        assert archive.testzip() is None


@pytest.mark.parametrize("fallback", ["link", "rename"])
def test_rename_noreplace_falls_back_without_replacing_existing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fallback: str
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"new")
    destination.write_bytes(b"old")

    def unsupported_renameat2(_source: Path, _destination: Path) -> None:
        raise OSError(backup.errno.EINVAL, "unsupported")

    monkeypatch.setattr(backup, "_renameat2_call", unsupported_renameat2)
    if fallback == "link":
        with pytest.raises(FileExistsError):
            backup._rename_noreplace(source, destination)
    else:

        def unsupported_link(*_args: object, **_kwargs: object) -> None:
            raise OSError(backup.errno.EPERM, "unsupported")

        monkeypatch.setattr(backup.os, "link", unsupported_link)
        with pytest.raises(FileExistsError):
            backup._rename_noreplace(source, destination)
    assert destination.read_bytes() == b"old"


@pytest.mark.parametrize(
    "link_errno",
    [
        backup.errno.EPERM,
        backup.errno.ENOTSUP,
        backup.errno.EOPNOTSUPP,
        backup.errno.EINVAL,
        backup.errno.ENOSYS,
    ],
)
def test_rename_noreplace_fallback_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, link_errno: int
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"content")

    def unavailable(_source: Path, _destination: Path) -> None:
        raise OSError(backup.errno.EINVAL, "unsupported")

    monkeypatch.setattr(backup, "_renameat2_call", unavailable)
    backup._rename_noreplace(source, destination)
    assert destination.read_bytes() == b"content" and not source.exists()

    source.write_bytes(b"rename")

    def unsupported_link(*_args: object, **_kwargs: object) -> None:
        raise OSError(link_errno, "unsupported")

    monkeypatch.setattr(backup.os, "link", unsupported_link)
    backup._rename_noreplace(source, destination.with_name("renamed"))
    assert destination.with_name("renamed").read_bytes() == b"rename"

    def other_error(_source: Path, _destination: Path) -> None:
        raise OSError(backup.errno.EIO, "other")

    monkeypatch.setattr(backup, "_renameat2_call", other_error)
    with pytest.raises(OSError) as error:
        backup._rename_noreplace(source, destination.with_name("other"))
    assert error.value.errno == backup.errno.EIO


def test_rename_noreplace_preserves_renameat2_eexist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"new")
    destination.write_bytes(b"old")

    def collision(_source: Path, _destination: Path) -> None:
        raise FileExistsError(backup.errno.EEXIST, "exists")

    monkeypatch.setattr(backup, "_renameat2_call", collision)
    with pytest.raises(FileExistsError):
        backup._rename_noreplace(source, destination)
    assert destination.read_bytes() == b"old"


def test_rename_noreplace_posix_last_resort_uses_exclusive_placeholder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"new content")

    def unsupported(*_args: object, **_kwargs: object) -> None:
        raise OSError(backup.errno.ENOTSUP, "unsupported")

    monkeypatch.setattr(backup, "_renameat2_call", unsupported)
    monkeypatch.setattr(backup.os, "link", unsupported)
    monkeypatch.setattr(backup.sys, "platform", "darwin")

    backup._rename_noreplace(source, destination)

    assert destination.read_bytes() == b"new content"
    assert not source.exists()


def test_rename_noreplace_posix_removes_its_placeholder_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"new content")

    def unsupported(*_args: object, **_kwargs: object) -> None:
        raise OSError(backup.errno.ENOTSUP, "unsupported")

    def failed_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError(backup.errno.EIO, "replace failed")

    monkeypatch.setattr(backup, "_renameat2_call", unsupported)
    monkeypatch.setattr(backup.os, "link", unsupported)
    monkeypatch.setattr(backup.os, "replace", failed_replace)
    monkeypatch.setattr(backup.sys, "platform", "darwin")

    with pytest.raises(OSError, match="replace failed"):
        backup._rename_noreplace(source, destination)

    assert source.read_bytes() == b"new content"
    assert not destination.exists()


def test_rename_noreplace_posix_exclusive_create_preserves_racing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"new")

    def unsupported(*_args: object, **_kwargs: object) -> None:
        raise OSError(backup.errno.ENOTSUP, "unsupported")

    original_open = backup.os.open

    def create_racing_destination(path: object, flags: int, mode: int = 0o777) -> int:
        if Path(path) == destination:
            destination.write_bytes(b"created by another party")
        return original_open(path, flags, mode)

    monkeypatch.setattr(backup, "_renameat2_call", unsupported)
    monkeypatch.setattr(backup.os, "link", unsupported)
    monkeypatch.setattr(backup.os, "open", create_racing_destination)
    monkeypatch.setattr(backup.sys, "platform", "darwin")

    with pytest.raises(FileExistsError):
        backup._rename_noreplace(source, destination)

    assert source.read_bytes() == b"new"
    assert destination.read_bytes() == b"created by another party"


def test_rename_noreplace_windows_last_resort_uses_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"new")
    destination.write_bytes(b"old")

    def unsupported(*_args: object, **_kwargs: object) -> None:
        raise OSError(backup.errno.ENOTSUP, "unsupported")

    called = False

    def refusing_rename(source_path: Path, destination_path: Path) -> None:
        nonlocal called
        called = True
        assert source_path == source and destination_path == destination
        raise FileExistsError(backup.errno.EEXIST, "exists", destination)

    monkeypatch.setattr(backup, "_renameat2_call", unsupported)
    monkeypatch.setattr(backup.os, "link", unsupported)
    monkeypatch.setattr(backup.os, "rename", refusing_rename)
    monkeypatch.setattr(backup.sys, "platform", "win32")

    with pytest.raises(FileExistsError):
        backup._rename_noreplace(source, destination)

    assert called
    assert destination.read_bytes() == b"old"
    assert source.exists()


def test_backup_redacts_rtmp_and_srt_secrets_everywhere_without_source_writes(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    service = source / "basic/profiles/default/service.json"
    original_service = (
        '{"type":"rtmp_custom","settings":{"server":"rtmp://live.example.com/app/'
        'LIVE_SECRET_123","key":"","srt":"srt://host:9000?streamid=publish:live/'
        'SRT_ID_SECRET&passphrase=SRT_PASS_SECRET"}}'
    )
    service.write_text(original_service, encoding="utf-8")
    log = source / "logs/2026-01-01.txt"
    original_log = (
        "[obs-outputs] Connecting to RTMP URL rtmp://live.example.com/app/LIVE_SECRET_123...\n"
        "SRT srt://host:9000?streamid=publish:live/SRT_ID_SECRET&passphrase=SRT_PASS_SECRET\n"
    )
    log.write_text(original_log, encoding="utf-8")
    before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    assert before == {
        p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()
    }
    with zipfile.ZipFile(result.archive) as archive:
        contents = b"\n".join(archive.read(name) for name in archive.namelist())
        for secret in (b"LIVE_SECRET_123", b"SRT_ID_SECRET", b"SRT_PASS_SECRET"):
            assert secret not in contents


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


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("log.txt", 'key="<REDACTED>"'),
        ("log.txt", 'token="<REDACTED>"'),
        ("basic.ini", 'token="<REDACTED>"'),
    ],
)
def test_private_verifier_accepts_quoted_redaction_marker(
    tmp_path: Path, filename: str, content: str
) -> None:
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")

    assert not backup._secret_scan(path)


def test_backup_includes_log_after_quoted_credentials_are_redacted(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    (source / "logs/2026-01-03.txt").write_text(
        'key="QUOTED_KEY_SECRET" token="QUOTED_TOKEN_SECRET"\n', encoding="utf-8"
    )
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        name = "logs/2026-01-03.txt"
        assert name in archive.namelist()
        assert archive.read(name).decode("utf-8") == 'key="<REDACTED>" token="<REDACTED>"\n'


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_backup_redacts_bom_marked_utf16_logs(tmp_path: Path, encoding: str) -> None:
    source = fixture(tmp_path / "obs")
    log = source / "logs/2026-01-01.txt"
    bom = b"\xff\xfe" if encoding.endswith("le") else b"\xfe\xff"
    log.write_bytes(bom + "key=UTF16SECRETVAL\n".encode(encoding))
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        body = archive.read("logs/2026-01-01.txt")
    assert b"UTF16SECRETVAL" not in body
    assert b"<REDACTED>" in body


def test_backup_redacts_utf8_bom_and_omits_nul_text_with_warning(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    (source / "logs/2026-01-01.txt").write_bytes(b"\xef\xbb\xbfkey=UTF8SECRET\n")
    (source / "logs/2026-01-02.txt").write_bytes(b"bad\x00key=NUL_SECRET")
    unsafe = tmp_path / "unsafe.txt"
    unsafe.write_bytes(b"bad\x00key=NUL_SECRET")
    assert backup._secret_scan(unsafe)
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        names = archive.namelist()
        text = archive.read("logs/2026-01-01.txt")
        all_data = b"".join(archive.read(name) for name in names)
    assert "logs/2026-01-02.txt" not in names
    assert b"UTF8SECRET" not in all_data and b"NUL_SECRET" not in all_data
    assert "Could not safely include" in " ".join(result.warnings)
    assert b"<REDACTED>" in text


def test_bracket_heavy_log_redaction_and_verification_is_fast(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(('[{"ordinary": [1, 2, 3]}] text\n' * 70000), encoding="utf-8")
    assert path.stat().st_size >= 2 * 1024 * 1024
    started = time.perf_counter()
    backup.redact_file_with_secrets(path)
    assert not backup._secret_scan(path)
    assert time.perf_counter() - started < 8


def test_fifo_profile_is_skipped_without_blocking_and_source_is_unchanged(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unsupported on this platform")
    source = fixture(tmp_path / "obs")
    fifo = source / "basic/profiles/default/blocked.txt"
    os.mkfifo(fifo)
    before = {
        p.relative_to(source): (p.lstat().st_mode, p.read_bytes() if p.is_file() else None)
        for p in source.rglob("*")
        if not p.is_dir()
    }
    destination = tmp_path / "out"
    destination.mkdir()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(create_backup, source, destination)
        result = future.result(timeout=10)
    after = {
        p.relative_to(source): (p.lstat().st_mode, p.read_bytes() if p.is_file() else None)
        for p in source.rglob("*")
        if not p.is_dir()
    }
    assert before == after
    with zipfile.ZipFile(result.archive) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert any(
        item["path"].endswith("blocked.txt") and item["reason"] == "unsupported_file_type"
        for item in manifest["skipped"]
    )
    assert "basic/profiles/default/service.json" in zipfile.ZipFile(result.archive).namelist()


def test_read_consistent_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unsupported on this platform")
    fifo = tmp_path / "blocked.txt"
    os.mkfifo(fifo)
    target = tmp_path / "target.txt"
    errors: list[Exception] = []

    def read_fifo() -> None:
        try:
            backup._read_consistent(fifo, target, 1024)
        except Exception as error:
            errors.append(error)

    worker = Thread(target=read_fifo, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "FIFO read blocked"
    assert len(errors) == 1 and isinstance(errors[0], backup.UnsupportedFileType)


def test_create_backup_fifo_inventory_handler_collects_regular_files(
    tmp_path: Path, monkeypatch
) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unsupported on this platform")
    source = fixture(tmp_path / "obs")
    fifo = source / "basic/profiles/default/blocked.txt"
    os.mkfifo(fifo)
    ordinary = backup._inventory

    def inventory_with_fifo(root: Path, skipped: list[dict[str, str]]) -> list[Path]:
        return [*ordinary(root, skipped), fifo]

    monkeypatch.setattr(backup, "_inventory", inventory_with_fifo)
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert "basic/profiles/default/service.json" in archive.namelist()
    assert any(
        item["path"].endswith("blocked.txt") and item["reason"] == "unsupported_file_type"
        for item in manifest["skipped"]
    )


def test_short_numeric_secret_does_not_omit_log_but_long_duplicate_is_caught(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    log = source / "logs/2026-01-01.txt"
    log.write_text("SortKey: 1\naudio_key: 0\nother=1 0\n", encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        assert "logs/2026-01-01.txt" in archive.namelist()
        log_body = archive.read("logs/2026-01-01.txt")
        assert b"SortKey: 1" in log_body
        assert b"other=1 0" in log_body

    private = tmp_path / "duplicate.txt"
    private.write_text("password=LONGSECRET123\ncopy LONGSECRET123\n", encoding="utf-8")
    assert backup._contains_private_secret(private, {"LONGSECRET123"})


def test_cross_file_redaction_searches_long_numeric_credentials(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    service = source / "basic/profiles/default/service.json"
    service.write_text('{"password":"12345678"}', encoding="utf-8")
    log = source / "logs/2026-01-01.txt"
    log.write_text("connected using 12345678 ok\n", encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    with zipfile.ZipFile(result.archive) as archive:
        names = archive.namelist()
        log_body = archive.read("logs/2026-01-01.txt").decode("utf-8")
        all_content = b"".join(archive.read(name) for name in names)
        manifest = json.loads(archive.read("manifest.json"))
    assert "logs/2026-01-01.txt" in names
    assert not any(item["path"] == "logs/2026-01-01.txt" for item in manifest["skipped"])
    assert "connected using <REDACTED> ok" in log_body
    assert b"12345678" not in all_content


def test_numeric_json_credentials_are_harvested_for_log_scrubbing(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    service = source / "basic/profiles/default/service.json"
    service.write_text('{"settings":{"password":123456789,"token":1.25}}', encoding="utf-8")
    log = source / "logs/2026-01-01.txt"
    log.write_text("server accepted 123456789 and 1.25; ordinary 12345\n", encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        body = archive.read("logs/2026-01-01.txt").decode("utf-8")
    assert "123456789" not in body and "1.25" not in body
    assert "12345" in body


def test_weak_rtmp_and_generic_key_literals_do_not_rewrite_benign_logs_or_names(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    service = source / "basic/profiles/default/service.json"
    service.write_text(
        '{"settings":{"server":"rtmp://ingest.example.com/app/live",'
        '"key":"uniqueKeyZZZ999","SortKey":"Name","streamKey":"STREAMKEYSECRET999",'
        '"apiKey":"APIKEYSECRET999"},"sources":[{"name":"Name"}]}',
        encoding="utf-8",
    )
    log = source / "logs/2026-01-01.txt"
    log.write_text(
        "Connecting to rtmp://live.twitch.tv/app\n[rtmp stream: 'adv_stream'] go live now\n"
        "14:00:00.000: CPU Name: Test CPU\nSortKey=Name\n"
        "keys STREAMKEYSECRET999 APIKEYSECRET999\n",
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        names = archive.namelist()
        scene = json.loads(archive.read("basic/profiles/default/service.json"))
        assert "logs/2026-01-01.txt" in names
        body = archive.read("logs/2026-01-01.txt").decode("utf-8")
    assert scene["sources"][0]["name"] == "Name"
    assert "live.twitch.tv" in body and "go live now" in body and "CPU Name: Test CPU" in body
    assert "SortKey=Name" in body
    assert "STREAMKEYSECRET999" not in body and "APIKEYSECRET999" not in body


def test_percent_encoded_known_credentials_are_scrubbed_case_insensitively(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    (source / "basic/profiles/default/service.json").write_text(
        '{"settings":{"key":"abc/def+ghi="}}', encoding="utf-8"
    )
    (source / "logs/2026-01-01.txt").write_text(
        "seen abc/def+ghi= and abc%2Fdef%2Bghi%3D and abc%2fdef%2bghi%3d; benign %2F\n",
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        body = archive.read("logs/2026-01-01.txt").decode("utf-8")
    assert "abc/def+ghi=" not in body and "%2Fdef%2Bghi%3D" not in body
    assert "benign %2F" in body


@pytest.mark.parametrize(
    "files,secrets",
    [
        (
            {
                "basic/scenes/S.json": (
                    '{"sources":[{"hotkeys":{"libobs.mute":[{"key":"OBS_KEY_M",'
                    '"settings":{"key":"NESTED_STREAM_KEY_9988"}}]}}]}'
                )
            },
            ["NESTED_STREAM_KEY_9988"],
        ),
        (
            {"basic/scenes/S.json": '{"hotkeys":{"key":"live_actual_stream_key_zzzz"}}'},
            ["live_actual_stream_key_zzzz"],
        ),
        (
            {"basic/scenes/S.json": '{"bindings":{"settings":{"key":"BINDINGS_SETTINGS_KEY_42"}}}'},
            ["BINDINGS_SETTINGS_KEY_42"],
        ),
        (
            {"logs/a.txt": "source https://example.com/cb#access_token=FRAGMENTLOG99&foo=1\n"},
            ["FRAGMENTLOG99"],
        ),
        (
            {"logs/a.txt": "10:00:00.000: note Authorization: Api-Key SUPERAUTHSECRET99 later\n"},
            ["SUPERAUTHSECRET99"],
        ),
        (
            {
                "basic/profiles/P/service.json": '{"settings":{"password":123456789}}',
                "logs/a.txt": "server accepted 123456789\n",
            },
            ["123456789"],
        ),
        (
            {"basic/profiles/P/basic.ini": "[Output]\npassword = \\\n  CONT_SECRET_LINE\n"},
            ["CONT_SECRET_LINE"],
        ),
    ],
)
def test_g1_findings_do_not_ship_synthetic_secrets(tmp_path: Path, files, secrets) -> None:
    source = fixture(tmp_path / "obs")
    for relative, content in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        all_content = b"\n".join(archive.read(name) for name in archive.namelist())
    for secret in secrets:
        assert secret.encode() not in all_content
    assert not result.warnings


def test_cross_file_redaction_exempts_short_and_five_digit_literals(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    service = source / "basic/profiles/default/service.json"
    service.write_text(
        '{"password":"12345","token":"abc","bearer_token":"4096"}',
        encoding="utf-8",
    )
    log = source / "logs/2026-01-01.txt"
    log.write_text("secrets 12345 abc; benign 1 0 4096\n", encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    with zipfile.ZipFile(result.archive) as archive:
        log_body = archive.read("logs/2026-01-01.txt").decode("utf-8")
        service_body = json.loads(
            archive.read("basic/profiles/default/service.json").decode("utf-8")
        )
    assert log_body == "secrets 12345 abc; benign 1 0 4096\n"
    assert service_body == {
        "password": "<REDACTED>",
        "token": "<REDACTED>",
        "bearer_token": "<REDACTED>",
    }


def test_private_verifier_flags_long_numeric_secret(tmp_path: Path) -> None:
    private = tmp_path / "duplicate.txt"
    private.write_text("connected using 12345678\n", encoding="utf-8")

    assert backup._contains_private_secret(private, {"12345678"})
    assert not backup._contains_private_secret(private, {"12345", "abc"})


@pytest.mark.parametrize(
    "content",
    [
        "password=VALUE#TAIL\n",
        "apitoken=<REDACTED>&x\n",
        "serverpassword=<REDACTED>\\tail\n",
        "?twitchtoken=VALUE#TAIL\n",
        '{"key":"VALUE"}\n',
    ],
)
def test_independent_signature_scan_rejects_redactor_blind_spots(
    tmp_path: Path, monkeypatch, content: str
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(backup, "has_unredacted_embedded_json", lambda _text: False)
    monkeypatch.setattr(backup, "has_unredacted_fields", lambda *_args: False)
    monkeypatch.setattr(backup, "has_unredacted_ini_fields", lambda *_args: False)
    assert backup._secret_scan(path)


def test_large_assignment_log_redact_and_verify_is_fast(tmp_path: Path) -> None:
    path = tmp_path / "large.txt"
    path.write_text("key=1\n" * ((2 * 1024 * 1024 + 5) // 6), encoding="utf-8")
    assert path.stat().st_size >= 2 * 1024 * 1024
    started = time.perf_counter()
    backup.redact_file_with_secrets(path)
    assert not backup._secret_scan(path)
    assert time.perf_counter() - started < 8


def test_realistic_token_console_log_redact_and_verify_is_fast(tmp_path: Path) -> None:
    path = tmp_path / "console.txt"
    line = (
        "console: request token refreshed for browser source id=1234567890 status=ok "
        "method=GET response=200 latency=32ms\n"
    )
    path.write_text(line * ((1024 * 1024 + len(line) - 1) // len(line)), encoding="utf-8")
    assert path.stat().st_size >= 1024 * 1024
    started = time.perf_counter()
    backup.redact_file_with_secrets(path)
    assert not backup._secret_scan(path)
    assert time.perf_counter() - started < 8


def test_backslash_assignment_name_is_fast(tmp_path: Path) -> None:
    path = tmp_path / "hostile.txt"
    path.write_text("key " + "\\" * 20000 + "\n", encoding="utf-8")
    started = time.perf_counter()
    backup.redact_file_with_secrets(path)
    assert time.perf_counter() - started < 2


def test_backslash_quoted_password_is_fast(tmp_path: Path) -> None:
    path = tmp_path / "hostile.txt"
    path.write_text('password="' + "\\" * 16000 + "\n", encoding="utf-8")
    started = time.perf_counter()
    backup.redact_file_with_secrets(path)
    assert time.perf_counter() - started < 2


def test_dense_quoted_key_verification_is_linear(tmp_path: Path) -> None:
    path = tmp_path / "dense-keys.txt"
    path.write_text('"key": "abcd"\n' * 18000, encoding="utf-8")
    started = time.perf_counter()
    backup.redact_file_with_secrets(path)
    assert not backup._secret_scan(path)
    assert time.perf_counter() - started < 3


def test_benign_ffmpeg_muxer_log_redact_and_verify_is_fast(tmp_path: Path) -> None:
    path = tmp_path / "benign.txt"
    line = "10:00:00.123: [ffmpeg muxer: ...] settings: rate_control=CBR\n"
    path.write_text(line * ((1024 * 1024 + len(line) - 1) // len(line)), encoding="utf-8")
    started = time.perf_counter()
    backup.redact_file_with_secrets(path)
    assert not backup._secret_scan(path)
    assert time.perf_counter() - started < 6


@pytest.mark.parametrize(
    ("label", "content"),
    [
        ("backslashes", "\\" * (256 * 1024) + " key"),
        ("query", "http://h/?x=1" + "&a=b" * (256 * 1024 // 4) + " token=x"),
        ("semicolon", "a=b;" * (256 * 1024 // 4) + " key=x"),
        ("brace-quote", '{"' * (256 * 1024 // 2)),
    ],
)
def test_r4_hostile_inputs_redact_and_verify_under_three_seconds(
    tmp_path: Path, label: str, content: str
) -> None:
    path = tmp_path / f"{label}.txt"
    path.write_text(content, encoding="utf-8")
    started = time.perf_counter()
    _counts, _total, secrets = backup.redact_file_with_secrets(path)
    assert not backup._contains_private_secret(path, secrets)
    assert not backup._secret_scan(path)
    assert time.perf_counter() - started < 3


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("basic.ini", 'OBSBasic.StartStreaming={"key":"OBS_KEY_F9","token":"INI_SECRET"}'),
        ("current.txt", '{"settings":{"key":"LOG_SECRET","token":"LOG_TOKEN_SECRET"}}'),
        ("scene.json", json.dumps({"payload": '{"key":"SCENE_SECRET"}'})),
    ],
)
def test_private_verifier_detects_credentials_inside_embedded_json(
    tmp_path: Path, filename: str, content: str
) -> None:
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")

    assert backup._secret_scan(path)


@pytest.mark.parametrize(
    "line",
    [
        r"escaped {\"token\":\"ESCAPED_SECRET\"}",
        r'double {\\"token\\":\\"DOUBLE_ESC_SECRET\\"}',
        "repr {'token': 'SINGLE_SECRET'}",
        'trail {"token":"TRAILING_SECRET",}',
        '{"token" /*comment*/: "COMMENT_SECRET"}',
        '{"token" /** user token */: "DOC_COMMENT_SECRET"}',
        '{"token" /* foo * bar */: "STAR_COMMENT_SECRET"}',
        '{"token" // note\n: "SLASH_COMMENT_SECRET"}',
        '{"token" /* unclosed : "UNCLOSED_COMMENT_SECRET"}',
        '{"token" /* &#39;password&#39;:&#39;NESTED_COMMENT_SECRET&#39; */'
        ' : "OUTER_COMMENT_SECRET"}',
        "{&quot;token&quot;:&quot;HTML_SECRET&quot;}",
        "{&#34;token&#34;:&#34;NUM_ENTITY_SECRET&#34;}",
        "{&#x22;token&#x22;:&#x22;HEX_ENTITY_SECRET&#x22;}",
        "{&apos;password&apos;:&apos;APOS_SECRET&apos;}",
        "{&#39;password&#39;:&#39;NUM_APOS_SECRET&#39;}",
        "{&#x27;token&#x27;:&#x27;HEX_APOS_SECRET&#x27;}",
        "{&#034;token&#034;:&#034;PADDED_NUM_SECRET&#034;}",
        "{&#x0022;token&#x0022;:&#x0022;PADDED_HEX_SECRET&#x0022;}",
        "{`token`: `BACKTICK_SECRET`}",
    ],
)
def test_private_verifier_detects_non_strict_quoted_credentials(tmp_path: Path, line: str) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line, encoding="utf-8")

    assert backup._secret_scan(path)


def test_backup_redacts_credentials_hidden_by_comments_and_quote_entities(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    lines = (
        '{"token" /** user token */: "DOC_COMMENT_SECRET"}\n'
        '{"token" /* &#39;password&#39;:&#39;NESTED_COMMENT_SECRET&#39; */'
        ' : "OUTER_COMMENT_SECRET"}\n'
        '{"token" /* unclosed : "UNCLOSED_COMMENT_SECRET"}\n'
        "{&#x0022;token&#x0022;:&#x0022;PADDED_ENTITY_SECRET&#x0022;}\n"
        "{`token`: `BACKTICK_SECRET`}\n"
    )
    (source / "logs/2026-01-01.txt").write_text(lines, encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        name = "logs/2026-01-01.txt"
        assert name in archive.namelist()
        log = archive.read(name).decode("utf-8")
    for secret in (
        "DOC_COMMENT_SECRET",
        "NESTED_COMMENT_SECRET",
        "OUTER_COMMENT_SECRET",
        "UNCLOSED_COMMENT_SECRET",
        "PADDED_ENTITY_SECRET",
        "BACKTICK_SECRET",
    ):
        assert secret not in log


@pytest.mark.parametrize("comment", ["// note\n", "/* note */\n", "/* note\n*/\n"])
def test_backup_preserves_hotkey_binding_with_c_style_comment_before_json(
    tmp_path: Path, comment: str
) -> None:
    source = fixture(tmp_path / "obs")
    (source / "basic/profiles/default/basic.ini").write_text(
        "[Output]\nOBSBasic.StartStreaming=\n"
        f"{comment}"
        '{"key":"OBS_KEY_F9","settings":{"key":"NESTED_HOTKEY_SECRET"}}\n'
        "OBSBasic.StopRecording=\n"
        f"{comment}"
        '{"key":"OBS_KEY_F10","settings":{"key":"NESTED_HOTKEY_SECRET_2"}}\n',
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        ini = archive.read("basic/profiles/default/basic.ini").decode("utf-8")
    assert '"key":"OBS_KEY_F9"' in ini
    assert '"key":"OBS_KEY_F10"' in ini
    assert "NESTED_HOTKEY_SECRET" not in ini
    assert "NESTED_HOTKEY_SECRET_2" not in ini


def test_backup_includes_redacted_logs_with_mixed_quote_encodings(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    (source / "logs/2026-01-01.txt").write_text(
        '{"token" /* note: "<REDACTED>" more : "UNCLOSED_SECOND_SECRET"}\n'
        '{"token" /*\n: "UNCLOSED_MULTILINE_SECRET"}\n'
        '{"token" /*\nnote\n*/ : "CLOSED_MULTILINE_SECRET"}\n'
        "password: &#39;ENTITY_QUOTE_SECRET&#39;\n"
        "token: `BACKTICK_QUOTE_SECRET`\n"
        "{“token”: “CURLY_QUOTE_SECRET”}\n"
        "{%22token%22:%22PERCENT_QUOTE_SECRET%22}\n"
        "{%27password%27:%27PERCENT_APOS_SECRET%27}\n"
        "{\u2018token\u2019: \u2018CURLY_APOS_VALUE\u2019}\n"
        "{&ldquo;token&rdquo;:&ldquo;NAMED_CURLY_SECRET&rdquo;}\n"
        "filter chroma color key /* note */: #00ff00\n"
        "hotkey binding key // note\n: F9\n",
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        name = "logs/2026-01-01.txt"
        assert name in archive.namelist()
        log = archive.read(name).decode("utf-8")
    for secret in (
        "UNCLOSED_SECOND_SECRET",
        "UNCLOSED_MULTILINE_SECRET",
        "CLOSED_MULTILINE_SECRET",
        "ENTITY_QUOTE_SECRET",
        "BACKTICK_QUOTE_SECRET",
        "CURLY_QUOTE_SECRET",
        "PERCENT_QUOTE_SECRET",
        "PERCENT_APOS_SECRET",
        "CURLY_APOS_VALUE",
        "NAMED_CURLY_SECRET",
    ):
        assert secret not in log
    assert "key /* note */: #00ff00" in log
    assert "key // note\n: F9" in log


@pytest.mark.parametrize(
    "line",
    [
        "password: &#39;<REDACTED>&#39;",
        "token: `<REDACTED>`",
        "{“token”: “<REDACTED>”}",
        "{%22token%22:%22<REDACTED>%22}",
        "{%27password%27:%27<REDACTED>%27}",
        "{\u2018token\u2019: \u2018<REDACTED>\u2019}",
        "{&ldquo;token&rdquo;:&ldquo;<REDACTED>&rdquo;}",
    ],
)
def test_private_verifier_accepts_redacted_values_with_encoded_quotes(
    tmp_path: Path, line: str
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line, encoding="utf-8")

    assert not backup._secret_scan(path)


def test_private_verifier_does_not_join_quoted_assignments_across_lines(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text('loaded {\\"token\\"\nsee "docs"\n', encoding="utf-8")

    assert not backup._secret_scan(path)


def test_backup_redacts_nested_key_in_obsbasic_binding_without_losing_hotkey(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "obs")
    (source / "basic/profiles/default/basic.ini").write_text(
        '[Output]\nOBSBasic.StartStreaming={"key":"OBS_KEY_F9",'
        '"token":"INI_TOKEN_SECRET","settings":{"key":"INI_NESTED_SECRET"}}\n',
        encoding="utf-8",
    )
    (source / "logs/2026-01-01.txt").write_text(
        'OBSBasic.StartStreaming={"key":"OBS_KEY_F9","settings":{"key":"LOG_NESTED_SECRET"}}\n',
        encoding="utf-8",
    )
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        ini = archive.read("basic/profiles/default/basic.ini").decode("utf-8")
        log = archive.read("logs/2026-01-01.txt").decode("utf-8")
    assert '"key":"OBS_KEY_F9"' in ini and '"key":"<REDACTED>"' in ini
    assert "INI_TOKEN_SECRET" not in ini and "INI_NESTED_SECRET" not in ini
    assert "LOG_NESTED_SECRET" not in log


def test_backup_preserves_hotkeys_and_chroma_after_json_log_fragment(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    lines = (
        '{"width": 1920, "height": 1080}\nfilter chroma color key: #00ff00\nhotkey binding key=F9\n'
    )
    (source / "logs/2026-01-01.txt").write_text(lines, encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        assert archive.read("logs/2026-01-01.txt").decode("utf-8") == lines


def test_backup_redacts_multiline_obsbasic_json_value_without_truncation(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    ini = (
        "[Output]\nOBSBasic.StartStreaming=\n"
        '{"key":"OBS_KEY_F9","settings":{"key":"MULTILINE_STREAM_SECRET",'
        '"token":"MULTILINE_TOKEN_SECRET"}}\n'
    )
    (source / "basic/profiles/default/basic.ini").write_text(ini, encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        cleaned = archive.read("basic/profiles/default/basic.ini").decode("utf-8")
    assert '"key":"OBS_KEY_F9"' in cleaned
    assert '"key":"<REDACTED>"' in cleaned
    assert "MULTILINE_STREAM_SECRET" not in cleaned
    assert "MULTILINE_TOKEN_SECRET" not in cleaned


def test_backup_preserves_hotkey_binding_with_blank_line_before_json(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    ini = (
        "[Output]\nOBSBasic.StartStreaming=\n\n"
        '{"key":"OBS_KEY_F9","settings":{"key":"BLANK_LINE_STREAM_SECRET"}}\n'
    )
    (source / "basic/profiles/default/basic.ini").write_text(ini, encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        cleaned = archive.read("basic/profiles/default/basic.ini").decode("utf-8")
    assert '"key":"OBS_KEY_F9"' in cleaned
    assert '"key":"<REDACTED>"' in cleaned
    assert "BLANK_LINE_STREAM_SECRET" not in cleaned


@pytest.mark.parametrize("comment", ["# retained\n", "; retained\n"])
def test_backup_preserves_hotkey_binding_with_comment_before_json(
    tmp_path: Path, comment: str
) -> None:
    source = fixture(tmp_path / "obs")
    ini = (
        "[Output]\nOBSBasic.StartStreaming=\n"
        f"{comment}"
        '{"key":"OBS_KEY_F9","settings":{"key":"COMMENT_LINE_STREAM_SECRET"}}\n'
    )
    (source / "basic/profiles/default/basic.ini").write_text(ini, encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        cleaned = archive.read("basic/profiles/default/basic.ini").decode("utf-8")
    assert '"key":"OBS_KEY_F9"' in cleaned
    assert '"key":"<REDACTED>"' in cleaned
    assert "COMMENT_LINE_STREAM_SECRET" not in cleaned


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


def test_round4_end_to_end_structural_redaction_keeps_scene_ini_and_log(tmp_path: Path) -> None:
    source = fixture(tmp_path / "obs")
    destination = tmp_path / "out"
    destination.mkdir()
    secrets = [
        "SCENE_TOKEN_R4",
        "GLOBAL_WS_R4",
        "AUTH_NO_SCHEME_R4",
        "AUTH_SCHEME_R4",
        "CLI_PASS_R4",
        "GLUED_PASS_R4",
        "COOKIE_R4",
    ]
    scene = {
        "sources": [
            {
                "id": "browser_source",
                "settings": {
                    "url": "https://example.com/widget?token=SCENE_TOKEN_R4&region=us",
                    "width": 800,
                },
            },
            {"hotkeys": {"mute": [{"key": "OBS_KEY_M"}], "unmute": [{"key": "OBS_KEY_U"}]}},
        ]
    }
    scene_path = source / "basic/scenes/Main.json"
    scene_path.write_text(json.dumps(scene, indent=2), encoding="utf-8")
    basic = source / "basic/profiles/default/basic.ini"
    basic.write_text(
        '[Hotkeys]\nOBSBasic.StartStreaming={"bindings":[{"key":"OBS_KEY_F9"},{"key":"OBS_KEY_F10"}]}\n',
        encoding="utf-8",
    )
    (source / "global.ini").write_text(
        "[OBSWebSocket]\nServerPassword=GLOBAL_WS_R4\n", encoding="utf-8"
    )
    log = source / "logs/2026-09-30.txt"
    log.write_text(
        "Authorization: AUTH_NO_SCHEME_R4 (expired)\n"
        "Authorization: Bearer AUTH_SCHEME_R4 - retrying\n"
        "Command Line Arguments: --websocket_password CLI_PASS_R4 --foo\n"
        "token=abc;password: GLUED_PASS_R4\nCookie: a=1; b=COOKIE_R4\n"
        "Raw config value was GLOBAL_WS_R4\n",
        encoding="utf-8",
    )
    before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}

    result = create_backup(source, destination, now=datetime(2026, 9, 30, 10, 0, 0))

    assert not result.warnings
    with zipfile.ZipFile(result.archive) as archive:
        names = archive.namelist()
        assert "basic/scenes/Main.json" in names
        assert "basic/profiles/default/basic.ini" in names
        assert "global.ini" in names
        assert "logs/2026-09-30.txt" in names
        payload = b"".join(archive.read(name) for name in names)
        assert all(secret.encode() not in payload for secret in secrets)
        cleaned_scene = json.loads(archive.read("basic/scenes/Main.json"))
        assert cleaned_scene["sources"][1]["hotkeys"]["mute"][0]["key"] == "OBS_KEY_M"
        cleaned_ini = archive.read("basic/profiles/default/basic.ini")
        assert b"OBS_KEY_F9" in cleaned_ini and b"OBS_KEY_F10" in cleaned_ini
    after = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    assert after == before


@pytest.mark.parametrize("line", ["[" * 100000, "x" * (512 * 1024 + 1)])
def test_unsafe_deep_or_long_log_is_omitted_and_backup_continues(tmp_path: Path, line: str) -> None:
    source = fixture(tmp_path / "obs")
    (source / "logs/2026-09-30.txt").write_text(line, encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()
    result = create_backup(source, destination)
    with zipfile.ZipFile(result.archive) as archive:
        assert "basic/profiles/default/service.json" in archive.namelist()
        assert "logs/2026-09-30.txt" not in archive.namelist()
        manifest = json.loads(archive.read("manifest.json"))
        assert any(item["path"] == "logs/2026-09-30.txt" for item in manifest["skipped"])
    assert any(
        "Could not safely include logs/2026-09-30.txt" in warning for warning in result.warnings
    )
