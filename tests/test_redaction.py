import json
from pathlib import Path

from tempesttrace.redaction import _is_sensitive_key, has_unredacted_fields, redact_file


def test_structured_redaction_preserves_other_values(tmp_path: Path) -> None:
    p = tmp_path / "service.json"
    original = {
        "type": "rtmp_custom",
        "settings": {
            "apiKey": "API_SECRET",
            "key": "STREAM_SECRET",
            "server": "rtmp://example",
            "streamlabs": {"source": "x", "token": "TOKEN_SECRET"},
        },
    }
    p.write_text(json.dumps(original), encoding="utf-8")
    categories, count = redact_file(p)
    value = json.loads(p.read_text(encoding="utf-8"))
    assert value["settings"]["key"] == "<REDACTED>"
    assert value["settings"]["server"] == "rtmp://example"
    assert value["settings"]["streamlabs"]["source"] == "x"
    assert value["settings"]["streamlabs"]["token"] == "<REDACTED>"
    assert value["settings"]["apiKey"] == "<REDACTED>"
    assert count == 3 and categories == {"credential_field": 3}


def test_ini_and_log_credentials_are_redacted(tmp_path: Path) -> None:
    ini = tmp_path / "basic.ini"
    ini.write_text("[Stream1]\nkey=INI_SECRET\nserver=rtmp://x\n", encoding="utf-8")
    categories, count = redact_file(ini)
    assert "INI_SECRET" not in ini.read_text(encoding="utf-8")
    assert "server=rtmp://x" in ini.read_text(encoding="utf-8")
    assert categories["credential_field"] == count == 1
    log = tmp_path / "current.txt"
    log.write_text("Starting stream key=LOG_SECRET connected\n", encoding="utf-8")
    _, count = redact_file(log)
    assert "LOG_SECRET" not in log.read_text(encoding="utf-8")
    assert count == 1


def test_ini_backup_is_redacted(tmp_path: Path) -> None:
    backup = tmp_path / "advanced.ini.bak"
    backup.write_text("[Stream]\nstreamKey=BACKUP_SECRET\n", encoding="utf-8")
    redact_file(backup)
    assert "BACKUP_SECRET" not in backup.read_text(encoding="utf-8")


def test_quoted_credentials_are_redacted_and_detected(tmp_path: Path) -> None:
    log = tmp_path / "quoted.txt"
    log.write_text("key=\"QUOTED_SECRET\" password='OTHER_SECRET'\n", encoding="utf-8")
    categories, count = redact_file(log)
    assert "QUOTED_SECRET" not in log.read_text(encoding="utf-8")
    assert "OTHER_SECRET" not in log.read_text(encoding="utf-8")
    assert categories == {"credential_pattern": 2} and count == 2

    ini = tmp_path / "quoted.ini"
    ini.write_text('password="INI_QUOTED_SECRET"\n', encoding="utf-8")
    redact_file(ini)
    assert "INI_QUOTED_SECRET" not in ini.read_text(encoding="utf-8")

    assert has_unredacted_fields({"password": '"JSON_QUOTED_SECRET"'})


def test_ordinary_words_ending_in_credential_suffix_are_not_sensitive() -> None:
    assert not _is_sensitive_key("monkey")
    assert not _is_sensitive_key("tokenizer")
    assert _is_sensitive_key("apiKey")
    assert _is_sensitive_key("stream_key")


def test_url_query_credentials_and_log_token_variants_are_redacted(tmp_path: Path) -> None:
    service = tmp_path / "service.json"
    service.write_text(
        json.dumps(
            {
                "widget_url": "https://streamlabs.com/widgets/alert-box/v3/WIDGET_PATH_TOKEN"
                "?theme=dark&token=WIDGET_QUERY_TOKEN",
                "alert_box_url": "https://streamlabs.com/alert-box/v3/ALERT_BOX_PATH_TOKEN",
                "server": "rtmp://ingest.example/app?key=RTMP_KEY&region=us",
                "api_url": "https://example.test/?access_token=ACCESS_TOKEN&keep=yes",
            }
        ),
        encoding="utf-8",
    )
    redact_file(service)
    value = json.loads(service.read_text(encoding="utf-8"))
    assert "WIDGET_PATH_TOKEN" not in value["widget_url"]
    assert "ALERT_BOX_PATH_TOKEN" not in value["alert_box_url"]
    assert "WIDGET_QUERY_TOKEN" not in value["widget_url"]
    assert "RTMP_KEY" not in value["server"]
    assert "ACCESS_TOKEN" not in value["api_url"]
    assert "theme=dark" in value["widget_url"] and "region=us" in value["server"]
    assert "keep=yes" in value["api_url"]

    log = tmp_path / "network.txt"
    log.write_text(
        "api_key=LOG_API_KEY token=LOG_TOKEN "
        "url=https://example.test/live?access_token=URL_TOKEN&quality=high\n"
        "hotkey binding key=F9\n",
        encoding="utf-8",
    )
    redact_file(log)
    cleaned = log.read_text(encoding="utf-8")
    for secret in ("LOG_API_KEY", "LOG_TOKEN", "URL_TOKEN"):
        assert secret not in cleaned
    assert "quality=high" in cleaned
    assert "hotkey binding key=F9" in cleaned


def test_key_context_and_case_variants_preserve_hotkey_bindings(tmp_path: Path) -> None:
    service = tmp_path / "service.json"
    service.write_text(
        json.dumps(
            {
                "settings": {
                    "api_key": "API_KEY_SECRET",
                    "apikey": "APIKEY_SECRET",
                    "authToken": "AUTH_TOKEN_SECRET",
                    "streamPassword": "STREAM_PASSWORD_SECRET",
                    "key": "STREAM_KEY_SECRET",
                }
            }
        ),
        encoding="utf-8",
    )
    redact_file(service)
    settings = json.loads(service.read_text(encoding="utf-8"))["settings"]
    assert all(settings[name] == "<REDACTED>" for name in settings)

    hotkeys = tmp_path / "hotkeys.json"
    hotkeys.write_text(
        json.dumps({"bindings": [{"key": "F9", "key_modifier": "SHIFT"}]}),
        encoding="utf-8",
    )
    redact_file(hotkeys)
    assert json.loads(hotkeys.read_text(encoding="utf-8"))["bindings"][0]["key"] == "F9"
    assert not has_unredacted_fields({"bindings": [{"key": "F9"}]}, ("hotkeys.json",))


def test_short_credentials_do_not_corrupt_substring_matches(tmp_path: Path) -> None:
    log = tmp_path / "short.txt"
    log.write_text("token=x description=texture\n", encoding="utf-8")
    redact_file(log)
    assert log.read_text(encoding="utf-8") == "token=<REDACTED> description=texture\n"

    structured = tmp_path / "service.json"
    structured.write_text(
        json.dumps({"token": "x", "mirror": "x", "description": "texture"}),
        encoding="utf-8",
    )
    redact_file(structured)
    value = json.loads(structured.read_text(encoding="utf-8"))
    assert value == {"token": "<REDACTED>", "mirror": "<REDACTED>", "description": "texture"}


def test_duplicate_credentials_under_nonsensitive_keys_are_counted(tmp_path: Path) -> None:
    structured = tmp_path / "service.json"
    structured.write_text(
        json.dumps(
            {
                "token": "DUPLICATE_SECRET",
                "mirror": "DUPLICATE_SECRET",
                "history": ["DUPLICATE_SECRET"],
            }
        ),
        encoding="utf-8",
    )

    categories, count = redact_file(structured)

    value = json.loads(structured.read_text(encoding="utf-8"))
    assert value == {
        "token": "<REDACTED>",
        "mirror": "<REDACTED>",
        "history": ["<REDACTED>"],
    }
    assert categories == {"credential_field": 3}
    assert count == 3
