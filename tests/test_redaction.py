import json
import random
import time
from pathlib import Path

import pytest

from tempesttrace.backup import _contains_private_secret, _secret_scan
from tempesttrace.redaction import (
    RULE_VERSION,
    _is_sensitive_key,
    has_unredacted_embedded_json,
    has_unredacted_fields,
    has_unredacted_ini_fields,
    read_text_safely,
    redact_file,
    redact_file_with_secrets,
)


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


def test_credentials_inside_json_encoded_strings_are_redacted(tmp_path: Path) -> None:
    path = tmp_path / "scene.json"
    path.write_text(
        json.dumps(
            {
                "payload": '{"key": "ENCODED_KEY_SECRET", "token": "ENCODED_TOKEN_SECRET"}',
                "hotkeys": {"libobs.mute": {"key": "F9"}},
            }
        ),
        encoding="utf-8",
    )

    redact_file(path)

    value = json.loads(path.read_text(encoding="utf-8"))
    assert json.loads(value["payload"]) == {"key": "<REDACTED>", "token": "<REDACTED>"}
    assert value["hotkeys"]["libobs.mute"]["key"] == "F9"


def test_quoted_json_credentials_in_ini_and_logs_are_redacted(tmp_path: Path) -> None:
    ini = tmp_path / "basic.ini"
    ini.write_text(
        '[Output]\nOBSBasic.StartStreaming={"key":"OBS_KEY_F9","token":"INI_JSON_SECRET"}\n',
        encoding="utf-8",
    )
    log = tmp_path / "current.txt"
    log.write_text(
        '{"settings":{"key":"LOG_JSON_SECRET","token":"LOG_TOKEN_SECRET"}}\n',
        encoding="utf-8",
    )

    redact_file(ini)
    redact_file(log)

    assert '"key":"OBS_KEY_F9"' in ini.read_text(encoding="utf-8")
    assert "INI_JSON_SECRET" not in ini.read_text(encoding="utf-8")
    assert "LOG_JSON_SECRET" not in log.read_text(encoding="utf-8")
    assert "LOG_TOKEN_SECRET" not in log.read_text(encoding="utf-8")


def test_obsbasic_hotkey_context_does_not_exempt_nested_settings_key(tmp_path: Path) -> None:
    ini = tmp_path / "basic.ini"
    ini.write_text(
        '[Output]\nOBSBasic.StartStreaming={"key":"OBS_KEY_F9",'
        '"settings":{"key":"NESTED_STREAM_SECRET"},"token":"TOKEN_SECRET"}\n',
        encoding="utf-8",
    )
    log = tmp_path / "current.txt"
    log.write_text(
        'OBSBasic.StartStreaming={"key":"OBS_KEY_F9",'
        '"settings":{"key":"LOG_NESTED_STREAM_SECRET"}}\n',
        encoding="utf-8",
    )

    redact_file(ini)
    redact_file(log)

    ini_clean = ini.read_text(encoding="utf-8")
    log_clean = log.read_text(encoding="utf-8")
    assert '"key":"OBS_KEY_F9"' in ini_clean and '"key":"<REDACTED>"' in ini_clean
    assert "NESTED_STREAM_SECRET" not in ini_clean and "TOKEN_SECRET" not in ini_clean
    assert "LOG_NESTED_STREAM_SECRET" not in log_clean


def test_credential_free_embedded_json_keeps_its_original_formatting(tmp_path: Path) -> None:
    path = tmp_path / "scene.json"
    layout = '{"width": 1920, "height": 1080}'
    path.write_text(json.dumps({"layout": layout}), encoding="utf-8")

    categories, count = redact_file(path)

    assert categories == {} and count == 0
    assert json.loads(path.read_text(encoding="utf-8"))["layout"] == layout


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
        '{"token" /* note: "<REDACTED>" more : "UNCLOSED_SECOND_SECRET"}',
        '{"token" /*\n: "UNCLOSED_MULTILINE_SECRET"}',
        '{"token" /*\nnote\n*/ : "CLOSED_MULTILINE_SECRET"}',
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
        "{“token”: “CURLY_QUOTE_SECRET”}",
        "{%22token%22:%22PERCENT_QUOTE_SECRET%22}",
        "{%27password%27:%27PERCENT_APOS_SECRET%27}",
        "{\u2018token\u2019: \u2018CURLY_APOS_VALUE\u2019}",
        "{&ldquo;token&rdquo;:&ldquo;NAMED_CURLY_SECRET&rdquo;}",
    ],
)
def test_non_strict_quoted_credential_text_is_redacted(tmp_path: Path, line: str) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line + "\n", encoding="utf-8")

    redact_file(path)

    cleaned = path.read_text(encoding="utf-8")
    for secret in (
        "ESCAPED_SECRET",
        "DOUBLE_ESC_SECRET",
        "SINGLE_SECRET",
        "TRAILING_SECRET",
        "COMMENT_SECRET",
        "DOC_COMMENT_SECRET",
        "STAR_COMMENT_SECRET",
        "SLASH_COMMENT_SECRET",
        "UNCLOSED_COMMENT_SECRET",
        "NESTED_COMMENT_SECRET",
        "OUTER_COMMENT_SECRET",
        "HTML_SECRET",
        "NUM_ENTITY_SECRET",
        "HEX_ENTITY_SECRET",
        "APOS_SECRET",
        "NUM_APOS_SECRET",
        "HEX_APOS_SECRET",
        "PADDED_NUM_SECRET",
        "PADDED_HEX_SECRET",
        "BACKTICK_SECRET",
        "UNCLOSED_SECOND_SECRET",
        "CURLY_QUOTE_SECRET",
        "PERCENT_QUOTE_SECRET",
        "UNCLOSED_MULTILINE_SECRET",
        "CLOSED_MULTILINE_SECRET",
        "PERCENT_APOS_SECRET",
        "CURLY_APOS_VALUE",
        "NAMED_CURLY_SECRET",
    ):
        assert secret not in cleaned


def test_non_strict_assignment_redaction_stays_on_its_line(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text('loaded {\\"token\\":\\"ESCAPED_SECRET\\"}\nsee "docs"\n', encoding="utf-8")

    redact_file(path)

    assert path.read_text(encoding="utf-8") == (
        'loaded {\\"token\\":\\"<REDACTED>\\"}\nsee "docs"\n'
    )


def test_ordinary_words_ending_in_credential_suffix_are_not_sensitive() -> None:
    assert not _is_sensitive_key("monkey")
    assert not _is_sensitive_key("tokenizer")
    assert _is_sensitive_key("apiKey")
    assert _is_sensitive_key("stream_key")
    assert _is_sensitive_key("CUSTOMTOKEN")
    assert _is_sensitive_key("REFRESH_TOKEN")
    assert _is_sensitive_key("OAUTH_TOKEN")


def test_redacts_uppercase_unknown_credential_suffix(tmp_path: Path) -> None:
    service = tmp_path / "service.json"
    service.write_text(
        json.dumps(
            {
                "CUSTOMTOKEN": "CUSTOM_SECRET",
                "REFRESH_TOKEN": "REFRESH_SECRET",
                "OAUTH_TOKEN": "OAUTH_SECRET",
            }
        ),
        encoding="utf-8",
    )

    redact_file(service)

    assert json.loads(service.read_text(encoding="utf-8")) == {
        "CUSTOMTOKEN": "<REDACTED>",
        "REFRESH_TOKEN": "<REDACTED>",
        "OAUTH_TOKEN": "<REDACTED>",
    }


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


def test_bare_key_is_redacted_in_backup_and_scene_files_but_not_hotkeys(tmp_path: Path) -> None:
    for filename in ("service.json.bak", "main.json", "Streaming Hotkeys.json"):
        path = tmp_path / filename
        path.write_text(
            json.dumps(
                {
                    "settings": {"key": "STREAM_KEY_SECRET"},
                    "hotkeys": [{"key": "F9"}],
                }
            ),
            encoding="utf-8",
        )

        redact_file(path)

        value = json.loads(path.read_text(encoding="utf-8"))
        assert value["settings"]["key"] == "<REDACTED>"
        assert value["hotkeys"][0]["key"] == "F9"
        assert not has_unredacted_fields(value, (path.name,))


def test_log_redaction_preserves_chroma_color_key_value(tmp_path: Path) -> None:
    log = tmp_path / "current.txt"
    original = "filter chroma color key: #00ff00 key=STREAM_SECRET\n"
    log.write_text(original, encoding="utf-8")

    redact_file(log)

    assert log.read_text(encoding="utf-8") == "filter chroma color key: #00ff00 key=<REDACTED>\n"


@pytest.mark.parametrize(
    "line",
    [
        "filter chroma color key /* note */: #00ff00",
        "filter chroma color key // note\n: #00ff00",
        "hotkey binding key /* note */: F9",
        "hotkey binding key // note\n: F9",
    ],
)
def test_noncredential_key_with_comment_is_preserved(tmp_path: Path, line: str) -> None:
    log = tmp_path / "current.txt"
    log.write_text(line + "\n", encoding="utf-8")

    redact_file(log)

    assert log.read_text(encoding="utf-8") == line + "\n"


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


@pytest.mark.parametrize("scheme", ["rtmp", "RTMPS", "rtmpe", "rtmpt", "rtmpte", "rtmfp"])
def test_rtmp_family_stream_key_redaction_preserves_punctuation_and_query(
    tmp_path: Path, scheme: str
) -> None:
    path = tmp_path / "network.txt"
    path.write_text(
        f"{scheme}://host:1935/app/live_SECRET?quality=high...\n",
        encoding="utf-8",
    )
    categories, count = redact_file(path)
    assert path.read_text(encoding="utf-8") == (
        f"{scheme}://host:1935/app/<REDACTED>?quality=high...\n"
    )
    assert categories == {"credential_pattern": 1} and count == 1
    assert not _secret_scan(path)


@pytest.mark.parametrize("punctuation", [",", ")", '"', "'", "..."])
def test_rtmp_key_redaction_preserves_attached_sentence_punctuation(
    tmp_path: Path, punctuation: str
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(f"connect rtmp://host/app/key_SECRET{punctuation}\n", encoding="utf-8")
    redact_file(path)
    assert path.read_text(encoding="utf-8") == (
        f"connect rtmp://host/app/<REDACTED>{punctuation}\n"
    )


def test_rtmp_single_segment_is_preserved_and_query_secrets_redacted(tmp_path: Path) -> None:
    path = tmp_path / "service.json"
    path.write_text(
        json.dumps(
            {
                "one": "rtmp://live.twitch.tv/app",
                "two": "rtmps://a.rtmps.youtube.com:443/live2",
                "srt": "srt://host:9000?streamid=publish:live/SID&passphrase=PASS",
            }
        ),
        encoding="utf-8",
    )
    redact_file(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    assert value["one"] == "rtmp://live.twitch.tv/app"
    assert value["two"] == "rtmps://a.rtmps.youtube.com:443/live2"
    assert "SID" not in value["srt"] and "PASS" not in value["srt"]


@pytest.mark.parametrize(
    "name",
    [
        "passphrase",
        "pwd",
        "cookie",
        "cookies",
        "sessionid",
        "session_id",
        "jwt",
        "credential",
        "credentials",
        "streamid",
        "SESSION-ID",
    ],
)
def test_new_sensitive_field_names_redacted_and_verified(tmp_path: Path, name: str) -> None:
    path = tmp_path / "service.json"
    path.write_text(json.dumps({name: "FIELD_SECRET"}), encoding="utf-8")
    redact_file(path)
    assert json.loads(path.read_text(encoding="utf-8"))[name] == "<REDACTED>"
    assert not has_unredacted_fields({name: "<REDACTED>"})
    assert has_unredacted_fields({name: "FIELD_SECRET"})


def test_false_positive_fields_and_single_segment_url_are_preserved(tmp_path: Path) -> None:
    original = {
        "use_auth": True,
        "auth_type": "basic",
        "key_color": "#00ff00",
        "key_color_type": 1,
        "keyint_sec": 2,
        "hotkeys": [{"key": "F9"}],
        "server": "rtmp://live.twitch.tv/app",
    }
    path = tmp_path / "scene.json"
    path.write_text(json.dumps(original), encoding="utf-8")
    redact_file(path)
    assert json.loads(path.read_text(encoding="utf-8")) == original
    assert not _is_sensitive_key("auth") and not _is_sensitive_key("pass")
    assert not _is_sensitive_key("signature")


def test_url_embedded_stream_key_is_collected_for_document_wide_scrubbing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "service.json"
    path.write_text(
        json.dumps(
            {"server": "rtmp://host/app/SAME_STREAM_SECRET", "mirror": "SAME_STREAM_SECRET"}
        ),
        encoding="utf-8",
    )
    redact_file(path)
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "server": "rtmp://host/app/<REDACTED>",
        "mirror": "<REDACTED>",
    }


def test_nonsecret_obs_ini_values_and_obsbasic_hotkey_survive(tmp_path: Path) -> None:
    path = tmp_path / "basic.ini"
    original = (
        "use_auth=true\nauth_type=basic\nkey_color=#00ff00\nkey_color_type=1\n"
        'keyint_sec=2\nOBSBasic.StartStreaming={"key":"F9"}\n'
    )
    path.write_text(original, encoding="utf-8")
    redact_file(path)
    assert path.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("filename", ["service.json", "basic.ini", "network.txt"])
def test_url_path_and_query_secrets_are_detected_in_all_formats(
    tmp_path: Path, filename: str
) -> None:
    value = "rtmp://host/app/STREAM_SECRET?passphrase=PASS_SECRET&streamid=SID_SECRET"
    path = tmp_path / filename
    content = (
        json.dumps({"server": value})
        if filename.endswith(".json")
        else (f"server={value}\n" if filename.endswith(".ini") else f"Connecting to {value}...\n")
    )
    path.write_text(content, encoding="utf-8")
    assert backup_secret_scan(path)
    redact_file(path)
    cleaned = path.read_text(encoding="utf-8")
    for secret in ("STREAM_SECRET", "PASS_SECRET", "SID_SECRET"):
        assert secret not in cleaned
    assert not backup_secret_scan(path)
    if filename.endswith(".json"):
        assert not has_unredacted_fields(json.loads(cleaned))
    elif filename.endswith(".ini"):
        assert not has_unredacted_ini_fields(cleaned, filename)
    else:
        assert not has_unredacted_embedded_json(cleaned)


def backup_secret_scan(path: Path) -> bool:
    return _secret_scan(path)


def test_rule_version_is_twelve() -> None:
    assert RULE_VERSION == 12


@pytest.mark.parametrize(
    "line",
    [
        "https://example.com/overlay?stream_key=QSECRET123",
        "https://example.com/overlay?streamkey=QSECRET123",
        "https://example.com/overlay?streamKey=QSECRET123",
        "https://example.com/overlay?secret_key=QSECRET123",
        "https://example.com/overlay?private_key=QSECRET123",
        "https://example.com/overlay?auth=QSECRET123",
        "https://example.com/overlay?sig=QSECRET123",
        "private_key=PKSECRET",
        "secret_key: SKSECRET",
        "aws_secret_access_key=AKSECRET",
        "twitch_stream_key = TSK",
        '"twitch_stream_key": "TSK"',
        "'server_password': 'PW'",
        '{"secret": "S",',
        "Authorization: token TOKSECRET",
        "Authorization: Custom TOKSECRET",
        "https://user:URLPASSWORD@host/path",
        "rtmp://user:URLPASSWORD@host/app/streamkey",
        "srt://user:URLPASSWORD@host:9000?streamid=publish:stream",
        "ftp://user:URLPASSWORD@host/path",
    ],
)
def test_generic_text_credentials_are_redacted_and_detected(tmp_path: Path, line: str) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line + "\n", encoding="utf-8")
    assert has_unredacted_embedded_json(line) and _secret_scan(path)
    redact_file(path)
    cleaned = path.read_text(encoding="utf-8")
    for secret in (
        "QSECRET123",
        "PKSECRET",
        "SKSECRET",
        "AKSECRET",
        "TSK",
        "PW",
        '"S"',
        "TOKSECRET",
        "URLPASSWORD",
    ):
        assert secret not in cleaned
    assert not has_unredacted_embedded_json(cleaned) and not _secret_scan(path)


@pytest.mark.parametrize(
    "line",
    [
        "keyint: 250",
        "keyint_sec=2",
        "key_color: 16711935",
        "frames dropped: 1",
        "Hotkey key: OBS_KEY_F1",
        "chroma key: 5",
        "https://x/?bandwidthtest=true&x=1",
        "rtmp://live.twitch.tv/app",
        "user@example.com",
    ],
)
def test_generic_scanner_preserves_noncredential_text(tmp_path: Path, line: str) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line, encoding="utf-8")
    redact_file(path)
    assert path.read_text(encoding="utf-8") == line
    assert not has_unredacted_embedded_json(line) and not _secret_scan(path)


@pytest.mark.parametrize(
    "line",
    [
        "info: password=SEC1",
        'info: key="SEC1"',
        "info: bearer_token = 'SEC1'",
        "info: token = 'SEC1'",
        "12:00:00.000: cookie = 'SEC1'",
        "config authToken='SEC1'",
        "[plugin] stream_key=SEC1",
        "password: SEC1",
        'key = "SEC1"',
        "token : 'SEC1'",
        "[plugin] bearer_token : SEC1",
    ],
)
def test_overlapping_assignment_is_redacted_and_unredacted_input_is_flagged(
    tmp_path: Path, line: str
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line + "\n", encoding="utf-8")

    assert has_unredacted_embedded_json(line)
    assert _secret_scan(path)
    redact_file(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "SEC1" not in cleaned
    assert not has_unredacted_embedded_json(cleaned)
    assert not _secret_scan(path)


def test_overlapping_sensitive_assignments_across_log_lines_preserve_benign_lines(
    tmp_path: Path,
) -> None:
    original = (
        "info: password=FIRST_SECRET\n"
        "ordinary diagnostic text stays byte-identical\n"
        '  StreamKey="SECOND_SECRET"\n'
        "frames dropped: 1\n"
        "config token = THIRD_SECRET\n"
    )
    path = tmp_path / "current.txt"
    path.write_text(original, encoding="utf-8")

    redact_file(path)

    cleaned = path.read_text(encoding="utf-8")
    assert all(
        secret not in cleaned for secret in ("FIRST_SECRET", "SECOND_SECRET", "THIRD_SECRET")
    )
    assert "ordinary diagnostic text stays byte-identical\n" in cleaned
    assert "frames dropped: 1\n" in cleaned
    assert not _secret_scan(path)


def test_seeded_multishape_fuzz_has_zero_shipped_leaks(tmp_path: Path) -> None:
    rng = random.Random(7)
    names = [
        "key",
        "stream_key",
        "StreamKey",
        "password",
        "Password",
        "token",
        "access_token",
        "bearer_token",
        "client_secret",
        "api_key",
        "apiKey",
        "authToken",
        "passphrase",
        "refresh_token",
        "cookie",
    ]
    separators = ["=", ": ", " = ", ":", "="]
    quotes = ["", '"', "'"]
    prefixes = ["", "12:00:00.000: ", "[plugin] ", "info: ", "  ", "config "]

    def secret(index: int) -> str:
        return f"SECRETVALUE{index:04d}xyz"

    def case(index: int) -> tuple[str, str, str]:
        name = rng.choice(names)
        separator = rng.choice(separators)
        quote = rng.choice(quotes)
        prefix = rng.choice(prefixes)
        value = secret(index)
        kind = rng.choice(("log", "ini", "json"))
        if kind == "log":
            return f"{prefix}{name}{separator}{quote}{value}{quote}\n", "current.txt", value
        if kind == "ini":
            return f"[Sec]\n{name}={quote}{value}{quote}\nOther=1\n", "basic.ini", value
        shapes = (
            {name: value},
            {"settings": {"a": {name: value}}},
            {"items": [{"x": 1}, {name: value}]},
            {"blob": json.dumps({name: value})},
            {"blob": f"{name}={value}; other=1"},
            {"server": f"rtmp://h.example.com/app/{value}"},
        )
        return json.dumps(rng.choice(shapes)), "service.json", value

    leaks: list[str] = []
    for index in range(1500):
        content, filename, literal = case(index)
        path = tmp_path / f"case-{index}" / filename
        path.parent.mkdir()
        path.write_text(content, encoding="utf-8")
        _counts, _total, secrets = redact_file_with_secrets(path)
        output = read_text_safely(path)
        flagged = _contains_private_secret(path, secrets) or _secret_scan(path)
        if literal in output and not flagged:
            leaks.append(f"{filename}: {content!r} -> {output!r}")
    assert leaks == []


def test_sensitive_json_booleans_and_null_are_preserved() -> None:
    value = {"show_password": False, "secret": None}
    assert not has_unredacted_fields(value)


def test_sensitive_json_boolean_and_null_are_not_replaced(tmp_path: Path) -> None:
    path = tmp_path / "service.json"
    path.write_text(json.dumps({"show_password": False, "secret": None, "password": "x"}))
    redact_file(path)
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "show_password": False,
        "secret": None,
        "password": "<REDACTED>",
    }


def test_url_credentials_inside_json_string_are_redacted_and_verified(tmp_path: Path) -> None:
    path = tmp_path / "service.json"
    path.write_text(json.dumps({"settings": {"url": "https://host/?stream_key=JSON_URL_SECRET"}}))
    assert _secret_scan(path)
    redact_file(path)
    assert "JSON_URL_SECRET" not in path.read_text(encoding="utf-8")
    assert not _secret_scan(path)


@pytest.mark.parametrize("n", [40])
def test_comment_separator_adversarial_input_is_fast(tmp_path: Path, n: int) -> None:
    path = tmp_path / "current.txt"
    path.write_text("key" + "/**/" * n + "\n", encoding="utf-8")
    started = time.perf_counter()
    redact_file(path)
    assert not has_unredacted_embedded_json(path.read_text(encoding="utf-8"))
    assert time.perf_counter() - started < 2


@pytest.mark.parametrize(
    "name",
    [
        "passphrase",
        "pwd",
        "cookie",
        "cookies",
        "session_id",
        "jwt",
        "credential",
        "credentials",
        "streamid",
    ],
)
def test_new_log_credential_assignments_are_redacted_and_verified(
    tmp_path: Path, name: str
) -> None:
    path = tmp_path / "network.txt"
    path.write_text(f"{name}=LOG_SECRET\n", encoding="utf-8")
    assert backup_secret_scan(path)
    redact_file(path)
    assert path.read_text(encoding="utf-8") == f"{name}=<REDACTED>\n"
    assert not backup_secret_scan(path)
