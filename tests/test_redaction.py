import json
import random
import re
import time
import zipfile
from pathlib import Path

import pytest

from tempesttrace.backup import (
    _compile_private_literals,
    _contains_private_secret,
    _secret_scan,
    create_backup,
)
from tempesttrace.redaction import (
    _OBS_KEY_NAMES,
    RULE_VERSION,
    _embedded_secrets,
    _free_text_credential_spans,
    _is_sensitive_key,
    _json_fragments,
    _scrub_text,
    _strong_embedded_secrets,
    has_unredacted_embedded_json,
    has_unredacted_fields,
    has_unredacted_ini_fields,
    read_text_safely,
    redact_file,
    redact_file_with_secrets,
)

SCHEME_WORDS = ("Bearer", "Basic", "Digest", "Token", "Bot", "ApiKey", "AWS4-HMAC-SHA256")


def _minimum_runtime(action, repeats: int = 2) -> float:
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        action()
        samples.append(time.perf_counter() - started)
    return min(samples)


def _assert_linear_pair(action, size: int, ceiling: float) -> tuple[float, float]:
    small = _minimum_runtime(lambda: action(size))
    large = _minimum_runtime(lambda: action(size * 2))
    if large / max(small, 0.001) >= 3.2:
        small = min(small, _minimum_runtime(lambda: action(size), repeats=1))
        large = min(large, _minimum_runtime(lambda: action(size * 2), repeats=1))
    assert large / max(small, 0.001) < 3.2
    assert large < ceiling
    return small, large


def _fuzz_scheme_value(rng: random.Random, form: str, secret: str) -> str:  # noqa: PLR0911
    scheme = rng.choice(SCHEME_WORDS)
    if form == "wrapped_scheme":
        return f"({scheme}) {secret}"
    if form == "glued_amp":
        return f"{scheme} {secret}&region=us"
    if form == "glued_semicolon":
        return f"{scheme} {secret};expires=123456"
    if form == "glued_hash":
        return f"{scheme} {secret}#note"
    if form == "scheme_suffix":
        scheme_suffix = rng.choice([".", ";", ")", "]", "}", "#", ":", ",", "="])
        credential_suffix = rng.choice([".", ",", ")", ";", "!", "?"])
        return f"{scheme}{scheme_suffix} {secret}{credential_suffix}"
    if form == "trailing_suffix":
        return f"{scheme} {secret}{rng.choice(['.', ',', ')', ';', '!', '?'])}"
    if form == "scheme":
        return f"{scheme} {secret}"
    if form == "scheme_colon":
        return f"{scheme}: {secret}"
    if form == "double_scheme":
        return f"{scheme} token {secret}"
    if form == "scheme_nextline":
        return f"\n    {scheme} {secret}"
    if form == "scheme_newline_token":
        return f"{scheme}\n    {secret}"
    return f"|\n    {secret}"


def test_free_text_span_results_are_reused_for_unchanged_input() -> None:
    text = "token=Bearer PerfRegression123\n"
    first = _free_text_credential_spans(text)
    misses_after_first_call = _free_text_credential_spans.cache_info().misses

    second = _free_text_credential_spans(text)

    assert first == second == [(13, 30, "PerfRegression123", False)]
    assert _free_text_credential_spans.cache_info().misses == misses_after_first_call


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
                "hotkeys": {"libobs.mute": {"key": "OBS_KEY_F9"}},
            }
        ),
        encoding="utf-8",
    )

    redact_file(path)

    value = json.loads(path.read_text(encoding="utf-8"))
    assert json.loads(value["payload"]) == {"key": "<REDACTED>", "token": "<REDACTED>"}
    assert value["hotkeys"]["libobs.mute"]["key"] == "OBS_KEY_F9"


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
        json.dumps({"bindings": [{"key": "OBS_KEY_F9", "key_modifier": "SHIFT"}]}),
        encoding="utf-8",
    )
    redact_file(hotkeys)
    assert json.loads(hotkeys.read_text(encoding="utf-8"))["bindings"][0]["key"] == "OBS_KEY_F9"
    assert not has_unredacted_fields({"bindings": [{"key": "OBS_KEY_F9"}]}, ("hotkeys.json",))


def test_bare_key_is_redacted_in_backup_and_scene_files_but_not_hotkeys(tmp_path: Path) -> None:
    for filename in ("service.json.bak", "main.json", "Streaming Hotkeys.json"):
        path = tmp_path / filename
        path.write_text(
            json.dumps(
                {
                    "settings": {"key": "STREAM_KEY_SECRET"},
                    "hotkeys": [{"key": "OBS_KEY_F9"}],
                }
            ),
            encoding="utf-8",
        )

        redact_file(path)

        value = json.loads(path.read_text(encoding="utf-8"))
        assert value["settings"]["key"] == "<REDACTED>"
        assert value["hotkeys"][0]["key"] == "OBS_KEY_F9"
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
        "hotkeys": [{"key": "OBS_KEY_F9"}],
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
        'keyint_sec=2\nOBSBasic.StartStreaming={"key":"OBS_KEY_F9"}\n'
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


def test_rule_version_is_twenty_three() -> None:
    assert RULE_VERSION == 23


@pytest.mark.parametrize(
    "assignment",
    [
        "token: Bearer: G8TOKEN123456",
        "token: Bearer token G8TOKEN123456",
        "password: Basic: G8PASSWORD123",
        "token:\n    Bearer G8TOKEN123456",
        "token: Bearer\n    G8TOKEN123456",
        "token:\n\n    Bearer\n\n      G8TOKEN123456",
        "token: |\n    G8TOKEN123456",
    ],
)
def test_scheme_resolver_redacts_only_credential_and_verifies(
    assignment: str, tmp_path: Path
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(assignment + "\nordinary line remains\n", encoding="utf-8")
    original = path.read_text(encoding="utf-8")
    assert has_unredacted_embedded_json(original)
    assert g8_secret(assignment) in _embedded_secrets(original)
    assert not ({"bearer", "basic", "token"} & _embedded_secrets(original))
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert g8_secret(assignment) not in cleaned
    assert "ordinary line remains" in cleaned
    for scheme in ("Bearer", "Basic"):
        if scheme in assignment:
            assert scheme in cleaned
    assert not has_unredacted_embedded_json(cleaned)
    assert not _secret_scan(path)


def g8_secret(assignment: str) -> str:
    match = re.search(r"(G8(?:TOKEN|PASSWORD)\d+)$", assignment)
    assert match is not None
    return match.group(1)


def test_authorization_cookie_free_text_promotion_requires_evidence(tmp_path: Path) -> None:
    prose = (
        "Authorization: failed to authenticate\n"
        "Cookie: session\n"
        "Failed to open encoder\n"
        "Scene: Failed Overlay\n"
        "connection failed\n"
        "WebSocket session started\n"
        "Input: jim_nvenc_h264\n"
    )
    assert not _embedded_secrets(prose)
    assert not _strong_embedded_secrets(prose)
    keyed = "Authorization: Qk7mN2pL9xR4\n"
    assert "Qk7mN2pL9xR4" in _embedded_secrets(keyed)


def test_cookie_pairs_promote_credentials_and_scheme_credentials_ungated() -> None:
    text = (
        "Authorization: Bearer abc\n"
        "Cookie: sid=abc; theme=dark\n"
        "Authorization: failed to authenticate\n"
    )
    harvested = _embedded_secrets(text)
    assert "abc" in harvested
    assert "dark" not in harvested
    assert "failed" not in harvested


def test_cookie_attributes_are_redacted_but_not_promoted(tmp_path: Path) -> None:
    text = "Cookie: session=SECRET1234; Domain=twitch.tv; theme=overlay\n"
    spans = _free_text_credential_spans(text)
    assert "SECRET1234" in _embedded_secrets(text)
    assert "twitch.tv" not in _embedded_secrets(text)
    assert "overlay" not in _embedded_secrets(text)
    path = tmp_path / "cookie.txt"
    path.write_text(text, encoding="utf-8")
    redact_file(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "Cookie: <REDACTED>" in cleaned
    assert spans


def test_quoted_redaction_marker_with_trailing_punctuation_verifies_clean(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cookie.txt"
    path.write_text("cookie=`<REDACTED>`)\n", encoding="utf-8")
    assert not _secret_scan(path)


def test_scheme_dense_redaction_and_verification_scale_linearly(tmp_path: Path) -> None:
    line = "14:22:01.123: token: Bearer Qk7mN2pL9xR4\n"

    def redact_and_verify(size: int) -> None:
        path = tmp_path / f"dense-{size}.txt"
        path.write_text((line * (size // len(line) + 1))[:size], encoding="utf-8")
        redact_file_with_secrets(path)
        assert not _secret_scan(path)

    _assert_linear_pair(redact_and_verify, 120 * 1024, 10.0)


@pytest.mark.parametrize(
    "label",
    [
        "token",
        "password",
        "key",
        "secret",
        "pwd",
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
        "Set-Cookie",
        "Cookie2",
    ],
)
@pytest.mark.parametrize(
    "scheme", ["Bearer", "Basic", "Digest", "Token", "Bot", "ApiKey", "AWS4-HMAC-SHA256"]
)
@pytest.mark.parametrize(
    "form",
    [
        "space",
        "tab",
        "quoted",
        "trailing-colon",
        "double-scheme",
        "next-line",
        "scheme-next-line",
        "blank-lines",
        "yaml-block",
        "scheme-dot",
        "scheme-semicolon",
        "scheme-paren",
        "scheme-bracket",
        "scheme-brace",
        "scheme-hash",
        "scheme-colon",
        "scheme-comma",
        "scheme-equals",
        "credential-dot",
        "credential-comma",
        "credential-paren",
        "credential-semicolon",
        "credential-bang",
        "credential-question",
        "wrapped-scheme",
        "glued-amp",
        "glued-semicolon",
        "glued-hash",
    ],
)
def test_scheme_credential_matrix_is_harvested_redacted_and_verified(  # noqa: PLR0912
    tmp_path: Path, label: str, scheme: str, form: str
) -> None:
    credential = "MATRIXSECRET123456"
    if form == "space":
        value = f"{scheme} {credential}"
    elif form == "tab":
        value = f"{scheme}\t{credential}"
    elif form == "quoted":
        value = f'"{scheme} {credential}"'
    elif form == "trailing-colon":
        value = f"{scheme}: {credential}"
    elif form == "double-scheme":
        value = f"{scheme} token {credential}"
    elif form == "next-line":
        value = f"\n    {scheme} {credential}"
    elif form == "scheme-next-line":
        value = f"{scheme}\n    {credential}"
    elif form == "blank-lines":
        value = f"{scheme}\n\n      {credential}"
    elif form == "yaml-block":
        value = f"|\n    {credential}"
    elif form.startswith("scheme-"):
        suffix = {
            "scheme-dot": ".",
            "scheme-semicolon": ";",
            "scheme-paren": ")",
            "scheme-bracket": "]",
            "scheme-brace": "}",
            "scheme-hash": "#",
            "scheme-colon": ":",
            "scheme-comma": ",",
            "scheme-equals": "=",
        }[form]
        value = f"{scheme}{suffix} {credential}"
    elif form == "wrapped-scheme":
        value = f"(Bearer) {credential}"
    elif form.startswith("glued-"):
        suffix = {
            "glued-amp": "&region=us",
            "glued-semicolon": ";expires=123456",
            "glued-hash": "#note",
        }[form]
        value = f"Bearer {credential}{suffix}"
    else:
        suffix = {
            "credential-dot": ".",
            "credential-comma": ",",
            "credential-paren": ")",
            "credential-semicolon": ";",
            "credential-bang": "!",
            "credential-question": "?",
        }[form]
        value = f"{scheme} {credential}{suffix}"
    content = f"{label}: {value}\r\nordinary diagnostic line\r\n"
    path = tmp_path / "matrix.txt"
    path.write_text(content, encoding="utf-8", newline="")
    assert has_unredacted_embedded_json(content)
    assert _secret_scan(path)
    harvested = _embedded_secrets(content)
    assert credential in harvested
    if label.casefold() in {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "cookie2",
    }:
        assert credential in _strong_embedded_secrets(content)
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert credential not in cleaned
    assert "ordinary diagnostic line" in cleaned
    if form != "yaml-block":
        expected_scheme = "Bearer" if form.startswith(("wrapped-", "glued-")) else scheme
        assert expected_scheme in cleaned
    else:
        assert f"{label}: |\n    <REDACTED>" in cleaned
    assert not has_unredacted_embedded_json(cleaned)
    assert not _secret_scan(path)


@pytest.mark.parametrize("scheme", ["(Bearer)", "[Bearer]", "<Bearer>", "Bearer("])
def test_wrapped_scheme_words_resolve_credential(scheme: str, tmp_path: Path) -> None:
    text = f"password: {scheme} WrappedSecret991\n"
    assert "WrappedSecret991" in _embedded_secrets(text)
    path = tmp_path / "wrapped.txt"
    path.write_text(text, encoding="utf-8")
    redact_file(path)
    assert "WrappedSecret991" not in path.read_text(encoding="utf-8")
    assert not _secret_scan(path)


def test_unindented_bare_token_lines_scale_linearly() -> None:
    def scan(size: int) -> float:
        text = ("token:\n" * (size // 7 + 1))[:size]
        started = time.perf_counter()
        assert _scrub_text(text, set()) == text
        return time.perf_counter() - started

    small = min(scan(256 * 1024), scan(256 * 1024))
    large = min(scan(512 * 1024), scan(512 * 1024))
    if large / max(small, 0.001) >= 3.2:
        small = min(small, scan(256 * 1024))
        large = min(large, scan(512 * 1024))
    assert large / max(small, 0.001) < 3.2
    assert large < max(10.0, 8 * small)


@pytest.mark.parametrize("suffix", [".", ";", ")", "]", "}", "#", ":", ",", "="])
@pytest.mark.parametrize("label", ["token", "password", "Authorization"])
def test_punctuated_scheme_and_credential_are_harvested_and_scrubbed(
    tmp_path: Path, label: str, suffix: str
) -> None:
    credential = "ab#cd&ef;gh99"
    content = f"{label}: Bearer{suffix} {credential}.\n"
    path = tmp_path / "current.txt"
    path.write_text(content, encoding="utf-8")
    _, _, secrets = redact_file_with_secrets(path)
    assert credential in secrets
    assert not has_unredacted_embedded_json(path.read_text(encoding="utf-8"))
    assert not _secret_scan(path)


@pytest.mark.parametrize("separator", [".", ",", ")", ";", "!", "?"])
def test_trailing_credential_punctuation_is_cleaned_for_cross_file_scrub(
    tmp_path: Path, separator: str
) -> None:
    credential = "s3cret99xxK"
    source = tmp_path / "source.txt"
    scene = tmp_path / "scene.json"
    source.write_text(f"password: {credential}{separator}\n", encoding="utf-8")
    scene.write_text(json.dumps({"copied": credential}), encoding="utf-8")
    _, _, secrets = redact_file_with_secrets(source)
    assert credential in secrets
    cleaned = _scrub_text(scene.read_text(encoding="utf-8"), set(secrets))
    scene.write_text(cleaned, encoding="utf-8")
    assert credential not in cleaned


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\u0085", "\x0b", "\x0c"])
def test_unicode_line_separators_resolve_continuation_credentials(
    tmp_path: Path, separator: str
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(f"password:{separator}    NextLineSecret99xx\n", encoding="utf-8")
    _, _, secrets = redact_file_with_secrets(path)
    assert "NextLineSecret99xx" in secrets
    assert "NextLineSecret99xx" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("marker", ["|", ">", "|-", ">+", "|2"])
def test_empty_yaml_block_marker_does_not_fail_independent_verification(
    tmp_path: Path, marker: str
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(f"password: {marker}\n14:22:01.123: ordinary diagnostic\n", encoding="utf-8")
    redact_file_with_secrets(path)
    assert "ordinary diagnostic" in path.read_text(encoding="utf-8")
    assert not _secret_scan(path)
    path.write_text(f"password: {marker}\n", encoding="utf-8")
    redact_file_with_secrets(path)
    assert not _secret_scan(path)


def test_empty_scheme_labels_are_linear() -> None:
    def scan(count: int) -> None:
        text = "token:\n" * count
        assert _free_text_credential_spans.__wrapped__(text) == []

    _assert_linear_pair(scan, 12000, 10.0)


@pytest.mark.parametrize(
    "continuation",
    [
        "jim_nvenc_h264 encoder started",
        "https://example.com/overlay",
        "14:22:01.123: [obs-browser] retry",
        "keyint=250",
    ],
)
def test_continuation_first_token_is_redacted_but_not_promoted(
    tmp_path: Path, continuation: str
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(f"password:\n    {continuation}\n", encoding="utf-8")
    _, _, secrets = redact_file_with_secrets(path)
    assert not secrets
    output = path.read_text(encoding="utf-8")
    first = continuation.split(maxsplit=1)[0]
    assert "    <REDACTED>" in output
    assert output.count(first) == continuation.count(first) - 1


def test_single_next_line_secret_is_still_promoted_and_redacted(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text("password:\n    RealNextLineSecret99xx\n", encoding="utf-8")
    _, _, secrets = redact_file_with_secrets(path)
    assert "RealNextLineSecret99xx" in secrets
    assert "RealNextLineSecret99xx" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("url", "token", "suffix"),
    [
        (
            "https://discord.com/api/webhooks/123456789012345678/DiscordWebhookToken123",
            "DiscordWebhookToken123",
            ".txt",
        ),
        (
            "https://discordapp.com/api/webhooks/123456789012345678/DiscordWebhookToken123",
            "DiscordWebhookToken123",
            ".json",
        ),
        (
            "https://hooks.slack.com/services/T12345678/B12345678/SlackWebhookToken123",
            "SlackWebhookToken123",
            ".ini",
        ),
    ],
)
def test_webhook_url_tokens_are_redacted_and_benign_urls_are_preserved(
    url: str, token: str, suffix: str, tmp_path: Path
) -> None:
    path = tmp_path / f"fixture{suffix}"
    benign = "https://discord.com/channels/123/456 https://slack.com/app_redirect?channel=C123"
    content = (
        json.dumps({"url": url, "benign": benign})
        if suffix == ".json"
        else f"url={url}\nbenign={benign}\n"
    )
    path.write_text(content, encoding="utf-8")
    assert _secret_scan(path)
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert token not in cleaned
    assert "<REDACTED>" in cleaned
    assert url.rsplit("/", 1)[0] in cleaned
    assert benign in cleaned
    assert not _secret_scan(path)


def test_weak_only_literal_remains_case_sensitive() -> None:
    compiled = _compile_private_literals({"Facebook"}, {"Facebook"}, set())
    assert compiled is not None
    assert compiled.search("Facebook")
    assert compiled.search("facebook") is None


@pytest.mark.parametrize("segment", ["mystreamkey", "abcdefghijklmno", "MYSTREAMKEY"])
@pytest.mark.parametrize("kind", ["log", "json", "ini"])
@pytest.mark.parametrize("path_prefix", ["", "live/"])
def test_rtmp_uniform_case_alpha_key_is_redacted_in_place(
    segment: str, kind: str, path_prefix: str, tmp_path: Path
) -> None:
    suffix = {"log": ".txt", "json": ".json", "ini": ".ini"}[kind]
    path = tmp_path / ("fixture" + suffix)
    value = f"rtmp://ingest.example.com/{path_prefix}{segment}"
    content = value if kind == "log" else json.dumps({"server": value, "FFURL": value})
    if kind == "ini":
        content = f"[Output]\nserver={value}\nFFURL={value}\n"
    path.write_text(content, encoding="utf-8")
    redact_file_with_secrets(path)
    assert segment not in path.read_text(encoding="utf-8")


def test_rtmp_harvesting_does_not_scrub_streaming_log_word(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(
        "rtmp://cdn.example/live/streaming\nstreaming production started\n", encoding="utf-8"
    )
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "streaming production started" in cleaned
    assert "live/<REDACTED>" in cleaned


@pytest.mark.parametrize(
    "server,log",
    [
        (
            "rtmp://live.example.com/live/1080p",
            "info: base resolution 1920x1080 output 1080p\ninfo: encoder stream_1080p_high\n",
        ),
        (
            "rtmp://host/Facebook/live",
            "facebook output started\nFacebook Live connected\n",
        ),
    ],
)
def test_rtmp_ordinary_path_segments_do_not_scrub_logs(
    server: str, log: str, tmp_path: Path
) -> None:
    source = tmp_path / "obs"
    (source / "basic/profiles/default").mkdir(parents=True)
    (source / "basic/scenes").mkdir()
    (source / "logs").mkdir()
    (source / "basic/profiles/default/service.json").write_text(
        json.dumps({"settings": {"server": server, "key": ""}}), encoding="utf-8"
    )
    (source / "basic/scenes/main.json").write_text(
        json.dumps({"name": server.rsplit("/", 1)[-1]}), encoding="utf-8"
    )
    (source / "logs/2026-01-01.txt").write_text(log, encoding="utf-8")
    destination = tmp_path / "out"
    destination.mkdir()

    result = create_backup(source, destination)

    with zipfile.ZipFile(result.archive) as archive:
        assert archive.read("logs/2026-01-01.txt").decode("utf-8") == log
        scene = json.loads(archive.read("basic/scenes/main.json"))
    assert scene["name"] == server.rsplit("/", 1)[-1]


@pytest.mark.parametrize(
    "url",
    [
        "http://user:abcd/EFGH12@ingest.example.com/live",
        "https://user:ab+cd/ef==@example.com/x",
        "redis://:p@ss/word@10.1.2.3:6379/0",
    ],
)
def test_userinfo_password_redacts_slashes_through_last_at(url: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(url, encoding="utf-8")
    redact_file_with_secrets(path)
    assert "<REDACTED>@" in path.read_text(encoding="utf-8")


def test_real_obs_key_enum_names_are_exempt_and_spoofs_are_not(tmp_path: Path) -> None:
    mouse_names = {f"OBS_KEY_MOUSE{number}" for number in range(1, 30)}
    keyboard_names = {
        "OBS_KEY_A",
        "OBS_KEY_F9",
        "OBS_KEY_CONTROL",
        "OBS_KEY_LEFT",
        "OBS_KEY_VK_VOLUME_MUTE",
        "OBS_KEY_AACUTE",
    }
    assert len(_OBS_KEY_NAMES) == 538
    assert mouse_names <= _OBS_KEY_NAMES
    assert keyboard_names <= _OBS_KEY_NAMES
    assert all(
        not has_unredacted_fields({"hotkeys": {"bindings": {"key": name}}})
        for name in _OBS_KEY_NAMES
    )
    ini_value = json.dumps(
        {
            "bindings": [{"key": name} for name in sorted(_OBS_KEY_NAMES)]
            + [{"key": "OBS_KEY_NK8SQ7WL91"}]
        }
    )
    ini = tmp_path / "OBSBasic.ini"
    ini.write_text(f"OBSBasic.Hotkeys={ini_value}\n", encoding="utf-8")
    redact_file(ini)
    ini_clean = ini.read_text(encoding="utf-8")
    assert all(name in ini_clean for name in _OBS_KEY_NAMES)
    assert "OBS_KEY_NK8SQ7WL91" not in ini_clean
    for name in ("OBS_KEY_NK8SQ7WL91", "OBS_KEY_A1B2C3D4E5F6", "obs_key_f9", "OBS_KEY_"):
        assert has_unredacted_fields({"hotkeys": {"bindings": {"key": name}}})


@pytest.mark.parametrize("mouse", ["OBS_KEY_MOUSE1", "OBS_KEY_MOUSE4", "OBS_KEY_MOUSE29"])
def test_mouse_hotkeys_survive_scene_and_obsbasic_ini_redaction(mouse: str, tmp_path: Path) -> None:
    scene = tmp_path / "scene.json"
    ini = tmp_path / "OBSBasic.ini"
    scene_text = json.dumps({"hotkeys": {"libobs.mute": [{"key": mouse}]}})
    ini_text = f'OBSBasic.PushToTalk={{"bindings":[{{"key":"{mouse}","control":true}}]}}\n'
    scene.write_text(scene_text, encoding="utf-8")
    ini.write_text(ini_text, encoding="utf-8")

    redact_file_with_secrets(scene)
    redact_file_with_secrets(ini)

    assert (
        json.loads(scene.read_text(encoding="utf-8"))["hotkeys"]["libobs.mute"][0]["key"] == mouse
    )
    assert ini.read_text(encoding="utf-8") == ini_text


def test_json_fragments_scales_for_many_small_objects() -> None:
    sample = '{"name":"Mic","volume":1,"mute":false} '

    def scan_fragments(size: int) -> None:
        text = (sample * (size // len(sample) + 1))[:size]
        _json_fragments.__wrapped__(text)

    _assert_linear_pair(scan_fragments, 352 * 1024, 20.0)

    for text in ('[{"a":1}] ' * 5000, "{ " * 5000):
        started = time.perf_counter()
        _json_fragments.__wrapped__(text)
        assert time.perf_counter() - started < 10.0


def test_dense_json_credential_fragments_redact_in_linear_time(tmp_path: Path) -> None:
    secret = "JSON_SECRET_DENSE_123456789"
    line = f'{{"token":"{secret}","volume":1,"mute":false}}\n'

    def redact_dense(size: int) -> None:
        path = tmp_path / f"dense-{size}.txt"
        path.write_text(line * (size // len(line)), encoding="utf-8")
        redact_file_with_secrets(path)
        assert secret not in path.read_text(encoding="utf-8")

    _assert_linear_pair(redact_dense, 144 * 1024, 10.0)


@pytest.mark.parametrize(
    "url, expected",
    [
        ("http://host:8080/path@name", "http://host:8080/path@name"),
        ("https://cdn.example.com/@creator/video", "https://cdn.example.com/@creator/video"),
        ("user@example.com", "user@example.com"),
        ("https://example.com?email=a:b@c.com", "https://example.com?email=a:b@c.com"),
        ("https://host#frag:x@y", "https://host#frag:x@y"),
    ],
)
def test_url_userinfo_password_guards(url: str, expected: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(url, encoding="utf-8")
    redact_file_with_secrets(path)
    assert path.read_text(encoding="utf-8").strip() == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://[2001:db8::1]:8080/path@name", "http://[2001:db8::1]:8080/path@name"),
        (
            "http://[2001:db8::1]:8080/path?password=SUPERSECRET99&email=a@b.com",
            "http://[2001:db8::1]:8080/path?password=<REDACTED>&email=a@b.com",
        ),
        (
            "http://[2001:db8::1]:8080/path@name?password=SUPERSECRET99&email=a@b.com",
            "http://[2001:db8::1]:8080/path@name?password=<REDACTED>&email=a@b.com",
        ),
        (
            "http://user:pass@[2001:db8::1]:443/path",
            "http://user:<REDACTED>@[2001:db8::1]:443/path",
        ),
        ("ssh://git@github.com/user/repo", "ssh://git@github.com/user/repo"),
        ("mailto:alice@example.com", "mailto:alice@example.com"),
        ("https://cdn.example.com/@creator/video", "https://cdn.example.com/@creator/video"),
        ("user@example.com", "user@example.com"),
    ],
)
def test_bracketed_ipv6_authority_and_userinfo(url: str, expected: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(url, encoding="utf-8")
    redact_file_with_secrets(path)
    assert path.read_text(encoding="utf-8").strip() == expected


@pytest.mark.parametrize(
    "url",
    [
        "rtmp://host.example/Nk8sQ7wL91",
        "rtmp://host.example/Nk8sQ7wL91/live",
        "rtmps://[2001:db8::1]:443/Nk8sQ7wL91?x=1",
        "rtmp://host.example/live/Nk8sQ7wL91&next=ok",
    ],
)
def test_rtmp_key_segments_are_redacted(url: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(url, encoding="utf-8")
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "Nk8sQ7wL91" not in cleaned
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "url",
    [
        "rtmp://live.twitch.tv/app",
        "rtmps://a.rtmps.youtube.com:443/live2",
        "rtmp://cdn.example/live/streaming",
        "rtmp://cdn.example/live/production",
    ],
)
def test_rtmp_application_words_are_preserved(url: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    content = f"{url}\n09:00:00.000: streaming production started\n"
    path.write_text(content, encoding="utf-8")
    redact_file_with_secrets(path)
    assert "streaming production started" in path.read_text(encoding="utf-8")
    assert not _secret_scan(path)


def test_rtmp_key_segments_are_redacted_in_scene_source_input(tmp_path: Path) -> None:
    path = tmp_path / "scene.json"
    path.write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "id": "ffmpeg_source",
                        "settings": {"input": "rtmp://ingest.example/Nk8sQ7wL91/live"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "Nk8sQ7wL91" not in cleaned
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/cb?region=us#access_token=SE<CRET99",
        "https://example.com/cb#access_token=SE>CRET77",
        'https://example.com/cb#access_token=SE"CRET88 tail',
        "https://example.com/cb#access_token=SE`CRET66 tail",
        'href="https://e/x#t=ABC">',
        "url='https://e/x#access_token=ABC'",
    ],
)
def test_url_fragment_value_handles_angle_and_quote_characters(url: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(url, encoding="utf-8")
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert not any(secret in cleaned for secret in ("SE<CRET99", "SE>CRET77", 'SE"CRET88'))
    assert not _secret_scan(path)


def test_duplicate_authorization_headers_and_idempotence(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(
        "Authorization: Bearer Nk8sQ7wL91 Authorization: Basic PARTTWO99\n"
        "Authorization: Bearer ONESECRET99 Authorization: Basic TWOSECRET99 "
        "Authorization: Bearer THREESECRET99\n"
        'Authorization: "Bearer" FOURSECRET99\n',
        encoding="utf-8",
    )
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert all(
        secret not in cleaned
        for secret in (
            "Nk8sQ7wL91",
            "PARTTWO99",
            "ONESECRET99",
            "TWOSECRET99",
            "THREESECRET99",
            "FOURSECRET99",
        )
    )
    assert "Authorization: Bearer <REDACTED>" in cleaned
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "line",
    [
        'authorization: "Bearer" TOKENSECRETX99',
        "authorization: 'Basic' TOKENSECRETX99",
        'authorization: "Bearer TOKENSECRETX99"',
        r'authorization: "Bearer \"quoted\" TOKENSECRETX99"',
    ],
)
def test_quoted_authorization_scheme_keeps_token_redacted(line: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line, encoding="utf-8")
    redact_file_with_secrets(path)
    assert "TOKENSECRETX99" not in path.read_text(encoding="utf-8")
    assert not _secret_scan(path)


def test_authorization_next_line_token_is_redacted(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(
        "Authorization: Bearer\n    NEXTLINESECRET99\nAuthorization:\nEMPTYVALUESECRET99\n"
        "Authorization: Basic\n\n  SECONDSECRET99\n",
        encoding="utf-8",
    )
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert all(
        secret not in cleaned
        for secret in ("NEXTLINESECRET99", "EMPTYVALUESECRET99", "SECONDSECRET99")
    )
    assert not _secret_scan(path)
    benign = tmp_path / "benign.txt"
    benign.write_text("Authorization: Bearer\nordinary diagnostic text follows\n", encoding="utf-8")
    redact_file_with_secrets(benign)
    assert benign.read_text(encoding="utf-8") == (
        "Authorization: Bearer\nordinary diagnostic text follows\n"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://user:p#assword@host/room",
        "https://user:sec?ret@host/path",
        "redis://user:p#assword@host:6379/0",
        "mongodb://user:sec?ret@host/db",
        "ftp://user:p#assword@host/file",
        "ws://user:sec?ret@host/path",
    ],
)
def test_userinfo_password_may_contain_url_punctuation(url: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(url, encoding="utf-8")
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "p#assword" not in cleaned and "sec?ret" not in cleaned
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com?email=a:b@c.com",
        "https://host#frag:x@y",
    ],
)
def test_url_colon_after_query_or_fragment_is_not_userinfo(url: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(url, encoding="utf-8")
    redact_file_with_secrets(path)
    assert path.read_text(encoding="utf-8").strip() == url
    assert not _secret_scan(path)


def test_weak_camel_key_only_redacts_key_material(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text("userKey=hunter22\nlayoutKey=default\n", encoding="utf-8")
    redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "userKey=<REDACTED>" in cleaned
    assert "layoutKey=default" in cleaned
    assert not _secret_scan(path)


def test_hotkey_exemption_rejects_secret_looking_obs_key_name() -> None:
    assert has_unredacted_fields({"hotkeys": {"bindings": {"key": "OBS_KEY_NK8SQ7WL91"}}})


@pytest.mark.parametrize(
    "text",
    [
        'info: {"authorization": "Bearer SUPERAUTHSECRET99",}',
        'info: response \'{"authorization": "Bearer SUPERAUTHSECRET99", '
        '"password": "OTHERSECRET99"}\'',
        '\' {"authorization": "Bearer SUPERAUTHSECRET99"}',
        '" {"authorization": "Bearer SUPERAUTHSECRET99"}',
        ', {"authorization": "Bearer SUPERAUTHSECRET99"}',
        '> {"authorization": "Bearer SUPERAUTHSECRET99"}',
        '[{ {"authorization": "Bearer SUPERAUTHSECRET99"}',
    ],
)
def test_quoted_json_authorization_assignment_is_redacted_and_verified(
    text: str, tmp_path: Path
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(text, encoding="utf-8")
    _categories, _count, _secrets = redact_file_with_secrets(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "SUPERAUTHSECRET99" not in cleaned
    assert not has_unredacted_embedded_json(cleaned)


@pytest.mark.parametrize(
    "payload",
    [
        'info: {"authorization": "Bearer SUPERAUTHSECRET99",}',
        'info: response \'{"authorization": "Bearer SUPERAUTHSECRET99", '
        '"password": "OTHERSECRET99"}\'',
        '\' {"authorization": "Bearer SUPERAUTHSECRET99"}',
    ],
)
@pytest.mark.parametrize("shape", ["log", "ini", "scene"])
def test_authorization_fragment_payload_is_redacted_in_every_file_shape(
    payload: str, shape: str, tmp_path: Path
) -> None:
    suffix = {"log": ".txt", "ini": ".ini", "scene": ".json"}[shape]
    path = tmp_path / f"payload{suffix}"
    if shape == "log":
        content = payload
    elif shape == "ini":
        content = f"[General]\nNote={payload}\n"
    else:
        content = json.dumps({"sources": [{"settings": {"text": payload}}]})
    path.write_text(content, encoding="utf-8")
    redact_file(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "SUPERAUTHSECRET99" not in cleaned
    assert "OTHERSECRET99" not in cleaned
    assert not has_unredacted_embedded_json(cleaned)


@pytest.mark.parametrize(
    "token",
    ["+/8gc3RyZWFtLWtleSD/Lw==", "ab/cd+EF==", "tok;enTAIL99"],
)
@pytest.mark.parametrize("marker", ["?access_token=", "#access_token="])
def test_url_secret_value_extent_does_not_truncate_token(
    token: str, marker: str, tmp_path: Path
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(f"https://host/{marker}{token}&state=ok\n", encoding="utf-8")
    redact_file(path)
    cleaned = path.read_text(encoding="utf-8")
    assert token not in cleaned
    assert "&state=ok" in cleaned
    assert not has_unredacted_embedded_json(cleaned)


@pytest.mark.parametrize(
    "text",
    [
        "msg='authorization: Bearer AUTHQUOTEDSECRET'",
        'msg="authorization: Bearer AUTHQUOTEDSECRET"',
        "msg=`authorization: Bearer AUTHQUOTEDSECRET`",
        r"\"password\":\"ESCAPEDQUOTEDSECRET\"",
    ],
)
def test_fully_redacted_quoted_values_are_not_over_omitted(text: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(text, encoding="utf-8")
    redact_file(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "AUTHQUOTEDSECRET" not in cleaned
    assert "ESCAPEDQUOTEDSECRET" not in cleaned
    assert not has_unredacted_embedded_json(cleaned)


@pytest.mark.parametrize(
    "value",
    [
        "a=b&cookie=&quot;LK4=]03b\\9Z;Q7ZZ&quot;;c=d",
        "a=b&cookie=%22LK4=]03b\\9Z;Q7ZZ%22;c=d",
        "a=b&cookie=\u201cLK4=]03b\\9Z;Q7ZZ\u201d;c=d",
    ],
)
def test_entity_quoted_query_values_end_at_matching_quote(value: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(value, encoding="utf-8")
    redact_file(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "LK4=]03b" not in cleaned and "Q7ZZ" not in cleaned
    assert cleaned.endswith(";c=d")
    assert not has_unredacted_embedded_json(cleaned)


def test_sensitive_ini_continuations_keep_indented_prose_and_assignments(tmp_path: Path) -> None:
    path = tmp_path / "basic.ini"
    path.write_text(
        "[Stream]\npassword=CorrectHorse99\n    Bitrate note stays\nBitrate=6000\n"
        "token=\n    SINGLE_TOKEN\n    Multi word note\n",
        encoding="utf-8",
    )
    redact_file(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "password=<REDACTED>\n    Bitrate note stays\nBitrate=6000" in cleaned
    assert "token=\n    <REDACTED>\n    Multi word note" in cleaned
    assert not has_unredacted_ini_fields(cleaned, path.name)


def test_reauthorization_is_not_a_sensitive_header_name(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text("reauthorization: completed for module audio\n", encoding="utf-8")
    redact_file(path)
    assert path.read_text(encoding="utf-8") == "reauthorization: completed for module audio\n"


@pytest.mark.parametrize("header", ["Authorization", "Proxy-Authorization", "X-Amz-Authorization"])
def test_hyphenated_authorization_header_names_are_supported(header: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(f"{header}: Bearer HEADERSECRET99\n", encoding="utf-8")
    redact_file(path)
    assert path.read_text(encoding="utf-8") == f"{header}: Bearer <REDACTED>\n"


@pytest.mark.parametrize(
    "url,suffix",
    [
        ("https://host/?key=VALUESECRET99&region=us", "&region=us"),
        ("https://host/?key=VALUESECRET99;region=us", ";region=us"),
        ("https://host/?key=VALUESECRET99&bare", ""),
    ],
)
def test_query_extent_preserves_only_named_following_parameters(
    url: str, suffix: str, tmp_path: Path
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(url, encoding="utf-8")
    redact_file(path)
    cleaned = path.read_text(encoding="utf-8")
    assert "VALUESECRET99" not in cleaned
    assert suffix in cleaned


@pytest.mark.parametrize(
    "value,preserved",
    [
        (
            {
                "sources": [
                    {
                        "hotkeys": {
                            "libobs.mute": [
                                {"key": "OBS_KEY_M", "settings": {"key": "NESTED_STREAM_KEY_9988"}}
                            ]
                        }
                    }
                ]
            },
            "OBS_KEY_M",
        ),
        ({"hotkeys": {"key": "live_actual_stream_key_zzzz"}}, "live_actual_stream_key_zzzz"),
        (
            {"bindings": {"settings": {"key": "BINDINGS_SETTINGS_KEY_42"}}},
            "BINDINGS_SETTINGS_KEY_42",
        ),
    ],
)
def test_hotkey_key_exemption_is_value_and_settings_ancestor_based(
    value, preserved, tmp_path: Path
) -> None:
    path = tmp_path / "scene.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    redact_file_with_secrets(path)
    output = path.read_text(encoding="utf-8")
    if preserved == "OBS_KEY_M":
        assert preserved in output
    else:
        assert "<REDACTED>" in output
    assert "NESTED_STREAM_KEY_9988" not in output
    if preserved != "OBS_KEY_M":
        assert preserved not in output
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/cb#access_token=FRAGMENTLOG99&foo=1",
        "https://example.com/cb?region=us#access_token=X",
        "https://example.com/app#/token=FRAGMENTSECRET99",
    ],
)
def test_url_fragment_credentials_are_redacted_and_verified(url: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(f"source {url}\n", encoding="utf-8")
    redact_file_with_secrets(path)
    output = path.read_text(encoding="utf-8")
    assert "FRAGMENTLOG99" not in output and "FRAGMENTSECRET99" not in output
    assert "#section-2" not in output or "section-2" in output
    if "region=us" in url:
        assert "region=us" in output
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "line,secret",
    [
        (
            "10:00:00.000: note Authorization: Api-Key SUPERAUTHSECRET99 later\n",
            "SUPERAUTHSECRET99",
        ),
        (
            '10:00:03.000: Authorization: Digest username="b", '
            'response="DIGESTRESPONSESECRET", qop=auth\n',
            "DIGESTRESPONSESECRET",
        ),
        ("10:00:02.000: saw authorization: SECRETNOSCHEME1 later\n", "SECRETNOSCHEME1"),
    ],
)
def test_authorization_remainder_is_redacted_to_line_end(
    line: str, secret: str, tmp_path: Path
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line, encoding="utf-8")
    redact_file_with_secrets(path)
    output = path.read_text(encoding="utf-8")
    assert secret not in output
    assert not _secret_scan(path)


def test_fragment_and_benign_authorization_text_survive(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text("authorization is enabled #section-2 and /#/settings/audio\n", encoding="utf-8")
    redact_file_with_secrets(path)
    assert (
        path.read_text(encoding="utf-8")
        == "authorization is enabled #section-2 and /#/settings/audio\n"
    )
    assert not _secret_scan(path)


def test_browser_source_json_fragment_credentials_are_redacted(tmp_path: Path) -> None:
    path = tmp_path / "scene.json"
    path.write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "id": "browser_source",
                        "settings": {
                            "url": "https://example.com/cb?region=us#access_token=BROWSERFRAGMENT99",
                            "width": 800,
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    redact_file_with_secrets(path)
    cleaned = json.loads(path.read_text(encoding="utf-8"))
    settings = cleaned["sources"][0]["settings"]
    assert "BROWSERFRAGMENT99" not in settings["url"]
    assert "region=us" in settings["url"] and settings["width"] == 800
    assert not _secret_scan(path)


def test_ini_sensitive_continuations_are_redacted_and_benign_indentation_kept(
    tmp_path: Path,
) -> None:
    path = tmp_path / "basic.ini"
    path.write_text(
        "[Output]\npassword = \\\n  CONT_SECRET_LINE\n"
        "password = first\n    INDENT_SECRET_LINE\nName=plain\n    description text\n",
        encoding="utf-8",
    )
    redact_file_with_secrets(path)
    output = path.read_text(encoding="utf-8")
    assert "CONT_SECRET_LINE" not in output and "INDENT_SECRET_LINE" not in output
    assert "description text" in output
    assert not _secret_scan(path)


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


def test_seeded_multishape_fuzz_has_zero_shipped_leaks(tmp_path: Path) -> None:  # noqa: PLR0915
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
            form = rng.choice(
                (
                    "plain",
                    "scheme",
                    "scheme-colon",
                    "double-scheme",
                    "scheme-nextline",
                    "scheme-newline-token",
                    "yaml-block",
                    "scheme-suffix",
                    "trailing-suffix",
                    "wrapped_scheme",
                    "glued_amp",
                    "glued_semicolon",
                    "glued_hash",
                )
            )
            if form != "plain":
                quote = ""
                scheme = rng.choice(SCHEME_WORDS)
                if form == "scheme":
                    value = f"{scheme} {value}"
                elif form == "scheme-colon":
                    value = f"{scheme}: {value}"
                elif form == "double-scheme":
                    value = f"{scheme} token {value}"
                elif form == "scheme-nextline":
                    value = f"\n    {scheme} {value}"
                elif form == "scheme-newline-token":
                    value = f"{scheme}\n    {value}"
                elif form == "yaml-block":
                    value = f"|\n    {value}"
                elif form == "scheme-suffix":
                    scheme_suffix = rng.choice([".", ";", ")", "]", "}", "#", ":", ",", "="])
                    credential_suffix = rng.choice([".", ",", ")", ";", "!", "?"])
                    value = f"{scheme}{scheme_suffix} {value}{credential_suffix}"
                else:
                    value = f"{scheme} {value}{rng.choice(['.', ',', ')', ';', '!', '?'])}"
            return f"{prefix}{name}{separator}{quote}{value}{quote}\n", "current.txt", secret(index)
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
        path = tmp_path / filename
        path.write_text(content, encoding="utf-8")
        _counts, _total, secrets = redact_file_with_secrets(path)
        output = read_text_safely(path)
        flagged = _contains_private_secret(path, secrets) or _secret_scan(path)
        if flagged:
            leaks.append(f"verifier rejected redacted {filename}: {content!r} -> {output!r}")
        if literal in output and not flagged:
            leaks.append(f"{filename}: {content!r} -> {output!r}")
        if literal in secrets:
            copied = _scrub_text(f"duplicate {literal}", secrets)
            if literal in copied:
                leaks.append(f"second-file duplicate survived for {filename}: {literal!r}")
            assert "duplicate" in copied
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


@pytest.mark.parametrize(
    "name",
    [
        "dbpassword",
        "serverpassword",
        "adminpassword",
        "userpassword",
        "apitoken",
        "sessiontoken",
        "oauthtoken",
        "idtoken",
        "twitchtoken",
    ],
)
@pytest.mark.parametrize("separator", ["=", ": "])
def test_compound_credential_suffixes_redact_in_free_text(
    name: str, separator: str, tmp_path: Path
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(f"{name}{separator}ABCD#LEAKTAIL\n", encoding="utf-8")
    assert _secret_scan(path)
    redact_file(path)
    assert "ABCD" not in path.read_text(encoding="utf-8")
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "name",
    [
        "dbpassword",
        "serverpassword",
        "adminpassword",
        "userpassword",
        "apitoken",
        "sessiontoken",
        "oauthtoken",
        "idtoken",
        "twitchtoken",
    ],
)
def test_compound_credential_suffixes_redact_in_json_and_ini(name: str, tmp_path: Path) -> None:
    secret = "COMPOUND_SECRET_987"
    json_path = tmp_path / "service.json"
    json_path.write_text(json.dumps({"settings": {name: secret}}), encoding="utf-8")
    assert _secret_scan(json_path)
    redact_file(json_path)
    assert secret not in json_path.read_text(encoding="utf-8")
    assert not _secret_scan(json_path)

    ini_path = tmp_path / "basic.ini"
    ini_path.write_text(f"{name}={secret}\n", encoding="utf-8")
    assert _secret_scan(ini_path)
    redact_file(ini_path)
    assert secret not in ini_path.read_text(encoding="utf-8")
    assert not _secret_scan(ini_path)


@pytest.mark.parametrize(
    "value",
    [
        "hunter2#LEAKTAIL",
        "hunter2&3xLEAKTAIL",
        "hunter2;LEAKTAILQ",
        "hunter2\\Zq9LEAK",
        "hunter2`TAIL",
        "hunter2}TAIL",
    ],
)
def test_log_unquoted_value_punctuation_is_fully_redacted(value: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(f"password={value}\n", encoding="utf-8")
    assert _secret_scan(path)
    redact_file(path)
    assert value not in path.read_text(encoding="utf-8")
    assert not _secret_scan(path)


@pytest.mark.parametrize("name", ["password", "token"])
@pytest.mark.parametrize("tail", ["#TAIL", "&x", "\\x"])
def test_verifier_rejects_trailing_token_after_redacted_marker(
    name: str, tail: str, tmp_path: Path
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(f"{name}=<REDACTED>{tail}\n", encoding="utf-8")
    assert _secret_scan(path)


@pytest.mark.parametrize("text", ["authorization=SECRET", "authorization: SECRET"])
def test_authorization_without_scheme_is_redacted(text: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(text + "\n", encoding="utf-8")
    assert _secret_scan(path)
    redact_file(path)
    assert "SECRET" not in path.read_text(encoding="utf-8")
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "line,secret,expected",
    [
        ("Authorization: Bearer LEAKBE", "LEAKBE", "Authorization: Bearer <REDACTED>\n"),
        ("Authorization: Basic LEAKB64", "LEAKB64", "Authorization: Basic <REDACTED>\n"),
        (
            "info: Authorization: Bearer LEAKBE",
            "LEAKBE",
            "info: Authorization: Bearer <REDACTED>\n",
        ),
        (
            "x Authorization: Basic LEAKB64 y",
            "LEAKB64",
            "x Authorization: Basic <REDACTED>\n",
        ),
        (
            "debug: aUtHoRiZaTiOn : dIgEsT DIGEST_SECRET trailing",
            "DIGEST_SECRET",
            "debug: aUtHoRiZaTiOn : dIgEsT <REDACTED>\n",
        ),
        ("Authorization=Bearer LEAKBE", "LEAKBE", "Authorization=Bearer <REDACTED>\n"),
        ("authorization=LEAKAUTH", "LEAKAUTH", "authorization=<REDACTED>\n"),
        ("authorization: LEAKAUTH", "LEAKAUTH", "authorization: <REDACTED>\n"),
        ("Authorization: token LEAKT", "LEAKT", "Authorization: token <REDACTED>\n"),
    ],
)
def test_authorization_headers_redact_value_and_verifier_agrees(
    line: str, secret: str, expected: str, tmp_path: Path
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line + "\n", encoding="utf-8")
    assert _secret_scan(path)

    _counts, _total, secrets = redact_file_with_secrets(path)

    cleaned = path.read_text(encoding="utf-8")
    assert cleaned == expected
    assert secret not in cleaned
    assert not _contains_private_secret(path, secrets)
    assert not _secret_scan(path)


@pytest.mark.parametrize("url", ["redis://:SECRET@host", "https://user:ab@SECRET@host/path"])
def test_url_userinfo_redacts_through_last_authority_at(url: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(url + "\n", encoding="utf-8")
    assert _secret_scan(path)
    redact_file(path)
    output = path.read_text(encoding="utf-8")
    assert "SECRET" not in output
    assert not _secret_scan(path)


def test_url_query_delimiters_end_only_that_query_parameter(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text("https://host/?token=QUERYSECRET&region=us\n", encoding="utf-8")
    redact_file(path)
    output = path.read_text(encoding="utf-8")
    assert "QUERYSECRET" not in output
    assert "&region=us" in output
    assert not _secret_scan(path)


def test_punctuation_seeded_fuzz_has_no_shipped_leaks(  # noqa: PLR0912, PLR0915
    tmp_path: Path,
) -> None:
    rng = random.Random(9031)
    names = [
        "password",
        "stream_key",
        "token",
        "api_key",
        "StreamKey",
        "passphrase",
        "client_secret",
        "auth_token",
        "secret",
        "access_token",
        "dbpassword",
        "twitchtoken",
        "Set-Cookie",
        "Cookie",
        "Authorization",
    ]
    alphabet = "abcXYZ123#&;\\`~!@$%^*(){}[]|/+.,-_="
    leaks = []
    overomissions = []
    for _index in range(3000):
        name = rng.choice(names)
        secret = "".join(rng.choice(alphabet) for _ in range(rng.randint(8, 20)))
        if rng.random() < 0.2:
            secret += chr(233)
        quote = rng.choice(["", "'", '"'])
        kind = rng.choice(["log", "ini", "json"])
        form = (
            rng.choice(
                [
                    "plain",
                    "scheme",
                    "nextline",
                    "prose",
                    "scheme_colon",
                    "double_scheme",
                    "scheme_nextline",
                    "scheme_newline_token",
                    "yaml_block",
                    "scheme_suffix",
                    "trailing_suffix",
                    "yaml_ordinary",
                    "wrapped_scheme",
                    "glued_amp",
                    "glued_semicolon",
                    "glued_hash",
                ]
            )
            if kind == "log"
            else "plain"
        )
        planted = form not in {"prose", "yaml_ordinary"}
        if form not in {"plain", "prose"}:
            quote = ""
        if form in {
            "scheme",
            "nextline",
            "scheme_colon",
            "double_scheme",
            "scheme_nextline",
            "scheme_newline_token",
            "yaml_block",
            "scheme_suffix",
            "trailing_suffix",
            "wrapped_scheme",
            "glued_amp",
            "glued_semicolon",
            "glued_hash",
        }:
            secret = "".join(character for character in secret if character.isalnum())
            if len(secret) < 8:
                secret = "SafeSecret99"
        if form == "nextline":
            value = f"\n    {secret}"
        elif form == "prose":
            value = "server returned 401"
        elif form == "yaml_ordinary":
            value = "|\n14:22:01.123: ordinary diagnostic"
        elif form in {
            "scheme",
            "scheme_colon",
            "double_scheme",
            "scheme_nextline",
            "scheme_newline_token",
            "yaml_block",
            "scheme_suffix",
            "trailing_suffix",
            "wrapped_scheme",
            "glued_amp",
            "glued_semicolon",
            "glued_hash",
        }:
            value = _fuzz_scheme_value(rng, form, secret)
        else:
            value = f"{quote}{secret}{quote}"
        if kind == "log":
            if name.casefold() in {"cookie", "set-cookie"} and form != "yaml_ordinary":
                content = (
                    f"14:22:01.123: [obs-browser] {name}: "
                    f"session={secret}; Domain=example.com; theme=dark\n"
                )
                filename = "current.txt"
            elif name.casefold() == "authorization" and form != "yaml_ordinary":
                content = f"14:22:01.123: Authorization: (Bearer) {secret}\n"
                filename = "current.txt"
            else:
                separator = (
                    ":"
                    if form
                    in {
                        "nextline",
                        "prose",
                        "yaml_ordinary",
                        "scheme_nextline",
                        "scheme_newline_token",
                        "yaml_block",
                    }
                    else " ="
                )
                content, filename = f"info: {name}{separator} {value}\n", "current.txt"
        elif kind == "ini":
            content, filename = f"[General]\nNote={name}={value}\n", "global.ini"
        else:
            content, filename = json.dumps({"note": f"{name}={value}"}), "scene.json"
        path = tmp_path / filename
        path.write_text(content, encoding="utf-8")
        _counts, _total, secrets = redact_file_with_secrets(path)
        output = read_text_safely(path)
        flagged = _contains_private_secret(path, secrets) or _secret_scan(path)
        if planted and secret in output and not flagged:
            leaks.append(content)
        elif planted and secret not in output and flagged:
            overomissions.append(content)
        if form == "prose":
            assert "server" not in _embedded_secrets(content)
        if form == "yaml_ordinary":
            assert "ordinary diagnostic" in output
        clean_secret = secret.lstrip("([{<\"'`").rstrip(".,;:)]}>!?\"'`")
        if planted and clean_secret in secrets:
            copied = _scrub_text(f"duplicate {clean_secret}", secrets)
            assert "duplicate" in copied
            if clean_secret in copied:
                leaks.append(
                    f"fuzz second-file duplicate survived: {content!r}; "
                    f"secret={clean_secret!r}, secrets={sorted(secrets)!r}"
                )
    assert leaks == [], leaks[:5]
    assert overomissions == [], overomissions[:5]


@pytest.mark.parametrize(
    ("line", "credential", "expected"),
    [
        (
            "token: Bearer eyJhbGciOiJIUzI1NiJ9.payloadDATA.sigPART99\n",
            "eyJhbGciOiJIUzI1NiJ9.payloadDATA.sigPART99",
            "token: Bearer <REDACTED>\n",
        ),
        (
            "password: Basic dXNlcjpzM2NyZXQ=\n",
            "dXNlcjpzM2NyZXQ=",
            "password: Basic <REDACTED>\n",
        ),
    ],
)
def test_non_authorization_scheme_assignments_redact_and_harvest_credential(
    tmp_path: Path, line: str, credential: str, expected: str
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line, encoding="utf-8")
    _counts, _total, secrets = redact_file_with_secrets(path)
    assert path.read_text(encoding="utf-8") == expected
    assert credential in secrets
    assert "Bearer" not in secrets and "Basic" not in secrets


@pytest.mark.parametrize(
    ("label", "prefix", "credential"),
    [
        ("password", "", "NextLineSecret99xx"),
        ("token", "Bearer", "eyJhbGciOiJIUzI1NiJ9.payloadDATA.sigPART99"),
        ("Authorization", "Bearer", "eyJhbGciOiJIUzI1NiJ9.payloadDATA.sigPART99"),
    ],
)
def test_indented_next_line_credentials_are_harvested(
    tmp_path: Path, label: str, prefix: str, credential: str
) -> None:
    path = tmp_path / "current.txt"
    same_line = f" {prefix}" if prefix else ""
    path.write_text(f"{label}:{same_line}\n    {credential}\n", encoding="utf-8")
    _counts, _total, secrets = redact_file_with_secrets(path)
    assert credential in secrets
    assert "<REDACTED>" in path.read_text(encoding="utf-8")


def test_single_alternation_scrub_scales_with_many_literals() -> None:
    def scrub(count: int) -> None:
        secrets = {f"word{index:05d}xx" for index in range(count)}
        text = "\n".join(f"event {secret} tail" for secret in secrets)
        cleaned = _scrub_text(text, secrets)
        assert f"word{0:05d}xx" not in cleaned
        assert f"word{count - 1:05d}xx" not in cleaned

    _assert_linear_pair(scrub, 24000, 20.0)


def test_free_text_harvest_promotion_requires_key_material(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(
        "token: server returned 401\npassword: required\nkey: expired\n"
        "stream key: (not set)\nStream Key: Test\nkey: 1920x1080\n"
        "key: bitrate\ntoken: nvenc\nkey: OBS_KEY_RETURN\n"
        "token: Qk7mN2pL9xR4\n",
        encoding="utf-8",
    )
    _counts, _total, secrets = redact_file_with_secrets(path)
    assert "Qk7mN2pL9xR4" in secrets
    assert not secrets.intersection(
        {
            "server",
            "required",
            "expired",
            "(not",
            "Test",
            "1920x1080",
            "bitrate",
            "nvenc",
            "OBS_KEY_RETURN",
        }
    )
    cli = tmp_path / "cli.txt"
    cli.write_text("obs --websocket_password Qk7mN2pL9xR4\n", encoding="utf-8")
    _counts, _total, cli_secrets = redact_file_with_secrets(cli)
    assert "Qk7mN2pL9xR4" in cli_secrets


def test_explicit_credential_field_still_promotes_short_literal(tmp_path: Path) -> None:
    path = tmp_path / "service.json"
    path.write_text('{"key":"Test"}', encoding="utf-8")
    _counts, _total, secrets = redact_file_with_secrets(path)
    assert "Test" in secrets


@pytest.mark.parametrize(
    "filename,content",
    [
        (
            "scene.json",
            json.dumps(
                {
                    "sources": [
                        {
                            "hotkeys": {"mute": [{"key": "OBS_KEY_M"}, {"key": "OBS_KEY_U"}]},
                            "settings": {
                                "url": "https://example.com/widget?token=URLSECRET&region=us"
                            },
                        }
                    ]
                }
            ),
        ),
        (
            "basic.ini",
            '[H]\nOBSBasic.StartStreaming={"bindings":[{"key":"OBS_KEY_F9"},{"key":"OBS_KEY_F10"}]}\n',
        ),
        (
            "basic.ini",
            "[H]\nOBSBasic.StartStreaming={\n"
            ' "bindings": [\n {"key":"OBS_KEY_F9"},\n'
            ' {"key":"OBS_KEY_F10"}\n ]\n}\n',
        ),
    ],
)
def test_hotkey_structures_and_browser_url_survive_verification(
    tmp_path: Path, filename: str, content: str
) -> None:
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    redact_file_with_secrets(path)
    for binding in re.findall(r"OBS_KEY_[A-Z0-9_]+", content):
        assert binding in path.read_text(encoding="utf-8")
    assert "URLSECRET" not in path.read_text(encoding="utf-8")
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "line",
    [
        "Authorization: ghp_LKsecret99 (expired)\n",
        "authorization=TOKEN user=bob\n",
        "HTTP 401 for Authorization: TOKEN - retrying\n",
        "x-authorization: TOKEN ok\n",
        "Proxy-Authorization: Basic abcdefgh\n",
        "Cookie: a=1; b=COOKIESECRET\n",
        "--websocket_password hunterLEAK22 --foo\n",
        "-Password X\n",
        "pwd=hunter22abcXY\n",
        "a=b;pwd: X\n",
        "token=abc;password: 99887766\n",
        "Authorization: Bearer <REDACTED>, retrying\n",
    ],
)
def test_structural_log_credentials_are_redacted_and_verifier_accepts(
    tmp_path: Path, line: str
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(line, encoding="utf-8")
    redact_file_with_secrets(path)
    output = path.read_text(encoding="utf-8")
    assert not any(
        secret in output
        for secret in ("hunterLEAK22", "COOKIESECRET", "hunter22abcXY", "99887766", "abcdefgh")
    )
    assert not _secret_scan(path)


@pytest.mark.parametrize("name", ["token", "password"])
def test_noncredential_literals_under_sensitive_names_are_unchanged(
    tmp_path: Path, name: str
) -> None:
    path = tmp_path / "current.txt"
    path.write_text(
        f"Console: {name}: null\nrequire password: false\nPortable mode: false\n", encoding="utf-8"
    )
    original = path.read_text(encoding="utf-8")
    redact_file_with_secrets(path)
    assert path.read_text(encoding="utf-8") == original
    assert not _secret_scan(path)


def test_redaction_is_idempotent_and_punctuation_fuzz_has_zero_overomission(tmp_path: Path) -> None:
    rng = random.Random(13)
    alphabet = "abcXYZ123#&;\\`~!@$%^*(){}[]|/+.,-_="
    for i in range(3000):
        secret = "LK" + "".join(rng.choice(alphabet) for _ in range(9)) + "ZZ"
        text = f"token={secret}; password: xyz\n"
        path = tmp_path / f"p{i}.txt"
        path.write_text(text, encoding="utf-8")
        counts, _, _ = redact_file_with_secrets(path)
        once = path.read_bytes()
        second_counts, second_total, _ = redact_file_with_secrets(path)
        assert path.read_bytes() == once
        assert not any(value in path.read_text(encoding="utf-8") for value in (secret,))
        assert not _secret_scan(path)
        assert not second_counts and second_total == 0
        assert counts


def test_sensitive_compound_keys_and_streamelements_overlay_token(tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(
        "secretkey=KEYSECRET\nhttps://www.streamelements.com/overlay/id/OVERLAYSECRET\n",
        encoding="utf-8",
    )
    redact_file_with_secrets(path)
    assert "KEYSECRET" not in path.read_text(encoding="utf-8")
    assert "OVERLAYSECRET" not in path.read_text(encoding="utf-8")
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/widget?token=URL_TOKEN_R4&region=us",
        "https://example.com/widget?api_key=URL_API_R4&region=us",
        "https://example.com/widget?region=us&token=URL_MIDDLE_R4&theme=dark",
        "https://example.com/widget?region=us&token=URL_END_R4",
    ],
)
def test_browser_source_query_secrets_are_redacted_structurally(tmp_path: Path, url: str) -> None:
    path = tmp_path / "scene.json"
    path.write_text(json.dumps({"sources": [{"settings": {"url": url, "width": 800}}]}))
    redact_file_with_secrets(path)
    output = path.read_text(encoding="utf-8")
    assert "URL_" not in output
    assert "region=us" in output
    assert not _secret_scan(path)


@pytest.mark.parametrize("literal", ["null", "undefined", "none", "nil", "true", "false"])
def test_sensitive_word_literals_are_not_credentials(tmp_path: Path, literal: str) -> None:
    path = tmp_path / "current.txt"
    content = f"token={literal}\npassword: {literal}\nvalue is {literal}\n"
    path.write_text(content, encoding="utf-8")
    redact_file_with_secrets(path)
    assert path.read_text(encoding="utf-8") == content
    assert not _secret_scan(path)


@pytest.mark.parametrize("name,value", [("SortKey", "Name"), ("audio_key", "1")])
def test_short_or_weak_key_values_do_not_drop_log(name: str, value: str, tmp_path: Path) -> None:
    path = tmp_path / "current.txt"
    path.write_text(
        f"14:00:00.000: CPU Name: Test CPU\n{name}: {value}\nvalue=1 and 0\n", encoding="utf-8"
    )
    redact_file_with_secrets(path)
    expected = value if name == "SortKey" and value == "Name" else "<REDACTED>"
    assert path.read_text(encoding="utf-8") == (
        f"14:00:00.000: CPU Name: Test CPU\n{name}: {expected}\nvalue=1 and 0\n"
    )
    if value != "Name":
        assert not _contains_private_secret(path, {value})
    assert not _secret_scan(path)


@pytest.mark.parametrize("n", [40])
def test_comment_separator_adversarial_input_is_fast(tmp_path: Path, n: int) -> None:
    path = tmp_path / "current.txt"
    path.write_text("key" + "/**/" * n + "\n", encoding="utf-8")
    started = time.perf_counter()
    redact_file(path)
    assert not has_unredacted_embedded_json(path.read_text(encoding="utf-8"))
    assert time.perf_counter() - started < 10


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


def test_ini_note_redacts_cli_style_sensitive_assignments(tmp_path: Path) -> None:
    path = tmp_path / "global.ini"
    path.write_text("[General]\nNote=--ApiKey=INI_API_SECRET\n", encoding="utf-8")
    redact_file_with_secrets(path)
    output = path.read_text(encoding="utf-8")
    assert "INI_API_SECRET" not in output
    assert not _secret_scan(path)


@pytest.mark.parametrize(
    "content,secret",
    [
        ("pwd:LKQ<Z&59043:Xcf5ZZ\n", "LKQ<Z&59043:Xcf5ZZ"),
        ('websocket_password=LK$?Q0=".eYaa9Z4\u6f22dZZ}\n', 'LK$?Q0=".eYaa9Z4\u6f22dZZ}'),
        ("Key = LK\u6f228X1?4f96Qa=d'42YZZ\n", "LK\u6f228X1?4f96Qa=d'42YZZ"),
        ("a=b&privateKey: LKd`|7c4ecbc=bQZ:9a}ZZ&region=us\n", "LKd`|7c4ecbc=bQZ:9a}ZZ"),
        ("a=b&streamKey=&quot;LKQb:{1=98!=0?bu794ZZ&quot;\n", "LKQb:{1=98!=0?bu794ZZ"),
        ("url=https://h.example/p?token : COLON_QUERY_SECRET\n", "COLON_QUERY_SECRET"),
    ],
)
def test_punctuation_in_secret_values_is_fully_redacted_and_accepted(
    tmp_path: Path, content: str, secret: str
) -> None:
    path = tmp_path / "punctuation.txt"
    path.write_text(content, encoding="utf-8")
    redact_file_with_secrets(path)
    output = path.read_text(encoding="utf-8")
    assert secret not in output
    assert not _secret_scan(path)
