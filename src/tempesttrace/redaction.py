"""Versioned, conservative credential redaction for staged OBS files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

RULE_VERSION = 4
REDACTED = "<REDACTED>"
_LOG_PATTERNS = (
    re.compile(
        r"(?i)((?<![?&])\b(?:key|stream[_ -]?key|api[_ -]?key|token|auth[_ -]?token|"
        r"bearer[_ -]?token|password|passwd|access[_ -]?token|client[_ -]?secret)"
        r"\s*[=:]\s*)"
        r'("[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;\]\"\']+)'
    ),
    re.compile(r"(?i)(\bAuthorization:\s*(?:Bearer|Basic)\s+)([^\s,;]+)"),
)
_URL_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:token|key|api[_-]?key|access[_-]?token|auth[_-]?token)=)"
    r"([^&#\s\"'<>]+)"
)
_STREAMLABS_WIDGET_TOKEN = re.compile(
    r"(?i)(https?://(?:www\.)?streamlabs\.com/(?:widgets/)?[^/?#\s]+/v\d+/)"
    r"([^/?#\s\"'<>]+)"
)
_ASSIGNMENT_VALUE = re.compile(
    r"(?im)(?P<prefix>(?:^|[\s,;])[^=\s,;]+[=:]\s*)"
    r'(?P<value>"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)'
)


def _is_sensitive_key(key: str, context: tuple[str, ...] = ()) -> bool:
    """Recognize credential names, treating the ambiguous `key` contextually."""
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    credential_names = {
        "apikey",
        "streamkey",
        "accesskey",
        "privatekey",
        "password",
        "streampassword",
        "passwd",
        "token",
        "authtoken",
        "accesstoken",
        "bearertoken",
        "clientsecret",
        "secret",
        "authorization",
    }
    if normalized == "key":
        structural_context = {re.sub(r"[^a-z0-9]", "", part.casefold()) for part in context[1:]}
        hotkey_fields = {
            "hotkey",
            "hotkeys",
            "binding",
            "bindings",
            "keybinding",
            "keybindings",
        }
        return not bool(structural_context & hotkey_fields)
    if normalized in credential_names:
        return True
    suffixes = ("key", "token", "password", "passwd", "secret")
    folded_key = key.casefold()
    return bool(
        re.search(r"(?:^|[^a-z0-9])(?:key|token|password|passwd|secret)$", folded_key)
        or any(folded_key.endswith(suffix) and key[-len(suffix) :] != suffix for suffix in suffixes)
    )


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def is_noncredential_log_match(text: str, match: re.Match[str]) -> bool:
    """Identify ambiguous key assignments that are not credential values."""
    field_name = re.split(r"\s*[=:]", match.group(1), maxsplit=1)[0].casefold()
    if field_name != "key":
        return False
    start = text.rfind("\n", 0, match.start()) + 1
    prefix = text[start : match.start()]
    return bool(
        re.search(r"(?i)\b(?:hotkey(?:\s+binding)?|key.?binding|shortcut)\s*$", prefix)
        or re.search(r"(?i)\b(?:chroma|colou?r)\s*$", prefix)
    )


def _embedded_secrets(text: str) -> set[str]:
    values = {match.group(2) for match in _URL_QUERY_SECRET.finditer(text)}
    values.update(match.group(2) for match in _STREAMLABS_WIDGET_TOKEN.finditer(text))
    for pattern in _LOG_PATTERNS:
        values.update(
            _unquote(match.group(2))
            for match in pattern.finditer(text)
            if not is_noncredential_log_match(text, match)
        )
    for _start, _end, value, context in _json_fragments(text):
        values.update(_credential_values(value, context))
    return {value for value in values if value and value != REDACTED}


def _json_fragments(text: str) -> list[tuple[int, int, Any, tuple[str, ...]]]:
    """Find valid JSON object/array fragments in otherwise free-form text."""
    decoder = json.JSONDecoder()
    fragments: list[tuple[int, int, Any, tuple[str, ...]]] = []
    index = 0
    while index < len(text):
        starts = [
            position for position in (text.find("{", index), text.find("[", index)) if position >= 0
        ]
        if not starts:
            break
        start = min(starts)
        try:
            value, length = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            index = start + 1
            continue
        end = start + length
        line_start = text.rfind("\n", 0, start) + 1
        assignment_prefix = text[line_start:start]
        # OBS stores individual action bindings as JSON-valued INI assignments.
        # Their bare `key` property is a hotkey, while other credential fields
        # in the same object still receive normal structural redaction.
        context = (
            ("<embedded>", "hotkeys")
            if re.search(r"(?i)\bOBSBasic\.[\w.]+\s*=\s*$", assignment_prefix)
            else ("<embedded>",)
        )
        fragments.append((start, end, value, context))
        index = end
    return fragments


def _string_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value} if value else set()
    if isinstance(value, dict):
        return set().union(*(_string_values(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(_string_values(child) for child in value))
    return set()


def _credential_values(value: Any, context: tuple[str, ...] = ()) -> set[str]:
    """Collect credential literals transiently so duplicate values can be checked."""
    values: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            child_context = context + ((key,) if isinstance(key, str) else ())
            if isinstance(key, str) and _is_sensitive_key(key, context):
                values.update(_string_values(child))
            else:
                values.update(_credential_values(child, child_context))
    elif isinstance(value, list):
        for child in value:
            values.update(_credential_values(child, context))
    elif isinstance(value, str):
        values.update(_embedded_secrets(value))
    return values


def _scrub_text(text: str, secrets: set[str]) -> str:
    """Replace only complete assignment values; never scrub arbitrary substrings."""
    if not secrets:
        return text

    def scrub(match: re.Match[str]) -> str:
        if _unquote(match.group("value")) in secrets:
            return f"{match.group('prefix')}{REDACTED}"
        return match.group(0)

    return _ASSIGNMENT_VALUE.sub(scrub, text)


def _redact_embedded(text: str, counts: dict[str, int], secrets: set[str] | None = None) -> str:
    def replace(match: re.Match[str]) -> str:
        if _unquote(match.group(2)) == REDACTED:
            return match.group(0)
        if is_noncredential_log_match(text, match):
            return match.group(0)
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{match.group(1)}{REDACTED}"

    fragments = _json_fragments(text)
    if fragments:
        pieces: list[str] = []
        cursor = 0
        for start, end, value, context in fragments:
            pieces.append(text[cursor:start])
            cleaned = _redact_object(value, counts, secrets or set(), context)
            pieces.append(json.dumps(cleaned, ensure_ascii=False, separators=(",", ":")))
            cursor = end
        pieces.append(text[cursor:])
        text = "".join(pieces)
    text = _URL_QUERY_SECRET.sub(replace, text)
    text = _STREAMLABS_WIDGET_TOKEN.sub(replace, text)
    for pattern in _LOG_PATTERNS:
        text = pattern.sub(replace, text)
    return text


def _redact_object(
    value: Any,
    counts: dict[str, int],
    secrets: set[str],
    context: tuple[str, ...] = (),
) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if isinstance(key, str) and _is_sensitive_key(key, context) and child not in (None, ""):
                result[key] = REDACTED
                counts["credential_field"] = counts.get("credential_field", 0) + 1
            else:
                child_context = context + ((key,) if isinstance(key, str) else ())
                result[key] = _redact_object(child, counts, secrets, child_context)
        return result
    if isinstance(value, list):
        return [_redact_object(child, counts, secrets, context) for child in value]
    if isinstance(value, str):
        if value in secrets:
            # Secret literals are collected across the whole document so that
            # duplicate values under otherwise benign keys are scrubbed too.
            # Count each replacement just like a sensitive-key replacement.
            if value != REDACTED:
                counts["credential_field"] = counts.get("credential_field", 0) + 1
            return REDACTED
        return _scrub_text(_redact_embedded(value, counts, secrets), secrets)
    return value


def has_unredacted_fields(value: Any, context: tuple[str, ...] = ()) -> bool:
    """Check parsed JSON for recognized credential keys with remaining values."""
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                isinstance(key, str)
                and _is_sensitive_key(key, context)
                and child not in (None, "", REDACTED)
            ):
                return True
            child_context = context + ((key,) if isinstance(key, str) else ())
            if has_unredacted_fields(child, child_context):
                return True
    elif isinstance(value, list):
        return any(has_unredacted_fields(child, context) for child in value)
    elif isinstance(value, str):
        return has_unredacted_embedded_json(value)
    return False


def has_unredacted_embedded_json(text: str) -> bool:
    """Check JSON embedded in INI values, logs, and other text for credentials."""
    return any(
        has_unredacted_fields(value, context) for _, _, value, context in _json_fragments(text)
    )


def has_unredacted_ini_fields(text: str, filename: str) -> bool:
    """Check INI assignments using the same key rules as the redactor."""
    for line in text.splitlines():
        match = re.match(r"^\s*([^=:#\s]+)\s*[=:]\s*(.*?)\s*$", line)
        if (
            match
            and _is_sensitive_key(match.group(1), (filename,))
            and match.group(2) not in ("", REDACTED)
        ):
            return True
    return False


def _ini_secret_values(text: str, filename: str) -> set[str]:
    secrets: set[str] = set()
    for line in text.splitlines():
        match = re.match(r"^\s*([^=:#\s]+)\s*[=:]\s*(.*?)\s*$", line)
        if match and _is_sensitive_key(match.group(1), (filename,)):
            secret = _unquote(match.group(2))
            if secret and secret != REDACTED:
                secrets.add(secret)
    return secrets


def _redact_ini(text: str, filename: str, counts: dict[str, int], secrets: set[str]) -> str:
    lines: list[str] = []
    for original_line in text.splitlines(keepends=True):
        match = re.match(r"^(\s*)([^=:#\s]+)(\s*[=:]\s*)(.*?)(\r?\n)?$", original_line)
        if match and _is_sensitive_key(match.group(2), (filename,)) and match.group(4).strip():
            cleaned = (
                f"{match.group(1)}{match.group(2)}{match.group(3)}{REDACTED}{match.group(5) or ''}"
            )
            counts["credential_field"] = counts.get("credential_field", 0) + 1
            lines.append(cleaned)
        else:
            lines.append(original_line)
    return _scrub_text("".join(lines), secrets)


def redact_file_with_secrets(path: Path) -> tuple[dict[str, int], int, set[str]]:
    """Redact one staged file and return secret literals for private verification."""
    suffix = path.suffix.lower()
    counts: dict[str, int] = {}
    is_json = suffix == ".json" or path.name.lower().endswith(".json.bak")
    is_ini = suffix == ".ini" or path.name.lower().endswith(".ini.bak")
    if is_json:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        secrets = _credential_values(raw, (path.name,))
        clean = _redact_object(raw, counts, secrets, (path.name,))
        path.write_text(json.dumps(clean, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif is_ini:
        text = path.read_text(encoding="utf-8-sig")
        secrets = _ini_secret_values(text, path.name) | _embedded_secrets(text)
        clean = _redact_ini(text, path.name, counts, secrets)
        clean = _redact_embedded(clean, counts, secrets)
        path.write_text(clean, encoding="utf-8", newline="")
    elif suffix == ".txt":
        text = path.read_text(encoding="utf-8", errors="replace")
        secrets = _embedded_secrets(text)
        text = _redact_embedded(text, counts, secrets)
        path.write_text(_scrub_text(text, secrets), encoding="utf-8")
    else:
        secrets = set()
    return counts, sum(counts.values()), secrets


def redact_file(path: Path) -> tuple[dict[str, int], int]:
    """Redact recognized secrets in one staged text file, preserving other values."""
    counts, total, _secrets = redact_file_with_secrets(path)
    return counts, total
