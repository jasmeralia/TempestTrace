"""Versioned, conservative credential redaction for staged OBS files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

RULE_VERSION = 1
REDACTED = "<REDACTED>"
_LOG_PATTERNS = (
    re.compile(
        r"(?i)(\b(?:key|stream[_ -]?key|bearer[_ -]?token|password|passwd|"
        r"access[_ -]?token|client[_ -]?secret)\s*[=:]\s*)"
        r'("[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;\]\"\']+)'
    ),
    re.compile(r"(?i)(\bAuthorization:\s*(?:Bearer|Basic)\s+)([^\s,;]+)"),
)


def _is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    return normalized in {
        "key",
        "streamkey",
        "password",
        "passwd",
        "token",
        "bearertoken",
        "clientsecret",
        "secret",
        "authorization",
    } or bool(
        re.search(
            r"(?:^|[^a-zA-Z0-9])(?:key|token|password|passwd|secret)$"
            r"|(?<=[a-z0-9])(?:Key|Token|Password|Passwd|Secret)$",
            key,
        )
    )


def _credential_values(value: Any) -> set[str]:
    """Collect credential literals transiently so duplicate values can be scrubbed."""
    values: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and _is_sensitive_key(key):
                values.update(_string_values(child))
            else:
                values.update(_credential_values(child))
    elif isinstance(value, list):
        for child in value:
            values.update(_credential_values(child))
    return values


def _string_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value} if value else set()
    if isinstance(value, dict):
        return set().union(*(_string_values(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(_string_values(child) for child in value))
    return set()


def _scrub_text(text: str, secrets: set[str]) -> str:
    for secret in sorted(secrets, key=len, reverse=True):
        if secret and secret != REDACTED:
            text = text.replace(secret, REDACTED)
    return text


def _redact_object(value: Any, counts: dict[str, int], secrets: set[str]) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if isinstance(key, str) and _is_sensitive_key(key) and child not in (None, ""):
                result[key] = REDACTED
                counts["credential_field"] = counts.get("credential_field", 0) + 1
            else:
                result[key] = _redact_object(child, counts, secrets)
        return result
    if isinstance(value, list):
        return [_redact_object(child, counts, secrets) for child in value]
    if isinstance(value, str):
        return _scrub_text(value, secrets)
    return value


def has_unredacted_fields(value: Any) -> bool:
    """Check parsed JSON for recognized credential keys with remaining values."""
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                isinstance(key, str)
                and _is_sensitive_key(key)
                and child not in (None, "", REDACTED)
            ):
                return True
            if has_unredacted_fields(child):
                return True
    elif isinstance(value, list):
        return any(has_unredacted_fields(child) for child in value)
    return False


def redact_file_with_secrets(path: Path) -> tuple[dict[str, int], int, set[str]]:
    """Redact one staged file and return secret literals for private verification."""
    suffix = path.suffix.lower()
    counts: dict[str, int] = {}
    secrets: set[str] = set()
    is_json = suffix == ".json" or path.name.lower().endswith(".json.bak")
    is_ini = suffix == ".ini" or path.name.lower().endswith(".ini.bak")
    if is_json:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        secrets = _credential_values(raw)
        clean = _redact_object(raw, counts, secrets)
        path.write_text(json.dumps(clean, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif is_ini:
        text = path.read_text(encoding="utf-8-sig")
        lines: list[str] = []
        for original_line in text.splitlines(keepends=True):
            match = re.match(r"^(\s*)([^=:#\s]+)(\s*[=:]\s*)(.*?)(\r?\n)?$", original_line)
            if match and _is_sensitive_key(match.group(2)) and match.group(4).strip():
                secret = match.group(4).strip()
                if len(secret) >= 2 and secret[0] == secret[-1] and secret[0] in "\"'":
                    secret = secret[1:-1]
                if secret:
                    secrets.add(secret)
                cleaned_line = (
                    f"{match.group(1)}{match.group(2)}{match.group(3)}"
                    f"{REDACTED}{match.group(5) or ''}"
                )
                counts["credential_field"] = counts.get("credential_field", 0) + 1
            else:
                cleaned_line = original_line
            lines.append(cleaned_line)
        path.write_text(_scrub_text("".join(lines), secrets), encoding="utf-8", newline="")
    elif suffix == ".txt":
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in _LOG_PATTERNS:

            def redact_match(match: re.Match[str]) -> str:
                secret = match.group(2)
                if len(secret) >= 2 and secret[0] == secret[-1] and secret[0] in "\"'":
                    secret = secret[1:-1]
                if secret:
                    secrets.add(secret)
                return f"{match.group(1)}{REDACTED}"

            text, number = pattern.subn(redact_match, text)
            if number:
                counts["credential_pattern"] = counts.get("credential_pattern", 0) + number
        path.write_text(_scrub_text(text, secrets), encoding="utf-8")
    return counts, sum(counts.values()), secrets


def redact_file(path: Path) -> tuple[dict[str, int], int]:
    """Redact recognized secrets in one staged text file, preserving other values."""
    counts, total, _secrets = redact_file_with_secrets(path)
    return counts, total
