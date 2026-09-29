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
        r"access[_ -]?token|client[_ -]?secret)\s*[=:]\s*)([^\s,;\]\"']+)"
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
    } or normalized.endswith(("key", "token", "password", "passwd", "secret"))


def _redact_object(value: Any, counts: dict[str, int]) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if isinstance(key, str) and _is_sensitive_key(key) and child not in (None, ""):
                result[key] = REDACTED
                counts["credential_field"] = counts.get("credential_field", 0) + 1
            else:
                result[key] = _redact_object(child, counts)
        return result
    if isinstance(value, list):
        return [_redact_object(child, counts) for child in value]
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


def redact_file(path: Path) -> tuple[dict[str, int], int]:
    """Redact recognized secrets in one staged text file, preserving other values."""
    suffix = path.suffix.lower()
    counts: dict[str, int] = {}
    is_json = suffix == ".json" or path.name.lower().endswith(".json.bak")
    is_ini = suffix == ".ini" or path.name.lower().endswith(".ini.bak")
    if is_json:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        clean = _redact_object(raw, counts)
        path.write_text(json.dumps(clean, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif is_ini:
        text = path.read_text(encoding="utf-8-sig")
        lines: list[str] = []
        for original_line in text.splitlines(keepends=True):
            match = re.match(r"^(\s*)([^=:#\s]+)(\s*[=:]\s*)(.*?)(\r?\n)?$", original_line)
            if match and _is_sensitive_key(match.group(2)) and match.group(4).strip():
                cleaned_line = (
                    f"{match.group(1)}{match.group(2)}{match.group(3)}"
                    f"{REDACTED}{match.group(5) or ''}"
                )
                counts["credential_field"] = counts.get("credential_field", 0) + 1
            else:
                cleaned_line = original_line
            lines.append(cleaned_line)
        path.write_text("".join(lines), encoding="utf-8", newline="")
    elif suffix == ".txt":
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in _LOG_PATTERNS:
            text, number = pattern.subn(rf"\g<1>{REDACTED}", text)
            if number:
                counts["credential_pattern"] = counts.get("credential_pattern", 0) + number
        path.write_text(text, encoding="utf-8")
    return counts, sum(counts.values())
