"""Read-only OBS snapshot, redaction, verification, and ZIP packaging."""

from __future__ import annotations

import configparser
import contextlib
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, quote_plus

from tempesttrace.redaction import (
    _SCHEME_NAMES,
    _SENSITIVE_FREE_NAME,
    REDACTED,
    RULE_VERSION,
    _guard_json_depth,
    _has_sensitive_query_assignment,
    _hotkey_key_exempt,
    _is_repeated_redacted_key_log,
    _is_repeated_redacted_quoted_key_log,
    _is_url_query_assignment,
    _is_weak_camel_key,
    _json_fragments,
    _looks_like_key_material,
    _mask_urls,
    _query_value_is_redacted,
    _query_value_parts,
    _redact_authorization_remainders,
    _redact_free_text_credential_spans,
    has_unredacted_embedded_json,
    has_unredacted_fields,
    has_unredacted_ini_fields,
    read_text_safely,
    redact_file_with_secrets,
)

MAX_FILE_SIZE = 32 * 1024 * 1024
MAX_TOTAL_SIZE = 512 * 1024 * 1024
MAX_LOG_FILES = 5
ALLOWED_PROFILE_SUFFIXES = {".ini", ".json", ".txt"}
_INDEPENDENT_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)(?<![A-Za-z0-9_.\-\"'])(?=(?P<name>{_SENSITIVE_FREE_NAME})"
    r"[ \t]*[=:][ \t]*(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|`[^`\r\n]*`|"
    r"\u201c[^\u201d\r\n]*\u201d|\u2018[^\u2019\r\n]*\u2019|"
    r"&quot;[^\r\n]*?&quot;|&apos;[^\r\n]*?&apos;|%22[^\r\n]*?%22|%27[^\r\n]*?%27|"
    r"[^\s](?:(?![;&,|/?(][A-Za-z0-9_.-]++[ \t]*[=:])[^\s])*))"
)
_INDEPENDENT_QUERY_ASSIGNMENT = re.compile(
    r"(?i)[?&;]([A-Za-z0-9_.-]+)=((?:\"[^\"\r\n]*\"|'[^'\r\n]*'|`[^`\r\n]*`|"
    r"(?:&quot;[^\r\n]*?&quot;|&apos;[^\r\n]*?&apos;|%22[^\r\n]*?%22|%27[^\r\n]*?%27)|"
    r"(?:(?![&;][A-Za-z0-9_.-]+=)[^\s])+))"
)


class BackupCancelled(Exception):
    """Raised when the user cancels between files."""


class FileLimitExceeded(Exception):
    """Raised if a file grows beyond its permitted read size."""


class UnsupportedFileType(Exception):
    """Raised when a selected path is not a regular file."""


@dataclass(frozen=True)
class BackupResult:
    archive: Path
    copied_count: int
    skipped_count: int
    redaction_counts: dict[str, int]
    warnings: tuple[str, ...]


Progress = Callable[[str, int, int], None]
CancelCheck = Callable[[], bool]


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    attrs = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attrs & reparse)


def _path_has_link(root: Path, path: Path) -> bool:
    """Check each selected path component, including ancestors, without resolving links."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    current = root
    for part in parts:
        current = current / part
        if _is_link_or_reparse(current):
            return True
    return False


def _recent_logs(root: Path, candidates: list[Path], skipped: list[dict[str, str]]) -> list[Path]:
    recent: list[tuple[int, Path]] = []
    for item in candidates:
        try:
            recent.append((item.stat().st_mtime_ns, item))
        except OSError:
            skipped.append({"path": item.relative_to(root).as_posix(), "reason": "unreadable"})
    recent.sort(key=lambda entry: entry[0], reverse=True)
    return [item for _, item in recent]


def _reserve_archive_name(
    target_dir: Path, base: str, start_suffix: int = 0
) -> tuple[int, Path, Path, Path]:
    """Exclusively reserve a candidate name for one backup run."""
    suffix = start_suffix
    while True:
        stem = base if suffix == 0 else f"{base}-{suffix}"
        final = target_dir / f"{stem}.zip"
        incomplete_zip = target_dir / f"{stem}.incomplete.zip"
        reservation = target_dir / f".{stem}.reserve"
        try:
            descriptor = os.open(reservation, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            suffix += 1
            continue
        os.close(descriptor)
        if final.exists() or incomplete_zip.exists():
            reservation.unlink(missing_ok=True)
            suffix += 1
            continue
        return suffix, final, incomplete_zip, reservation


def _private_temp_directory(target_dir: Path, prefix: str) -> Path:
    """Create private staging outside the destination, ignoring an unsafe TMPDIR."""
    target = target_dir.resolve()
    candidates = [Path(tempfile.gettempdir()), Path("/tmp"), Path("/var/tmp")]
    system_root = os.environ.get("SYSTEMROOT")
    if system_root:
        candidates.append(Path(system_root) / "Temp")
    candidates.extend((Path.home(), Path(tempfile.gettempdir()).parent))
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved in seen or not resolved.is_dir():
            continue
        seen.add(resolved)
        try:
            resolved.relative_to(target)
        except ValueError:
            pass
        else:
            continue
        try:
            created = Path(tempfile.mkdtemp(prefix=prefix, dir=resolved))
        except OSError:
            continue
        try:
            created.resolve().relative_to(target)
        except ValueError:
            return created
        shutil.rmtree(created, ignore_errors=True)
    raise ValueError("Could not create private staging outside the backup destination.")


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically rename a file without replacing any existing destination."""
    unsupported_rename = {errno.EINVAL, errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP}
    unsupported_link = unsupported_rename | {errno.EPERM}
    try:
        if not sys.platform.startswith("linux"):
            raise OSError(errno.ENOTSUP, "renameat2 is unavailable", destination)
        _renameat2_call(source, destination)
        return
    except OSError as error:
        if error.errno == errno.EEXIST:
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), destination) from error
        if error.errno not in unsupported_rename:
            raise

    try:
        os.link(source, destination)
    except FileExistsError:
        raise
    except OSError as error:
        if error.errno not in unsupported_link:
            raise
        _rename_noreplace_last_resort(source, destination)
    else:
        os.unlink(source)


def _rename_noreplace_last_resort(source: Path, destination: Path) -> None:
    if os.name == "nt" or sys.platform == "win32":
        os.rename(source, destination)
        return

    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    descriptor_open = True
    placeholder: os.stat_result | None = None
    try:
        placeholder = os.fstat(descriptor)
        os.close(descriptor)
        descriptor_open = False
        # Exclusive creation proves nobody else owns the name, so replace only
        # ever replaces our placeholder. A crash between these steps can leave
        # a zero-byte final-named file; it cannot be mistaken for a valid ZIP.
        os.replace(source, destination)
    except BaseException:
        if descriptor_open:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if placeholder is not None:
            try:
                current = destination.lstat()
            except OSError:
                pass
            else:
                if (
                    current.st_dev == placeholder.st_dev
                    and current.st_ino == placeholder.st_ino
                    and current.st_size == 0
                ):
                    with contextlib.suppress(OSError):
                        destination.unlink(missing_ok=True)
        raise


def _renameat2_call(source: Path, destination: Path) -> None:
    """Call Linux renameat2 with RENAME_NOREPLACE, raising its errno on failure."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOTSUP, "renameat2 is unavailable", destination)
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, os.strerror(error), destination)
        raise OSError(error, os.strerror(error), destination)


def _inventory(root: Path, skipped: list[dict[str, str]]) -> list[Path]:  # noqa: PLR0912, PLR0915
    candidates: list[Path] = []
    profiles = root / "basic/profiles"
    if profiles.exists() and _path_has_link(root, profiles):
        skipped.append({"path": "basic/profiles", "reason": "link_or_reparse_point"})
    elif profiles.exists():
        for current, dirs, files in os.walk(profiles, followlinks=False):
            current_path = Path(current)
            keep_dirs: list[str] = []
            for name in dirs:
                item = current_path / name
                if _is_link_or_reparse(item):
                    skipped.append(
                        {
                            "path": item.relative_to(root).as_posix(),
                            "reason": "link_or_reparse_point",
                        }
                    )
                else:
                    keep_dirs.append(name)
            dirs[:] = keep_dirs
            for name in files:
                item = current_path / name
                rel = item.relative_to(root).as_posix()
                if _is_link_or_reparse(item):
                    skipped.append({"path": rel, "reason": "link_or_reparse_point"})
                elif not stat.S_ISREG(item.lstat().st_mode):
                    skipped.append({"path": rel, "reason": "unsupported_file_type"})
                elif item.suffix.lower() in ALLOWED_PROFILE_SUFFIXES or item.name.lower().endswith(
                    (".json.bak", ".ini.bak")
                ):
                    candidates.append(item)
                else:
                    skipped.append({"path": rel, "reason": "unsupported_file_type"})
    scenes = root / "basic/scenes"
    if scenes.exists() and _path_has_link(root, scenes):
        skipped.append({"path": "basic/scenes", "reason": "link_or_reparse_point"})
    elif scenes.is_dir():
        for item in scenes.iterdir():
            if _is_link_or_reparse(item):
                skipped.append(
                    {"path": item.relative_to(root).as_posix(), "reason": "link_or_reparse_point"}
                )
            elif stat.S_ISREG(item.lstat().st_mode) and (
                item.suffix.lower() == ".json" or item.name.lower().endswith(".json.bak")
            ):
                candidates.append(item)
            elif not item.is_dir():
                skipped.append(
                    {"path": item.relative_to(root).as_posix(), "reason": "unsupported_file_type"}
                )
    global_ini = root / "global.ini"
    if global_ini.exists():
        if _path_has_link(root, global_ini):
            skipped.append({"path": "global.ini", "reason": "link_or_reparse_point"})
        elif global_ini.is_file():
            candidates.append(global_ini)
    logs = root / "logs"
    log_candidates = []
    if logs.exists() and _path_has_link(root, logs):
        skipped.append({"path": "logs", "reason": "link_or_reparse_point"})
    elif logs.is_dir():
        for item in logs.iterdir():
            if (
                not _is_link_or_reparse(item)
                and stat.S_ISREG(item.lstat().st_mode)
                and item.suffix.lower() == ".txt"
            ):
                log_candidates.append(item)
            elif not item.is_dir():
                skipped.append(
                    {"path": item.relative_to(root).as_posix(), "reason": "unsupported_file_type"}
                )
    log_candidates = _recent_logs(root, log_candidates, skipped)
    candidates.extend(log_candidates[:MAX_LOG_FILES])
    for item in log_candidates[MAX_LOG_FILES:]:
        skipped.append(
            {"path": item.relative_to(root).as_posix(), "reason": "outside_recent_log_limit"}
        )
    return sorted(set(candidates), key=lambda item: item.relative_to(root).as_posix().casefold())


def _read_consistent(source: Path, target: Path, max_bytes: int) -> tuple[bool, int]:
    for attempt in range(3):
        descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        with os.fdopen(descriptor, "rb") as source_file:
            before = os.fstat(source_file.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise UnsupportedFileType
            data = source_file.read(max_bytes + 1)
            after = os.fstat(source_file.fileno())
        if len(data) > max_bytes:
            raise FileLimitExceeded
        if before.st_size == after.st_size == len(data) and before.st_mtime_ns == after.st_mtime_ns:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            return True, len(data)
        if attempt < 2:
            time.sleep(0.03 * (attempt + 1))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return False, len(data)


def _secret_scan(path: Path) -> bool:  # noqa: PLR0911
    try:
        text = read_text_safely(path)
    except OSError, ValueError:
        return True
    if re.search(
        r"(?i)https?://(?:www\.)?(?:discord|discordapp)\.com/api/webhooks/\d+/"
        r"[^/?#\s\"'<>]+|https?://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/"
        r"[^/?#\s\"'<>]+",
        text,
    ):
        return True
    is_json = path.suffix.lower() == ".json" or path.name.lower().endswith(".json.bak")
    is_ini = path.suffix.lower() == ".ini" or path.name.lower().endswith(".ini.bak")
    if is_json:
        try:
            _guard_json_depth(text)
            structural = has_unredacted_fields(json.loads(text), (path.name,))
            if path.name.lower() == "manifest.json":
                return (
                    structural
                    or has_unredacted_embedded_json(text)
                    or _independent_secret_scan(text)
                )
            return structural
        except OSError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError, MemoryError:
            return True
    if is_ini:
        return has_unredacted_ini_fields(text, path.name)
    if _is_repeated_redacted_key_log(text) or _is_repeated_redacted_quoted_key_log(text):
        return False
    fragments = _json_fragments(text)
    if any(_independent_json_secret(value, context) for _start, _end, value, context in fragments):
        return True
    return has_unredacted_embedded_json(text) or _independent_secret_scan(text)


def _independent_json_secret(value: object, context: tuple[str, ...] = ()) -> bool:  # noqa: PLR0911
    """Check parsed JSON independently, with a narrow hotkey-key exemption."""
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                is_hotkey_key = _hotkey_key_exempt(key, context, child)
                weak_key_is_benign = _is_weak_camel_key(key) and not _looks_like_key_material(
                    child if isinstance(child, str) else ""
                )
                if (
                    _is_sensitive_signature_name(key)
                    and not is_hotkey_key
                    and not weak_key_is_benign
                    and child not in (None, "", "<REDACTED>", True, False)
                    and not (
                        isinstance(child, str)
                        and child.casefold()
                        in {"null", "undefined", "none", "nil", "true", "false"}
                    )
                ):
                    return True
                next_context = (*context, key)
                if _independent_json_secret(child, next_context):
                    return True
        return False
    if isinstance(value, list):
        return any(_independent_json_secret(item, context) for item in value)
    if isinstance(value, str):
        nested = _json_fragments(value)
        if any(
            _independent_json_secret(item, child_context) for _s, _e, item, child_context in nested
        ):
            return True
        return _independent_secret_scan(value)
    return False


def _independent_secret_scan(text: str) -> bool:  # noqa: PLR0912
    """Fail closed on credential assignments with a scanner independent of redactor patterns."""
    if _is_repeated_redacted_key_log(text) or _is_repeated_redacted_quoted_key_log(text):
        return False
    if _redact_authorization_remainders(text, {}) != text:
        return True
    if _redact_free_text_credential_spans(text, {}) != text:
        return True
    folded_text = text.casefold()
    possible_hotkeys = any(
        token in folded_text
        for token in ('"hotkey"', '"hotkeys"', '"binding"', '"bindings"', "obsbasic.", "keybinding")
    )
    assignment_text = _mask_urls(text)
    for match in _INDEPENDENT_SECRET_ASSIGNMENT.finditer(assignment_text):
        name = match.group("name").strip("\\\"'")
        normalized = re.sub(r"[^a-z0-9]", "", name.casefold())
        if not _is_sensitive_signature_name(name):
            continue
        if normalized == "authorization" or ("-" in name and normalized.endswith("authorization")):
            continue
        if _is_url_query_assignment(assignment_text, match.start("name")):
            continue
        if (
            normalized == "key"
            and match.group("name").startswith(('"', "'"))
            and possible_hotkeys
            and _is_hotkey_signature_context(text, match.start("name"))
        ):
            continue
        if normalized == "key":
            line_start = text.rfind("\n", 0, match.start()) + 1
            if re.search(
                r"(?i)\b(?:hotkey(?:\s+binding)?|key.?binding|shortcut|chroma|colou?r)\s*$",
                text[line_start : match.start()],
            ):
                continue
        value = match.group("value").strip()
        unquoted = _unwrap_signature_value(value)
        if unquoted in {"", "<REDACTED>"} or unquoted.casefold() in {
            "true",
            "false",
            "null",
            "undefined",
            "none",
            "nil",
        }:
            continue
        if _is_weak_camel_key(name) and not _looks_like_key_material(unquoted):
            continue
        if normalized == "authorization" or _is_sensitive_signature_name(name):
            parts = unquoted.split(None, 1)
            if parts and parts[0].casefold() in _SCHEME_NAMES:
                if len(parts) == 1:
                    continue
                tail = text[match.end("value") :]
                next_value = re.match(r"[ \t]+([^\s,;]+)", tail)
                if next_value and _unwrap_signature_value(next_value.group(1)) == "<REDACTED>":
                    continue
                if _unwrap_signature_value(parts[1].split(None, 1)[0]) == "<REDACTED>":
                    continue
        return True
    if _has_sensitive_query_assignment(text):
        query_matches = _INDEPENDENT_QUERY_ASSIGNMENT.finditer(text)
    else:
        query_matches = iter(())
    for match in query_matches:
        normalized = re.sub(r"[^a-z0-9]", "", match.group(1).casefold())
        value = _query_value_parts(match.group(2))[0]
        value = _unwrap_signature_value(value)
        if (
            (normalized in {"auth", "sig"} or _is_sensitive_signature_name(match.group(1)))
            and not _query_value_is_redacted(match.group(2) + text[match.end(2) :])
            and value.casefold() not in {"null", "undefined", "none", "nil", "true", "false"}
        ):
            return True
    return False


def _is_sensitive_signature_name(name: str) -> bool:
    """Classify known credential signatures without relying on redactor boundaries."""
    normalized = re.sub(r"[^a-z0-9]", "", name.casefold())
    return (
        normalized
        in {
            "authorization",
            "passphrase",
            "pwd",
            "cookie",
            "cookies",
            "sessionid",
            "jwt",
            "credential",
            "credentials",
            "streamid",
        }
        or normalized in {"key", "authorization"}
        or ("-" in name and normalized.endswith("authorization"))
        or normalized.endswith(("password", "passwd", "secret", "token"))
        or normalized
        in {
            "apikey",
            "streamkey",
            "privatekey",
            "secretkey",
            "authkey",
            "signingkey",
            "encryptionkey",
            "masterkey",
            "sharedkey",
            "sessionkey",
            "accesskey",
        }
        or (
            normalized.endswith("key")
            and normalized != "key"
            and (name[-3:] != "key" or name.casefold().endswith(("_key", "-key", ".key")))
        )
    )


def _is_hotkey_signature_context(text: str, start: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    prefix = text[line_start:start]
    if re.search(r"(?i)OBSBasic\.[\w.]+\s*=\s*(?:\r?\n\s*)*$", prefix):
        return True
    preceding = text[:start]
    assignments = list(re.finditer(r"(?i)OBSBasic\.[\w.]+\s*=", preceding))
    if assignments:
        between = preceding[assignments[-1].end() :]
        between = re.sub(r"(?m)^\s*(?:#|;|//)[^\r\n]*", "", between)
        between = re.sub(r"/\*[\s\S]*?(?:\*/|$)", "", between)
        if re.fullmatch(r"\s*\{\s*", between):
            return True
    for field in ("hotkey", "hotkeys", "binding", "bindings", "keybinding", "keybindings"):
        candidates = (
            text.rfind(f'"{field}"', 0, start),
            text.rfind(f"'{field}'", 0, start),
        )
        field_start = max(candidates)
        if field_start < 0:
            continue
        between = text[field_start:start].casefold()
        if "}" not in between and '"settings"' not in between and "'settings'" not in between:
            return True
    return False


def _unwrap_signature_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'`":
        return value[1:-1]
    for opening, closing in (("\u201c", "\u201d"), ("\u2018", "\u2019")):
        if value.startswith(opening) and closing in value:
            return value[1 : value.rfind(closing)]
    if len(value) >= 2 and value[-1] in "\"'`" and value[0] != value[-1]:
        value = value[:-1]
    for opening, closing in (
        ("&#39;", "&#39;"),
        ("&#x27;", "&#x27;"),
        ("&apos;", "&apos;"),
        ("&quot;", "&quot;"),
        ("%27", "%27"),
        ("%22", "%22"),
        ("&#34;", "&#34;"),
        ("&#x22;", "&#x22;"),
    ):
        if value.casefold().startswith(opening.casefold()) and value.casefold().endswith(
            closing.casefold()
        ):
            return value[len(opening) : -len(closing)]
    return value


def _is_searchable_secret(secret: str) -> bool:
    """Return whether a collected credential literal is safe to scan elsewhere."""
    return len(secret) >= 4 and not (secret.isdigit() and len(secret) < 6)


def _private_literal_patterns(secret: str) -> set[str]:
    patterns: set[str] = set()
    mixed: list[str] = []
    for char in secret:
        if char == " ":
            mixed.append(r"(?:\ |\+|%20|%2520)")
        elif ord(char) < 128:
            code = f"{ord(char):02X}"
            hex_pattern = "".join(f"[{c.lower()}{c.upper()}]" if c.isalpha() else c for c in code)
            mixed.append(rf"(?:{re.escape(char)}|%{hex_pattern}|%25{hex_pattern})")
        else:
            mixed.append(re.escape(char))
    # Fully encoded forms below cover alphanumeric literals. Avoid a costly
    # per-character mixed-encoding expression for large harvested token sets.
    if any(not character.isalnum() for character in secret):
        patterns.add("".join(mixed))
    for candidate in (secret, quote(secret, safe=""), quote_plus(secret)):
        if candidate:
            escaped = re.escape(candidate)
            escaped = re.sub(
                r"%[0-9A-Fa-f]{2}",
                lambda match: (
                    "%"
                    + "".join(
                        "[" + character.lower() + character.upper() + "]"
                        for character in match.group(0)[1:]
                    )
                ),
                escaped,
            )
            patterns.add(escaped)
    if secret.isascii() and secret:
        patterns.add("".join(f"%{ord(character):02X}" for character in secret))
        unicode_escaped = "".join(chr(92) + f"u00{ord(character):02x}" for character in secret)
        hex_escaped = "".join(chr(92) + f"x{ord(character):02x}" for character in secret)
        patterns.add(re.escape(unicode_escaped))
        patterns.add(re.escape(hex_escaped))
    elif secret:
        patterns.add(re.escape("".join(chr(92) + f"u{ord(character):04x}" for character in secret)))
    return patterns


def _compile_private_literals(
    secrets: set[str], weak_secrets: set[str] | None = None, strong_secrets: set[str] | None = None
) -> re.Pattern[str] | None:
    embedded: set[str] = set()
    weak_embedded: set[str] = set()
    bounded: set[str] = set()
    weak_bounded: set[str] = set()
    numeric: set[str] = set()
    weak_secrets = weak_secrets or set()
    strong_secrets = strong_secrets if strong_secrets is not None else secrets - weak_secrets
    for secret in secrets:
        if not _is_searchable_secret(secret):
            continue
        if re.fullmatch(r"-?\d+(?:\.\d+)?", secret):
            numeric.add(secret)
            continue
        is_long_key = len(secret) >= 12 and any(char.isdigit() for char in secret)
        if secret in weak_secrets and secret not in strong_secrets:
            target = weak_embedded if is_long_key else weak_bounded
        else:
            target = embedded if is_long_key else bounded
        target.update(_private_literal_patterns(secret))
    alternatives = []
    if embedded:
        alternatives.append("(?i:" + "|".join(sorted(embedded, key=len, reverse=True)) + ")")
    if weak_embedded:
        alternatives.append("(?:" + "|".join(sorted(weak_embedded, key=len, reverse=True)) + ")")
    if bounded:
        alternatives.append(
            "(?i:"
            + r"(?<![A-Za-z0-9])(?:"
            + "|".join(sorted(bounded, key=len, reverse=True))
            + r")(?![A-Za-z0-9]))"
        )
    if weak_bounded:
        alternatives.append(
            "(?-i:(?<![A-Za-z0-9])(?:"
            + "|".join(sorted(weak_bounded, key=len, reverse=True))
            + r")(?![A-Za-z0-9]))"
        )
    if numeric:
        alternatives.append(
            r"(?<![A-Za-z0-9.-])(?:"
            + "|".join(sorted(numeric, key=len, reverse=True))
            + r")(?![A-Za-z0-9.-])"
        )
    return re.compile("(?:" + "|".join(alternatives) + ")") if alternatives else None


def _scrub_private_literals(
    path: Path,
    pattern: re.Pattern[str] | None,
    numeric_secrets: set[str] | None = None,
) -> int:
    if pattern is None and not numeric_secrets:
        return 0
    text = read_text_safely(path)
    suffix = path.name.casefold()
    is_json = suffix.endswith(".json") or suffix.endswith(".json.bak")
    replacements = 0

    def scrub(value: str) -> str:
        nonlocal replacements
        if pattern is None:
            return value
        cleaned, count = pattern.subn("<REDACTED>", value)
        replacements += count
        return cleaned

    def scrub_embedded_values(value: object) -> object:
        if isinstance(value, str):
            return scrub(value)
        if isinstance(value, list):
            return [scrub_embedded_values(item) for item in value]
        if isinstance(value, dict):
            return {key: scrub_embedded_values(child) for key, child in value.items()}
        if isinstance(value, int) and not isinstance(value, bool):
            return REDACTED if str(value) in (numeric_secrets or set()) else value
        if isinstance(value, float):
            return REDACTED if json.dumps(value) in (numeric_secrets or set()) else value
        return value

    def scrub_ini_value(value: str) -> str:
        fragments = _json_fragments(value)
        if not fragments:
            return scrub(value)
        pieces: list[str] = []
        cursor = 0
        for start, end, document, _context in fragments:
            pieces.append(scrub(value[cursor:start]))
            pieces.append(
                json.dumps(
                    scrub_embedded_values(document), ensure_ascii=False, separators=(",", ":")
                )
            )
            cursor = end
        pieces.append(scrub(value[cursor:]))
        return "".join(pieces)

    if is_json:
        document = json.loads(text)

        def scrub_values(value: object) -> object:
            if isinstance(value, str):
                return scrub(value)
            if isinstance(value, list):
                return [scrub_values(item) for item in value]
            if isinstance(value, dict):
                return {key: scrub_values(child) for key, child in value.items()}
            if isinstance(value, int) and not isinstance(value, bool):
                return REDACTED if str(value) in (numeric_secrets or set()) else value
            if isinstance(value, float):
                return REDACTED if json.dumps(value) in (numeric_secrets or set()) else value
            return value

        cleaned_text = json.dumps(scrub_values(document), ensure_ascii=False, indent=2) + "\n"
    elif suffix.endswith(".ini") or suffix.endswith(".ini.bak"):
        lines = []
        for line in text.splitlines(keepends=True):
            match = re.match(r"([^=:\r\n]*[=:])", line)
            clean_line = (
                line[: match.end()] + scrub_ini_value(line[match.end() :]) if match else scrub(line)
            )
            lines.append(clean_line)
        cleaned_text = "".join(lines)
    else:
        cleaned_text = scrub(text)
    if cleaned_text != text:
        path.write_text(cleaned_text, encoding="utf-8", newline="")
    return replacements


def _contains_private_secret(  # noqa: PLR0911, PLR0912
    path: Path, secrets: set[str], compiled: re.Pattern[str] | None = None
) -> bool:
    """Check that redacted credential literals did not survive in the staged file."""
    if not secrets:
        return False
    try:
        text = read_text_safely(path)
    except OSError, ValueError:
        return True
    pattern = (
        compiled
        if compiled is not None
        else _compile_private_literals(
            secrets,
            getattr(secrets, "weak", None),
            getattr(secrets, "strong", None),
        )
    )
    suffix = path.name.casefold()
    if suffix.endswith(".json") or suffix.endswith(".json.bak"):
        try:
            _guard_json_depth(text)
            value = json.loads(text)
        except ValueError, UnicodeError, json.JSONDecodeError, RecursionError, MemoryError:
            return True

        def contains_value(child: object) -> bool:
            if isinstance(child, str):
                return bool(pattern and pattern.search(child))
            if isinstance(child, bool) or child is None:
                return False
            if isinstance(child, (int, float)):
                return bool(pattern and pattern.search(json.dumps(child, ensure_ascii=False)))
            if isinstance(child, list):
                return any(contains_value(item) for item in child)
            if isinstance(child, dict):
                return any(contains_value(item) for item in child.values())
            return False

        return contains_value(value)
    if suffix.endswith(".ini") or suffix.endswith(".ini.bak"):
        for line in text.splitlines():
            assignment = re.match(r"^\s*[^=:#\s][^=:]*\s*[=:]\s*(.*)$", line)
            if not assignment:
                continue
            value = assignment.group(1)
            fragments = _json_fragments(value)
            if not fragments:
                if pattern and pattern.search(value):
                    return True
                continue
            cursor = 0
            for start, end, embedded, _context in fragments:
                if pattern and pattern.search(value[cursor:start]):
                    return True
                if _contains_in_value(embedded, pattern):
                    return True
                cursor = end
            if pattern and pattern.search(value[cursor:]):
                return True
        return False
    return bool(pattern and pattern.search(text))


def _contains_in_value(value: object, pattern: re.Pattern[str] | None) -> bool:
    if isinstance(value, str):
        return bool(pattern and pattern.search(value))
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(pattern and pattern.search(json.dumps(value, ensure_ascii=False)))
    if isinstance(value, list):
        return any(_contains_in_value(item, pattern) for item in value)
    if isinstance(value, dict):
        return any(_contains_in_value(item, pattern) for item in value.values())
    return False


def create_backup(  # noqa: PLR0912, PLR0915
    source: Path,
    destination: Path,
    *,
    now: datetime | None = None,
    progress: Progress | None = None,
    cancelled: CancelCheck | None = None,
) -> BackupResult:
    """Create a sanitized, verified archive without writing to the OBS source."""
    root = source.expanduser().resolve(strict=True)
    target_dir = destination.expanduser().resolve(strict=True)
    if not root.is_dir() or not target_dir.is_dir():
        raise ValueError("Choose an existing OBS folder and output folder.")
    try:
        target_dir.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("The backup destination cannot be inside the OBS configuration folder.")
    try:
        with tempfile.NamedTemporaryFile(
            dir=target_dir, prefix=".tempesttrace-write-test-", delete=True
        ):
            pass
    except OSError as exc:
        raise ValueError("The selected backup folder is not writable.") from exc

    when = now or datetime.now().astimezone()
    base = f"TempestTrace-{when.strftime('%Y-%m-%d_%H-%M-%S')}"
    suffix, final, incomplete_zip, reservation = _reserve_archive_name(target_dir, base)
    skipped: list[dict[str, str]] = []
    warnings: list[str] = []
    records: list[dict[str, object]] = []
    redaction_counts: dict[str, int] = {}
    private_staging: Path | None = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{base}.incomplete-", dir=target_dir))
        private_staging = _private_temp_directory(target_dir, f".{base}.private-")
        if progress:
            progress("scanning", 0, 0)
        files = _inventory(root, skipped)
        total = 0
        discovered_secrets: set[str] = set()
        weak_secrets: set[str] = set()
        strong_secrets: set[str] = set()
        pending: list[tuple[Path, Path, Path, dict[str, int], bool, str]] = []
        redacting_total = 2 * len(files)
        for index, source_file in enumerate(files, 1):
            if cancelled is not None and cancelled():
                raise BackupCancelled("Collection cancelled.")
            relative = source_file.relative_to(root)
            rel_text = relative.as_posix()
            if _path_has_link(root, source_file):
                skipped.append({"path": rel_text, "reason": "link_or_reparse_point"})
                continue
            try:
                size = source_file.stat().st_size
            except OSError:
                skipped.append({"path": rel_text, "reason": "unreadable"})
                continue
            if size > MAX_FILE_SIZE:
                skipped.append({"path": rel_text, "reason": "per_file_size_limit"})
                continue
            if total + size > MAX_TOTAL_SIZE:
                skipped.append({"path": rel_text, "reason": "total_size_limit"})
                continue
            staged = staging / relative
            private_staged = private_staging / relative
            try:
                if progress:
                    progress("copying", index - 1, len(files))
                byte_limit = min(MAX_FILE_SIZE, MAX_TOTAL_SIZE - total)
                consistent, actual_size = _read_consistent(source_file, private_staged, byte_limit)
                total += actual_size
                if relative.parts[0] == "logs":
                    log_text = read_text_safely(private_staged)
                    if any(len(line) > 512 * 1024 for line in log_text.splitlines()):
                        raise ValueError("Text line exceeds the safe scan limit.")
                    if re.search(r"\[{201,}", log_text):
                        raise ValueError("Log contains excessive nested brackets.")
                if progress:
                    progress("redacting", index - 1, redacting_total)
                categories, _redaction_count, secrets = redact_file_with_secrets(private_staged)
                discovered_secrets.update(secrets)
                weak_secrets.update(getattr(secrets, "weak", set()))
                strong_secrets.update(getattr(secrets, "strong", set()))
            except UnsupportedFileType:
                private_staged.unlink(missing_ok=True)
                skipped.append({"path": rel_text, "reason": "unsupported_file_type"})
                continue
            except FileLimitExceeded:
                skipped.append({"path": rel_text, "reason": "size_limit_exceeded_during_read"})
                continue
            except (
                OSError,
                UnicodeError,
                ValueError,
                configparser.Error,
                RecursionError,
                MemoryError,
            ):
                private_staged.unlink(missing_ok=True)
                reason = (
                    "unreadable" if relative.parts[0] == "logs" else "unreadable_or_unsanitizable"
                )
                skipped.append({"path": rel_text, "reason": reason})
                warnings.append(f"Could not safely include {rel_text}.")
                continue
            if not consistent:
                warnings.append(
                    f"{rel_text} changed while it was being read; "
                    "the captured copy may be inconsistent."
                )
            if relative.parts[0] == "logs" and not consistent:
                warnings.append(
                    "OBS may be writing its current log while collection runs; OBS can remain open."
                )
            for category, amount in categories.items():
                redaction_counts[category] = redaction_counts.get(category, 0) + amount
            pending.append((source_file, staged, private_staged, categories, consistent, rel_text))

        # Every file has now contributed its sensitive literals. Scrub the full set
        # from every staged copy before any bytes enter the output staging tree.
        private_patterns = _compile_private_literals(
            discovered_secrets, weak_secrets, strong_secrets
        )
        numeric_secrets = {
            secret for secret in discovered_secrets if re.fullmatch(r"-?\d+(?:\.\d+)?", secret)
        }
        for index, (
            _source_file,
            staged,
            private_staged,
            categories,
            consistent,
            rel_text,
        ) in enumerate(pending, 1):
            if cancelled is not None and cancelled():
                raise BackupCancelled("Collection cancelled.")
            if progress:
                progress("redacting", len(files) + index - 1, redacting_total)
            try:
                cross_redaction_count = _scrub_private_literals(
                    private_staged, private_patterns, numeric_secrets
                )
            except OSError, UnicodeError, ValueError, RecursionError, MemoryError:
                private_staged.unlink(missing_ok=True)
                skipped.append({"path": rel_text, "reason": "unreadable_or_unsanitizable"})
                warnings.append(f"Could not safely include {rel_text}.")
                continue
            if cross_redaction_count:
                redaction_counts["credential_pattern"] = (
                    redaction_counts.get("credential_pattern", 0) + cross_redaction_count
                )
                categories["credential_pattern"] = (
                    categories.get("credential_pattern", 0) + cross_redaction_count
                )
            if progress:
                progress("verifying", index, len(pending))
            if _contains_private_secret(
                private_staged, discovered_secrets, private_patterns
            ) or _secret_scan(private_staged):
                private_staged.unlink(missing_ok=True)
                skipped.append({"path": rel_text, "reason": "verification_secret_found"})
                warnings.append(
                    f"A credential pattern remained in {rel_text}; the file was omitted."
                )
                continue
            try:
                staged.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(private_staged, staged)
            except OSError:
                staged.unlink(missing_ok=True)
                private_staged.unlink(missing_ok=True)
                skipped.append({"path": rel_text, "reason": "unreadable_or_unsanitizable"})
                warnings.append(f"Could not safely include {rel_text}.")
                continue
            private_staged.unlink(missing_ok=True)
            records.append(
                {
                    "source_path": rel_text,
                    "output_path": rel_text,
                    "size": staged.stat().st_size,
                    "sha256": hashlib.sha256(staged.read_bytes()).hexdigest(),
                    "redactions": categories,
                    "read_consistent": consistent,
                    "warning": not consistent,
                }
            )

        if progress:
            progress("redacting", redacting_total, redacting_total)
        if not records:
            raise ValueError("No supported OBS files could be safely included.")
        if cancelled is not None and cancelled():
            raise BackupCancelled("Collection cancelled.")
        manifest: dict[str, object] = {
            "format_version": 1,
            "redaction_rules_version": RULE_VERSION,
            "created_at": when.astimezone().isoformat(timespec="seconds"),
            "complete": True,
            "copied_count": len(records),
            "skipped_count": len(skipped),
            "redaction_counts": redaction_counts,
            "files": records,
            "skipped": skipped,
            "warnings": warnings,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        summary = [
            "TempestTrace OBS diagnostic backup",
            f"Created: {manifest['created_at']}",
            f"Files copied: {len(records)}",
            f"Files skipped: {len(skipped)}",
            "Redactions: "
            + (
                ", ".join(f"{key}: {value}" for key, value in sorted(redaction_counts.items()))
                or "none"
            ),
            "",
            "OBS remained open. The source configuration was read only.",
            "See manifest.json for file checksums, skipped items, and warnings.",
        ]
        (staging / "README.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
        for report in (staging / "manifest.json", staging / "README.txt"):
            if _secret_scan(report):
                raise ValueError("A credential pattern was detected in the backup report.")
        if progress:
            progress("verifying", len(files), len(files))
        with zipfile.ZipFile(
            incomplete_zip, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as archive:
            archive_files = [
                item
                for item in sorted(staging.rglob("*"))
                if item.is_file() and not _is_link_or_reparse(item)
            ]
            if progress:
                progress("packaging", 0, len(archive_files))
            for index, item in enumerate(archive_files, 1):
                if cancelled is not None and cancelled():
                    raise BackupCancelled("Collection cancelled.")
                if progress:
                    progress("packaging", index - 1, len(archive_files))
                if item.is_file() and not _is_link_or_reparse(item):
                    archive.write(item, item.relative_to(staging).as_posix())
            if cancelled is not None and cancelled():
                raise BackupCancelled("Collection cancelled.")
            if progress:
                progress("packaging", len(archive_files), len(archive_files))
        with zipfile.ZipFile(incomplete_zip) as archive:
            bad_member = archive.testzip()
            if bad_member:
                raise ValueError("The completed ZIP did not pass integrity verification.")
        if progress:
            progress("promoting", len(records), len(records))
        if cancelled is not None and cancelled():
            raise BackupCancelled("Collection cancelled.")
        while True:
            if final.exists():
                reservation.unlink(missing_ok=True)
                suffix, final, _reserved_incomplete, reservation = _reserve_archive_name(
                    target_dir, base, suffix + 1
                )
                continue
            try:
                _rename_noreplace(incomplete_zip, final)
            except FileExistsError:
                reservation.unlink(missing_ok=True)
                suffix, final, _reserved_incomplete, reservation = _reserve_archive_name(
                    target_dir, base, suffix + 1
                )
            else:
                break
        try:
            shutil.rmtree(staging)
        except OSError:
            warnings.append(
                "The backup ZIP was created, but the temporary sanitized snapshot "
                "could not be removed."
            )
        if progress:
            progress("finishing", len(records), len(records))
        return BackupResult(final, len(records), len(skipped), redaction_counts, tuple(warnings))
    except BaseException:
        # Preserve the incomplete staging tree/archive so the UI can offer cleanup.
        # Preserve both the incomplete staging tree and any partial archive.
        raise
    finally:
        reservation.unlink(missing_ok=True)
        if private_staging is not None:
            shutil.rmtree(private_staging, ignore_errors=True)
