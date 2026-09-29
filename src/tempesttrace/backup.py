"""Read-only OBS snapshot, redaction, verification, and ZIP packaging."""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from tempesttrace.redaction import (
    RULE_VERSION,
    has_unredacted_fields,
    redact_file_with_secrets,
)

MAX_FILE_SIZE = 32 * 1024 * 1024
MAX_TOTAL_SIZE = 512 * 1024 * 1024
MAX_LOG_FILES = 5
ALLOWED_PROFILE_SUFFIXES = {".ini", ".json", ".txt"}
_SECRET_SCAN = re.compile(
    rb"(?i)(?:\bkey|api[_ -]?key|stream[_ -]?key|token|auth[_ -]?token|"
    rb"bearer[_ -]?token|password|passwd|access[_ -]?token|client[_ -]?secret|secret)"
    rb"\s*[=:]\s*"
    rb"(?!<REDACTED>)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;\]\"']+)"
)


class BackupCancelled(Exception):
    """Raised when the user cancels between files."""


class FileLimitExceeded(Exception):
    """Raised if a file grows beyond its permitted read size."""


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
    """Exclusively reserve a candidate name; final promotion still uses no-clobber link."""
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


def _inventory(root: Path, skipped: list[dict[str, str]]) -> list[Path]:  # noqa: PLR0912
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
            elif item.is_file() and (
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
            if item.is_file() and item.suffix.lower() == ".txt" and not _is_link_or_reparse(item):
                log_candidates.append(item)
            elif item.is_file():
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
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source_file:
            before = os.fstat(source_file.fileno())
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


def _secret_scan(path: Path) -> bool:
    if _SECRET_SCAN.search(path.read_bytes()):
        return True
    if path.suffix.lower() == ".json" or path.name.lower().endswith(".json.bak"):
        try:
            return has_unredacted_fields(json.loads(path.read_text(encoding="utf-8")), (path.name,))
        except OSError, UnicodeError, json.JSONDecodeError:
            return True
    if path.suffix.lower() == ".ini" or path.name.lower().endswith(".ini.bak"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError, UnicodeError:
            return True
        return bool(
            re.search(
                r"(?im)^\s*(?:\w*key|\w*token|\w*password|\w*passwd|\w*secret)"
                r"\s*[=:]\s*(?!<REDACTED>)\S+",
                text,
            )
        )
    return False


def _contains_private_secret(path: Path, secrets: set[str]) -> bool:
    """Check that redacted credential literals did not survive in the staged file."""
    if not secrets:
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    return any(
        secret and re.search(rf"(?<!\w){re.escape(secret)}(?!\w)", text) for secret in secrets
    )


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
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{base}.incomplete-", dir=target_dir))
        if progress:
            progress("scanning", 0, 0)
        files = _inventory(root, skipped)
        total = 0
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
            try:
                if progress:
                    progress("copying", index - 1, len(files))
                byte_limit = min(MAX_FILE_SIZE, MAX_TOTAL_SIZE - total)
                consistent, actual_size = _read_consistent(source_file, staged, byte_limit)
                total += actual_size
                if progress:
                    progress("redacting", index - 1, len(files))
                categories, _redaction_count, secrets = redact_file_with_secrets(staged)
            except FileLimitExceeded:
                skipped.append({"path": rel_text, "reason": "size_limit_exceeded_during_read"})
                continue
            except OSError, UnicodeError, ValueError, configparser.Error:
                staged.unlink(missing_ok=True)
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
            if progress:
                progress("verifying", index, len(files))
            if _contains_private_secret(staged, secrets) or _secret_scan(staged):
                staged.unlink(missing_ok=True)
                skipped.append({"path": rel_text, "reason": "verification_secret_found"})
                warnings.append(
                    f"A credential pattern remained in {rel_text}; the file was omitted."
                )
                continue
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
            try:
                os.link(incomplete_zip, final)
            except FileExistsError:
                reservation.unlink(missing_ok=True)
                suffix, final, _reserved_incomplete, reservation = _reserve_archive_name(
                    target_dir, base, suffix + 1
                )
            else:
                break
        try:
            incomplete_zip.unlink()
        except OSError:
            warnings.append("The backup is complete, but its temporary ZIP could not be removed.")
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
