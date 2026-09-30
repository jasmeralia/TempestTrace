"""Versioned, conservative credential redaction for staged OBS files."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

RULE_VERSION = 12
REDACTED = "<REDACTED>"
_QUOTE_DELIMITER = (
    r"(?:\\*['\"]|`|&(?:quot|apos|ldquo|rdquo|lsquo|rsquo);|"
    r"&#0*(?:34|39);|&#x0*(?:22|27);|%22|%27|[\u201c\u201d\u2018\u2019])"
)
_QUOTED_CREDENTIAL_VALUE = (
    r'(\\*"(?:\\[^\r\n]|[^"\\\r\n])*\\*"|'
    r"\\*'(?:\\[^\r\n]|[^'\\\r\n])*\\*'|"
    r"`[^\r\n]*?`|"
    r"&quot;[^\r\n]*?&quot;|&apos;[^\r\n]*?&apos;|"
    r"&#0*34;[^\r\n]*?&#0*34;|&#x0*22;[^\r\n]*?&#x0*22;|"
    r"&#0*39;[^\r\n]*?&#0*39;|&#x0*27;[^\r\n]*?&#x0*27;|"
    r"%22[^\r\n]*?%22|%27[^\r\n]*?%27|"
    r"&ldquo;[^\r\n]*?&rdquo;|&lsquo;[^\r\n]*?&rsquo;|"
    r"\u201c[^\r\n]*?\u201d|\u2018[^\r\n]*?\u2019|"
    r"[^\s,;\]\\\"'`}]+)"
)
_LOG_ASSIGNMENT_VALUE = _QUOTED_CREDENTIAL_VALUE.rsplit("|", 1)[0] + r"|[^\s,;#&\\\"'`}]+)"
_SENSITIVE_NAME_HINT = re.compile(
    r"(?i)(?:key|token|password|passwd|secret|passphrase|cookie|sessionid|jwt|credential|streamid)"
)
_FREE_NAME = r"(?:\\*[\"']?[A-Za-z0-9_.-]+\\*[\"']?|%22[A-Za-z0-9_.-]+%22|%27[A-Za-z0-9_.-]+%27)"
_LOG_PATTERNS = (
    re.compile(
        rf"(?im)(?=(?P<prefix>(?<![A-Za-z0-9_.-]){_FREE_NAME}{_QUOTE_DELIMITER}?[ \t]*[=:][ \t]*)"
        rf"(?P<value>{_LOG_ASSIGNMENT_VALUE}))"
    ),
    re.compile(r"(?i)(\bAuthorization:\s*[A-Za-z][A-Za-z0-9_-]*\s+)([^\s,;]+)"),
)
_URL_QUERY_SECRET = re.compile(r"(?i)([?&;]([A-Za-z0-9_.-]+)=)([^&#;\s\"'<>]+)")
_URL_USERINFO = re.compile(r"(?i)(\b[A-Za-z][A-Za-z0-9+.-]*://[^:/@\s]+:)([^/@\s]+)(@)")
_RTMP_STREAM_KEY = re.compile(
    r"(?i)\b((?:rtmp|rtmps|rtmpe|rtmpt|rtmpte|rtmfp)://[^/?#\s\"'<>]+/"
    r"(?:[^/?#\s\"'<>]+/)+)([^/?#\s\"'<>]+)"
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
    if normalized == "key":
        if context and context[-1] == "__obsbasic_hotkey_binding__":
            return False
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
    if context and context[-1] == "__url_query__" and normalized in {"auth", "sig"}:
        return True
    suffixes = ("key", "token", "password", "passwd", "secret")
    folded_key = key.casefold()
    return bool(
        re.search(r"(?:^|[^a-z0-9])(?:key|token|password|passwd|secret)$", folded_key)
        or any(folded_key.endswith(suffix) and key[-len(suffix) :] != suffix for suffix in suffixes)
    )


def _unquote(value: str) -> str:
    value = value.strip()
    entity_quoted = re.match(
        r"(?i)^(&quot;|&apos;|&#0*34;|&#x0*22;|&#0*39;|&#x0*27;|%22|%27)(.*?)(\1)$", value
    )
    if entity_quoted:
        return entity_quoted.group(2)
    for opening, closing in (
        ("&ldquo;", "&rdquo;"),
        ("&lsquo;", "&rsquo;"),
        ("“", "”"),
        ("\u2018", "\u2019"),
    ):
        if value.casefold().startswith(opening.casefold()) and value.casefold().endswith(
            closing.casefold()
        ):
            return value[len(opening) : -len(closing)]
    if len(value) >= 2 and value[0] == value[-1] == "`":
        return value[1:-1]
    quoted = re.match(r"^(\\*[\"'])(.*?)(\\*[\"'])$", value)
    if quoted and quoted.group(1).lstrip("\\") == quoted.group(3).lstrip("\\"):
        return quoted.group(2)
    return value


def _quoted_redacted(value: str) -> str:
    entity_quoted = re.match(
        r"(?i)^(&quot;|&apos;|&#0*34;|&#x0*22;|&#0*39;|&#x0*27;|%22|%27)(.*?)(\1)$", value
    )
    if entity_quoted:
        return f"{entity_quoted.group(1)}{REDACTED}{entity_quoted.group(3)}"
    for opening, closing in (
        ("&ldquo;", "&rdquo;"),
        ("&lsquo;", "&rsquo;"),
        ("“", "”"),
        ("\u2018", "\u2019"),
    ):
        if value.casefold().startswith(opening.casefold()) and value.casefold().endswith(
            closing.casefold()
        ):
            return f"{value[: len(opening)]}{REDACTED}{value[-len(closing) :]}"
    if len(value) >= 2 and value[0] == value[-1] == "`":
        return f"`{REDACTED}`"
    quoted = re.match(r"^(\\*[\"'])(.*?)(\\*[\"'])$", value)
    if quoted and quoted.group(1).lstrip("\\") == quoted.group(3).lstrip("\\"):
        return f"{quoted.group(1)}{REDACTED}{quoted.group(3)}"
    return REDACTED


def _outside_json_segments(text: str) -> list[tuple[int, int]]:
    """Return text spans outside valid JSON fragments."""
    spans: list[tuple[int, int]] = []
    cursor = 0
    for start, end, _value, _context in _json_fragments(text):
        if cursor < start:
            spans.append((cursor, start))
        cursor = end
    if cursor < len(text):
        spans.append((cursor, len(text)))
    return spans


def _sub_outside_json(text: str, pattern: re.Pattern[str], replace: Any) -> str:
    pieces: list[str] = []
    cursor = 0
    for start, end, _value, _context in _json_fragments(text):
        if cursor < start:
            pieces.append(pattern.sub(replace, text[cursor:start]))
        pieces.append(text[start:end])
        cursor = end
    if cursor < len(text):
        pieces.append(pattern.sub(replace, text[cursor:]))
    return "".join(pieces)


def _sub_overlapping_assignments(text: str, replace: Any) -> str:
    """Replace credential assignments even when they start inside another value."""
    pattern = _LOG_PATTERNS[0]
    fragments = _json_fragments(text)
    pieces: list[str] = []
    fragment_cursor = 0
    spans = [(0, len(text))]
    if fragments:
        spans = []
        for start, end, _value, _context in fragments:
            if fragment_cursor < start:
                spans.append((fragment_cursor, start))
            fragment_cursor = end
        if fragment_cursor < len(text):
            spans.append((fragment_cursor, len(text)))

    cursor = 0
    for start, end in spans:
        pieces.append(text[cursor:start])
        segment = text[start:end]
        replacements: list[tuple[int, int, str]] = []
        for match in pattern.finditer(segment):
            replacement = replace(match)
            original = match.group(1) + match.group(2)
            if replacement != original:
                replacements.append((match.start(1), match.end(2), replacement))
        segment_cursor = 0
        for replace_start, replace_end, replacement in replacements:
            if replace_start < segment_cursor:
                continue
            pieces.append(segment[segment_cursor:replace_start])
            pieces.append(replacement)
            segment_cursor = replace_end
        pieces.append(segment[segment_cursor:])
        cursor = end
    if cursor < len(text):
        pieces.append(text[cursor:])
    return "".join(pieces)


def is_noncredential_log_match(_text: str, match: re.Match[str]) -> bool:
    """Identify ambiguous key assignments that are not credential values."""
    field_name = re.split(r"\s*[=:]", match.group(1), maxsplit=1)[0].casefold()
    field_name = re.sub(r"/\*[\s\S]*?(?:\*/|$)|//[^\r\n]*", "", field_name)
    field_name = re.sub(r"[\\\"']", "", field_name).strip()
    if field_name != "key":
        return False
    match_text = match.string
    start = match_text.rfind("\n", 0, match.start()) + 1
    prefix = match_text[start : match.start()]
    return bool(
        re.search(r"(?i)\b(?:hotkey(?:\s+binding)?|key.?binding|shortcut)\s*$", prefix)
        or re.search(r"(?i)\b(?:chroma|colou?r)\s*$", prefix)
    )


def _log_match_key(match: re.Match[str]) -> str:
    field = re.match(
        r"(?i)(?:%22|%27)([A-Za-z0-9_.-]+)(?:%22|%27)|(?:\\*[\"']?)([A-Za-z0-9_.-]+)",
        match.group(1),
    )
    return next((value for value in field.groups() if value), "") if field else ""


_COMMENT_NAME = re.compile(rf"(?i)(?<![A-Za-z0-9_.-])({_FREE_NAME})")
_QUOTE_DELIMITER_RE = re.compile(_QUOTE_DELIMITER)


def _comment_assignments(text: str) -> list[tuple[str, str, int, int, bool]]:  # noqa: PLR0912, PLR0915
    """Tokenize credential assignments separated from their value by comments."""
    found: list[tuple[str, str, int, int, bool]] = []
    for span_start, span_end in _outside_json_segments(text):
        segment = text[span_start:span_end]
        for name_match in _COMMENT_NAME.finditer(segment):
            name = _clean_log_key(name_match.group(1))
            if not _is_sensitive_key(name):
                continue
            cursor = name_match.end()
            delimiter = _QUOTE_DELIMITER_RE.match(segment, cursor)
            if delimiter:
                cursor = delimiter.end()
            used_comment = False
            while cursor < len(segment):
                whitespace = re.match(r"\s*", segment[cursor:])
                cursor += whitespace.end() if whitespace else 0
                if segment.startswith("//", cursor):
                    used_comment = True
                    newline = segment.find("\n", cursor + 2)
                    cursor = len(segment) if newline < 0 else newline + 1
                    continue
                if segment.startswith("/*", cursor):
                    used_comment = True
                    close = segment.find("*/", cursor + 2)
                    object_end = segment.find("}", cursor + 2)
                    if close >= 0 and (object_end < 0 or close < object_end):
                        cursor = close + 2
                        continue
                    line_end = segment.find("\n", cursor + 2)
                    if line_end < 0:
                        line_end = len(segment)
                    delimiters = list(re.finditer(r"[=:]", segment[cursor + 2 : line_end]))
                    if delimiters:
                        cursor += 2 + delimiters[-1].start()
                    elif line_end < len(segment):
                        cursor = line_end + 1
                    else:
                        break
                    continue
                break
            if not used_comment:
                continue
            while cursor < len(segment) and segment[cursor].isspace():
                cursor += 1
            if cursor >= len(segment) or segment[cursor] not in "=:":
                continue
            cursor += 1
            while cursor < len(segment) and segment[cursor].isspace():
                cursor += 1
            value_match = re.match(_QUOTED_CREDENTIAL_VALUE, segment[cursor:])
            if not value_match:
                continue
            value = value_match.group(0)
            line_start = segment.rfind("\n", 0, name_match.start()) + 1
            prefix = segment[line_start : name_match.start()]
            noncredential = name.casefold() == "key" and bool(
                re.search(
                    r"(?i)\b(?:hotkey(?:\s+binding)?|key.?binding|shortcut|chroma|colou?r)\s*$",
                    prefix,
                )
            )
            found.append(
                (
                    name,
                    value,
                    span_start + cursor,
                    span_start + cursor + len(value),
                    noncredential,
                )
            )
    return list(dict.fromkeys(found))


def _clean_log_key(token: str) -> str:
    field = re.match(
        r"(?i)(?:%22|%27)([A-Za-z0-9_.-]+)(?:%22|%27)|(?:\\*[\"']?)([A-Za-z0-9_.-]+)",
        token,
    )
    return next((value for value in field.groups() if value), "") if field else ""


def _embedded_secrets(text: str) -> set[str]:
    values = {
        match.group(3)
        for match in _URL_QUERY_SECRET.finditer(text)
        if _is_sensitive_key(match.group(2), ("__url_query__",))
    }
    values.update(match.group(2) for match in _URL_USERINFO.finditer(text))
    values.update(_rtmp_key(match.group(2)) for match in _RTMP_STREAM_KEY.finditer(text))
    values.update(match.group(2) for match in _STREAMLABS_WIDGET_TOKEN.finditer(text))
    if _SENSITIVE_NAME_HINT.search(text):
        values.update(
            _unquote(value)
            for _name, value, _start, _end, noncredential in _comment_assignments(text)
            if not noncredential
        )
    for pattern in _LOG_PATTERNS if _SENSITIVE_NAME_HINT.search(text) else ():

        def collect(match: re.Match[str], pattern: re.Pattern[str] = pattern) -> str:
            if not is_noncredential_log_match(text, match) and (
                pattern is _LOG_PATTERNS[-1]
                or (
                    _log_match_key(match).casefold() != "authorization"
                    and _is_sensitive_key(_log_match_key(match))
                )
            ):
                values.add(_unquote(match.group(2)))
            return match.group(0)

        _sub_outside_json(text, pattern, collect)
    for _start, _end, value, context in _json_fragments(text):
        values.update(_credential_values(value, context))
    return {value for value in values if value and value != REDACTED}


def _rtmp_key(value: str) -> str:
    """Drop sentence punctuation accidentally attached to a URL path segment."""
    return value.rstrip(".,;:!?)]}\\'\u201d\u2019")


@lru_cache(maxsize=2)
def _json_fragments(text: str) -> list[tuple[int, int, Any, tuple[str, ...]]]:  # noqa: PLR0912, PLR0915
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
        opening = text[start]
        following = start + 1
        while following < len(text) and text[following].isspace():
            following += 1
        if following >= len(text):
            break
        first = text[following]
        valid_start = first in '"}' if opening == "{" else first in ']}[{"-0123456789tfn'
        if not valid_start:
            index = start + 1
            continue
        try:
            value, length = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            index = start + 1
            continue
        end = length
        assignment_end = start
        while assignment_end > 0:
            while assignment_end > 0 and text[assignment_end - 1].isspace():
                assignment_end -= 1
            line_start = text.rfind("\n", 0, assignment_end) + 1
            previous_line = text[line_start:assignment_end].strip()
            if previous_line.startswith(("#", ";", "//")) or (
                previous_line.startswith("/*") and previous_line.endswith("*/")
            ):
                assignment_end = max(0, line_start - 1)
                continue
            if previous_line.endswith("*/"):
                comment_cursor = line_start
                while comment_cursor > 0:
                    comment_line_start = text.rfind("\n", 0, comment_cursor - 1) + 1
                    comment_line = text[comment_line_start:comment_cursor].strip()
                    if comment_line.startswith("/*"):
                        assignment_end = max(0, comment_line_start - 1)
                        break
                    comment_cursor = max(0, comment_line_start - 1)
                if assignment_end < line_start:
                    continue
            break
        line_start = text.rfind("\n", 0, assignment_end) + 1
        assignment_prefix = text[line_start:assignment_end]
        # OBS stores individual action bindings as JSON-valued INI assignments.
        # Their bare `key` property is a hotkey, while other credential fields
        # in the same object still receive normal structural redaction.
        context = (
            ("<embedded>", "__obsbasic_hotkey_binding__")
            if re.search(r"(?i)\bOBSBasic\.[\w.]+\s*=\s*(?:\r?\n\s*)*$", assignment_prefix)
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

    return _sub_outside_json(text, _ASSIGNMENT_VALUE, scrub)


def _redact_embedded(text: str, counts: dict[str, int], secrets: set[str] | None = None) -> str:
    def replace(match: re.Match[str]) -> str:
        if _unquote(match.group(2)) == REDACTED:
            return match.group(1) + match.group(2)
        if is_noncredential_log_match(text, match):
            return match.group(1) + match.group(2)
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{match.group(1)}{_quoted_redacted(match.group(2))}"

    def replace_log(match: re.Match[str], pattern: re.Pattern[str]) -> str:
        key = _log_match_key(match)
        if pattern is not _LOG_PATTERNS[-1] and (
            key.casefold() == "authorization" or not _is_sensitive_key(key)
        ):
            return match.group(1) + match.group(2)
        return replace(match)

    fragments = _json_fragments(text)
    if fragments:
        pieces: list[str] = []
        cursor = 0
        for start, end, value, context in fragments:
            pieces.append(text[cursor:start])
            previous_count = sum(counts.values())
            cleaned = _redact_object(value, counts, secrets or set(), context)
            if sum(counts.values()) == previous_count:
                pieces.append(text[start:end])
            else:
                pieces.append(json.dumps(cleaned, ensure_ascii=False, separators=(",", ":")))
            cursor = end
        pieces.append(text[cursor:])
        text = "".join(pieces)

    def redact_rtmp(match: re.Match[str]) -> str:
        key = _rtmp_key(match.group(2))
        if not key or key == REDACTED:
            return match.group(0)
        trailing = match.group(2)[len(key) :]
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{match.group(1)}{REDACTED}{trailing}"

    text = _sub_outside_json(text, _RTMP_STREAM_KEY, redact_rtmp)

    def replace_query(match: re.Match[str]) -> str:
        if not _is_sensitive_key(match.group(2), ("__url_query__",)):
            return match.group(0)
        if match.group(3) != REDACTED:
            counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{match.group(1)}{_quoted_redacted(match.group(3))}"

    text = _sub_outside_json(text, _URL_QUERY_SECRET, replace_query)

    def redact_userinfo(match: re.Match[str]) -> str:
        if match.group(2) == REDACTED:
            return match.group(0)
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{match.group(1)}{REDACTED}{match.group(3)}"

    text = _sub_outside_json(text, _URL_USERINFO, redact_userinfo)
    text = _sub_outside_json(text, _STREAMLABS_WIDGET_TOKEN, replace)
    comment_replacements = (
        [
            (start, end, _quoted_redacted(value))
            for _name, value, start, end, noncredential in _comment_assignments(text)
            if not noncredential and _unquote(value) != REDACTED
        ]
        if _SENSITIVE_NAME_HINT.search(text)
        else []
    )
    if comment_replacements:
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + len(
            comment_replacements
        )
    for start, end, replacement in reversed(comment_replacements):
        text = text[:start] + replacement + text[end:]
    for pattern in _LOG_PATTERNS if _SENSITIVE_NAME_HINT.search(text) else ():

        def replace_match(match: re.Match[str], pattern: re.Pattern[str] = pattern) -> str:
            return replace_log(match, pattern)

        if pattern is _LOG_PATTERNS[0]:
            text = _sub_overlapping_assignments(text, replace_match)
        else:
            text = _sub_outside_json(text, pattern, replace_match)
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
            if (
                isinstance(key, str)
                and _is_sensitive_key(key, context)
                and child not in (None, "")
                and not isinstance(child, bool)
            ):
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
                and not isinstance(child, bool)
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


def has_unredacted_embedded_json(text: str) -> bool:  # noqa: PLR0911
    """Check JSON-like credential assignments embedded in other text."""
    if any(has_unredacted_fields(value, context) for _, _, value, context in _json_fragments(text)):
        return True
    if any(_rtmp_key(match.group(2)) != REDACTED for match in _RTMP_STREAM_KEY.finditer(text)):
        return True
    if any(
        _is_sensitive_key(match.group(2), ("__url_query__",))
        and _unquote(match.group(3)) != REDACTED
        for match in _URL_QUERY_SECRET.finditer(text)
    ):
        return True
    if any(match.group(2) != REDACTED for match in _URL_USERINFO.finditer(text)):
        return True
    if _SENSITIVE_NAME_HINT.search(text) and any(
        _unquote(value) != REDACTED and not noncredential
        for _name, value, _start, _end, noncredential in _comment_assignments(text)
    ):
        return True
    for pattern in _LOG_PATTERNS if _SENSITIVE_NAME_HINT.search(text) else ():
        for start, end in _outside_json_segments(text):
            segment = text[start:end]
            if any(
                _unquote(match.group(2)) != REDACTED
                and not is_noncredential_log_match(segment, match)
                and (
                    pattern is _LOG_PATTERNS[-1]
                    or (
                        _log_match_key(match).casefold() != "authorization"
                        and _is_sensitive_key(_log_match_key(match))
                    )
                )
                for match in pattern.finditer(segment)
            ):
                return True
    return False


def has_unredacted_ini_fields(text: str, filename: str) -> bool:
    """Check INI assignments using the same key rules as the redactor."""
    for line in text.splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_.-][^=:#\s]*)\s*[=:]\s*(.*?)\s*$", line)
        if (
            match
            and _is_sensitive_key(match.group(1), (filename,))
            and _unquote(match.group(2)) not in ("", REDACTED)
        ):
            return True
    return False


def _ini_secret_values(text: str, filename: str) -> set[str]:
    secrets: set[str] = set()
    for line in text.splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_.-][^=:#\s]*)\s*[=:]\s*(.*?)\s*$", line)
        if match and _is_sensitive_key(match.group(1), (filename,)):
            secret = _unquote(match.group(2))
            if secret and secret != REDACTED:
                secrets.add(secret)
    return secrets


def _redact_ini(text: str, filename: str, counts: dict[str, int], secrets: set[str]) -> str:
    lines: list[str] = []
    for original_line in text.splitlines(keepends=True):
        match = re.match(
            r"^(\s*)([A-Za-z0-9_.-][^=:#\s]*)(\s*[=:]\s*)(.*?)(\r?\n)?$",
            original_line,
        )
        if match and _is_sensitive_key(match.group(2), (filename,)) and match.group(4).strip():
            cleaned = (
                f"{match.group(1)}{match.group(2)}{match.group(3)}{REDACTED}{match.group(5) or ''}"
            )
            counts["credential_field"] = counts.get("credential_field", 0) + 1
            lines.append(cleaned)
        else:
            lines.append(original_line)
    return "".join(lines)


def redact_file_with_secrets(path: Path) -> tuple[dict[str, int], int, set[str]]:
    """Redact one staged file and return secret literals for private verification."""
    suffix = path.suffix.lower()
    counts: dict[str, int] = {}
    is_json = suffix == ".json" or path.name.lower().endswith(".json.bak")
    is_ini = suffix == ".ini" or path.name.lower().endswith(".ini.bak")
    if is_json:
        raw = json.loads(read_text_safely(path))
        secrets = _credential_values(raw, (path.name,))
        clean = _redact_object(raw, counts, secrets, (path.name,))
        path.write_text(json.dumps(clean, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif is_ini:
        text = read_text_safely(path)
        secrets = _ini_secret_values(text, path.name) | _embedded_secrets(text)
        clean = _redact_ini(text, path.name, counts, secrets)
        clean = _scrub_text(_redact_embedded(clean, counts, secrets), secrets)
        path.write_text(clean, encoding="utf-8", newline="")
    elif suffix == ".txt":
        text = read_text_safely(path)
        secrets = _embedded_secrets(text)
        text = _redact_embedded(text, counts, secrets)
        # Supported UTF-16 input is deliberately normalized to UTF-8 in staging.
        path.write_text(_scrub_text(text, secrets), encoding="utf-8")
    else:
        secrets = set()
    return counts, sum(counts.values()), secrets


def read_text_safely(path: Path) -> str:
    """Decode supported text encodings; reject unmarked NUL-containing data."""
    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace")
    if b"\x00" in data:
        raise ValueError("Text file contains NUL bytes without a UTF-16 BOM.")
    return data.decode("utf-8", errors="replace")


def redact_file(path: Path) -> tuple[dict[str, int], int]:
    """Redact recognized secrets in one staged text file, preserving other values."""
    counts, total, _secrets = redact_file_with_secrets(path)
    return counts, total
