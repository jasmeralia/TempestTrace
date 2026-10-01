"""Versioned, conservative credential redaction for staged OBS files."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

RULE_VERSION = 15
REDACTED = "<REDACTED>"
_QUOTE_DELIMITER = (
    r"(?:\\*['\"]|`|&(?:quot|apos|ldquo|rdquo|lsquo|rsquo);|"
    r"&#0*(?:34|39);|&#x0*(?:22|27);|%22|%27|[\u201c\u201d\u2018\u2019])"
)
_QUOTED_CREDENTIAL_VALUE = (
    r'(?:\\*+"(?:\\[^\r\n]|[^"\\\r\n])*\\*+"|'
    r"\\*+'(?:\\[^\r\n]|[^'\\\r\n])*\\*+'|"
    r"`[^\r\n]*?`|"
    r"&quot;[^\r\n]*?&quot;|&apos;[^\r\n]*?&apos;|"
    r"&#0*34;[^\r\n]*?&#0*34;|&#x0*22;[^\r\n]*?&#x0*22;|"
    r"&#0*39;[^\r\n]*?&#0*39;|&#x0*27;[^\r\n]*?&#x0*27;|"
    r"%22[^\r\n]*?%22|%27[^\r\n]*?%27|"
    r"&ldquo;[^\r\n]*?&rdquo;|&lsquo;[^\r\n]*?&rsquo;|"
    r"\u201c[^\r\n]*?\u201d|\u2018[^\r\n]*?\u2019|"
    r"[^\s](?:(?![;&,|/?(](?=[A-Za-z0-9_.-]{0,80}(?:password|passwd|pwd|secret|token|"
    r"cookie|sessionid|jwt|credential|streamid|authorization|"
    r"(?:api|private|secret|auth|signing|encryption|master|shared|session|access)[_.-]?key)"
    r"[ \t]*[=:])[A-Za-z0-9_.-]++[ \t]*[=:])[^\s])*"
    r")"
)
_LOG_ASSIGNMENT_VALUE = _QUOTED_CREDENTIAL_VALUE
_SENSITIVE_NAME_HINT = re.compile(
    r"(?i)(?:key|token|password|passwd|pwd|secret|passphrase|cookie|sessionid|jwt|credential|streamid|authorization)"
)
_REPEATED_NUMERIC_KEY_LINES = re.compile(r"(?i)(?:[ \t]*key[ \t]*=[ \t]*[0-9]+[ \t]*\r?\n)++")
_NUMERIC_KEY_ASSIGNMENT = re.compile(r"(?i)(key[ \t]*=[ \t]*)[0-9]+")
_REPEATED_REDACTED_KEY_LINES = re.compile(r"(?i)(?:[ \t]*key[ \t]*=[ \t]*<REDACTED>[ \t]*\r?\n)++")
_REPEATED_REDACTED_QUOTED_KEY_LINES = re.compile(
    r"""(?im)(?:[ \t]*["']key["'][ \t]*:[ \t]*["']<REDACTED>["'][ \t]*\r?\n)++"""
)
_QUOTED_KEY_LINE = re.compile(
    r"""(?im)(?P<prefix>[ \t]*["']key["'][ \t]*:[ \t]*)(?P<quote>["'])"""
    r"""(?P<value>[^"'\r\n]*)(?P=quote)[ \t]*(?P<newline>\r?\n|$)"""
)
_BROKEN_BACKSLASH_ASSIGNMENT = re.compile(
    r"""(?im)(?P<prefix>[ \t]*(?P<name>[A-Za-z0-9_.-]+)[ \t]*=[ \t]*)(?P<quote>["'])"""
    r"""\\{128,}[ \t]*(?P<newline>\r?\n|$)"""
)
_REPEATED_QUOTED_KEY_LINES = re.compile(
    r"""(?im)(?:[ \t]*["']key["'][ \t]*:[ \t]*["'][^"'\r\n]*["'][ \t]*\r?\n)++"""
)
_JSON_OBJECT_START = re.compile(r'\{\s*(?:"|})')
_JSON_ARRAY_START = re.compile(r'\[\s*(?:"|\[|\{|\]|-|[0-9]|(?:true|false|null)(?=[ \t\r\n,\]]))')
_FREE_NAME = (
    r"(?:\\{0,8}+[\"']?[A-Za-z0-9_.-]++\\{0,8}+[\"']?|"
    r"%22[A-Za-z0-9_.-]++%22|%27[A-Za-z0-9_.-]++%27)"
)
_SENSITIVE_NAME_CORE = (
    r"(?:[A-Za-z0-9_.-]*?(?:password|passwd|pwd|secret|token|passphrase|cookies?|"
    r"session[_-]?id|jwt|credentials?|streamid)|[A-Za-z0-9_.-]*?[_\-.]key|"
    r"(?:[A-Za-z0-9_.]+-)*authorization|"
    r"(?-i:[A-Za-z0-9_.-]*[Kk][Ee][Yy])|"
    r"(?:apikey|streamkey|privatekey|secretkey|authkey|signingkey|encryptionkey|masterkey|"
    r"sharedkey|sessionkey|accesskey)|key)"
)
_SENSITIVE_QUERY_NAME = rf"(?:{_SENSITIVE_NAME_CORE}|auth|sig)"
_QUERY_HINTS = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "authorization",
    "cookie",
    "sessionid",
    "jwt",
    "credential",
    "streamid",
    "key",
    "auth",
    "sig",
)
_SENSITIVE_FREE_NAME = (
    rf"(?:\\{{0,8}}+[\"']?(?:--?{_SENSITIVE_NAME_CORE}|{_SENSITIVE_NAME_CORE})"
    rf"\\{{0,8}}+[\"']?|"
    rf"%22{_SENSITIVE_NAME_CORE}%22|%27{_SENSITIVE_NAME_CORE}%27)"
)
_LOG_PATTERNS = (
    re.compile(
        rf"(?im)(?=(?P<prefix>(?<![A-Za-z0-9_.-]){_SENSITIVE_FREE_NAME}"
        rf"{_QUOTE_DELIMITER}?[ \t]*[=:][ \t]*)"
        rf"(?P<value>{_LOG_ASSIGNMENT_VALUE}))"
    ),
    re.compile(r"(?i)(\bAuthorization[ \t]*[=:][ \t]*[A-Za-z][A-Za-z0-9_-]*[ \t]+)([^\s,;]+)"),
)
_URL_QUERY_SECRET = re.compile(
    rf"(?i)([?&;]({_SENSITIVE_QUERY_NAME})[ \t]*[=:][ \t]*)"
    r'((?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27|`[^`\r\n]*`|'
    r"(?:&quot;[^\r\n]*?&quot;|&apos;[^\r\n]*?&apos;|%22[^\r\n]*?%22|%27[^\r\n]*?%27)|"
    r"(?:(?![&;][A-Za-z0-9_.-]+=)[^\s])+))"
)
_URL_USERINFO = re.compile(
    r"(?i)(\b[A-Za-z][A-Za-z0-9+.-]*://)([^:/?#@\s]*):([^/?#\s]*)@([^/?#\s]*)"
)
_RTMP_STREAM_KEY = re.compile(
    r"(?i)\b((?:rtmp|rtmps|rtmpe|rtmpt|rtmpte|rtmfp)://[^/?#\s\"'<>]+/"
    r"(?:[^/?#\s\"'<>]+/)+)([^/?#\s\"'<>]+)"
)
_STREAMLABS_WIDGET_TOKEN = re.compile(
    r"(?i)(https?://(?:www\.)?streamlabs\.com/(?:widgets/)?[^/?#\s]+/v\d+/)"
    r"([^/?#\s\"'<>]+)"
)
_STREAMELEMENTS_TOKEN = re.compile(
    r"(?i)(https?://(?:www\.)?streamelements\.com/overlay/[^/?#\s]+/)"
    r"([^/?#\s\"'<>]+)"
)
_SCHEME_NAMES = frozenset(
    [
        "bearer",
        "basic",
        "digest",
        "token",
        "bot",
        "oauth",
        "oauth2",
        "negotiate",
        "ntlm",
        "kerberos",
        "mac",
        "hawk",
        "aws4-hmac-sha256",
        "splunk",
        "key",
        "apikey",
        "sharedaccesssignature",
        "client-id",
        "api-key",
    ]
)
_CLI_ASSIGNMENT = re.compile(
    r"(?i)(?<!\S)(--?[A-Za-z0-9_.-]+(?:[ \t]*[=:][ \t]*|[ \t]+))([^\s-][^\s]*)"
)
_COOKIE_HEADER = re.compile(r"(?im)^([ \t]*(?:set-cookie|cookie)[ \t]*:[ \t]*)([^\r\n]*)")
_AUTH_HEADER = re.compile(
    r"(?im)^([ \t]*[A-Za-z0-9_.-]*authorization[ \t]*[=:][ \t]*)([^\s,;]+)(?:[ \t]+([^\s,;]+))?"
)
_URL_TEXT = re.compile(r"(?i)\b[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"'`]+")
_ASSIGNMENT_VALUE = re.compile(
    r"(?im)(?P<prefix>(?:^|[\s,;])[^=\s,;]+[=:]\s*)"
    r'(?P<value>"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)'
)


def _mask_urls(text: str) -> str:
    """Hide URL spans from free-text assignment scans; query rules scan them separately."""
    if "://" not in text:
        return text
    chars = list(text)
    for match in _URL_TEXT.finditer(text):
        for index in range(match.start(), match.end()):
            if chars[index] not in "\r\n":
                chars[index] = " "
    return "".join(chars)


def _fragment_secret_spans(text: str) -> list[tuple[int, int]]:
    """Return URL fragment value spans whose parameter names are credentials."""
    found: list[tuple[int, int]] = []
    for url_match in _URL_TEXT.finditer(text):
        fragment = text.find("#", url_match.start(), url_match.end())
        if fragment < 0:
            continue
        end = url_match.end()
        body = text[fragment + 1 : end]
        for match in re.finditer(
            r"(?:^|[&;]|/(?=[A-Za-z0-9_.-]+=))([A-Za-z0-9_.-]+)[ \t]*=[ \t]*([^\s<>]*)",
            body,
        ):
            if _is_sensitive_key(match.group(1), ("__url_query__",)):
                start = fragment + 1 + match.start(2)
                value, _following = _query_value_parts(match.group(2))
                stop = start + len(value)
                if start == stop:
                    continue
                found.append((start, stop))
    return found


def _redact_url_fragments(text: str, counts: dict[str, int]) -> str:
    spans = _fragment_secret_spans(text)
    for start, end in reversed(spans):
        if _unquote(text[start:end]) == REDACTED:
            continue
        text = text[:start] + _quoted_redacted(text[start:end]) + text[end:]
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
    return text


def _looks_like_key_material(value: str) -> bool:
    return len(value) >= 8 and any(not character.isalpha() for character in value)


_RTMP_APPLICATION_NAMES = frozenset(
    {
        "live",
        "live2",
        "app",
        "stream",
        "streams",
        "rtmp",
        "ingest",
        "publish",
        "broadcast",
        "hls",
        "vod",
        "origin",
        "edge",
        "input",
    }
)


def _looks_like_rtmp_key(value: str) -> bool:
    return value.casefold() not in _RTMP_APPLICATION_NAMES and (
        len(value) >= 8 or (len(value) >= 4 and any(not char.isalpha() for char in value))
    )


def _is_explicit_camel_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    return normalized in {
        "streamkey",
        "apikey",
        "accesskey",
        "secretkey",
        "privatekey",
        "authkey",
        "signingkey",
        "encryptionkey",
        "masterkey",
        "sharedkey",
        "sessionkey",
        "licensekey",
        "clientkey",
        "servicekey",
        "bearerkey",
    }


def _is_weak_camel_key(key: str) -> bool:
    return key.endswith("Key") and not _is_explicit_camel_key(key)


def _hotkey_key_exempt(key: str, context: tuple[str, ...], value: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    if normalized != "key":
        return False
    if "__obsbasic_hotkey_binding__" in context:
        if any(re.sub(r"[^a-z0-9]", "", part.casefold()) == "settings" for part in context):
            return False
        context = (*context, "bindings")
    parts = [re.sub(r"[^a-z0-9]", "", part.casefold()) for part in context]
    hotkeys = {"hotkey", "hotkeys", "binding", "bindings", "keybinding", "keybindings"}
    positions = [index for index, part in enumerate(parts) if part in hotkeys]
    if not positions:
        return False
    closest = positions[-1]
    if "settings" in parts[closest + 1 :]:
        return False
    return value == "" or (
        isinstance(value, str) and bool(re.fullmatch(r"OBS_KEY_[A-Z0-9_]+", value))
    )


_CREDENTIAL_NAMES = frozenset(
    {
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
        "secretkey",
        "authkey",
        "signingkey",
        "encryptionkey",
        "masterkey",
        "sharedkey",
        "sessionkey",
    }
)


def _is_sensitive_key(key: str, context: tuple[str, ...] = (), value: Any = None) -> bool:  # noqa: PLR0911
    """Recognize credential names, treating the ambiguous `key` contextually."""
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    if normalized == "key":
        if context and context[-1] == "__obsbasic_hotkey_binding__":
            return not _hotkey_key_exempt(key, context, value)
        return not _hotkey_key_exempt(key, context, value)
    if normalized in _CREDENTIAL_NAMES:
        return True
    if normalized == "authorization" or ("-" in key and normalized.endswith("authorization")):
        return True
    if context and context[-1] == "__url_query__" and normalized in {"auth", "sig"}:
        return True
    # Credential suffixes apply regardless of lowercase compound prefixes.
    if normalized.endswith(("password", "passwd", "secret", "token")):
        return True
    # Preserve the existing explicit/generic key recognition without treating
    # ordinary OBS settings such as keyint and key_color as credentials.
    return normalized in {
        "apikey",
        "privatekey",
        "secretkey",
        "authkey",
        "signingkey",
        "encryptionkey",
        "masterkey",
        "sharedkey",
        "sessionkey",
        "accesskey",
    } or (
        normalized.endswith("key")
        and normalized != "key"
        and (key[-3:] != "key" or key.casefold().endswith(("_key", "-key", ".key")))
    )


def _unquote(value: str) -> str:
    value = value.strip()
    if not value or value[0] not in "\\\"'`&%#\u201c\u2018":
        return value
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
    leading_offset = len(value) - len(value.lstrip("\\"))
    trailing_offset = len(value.rstrip("\\")) - 1
    leading = value[leading_offset : leading_offset + 1]
    trailing = value[trailing_offset : trailing_offset + 1]
    if trailing_offset > leading_offset and leading in {"'", '"'} and trailing == leading:
        quoted = re.match(r"^(\\*[\"'])(.*?)(\\*[\"'])$", value)
        if quoted and quoted.group(1).lstrip("\\") == quoted.group(3).lstrip("\\"):
            return quoted.group(2)
    return value


def _quoted_redacted(value: str) -> str:  # noqa: PLR0911
    if not value or value[0] not in "\\\"'`&%#\u201c\u2018":
        return REDACTED
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
        if quoted.group(1).count("\\") != quoted.group(3).count("\\"):
            return f"{quoted.group(1)}{REDACTED}{quoted.group(1)}"
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
    full_scan = _mask_urls(text)
    covered = [
        (match.start(1), match.end(2))
        for match in pattern.finditer(full_scan)
        if _is_sensitive_key(_log_match_key(match))
    ]
    fragments = [
        fragment
        for fragment in fragments
        if not any(start < fragment[0] and end > fragment[1] for start, end in covered)
    ]
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
        scan_segment = _mask_urls(segment)
        replacements: list[tuple[int, int, str]] = []
        for match in pattern.finditer(scan_segment):
            replacement = replace(match)
            original = match.group(1) + match.group(2)
            if replacement != original:
                replacements.append((match.start(1), match.end(2), replacement))
        # Merge the union of every sensitive value span. A later name can
        # begin inside an earlier unquoted value, so filtering overlaps loses
        # credentials such as token=x;password=y.
        merged: list[tuple[int, int, str]] = []
        for replace_start, replace_end, replacement in replacements:
            if merged and replace_start <= merged[-1][1]:
                old_start, old_end, old_replacement = merged[-1]
                merged[-1] = (old_start, max(old_end, replace_end), old_replacement)
            else:
                merged.append((replace_start, replace_end, replacement))
        segment_cursor = 0
        for replace_start, replace_end, replacement in merged:
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
    if not prefix or not prefix[-1].isspace():
        return False
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


def _is_url_query_assignment(text: str, start: int) -> bool:
    """Tell URL query separators from punctuation in a free-text log value."""
    if start == 0 or text[start - 1] not in "?&;":
        return False
    name_end = start
    while name_end < len(text) and (text[name_end].isalnum() or text[name_end] in "_.-"):
        name_end += 1
    if name_end <= start or name_end >= len(text) or text[name_end] != "=":
        return False
    value_start = name_end + 1
    return not (
        value_start >= len(text) or text[value_start].isspace() or text[value_start] in "\"'`"
    )


def _query_value_parts(value: str) -> tuple[str, str]:
    """Keep a following named parameter intact while absorbing token punctuation."""
    if value.startswith(REDACTED):
        next_parameter = re.search(r"[&;](?=[A-Za-z0-9_.-]+=)", value)
        if next_parameter:
            return REDACTED, value[next_parameter.start() :]
        return REDACTED, value[len(REDACTED) :]
    quoted_pairs = (
        ('"', '"'),
        ("'", "'"),
        ("`", "`"),
        ("&quot;", "&quot;"),
        ("&apos;", "&apos;"),
        ("%22", "%22"),
        ("%27", "%27"),
        ("&#34;", "&#34;"),
        ("&#39;", "&#39;"),
        ("&#x22;", "&#x22;"),
        ("&#x27;", "&#x27;"),
        ("&ldquo;", "&rdquo;"),
        ("&lsquo;", "&rsquo;"),
        ("\u201c", "\u201d"),
        ("\u2018", "\u2019"),
    )
    folded = value.casefold()
    for opening, closing in quoted_pairs:
        if folded.startswith(opening.casefold()):
            close = folded.find(closing.casefold(), len(opening))
            if close >= 0:
                end = close + len(closing)
                return value[:end], value[end:]
    next_parameter = re.search(r"[&;](?=[A-Za-z0-9_.-]+=)", value)
    if next_parameter:
        value, following = value[: next_parameter.start()], value[next_parameter.start() :]
    else:
        following = ""
    boundary = re.search(r"\s", value)
    if boundary:
        following = value[boundary.start() :] + following
        value = value[: boundary.start()]
    return value, following


def _query_value_is_redacted(value: str) -> bool:
    """Accept a redaction marker only when no unquoted value tail remains."""
    clean, following = _query_value_parts(value)
    if _unquote(clean) != REDACTED:
        return False
    if clean != REDACTED:
        return True
    return (
        not following
        or following[0].isspace()
        or bool(re.match(r"[&;][A-Za-z0-9_.-]+=", following))
    )


def _has_sensitive_query_assignment(text: str) -> bool:
    """Avoid scanning dense benign query pairs when no credential key is present."""
    folded = text.casefold()
    for hint in _QUERY_HINTS:
        cursor = 0
        while (position := folded.find(hint, cursor)) >= 0:
            start = position
            while start and (folded[start - 1].isalnum() or folded[start - 1] in "_.-"):
                start -= 1
            if start and text[start - 1] in "?&;":
                end = position + len(hint)
                while end < len(text) and (folded[end].isalnum() or folded[end] in "_.-"):
                    end += 1
                name = text[start:end]
                while end < len(text) and text[end] in " \t":
                    end += 1
                if (
                    end < len(text)
                    and text[end] in "=:"
                    and _is_sensitive_key(name, ("__url_query__",))
                ):
                    return True
            cursor = position + len(hint)
    return False


def _is_repeated_redacted_key_log(text: str) -> bool:
    return bool(_REPEATED_REDACTED_KEY_LINES.fullmatch(text))


def _is_repeated_redacted_quoted_key_log(text: str) -> bool:
    return bool(_REPEATED_REDACTED_QUOTED_KEY_LINES.fullmatch(text))


def _authorization_has_scheme(match: re.Match[str]) -> bool:
    if match.re is _LOG_PATTERNS[-1]:
        cleaned = match.group(2).rstrip("'\"` ,;}")
        return _authorization_scheme(match) and _unquote(cleaned) == REDACTED
    tail = match.string[match.end(1) :]
    tail = tail.splitlines()[0]
    tail = re.sub(r"^[ \t'\"`,;}]+|[ \t'\"`,;}]+$", "", tail)
    value = tail.split(None, 1)
    if value and value[0].strip('"').casefold().rstrip(":=") in _SCHEME_NAMES and len(value) > 1:
        return bool(re.match(r"(?i)^[\"'`]?<REDACTED>[\"'`]?(?=[,;}\s]|$)", value[1]))
    prefix = match.group(1).rstrip()
    scheme_match = re.search(r"(?i)([A-Za-z][A-Za-z0-9_-]*)[ \t]*$", prefix)
    if scheme_match and scheme_match.group(1).casefold() in _SCHEME_NAMES:
        value_text = _unquote(match.group(2).rstrip("'\"` ,;}"))
        return value_text == REDACTED
    return bool(
        value
        and value[0].casefold().rstrip(":=") in _SCHEME_NAMES
        and len(value) > 1
        and _unquote(value[1].rstrip(",;} ")).strip("'\"`") == REDACTED
    )


def _authorization_scheme(match: re.Match[str]) -> bool:
    if match.re is _LOG_PATTERNS[-1]:
        scheme = match.group(1).split()[-1].casefold()
    else:
        pieces = _unquote(match.group(2)).split(None, 1)
        scheme = pieces[0].casefold() if pieces else ""
    return scheme in _SCHEME_NAMES


def _redact_authorization_remainders(text: str, counts: dict[str, int]) -> str:  # noqa: PLR0912
    header = re.compile(
        r"(?i)(?<![\w.-])(?:[A-Za-z0-9_.]+-)*authorization[\"']?[ \t]*[=:][ \t]*([\"'`]?)"
    )
    replacements: list[tuple[int, int, str]] = []
    for match in header.finditer(text):
        line_start = max(text.rfind("\n", 0, match.start()), text.rfind("\r", 0, match.start())) + 1
        line_end = len(text)
        for marker in ("\n", "\r"):
            found = text.find(marker, match.end())
            if found >= 0:
                line_end = min(line_end, found)
        quote_char = ""
        escaped = False
        for char in text[line_start : match.start()]:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif quote_char and char == quote_char:
                quote_char = ""
            elif not quote_char and char in "\"'`":
                quote_char = char
        if match.group(1):
            quote_char = match.group(1)
        if quote_char:
            cursor = match.end()
            escaped = False
            while cursor < line_end:
                char = text[cursor]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote_char:
                    line_end = cursor
                    break
                cursor += 1
        value_start = match.end()
        value = text[value_start:line_end]
        if not value.strip() or value.strip() == REDACTED:
            continue
        stripped = value.strip()
        pieces = stripped.split(None, 1)
        first = pieces[0].rstrip(",;") if pieces else ""
        if first.casefold() in _SCHEME_NAMES and len(pieces) > 1 and pieces[1].strip() == REDACTED:
            continue
        if first.casefold() in _SCHEME_NAMES and len(pieces) > 1:
            replacement = value[: len(value) - len(value.lstrip())] + first + " " + REDACTED
        else:
            replacement = REDACTED
        replacements.append((value_start, line_end, replacement))
    for start, end, replacement in reversed(replacements):
        text = text[:start] + replacement + text[end:]
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
    return text


_COMMENT_NAME = re.compile(rf"(?i)(?<![A-Za-z0-9_.-])({_FREE_NAME})")
_QUOTE_DELIMITER_RE = re.compile(_QUOTE_DELIMITER)
_WHITESPACE_RE = re.compile(r"\s*")
_QUOTED_VALUE_RE = re.compile(_QUOTED_CREDENTIAL_VALUE)


def _comment_assignments(text: str) -> list[tuple[str, str, int, int, bool]]:  # noqa: PLR0912, PLR0915
    """Tokenize credential assignments separated from their value by comments."""
    found: list[tuple[str, str, int, int, bool]] = []
    for span_start, span_end in _outside_json_segments(text):
        segment = text[span_start:span_end]
        if "/*" not in segment and "//" not in segment:
            continue
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
                whitespace = _WHITESPACE_RE.match(segment, cursor)
                cursor = whitespace.end() if whitespace else cursor
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
            value_match = _QUOTED_VALUE_RE.match(segment, cursor)
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
                    span_start + value_match.end(),
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
    values: set[str] = set()
    if _BROKEN_BACKSLASH_ASSIGNMENT.fullmatch(text):
        return values
    if _REPEATED_NUMERIC_KEY_LINES.fullmatch(text):
        return values
    if _REPEATED_QUOTED_KEY_LINES.fullmatch(text):
        return {
            match.group("value")
            for match in _QUOTED_KEY_LINE.finditer(text)
            if len(match.group("value")) >= 4
            and not match.group("value").isdigit()
            and match.group("value") != REDACTED
        }
    if _has_sensitive_query_assignment(text):
        values.update(
            _query_value_parts(match.group(3))[0]
            for match in _URL_QUERY_SECRET.finditer(text)
            if _is_sensitive_key(match.group(2), ("__url_query__",))
            and _unquote(_query_value_parts(match.group(3))[0]).casefold()
            not in {"null", "undefined", "none", "nil", "true", "false"}
        )
    if "://" in text:
        values.update(match.group(3) for match in _URL_USERINFO.finditer(text))
        values.update(
            _rtmp_key(match.group(2))
            for match in _RTMP_STREAM_KEY.finditer(text)
            if _looks_like_rtmp_key(_rtmp_key(match.group(2)))
        )
    if "streamlabs.com/" in text.casefold():
        values.update(match.group(2) for match in _STREAMLABS_WIDGET_TOKEN.finditer(text))
    if _SENSITIVE_NAME_HINT.search(text):
        values.update(
            literal
            for _name, value, _start, _end, noncredential in _comment_assignments(text)
            if not noncredential
            for literal in [_unquote(value)]
            if literal.casefold() not in {"null", "undefined", "none", "nil", "true", "false"}
        )
    for pattern in _LOG_PATTERNS if _SENSITIVE_NAME_HINT.search(text) else ():
        if pattern is _LOG_PATTERNS[-1] and "authorization" not in text.casefold():
            continue

        def collect(match: re.Match[str], pattern: re.Pattern[str] = pattern) -> str:
            if pattern is _LOG_PATTERNS[0] and _is_url_query_assignment(
                match.string, match.start(1)
            ):
                return match.group(0)
            if (
                pattern is _LOG_PATTERNS[-1]
                or _log_match_key(match).casefold() != "key"
                or not is_noncredential_log_match(text, match)
            ) and (pattern is _LOG_PATTERNS[-1] or _is_sensitive_key(_log_match_key(match))):
                if (
                    pattern is _LOG_PATTERNS[0]
                    and _log_match_key(match).casefold().endswith("authorization")
                    and _authorization_scheme(match)
                ):
                    return match.group(0)
                if pattern is _LOG_PATTERNS[-1] and not _authorization_scheme(match):
                    return match.group(0)
                literal = _unquote(match.group(2))
                if (
                    len(literal) >= 4
                    and not literal.isdigit()
                    and literal.casefold()
                    not in {"null", "undefined", "none", "nil", "true", "false"}
                ):
                    key = _log_match_key(match)
                    if _is_weak_camel_key(key) and not _looks_like_key_material(literal):
                        return match.group(0)
                    values.add(literal)
            return match.group(0)

        scan_text = _mask_urls(text)
        for start, end in _outside_json_segments(scan_text):
            for match in pattern.finditer(scan_text[start:end]):
                collect(match)
    for _start, _end, value, context in _json_fragments(text):
        values.update(_credential_values(value, context))
    return {
        value
        for value in values
        if value
        and value != REDACTED
        and value.casefold() not in {"null", "undefined", "none", "nil", "true", "false"}
    }


def _rtmp_key(value: str) -> str:
    """Drop sentence punctuation accidentally attached to a URL path segment."""
    return value.rstrip(".,;:!?)]}\\'\u201d\u2019")


@lru_cache(maxsize=2)
def _json_fragments(text: str) -> list[tuple[int, int, Any, tuple[str, ...]]]:  # noqa: PLR0912, PLR0915
    """Find valid JSON object/array fragments in otherwise free-form text."""
    decoder = json.JSONDecoder()
    fragments: list[tuple[int, int, Any, tuple[str, ...]]] = []
    quoted_positions = bytearray(len(text))
    quote_char = ""
    escaped = False
    for position, char in enumerate(text):
        if char in "\r\n":
            quote_char = ""
            escaped = False
            continue
        if quote_char:
            quoted_positions[position] = 1
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                quote_char = ""
        elif char in "\"'`":
            quote_char = char
            quoted_positions[position] = 1
    index = 0
    while index < len(text):
        starts = [
            position for position in (text.find("{", index), text.find("[", index)) if position >= 0
        ]
        if not starts:
            break
        start = min(starts)
        if quoted_positions[start]:
            index = start + 1
            continue
        opening = text[start]
        following = start + 1
        while following < len(text) and text[following].isspace():
            following += 1
        if following >= len(text):
            break
        first = text[following]
        valid_start = bool(
            _JSON_OBJECT_START.match(text, start)
            if opening == "{"
            else _JSON_ARRAY_START.match(text, start)
        )
        if not valid_start:
            index = start + 1
            continue
        if opening == "{" and first == '"' and text.find("}", following) < 0:
            index = start + 1
            continue
        if opening == "[" and first in '[{"-0123456789tfn' and text.find("]", following) < 0:
            index = start + 1
            continue
        try:
            value, length = decoder.raw_decode(text, start)
        except (json.JSONDecodeError, RecursionError, MemoryError) as error:
            error_position = getattr(error, "pos", start + 1)
            index = max(start + 1, min(error_position, len(text)))
            continue
        end = length
        before_ok = start == 0 or text[start - 1] in " \t\r\n=:([{'\",>"
        after_ok = end == len(text) or text[end] in " \t\r\n,;)]}\"'"
        if not before_ok or not after_ok:
            index = start + 1
            continue
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


def _credential_literals(value: Any) -> set[str]:  # noqa: PLR0911
    if isinstance(value, str):
        return {value} if value else set()
    if isinstance(value, bool) or value is None:
        return set()
    if isinstance(value, int):
        return {str(value)}
    if isinstance(value, float):
        return {repr(value), format(value, "f").rstrip("0").rstrip(".")}
    if isinstance(value, dict):
        return set().union(*(_credential_literals(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(_credential_literals(child) for child in value))
    return set()


def _credential_values(value: Any, context: tuple[str, ...] = ()) -> set[str]:
    """Collect credential literals transiently so duplicate values can be checked."""
    values: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            child_context = context + ((key,) if isinstance(key, str) else ())
            if isinstance(key, str) and _is_sensitive_key(key, context, child):
                literals = _credential_literals(child)
                if _is_weak_camel_key(key):
                    literals = {item for item in literals if _looks_like_key_material(item)}
                values.update(
                    literal
                    for literal in literals
                    if literal.casefold()
                    not in {"null", "undefined", "none", "nil", "true", "false"}
                )
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
        literal = _unquote(match.group("value"))
        if literal in secrets and len(literal) >= 4 and not literal.isdigit():
            return f"{match.group('prefix')}{REDACTED}"
        return match.group(0)

    text = _sub_outside_json(text, _ASSIGNMENT_VALUE, scrub)
    for literal in sorted(secrets, key=len, reverse=True):
        if len(literal) >= 4 and not literal.isdigit():
            text = re.sub(rf"(?<!\w){re.escape(literal)}(?!\w)", REDACTED, text)
    return text


def _redact_embedded(  # noqa: PLR0912, PLR0915
    text: str, counts: dict[str, int], secrets: set[str] | None = None
) -> str:
    broken_backslash = _BROKEN_BACKSLASH_ASSIGNMENT.fullmatch(text)
    if broken_backslash and _is_sensitive_key(broken_backslash.group("name")):
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{broken_backslash.group('prefix')}{REDACTED}{broken_backslash.group('newline')}"
    if _REPEATED_NUMERIC_KEY_LINES.fullmatch(text):
        count = text.count("\n")
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + count
        return _NUMERIC_KEY_ASSIGNMENT.sub(rf"\g<1>{REDACTED}", text)
    if _REPEATED_QUOTED_KEY_LINES.fullmatch(text):
        matches = [
            match for match in _QUOTED_KEY_LINE.finditer(text) if match.group("value") != REDACTED
        ]
        if not matches:
            return text
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + len(matches)
        return _QUOTED_KEY_LINE.sub(
            lambda match: (
                match.group("prefix")
                + match.group("quote")
                + REDACTED
                + match.group("quote")
                + match.group("newline")
            ),
            text,
        )

    def replace(match: re.Match[str], *, check_noncredential: bool = True) -> str:
        literal = _unquote(match.group(2))
        if literal == REDACTED or literal.casefold() in {
            "null",
            "undefined",
            "none",
            "nil",
            "true",
            "false",
        }:
            return match.group(1) + match.group(2)
        if (
            check_noncredential
            and _log_match_key(match).casefold() == "key"
            and is_noncredential_log_match(text, match)
        ):
            return match.group(1) + match.group(2)
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{match.group(1)}{_quoted_redacted(match.group(2))}"

    def replace_log(match: re.Match[str], pattern: re.Pattern[str]) -> str:  # noqa: PLR0911
        key = _log_match_key(match)
        if key.casefold().endswith("authorization") and _authorization_has_scheme(match):
            return match.group(1) + match.group(2)
        if pattern is _LOG_PATTERNS[-1] and not _authorization_scheme(match):
            return match.group(0)
        if pattern is _LOG_PATTERNS[0] and _is_url_query_assignment(match.string, match.start(1)):
            return match.group(1) + match.group(2)
        if pattern is not _LOG_PATTERNS[-1] and not _is_sensitive_key(key):
            return match.group(1) + match.group(2)
        if (
            pattern is _LOG_PATTERNS[0]
            and key.casefold() == "key"
            and is_noncredential_log_match(text, match)
        ):
            return match.group(1) + match.group(2)
        if (
            pattern is _LOG_PATTERNS[0]
            and key.casefold() == "authorization"
            and _authorization_has_scheme(match)
        ):
            return match.group(0)
        return replace(match, check_noncredential=False)

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
        if not key or key == REDACTED or not _looks_like_rtmp_key(key):
            return match.group(0)
        trailing = match.group(2)[len(key) :]
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{match.group(1)}{REDACTED}{trailing}"

    if "://" in text:
        text = _sub_outside_json(text, _RTMP_STREAM_KEY, redact_rtmp)

    def replace_query(match: re.Match[str]) -> str:
        if not _is_sensitive_key(match.group(2), ("__url_query__",)):
            return match.group(0)
        value, following = _query_value_parts(match.group(3))
        if _unquote(value).casefold() in {"null", "undefined", "none", "nil", "true", "false"}:
            return match.group(0)
        if _unquote(value) != REDACTED:
            counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{match.group(1)}{_quoted_redacted(value)}{following}"

    if _has_sensitive_query_assignment(text):
        text = _sub_outside_json(text, _URL_QUERY_SECRET, replace_query)
    text = _redact_url_fragments(text, counts)

    def redact_userinfo(match: re.Match[str]) -> str:
        if match.group(3) == REDACTED:
            return match.group(0)
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{match.group(1)}{match.group(2)}:{REDACTED}@{match.group(4)}"

    if "://" in text and "@" in text:
        text = _sub_outside_json(text, _URL_USERINFO, redact_userinfo)
    if "streamlabs.com/" in text.casefold():
        text = _sub_outside_json(text, _STREAMLABS_WIDGET_TOKEN, replace)
    if "streamelements.com/overlay/" in text.casefold():

        def redact_elements(match: re.Match[str]) -> str:
            counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
            return f"{match.group(1)}{REDACTED}"

        text = _sub_outside_json(text, _STREAMELEMENTS_TOKEN, redact_elements)
    if "cookie:" in text.casefold() or "set-cookie:" in text.casefold():

        def redact_cookie(match: re.Match[str]) -> str:
            value = match.group(2)
            if value.strip() and value.strip() != REDACTED:
                counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
            return match.group(1) + REDACTED

        text = _COOKIE_HEADER.sub(redact_cookie, text)
    if "authorization" in text.casefold():
        text = _redact_authorization_remainders(text, counts)
    if "--" in text or re.search(r"(?i)(?:^|\s)-[A-Za-z]", text):

        def redact_cli(match: re.Match[str]) -> str:
            prefix, value = match.group(1), match.group(2)
            option = re.match(r"--?([A-Za-z0-9_.-]+)", prefix)
            if option is None:
                return match.group(0)
            name = option.group(1)
            if not _is_sensitive_key(name) or value.casefold() in {
                "null",
                "undefined",
                "none",
                "nil",
                "true",
                "false",
            }:
                return match.group(0)
            counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
            return prefix + REDACTED

        text = _CLI_ASSIGNMENT.sub(redact_cli, text)
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
        if pattern is _LOG_PATTERNS[-1] and "authorization" not in text.casefold():
            continue

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
                and _is_sensitive_key(key, context, child)
                and child not in (None, "")
                and not isinstance(child, bool)
                and not (
                    isinstance(child, str)
                    and child.casefold() in {"null", "undefined", "none", "nil", "true", "false"}
                )
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
                and _is_sensitive_key(key, context, child)
                and child not in (None, "", REDACTED)
                and not isinstance(child, bool)
                and not (
                    isinstance(child, str)
                    and child.casefold() in {"null", "undefined", "none", "nil", "true", "false"}
                )
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
    if _is_repeated_redacted_key_log(text) or _is_repeated_redacted_quoted_key_log(text):
        return False
    if any(has_unredacted_fields(value, context) for _, _, value, context in _json_fragments(text)):
        return True
    if any(
        _rtmp_key(match.group(2)) != REDACTED and _looks_like_rtmp_key(_rtmp_key(match.group(2)))
        for match in _RTMP_STREAM_KEY.finditer(text)
    ):
        return True
    if any(_unquote(text[start:end]) != REDACTED for start, end in _fragment_secret_spans(text)):
        return True
    if _has_sensitive_query_assignment(text) and any(
        _is_sensitive_key(match.group(2), ("__url_query__",))
        and _unquote(_query_value_parts(match.group(3))[0]).casefold()
        not in {"null", "undefined", "none", "nil", "true", "false"}
        and not _query_value_is_redacted(match.group(3) + text[match.end(3) :])
        for match in _URL_QUERY_SECRET.finditer(text)
    ):
        return True
    if any(match.group(3) != REDACTED for match in _URL_USERINFO.finditer(text)):
        return True
    if _SENSITIVE_NAME_HINT.search(text) and any(
        _unquote(value) != REDACTED and not noncredential
        for _name, value, _start, _end, noncredential in _comment_assignments(text)
    ):
        return True
    for pattern in _LOG_PATTERNS if _SENSITIVE_NAME_HINT.search(text) else ():
        if pattern is _LOG_PATTERNS[-1] and "authorization" not in text.casefold():
            continue
        for start, end in _outside_json_segments(text):
            segment = text[start:end]
            scan_segment = _mask_urls(segment)
            if any(
                _unquote(match.group(2)) != REDACTED
                and _unquote(match.group(2)).casefold()
                not in {"null", "undefined", "none", "nil", "true", "false"}
                and (pattern is not _LOG_PATTERNS[-1] or _authorization_scheme(match))
                and not _is_url_query_assignment(segment, match.start(1))
                and (
                    _log_match_key(match).casefold() != "key"
                    or not is_noncredential_log_match(segment, match)
                )
                and not (
                    pattern in (_LOG_PATTERNS[0], _LOG_PATTERNS[-1])
                    and _log_match_key(match).casefold().endswith("authorization")
                    and _authorization_has_scheme(match)
                )
                and (pattern is _LOG_PATTERNS[-1] or _is_sensitive_key(_log_match_key(match)))
                for match in pattern.finditer(scan_segment)
            ):
                return True
    return False


def has_unredacted_ini_fields(text: str, filename: str) -> bool:  # noqa: PLR0911
    """Check INI assignments using the same key rules as the redactor."""
    fragments = _json_fragments(text)
    if any(has_unredacted_fields(value, context) for _start, _end, value, context in fragments):
        return True
    remaining: list[str] = []
    cursor = 0
    for start, end, _value, _context in fragments:
        remaining.append(text[cursor:start])
        cursor = end
    remaining.append(text[cursor:])
    lines = "".join(remaining).splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^\s*([^=:#\s][^=:#]*?)\s*[=:]\s*(.*?)\s*$", line)
        if not match:
            if has_unredacted_embedded_json(line):
                return True
            index += 1
            continue
        key, value = match.group(1).strip(), match.group(2)
        literal = _unquote(value)
        if (
            _is_sensitive_key(key, (filename,), value)
            and literal not in ("", REDACTED)
            and literal.casefold() not in {"null", "undefined", "none", "nil", "true", "false"}
        ):
            return True
        try:
            parsed = json.loads(value)
        except ValueError, json.JSONDecodeError:
            if has_unredacted_embedded_json(value):
                return True
        else:
            if has_unredacted_embedded_json(value) or has_unredacted_fields(
                parsed, (filename, "__embedded_ini__")
            ):
                return True
        if _is_sensitive_key(key, (filename,), value):
            continuation = _ini_continuation_end(lines, index, value)
            if any(
                lines[pos].strip() not in ("", REDACTED) for pos in range(index + 1, continuation)
            ):
                return True
            index = continuation
        index += 1
    return False


def _ini_continuation_end(lines: list[str], index: int, value: str) -> int:
    """Return the exclusive end of a sensitive assignment's continuation block."""
    end = index + 1
    backslash = len(value) - len(value.rstrip("\\"))
    pending = backslash % 2 == 1
    while end < len(lines):
        candidate = lines[end]
        if not candidate.strip():
            end += 1
            continue
        if re.match(r"^\s*\[[^]]+\]\s*$", candidate) or re.match(
            r"^\s*[A-Za-z0-9_.-][^=:#\s]*\s*[=:]", candidate
        ):
            break
        if pending or (
            candidate[:1].isspace()
            and len(candidate.split()) == 1
            and not re.match(r"^\s*[A-Za-z0-9_.-][^=:#\s]*\s*[=:]", candidate)
        ):
            pending = (len(candidate) - len(candidate.rstrip("\\"))) % 2 == 1
            end += 1
            continue
        break
    return end


def _ini_secret_values(text: str, filename: str) -> set[str]:
    secrets: set[str] = set()
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^\s*([A-Za-z0-9_.-][^=:#\s]*)\s*[=:]\s*(.*?)\s*$", line)
        if match and _is_sensitive_key(match.group(1), (filename,), match.group(2)):
            secret = _unquote(match.group(2))
            if (
                secret
                and secret != REDACTED
                and secret.casefold() not in {"null", "undefined", "none", "nil", "true", "false"}
            ):
                secrets.add(secret)
            end = _ini_continuation_end(lines, index, match.group(2))
            secrets.update(
                lines[pos].strip() for pos in range(index + 1, end) if lines[pos].strip()
            )
            index = end
        else:
            index += 1
    return secrets


def _redact_ini(text: str, filename: str, counts: dict[str, int], secrets: set[str]) -> str:
    original_lines = text.splitlines(keepends=True)
    output: list[str] = []
    index = 0
    while index < len(original_lines):
        original_line = original_lines[index]
        match = re.match(
            r"^(\s*)([A-Za-z0-9_.-][^=:#\s]*)(\s*[=:]\s*)(.*?)(\r?\n)?$",
            original_line,
        )
        if (
            match
            and _is_sensitive_key(match.group(2), (filename,), match.group(4))
            and (
                match.group(4).strip()
                or _ini_continuation_end(
                    [line.rstrip("\r\n") for line in original_lines], index, match.group(4)
                )
                > index + 1
            )
            and _unquote(match.group(4)).casefold()
            not in {"null", "undefined", "none", "nil", "true", "false"}
        ):
            replacement_value = REDACTED if match.group(4).strip() else match.group(4)
            cleaned = (
                f"{match.group(1)}{match.group(2)}{match.group(3)}"
                f"{replacement_value}{match.group(5) or ''}"
            )
            if match.group(4).strip():
                counts["credential_field"] = counts.get("credential_field", 0) + 1
            output.append(cleaned)
            plain_lines = [line.rstrip("\r\n") for line in original_lines]
            end = _ini_continuation_end(plain_lines, index, match.group(4))
            for continuation in original_lines[index + 1 : end]:
                if continuation.strip():
                    indent = continuation[: len(continuation) - len(continuation.lstrip())]
                    newline = (
                        "\r\n"
                        if continuation.endswith("\r\n")
                        else "\n"
                        if continuation.endswith("\n")
                        else ""
                    )
                    output.append(f"{indent}{REDACTED}{newline}")
                    counts["credential_field"] = counts.get("credential_field", 0) + 1
                else:
                    output.append(continuation)
            index = end
        else:
            output.append(original_line)
            index += 1
    return "".join(output)


def redact_file_with_secrets(path: Path) -> tuple[dict[str, int], int, set[str]]:
    """Redact one staged file and return secret literals for private verification."""
    suffix = path.suffix.lower()
    counts: dict[str, int] = {}
    is_json = suffix == ".json" or path.name.lower().endswith(".json.bak")
    is_ini = suffix == ".ini" or path.name.lower().endswith(".ini.bak")
    if is_json:
        text = read_text_safely(path)
        _guard_json_depth(text)
        raw = json.loads(text)
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


def _guard_json_depth(text: str, limit: int = 200) -> None:
    """Reject excessive structural nesting before the recursive JSON parser runs."""
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                raise ValueError("JSON nesting exceeds the safe depth limit.")
        elif char in "]}":
            depth = max(0, depth - 1)


def redact_file(path: Path) -> tuple[dict[str, int], int]:
    """Redact recognized secrets in one staged text file, preserving other values."""
    counts, total, _secrets = redact_file_with_secrets(path)
    return counts, total
