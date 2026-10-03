"""Versioned, conservative credential redaction for staged OBS files."""

from __future__ import annotations

import json
import re
from bisect import bisect_right
from functools import lru_cache
from pathlib import Path
from typing import Any

RULE_VERSION = 26
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
    r"(?i)(?:key|token|password|passwd|pwd|secret|passphrase|cookie|sessionid|jwt|credential|streamid|authorization|authentication|www-authenticate|proxy-authenticate)"
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
_JSON_OPENING = re.compile(r"[\{\[]")
_FREE_NAME = (
    r"(?:\\{0,8}+[\"']?[A-Za-z0-9_.-]{1,128}+\\{0,8}+[\"']?|"
    r"%22[A-Za-z0-9_.-]{1,128}+%22|%27[A-Za-z0-9_.-]{1,128}+%27)"
)
_SENSITIVE_NAME_CORE = (
    r"(?:[A-Za-z0-9_.-]*?(?:password|passwd|pwd|secret|token|passphrase|cookie(?:s|2)?|"
    r"session[_-]?id|jwt|credentials?|streamid)|[A-Za-z0-9_.-]*?[_\-.]key|"
    r"(?:[A-Za-z0-9_.]+-)*authorization|authentication|www-authenticate|proxy-authenticate|"
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
    re.compile(
        r"(?i)(\b(?:Authorization|Authentication|WWW-Authenticate|Proxy-Authenticate)"
        r"[ \t]*[=:][ \t]*[A-Za-z][A-Za-z0-9_-]*[ \t]+)([^\s,;]+)"
    ),
)
_URL_QUERY_SECRET = re.compile(
    rf"(?i)([?&;]({_SENSITIVE_QUERY_NAME})[ \t]*[=:][ \t]*)"
    r'((?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27|`[^`\r\n]*`|'
    r"(?:&quot;[^\r\n]*?&quot;|&apos;[^\r\n]*?&apos;|%22[^\r\n]*?%22|%27[^\r\n]*?%27)|"
    r"(?:(?![&;][A-Za-z0-9_.-]+=)[^\s])+))"
)
_URL_USERINFO = re.compile(r"(?i)(\b[A-Za-z][A-Za-z0-9+.-]*://)([^:/?#@\[\]\s]*):([^\s]*@)([^\s]*)")
_RTMP_URL = re.compile(r"(?i)\b(?:rtmp|rtmps|rtmpe|rtmpt|rtmpte|rtmfp)://[^\s]+")
_STREAMLABS_WIDGET_TOKEN = re.compile(
    r"(?i)(https?://(?:www\.)?streamlabs\.com/(?:widgets/)?[^/?#\s]+/v\d+/)"
    r"([^/?#\s\"'<>]+)"
)
_STREAMELEMENTS_TOKEN = re.compile(
    r"(?i)(https?://(?:www\.)?streamelements\.com/overlay/[^/?#\s]+/)"
    r"([^/?#\s\"'<>]+)"
)
_DISCORD_WEBHOOK_TOKEN = re.compile(
    r"(?i)(https?://(?:(?:www|ptb|canary)\.)?(?:discord|discordapp)\.com/api(?:/v\d+)?/webhooks/\d+/)"
    r"([^/?#\s\"'<>]+)"
)
_SLACK_WEBHOOK_TOKEN = re.compile(
    r"(?i)(https?://hooks\.slack\.com/(?:services|workflows|triggers)/(?:[^/?#\s]+/)*)"
    r"([^/?#\s\"'<>]+)(?=[?#\s\"'<>]|$)"
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
_FREE_TEXT_SCHEME_WORDS = "|".join(
    re.escape(value) for value in sorted(_SCHEME_NAMES, key=len, reverse=True)
)
_FREE_TEXT_SPECIAL_HINT = re.compile(
    rf"(?i)(?<![A-Za-z0-9_.-]){_FREE_NAME}[ \t]*[=:][ \t]*"
    rf"[\"'`]?(?:{_FREE_TEXT_SCHEME_WORDS})[\"'`]?"
    rf"(?:[ \t]+\S|[ \t]*\r?\n(?:[ \t]*\r?\n)*[ \t]*\S)|"
    rf"(?<![A-Za-z0-9_.-]){_FREE_NAME}[ \t]*[=:][ \t]*"
    r"(?:[ \t]*\r?\n)+[ \t]*\S"
)


def _userinfo_candidate(match: re.Match[str]) -> bool:
    """Accept URL userinfo passwords, including slashes, but not host ports."""
    username = match.group(2)
    password = match.group(3)[:-1]
    first_slash = password.find("/")
    return not (username.startswith("[") or "[" in username or "]" in username) and not (
        first_slash >= 0 and password[:first_slash].isdigit()
    )


_CLI_ASSIGNMENT = re.compile(
    r"(?i)(?<!\S)(--?[A-Za-z0-9_.-]+(?:[ \t]*[=:][ \t]*|[ \t]+))([^\s-][^\s]*)"
)
_COOKIE_HEADER = re.compile(
    r"(?im)((?:^|[ \t\]:\"'([{<\u201c\u2018])(?:set-cookie2?|cookie2?)[ \t]*:[ \t]*)([^\r\n]*)"
)
_COOKIE_PAIR = re.compile(r"(?:^|;)[ \t]*([^=;\s]+)[ \t]*=[ \t]*([^;\s]+)")
_AUTH_HEADER = re.compile(
    r"(?im)^([ \t]*[A-Za-z0-9_.-]*(?:authorization|authentication|"
    r"www-authenticate|proxy-authenticate)"
    r"[ \t]*[=:][ \t]*)([^\s,;]+)(?:[ \t]+([^\s,;]+))?"
)
_URL_TEXT = re.compile(r"(?i)\b[A-Za-z][A-Za-z0-9+.-]*://[^\s]+")
_LINE_SEPARATOR_RE = re.compile(r"[\n\r\u2028\u2029\u0085\x0b\x0c]")
_CREDENTIAL_COMPONENT_SEPARATOR_RE = re.compile(
    r"(?i:%(?:26|2c|3b|7c|23|3f))|[,;|&#?:/\"'()\[\]{}<>`\s]+"
)
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


def _is_cookie_header_name(name: str) -> bool:
    return re.sub(r"[^a-z0-9]", "", name.casefold()) in {
        "cookie",
        "cookie2",
        "setcookie",
        "setcookie2",
    }


def _is_auth_header_name(name: str) -> bool:
    folded = name.casefold()
    return folded in {
        "authorization",
        "authentication",
        "www-authenticate",
        "proxy-authenticate",
    } or folded.endswith("authorization")


def _is_whole_authorization_header(name: str) -> bool:
    folded = name.casefold()
    return folded in {"authorization", "authentication"} or folded.endswith("authorization")


def _is_challenge_realm_match(match: re.Match[str]) -> bool:
    prefix = match.group(1).casefold()
    if "www-authenticate" not in prefix and "proxy-authenticate" not in prefix:
        return False
    return bool(re.search(r"(?i)\brealm\s*=", _unquote(match.group(2))))


def _header_pair_keys(value: dict[str, Any]) -> tuple[str, str] | None:
    """Return name/value member keys for a credential header pair object."""
    aliases = {
        "value",
        "val",
        "v",
        "headervalue",
        "content",
        "data",
        "text",
        "string",
        "defaultvalue",
    }
    value_key = next(
        (
            key
            for key, child in value.items()
            if isinstance(key, str)
            and re.sub(r"[^a-z0-9]", "", key.casefold()) in aliases
            and isinstance(child, (str, list, dict, int, float))
        ),
        None,
    )
    if value_key is None:
        return None
    if isinstance(value[value_key], str) and _is_obs_key_enum(value[value_key]):
        return None
    name_aliases = {
        "name",
        "header",
        "headername",
        "headerkey",
        "n",
        "key",
        "field",
        "label",
        "k",
        "id",
        "param",
        "parameter",
    }
    for name_key, name in value.items():
        if (
            not isinstance(name_key, str)
            or re.sub(r"[^a-z0-9]", "", name_key.casefold()) not in name_aliases
        ):
            continue
        if not isinstance(name, str):
            continue
        if name_key.casefold() == "key" and (
            len(name) > 128 or not re.fullmatch(r"(?i)[A-Za-z][A-Za-z0-9_.-]*", name)
        ):
            continue
        if _is_sensitive_name(name):
            return name_key, value_key
    return None


def _header_pair_value_keys(value: dict[str, Any], name_key: str) -> set[str]:
    aliases = {
        "value",
        "val",
        "v",
        "headervalue",
        "content",
        "data",
        "text",
        "string",
        "defaultvalue",
    }
    name = value.get(name_key)
    if not isinstance(name, str) or not _is_sensitive_name(name):
        return set()
    return {
        key
        for key, child in value.items()
        if isinstance(key, str)
        and re.sub(r"[^a-z0-9]", "", key.casefold()) in aliases
        and isinstance(child, (str, list, int, float, dict))
    }


def _is_sensitive_header_name(name: str) -> bool:
    normalized = re.sub(r"[-_ ]", "", name.casefold())
    suffixes = (
        "token",
        "secret",
        "password",
        "passwd",
        "authorization",
        "authentication",
        "authenticate",
    )
    del suffixes
    return (
        normalized in {"setcookie", "cookie2", "setcookie2"}
        or normalized.endswith(
            (
                "token",
                "secret",
                "password",
                "passwd",
                "authorization",
                "authentication",
                "authenticate",
            )
        )
        or (normalized.endswith("key") and any(separator in name for separator in ("-", "_", " ")))
        or _is_sensitive_key(name)
    )


def _is_sensitive_name(name: str) -> bool:
    """Shared field/header-name predicate for redaction and independent verification."""
    return _is_sensitive_key(name) or _is_sensitive_header_name(name)


def _header_pair_list(value: list[Any]) -> bool:
    return len(value) >= 2 and isinstance(value[0], str) and _is_sensitive_name(value[0])


def _alternating_list_name(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and len(value) == 1:
        item = next(iter(value.values()))
        return item if isinstance(item, str) else None
    return None


def _alternating_sensitive_name(name: str, next_value: Any) -> bool:
    if name in {"-p", "-P"}:
        return isinstance(next_value, str) and _looks_like_key_material(next_value)
    option = re.fullmatch(r"--?([A-Za-z0-9_.-]+)", name)
    if option:
        name = option.group(1)
    return _is_sensitive_name(name)


def _scheme_redacted_value(value: Any, counts: dict[str, int] | None = None) -> Any:
    if not isinstance(value, str):
        if isinstance(value, (dict, list)):
            return _redact_object(value, counts if counts is not None else {}, set())
        return REDACTED
    token = resolve_credential_token(value, 0)
    if (
        token is not None
        and token[0] > 0
        and value[token[0] : token[1]] not in {":", "="}
        and _has_scheme_prefix(value, token[0])
    ):
        if counts is not None:
            counts["credential_field"] = counts.get("credential_field", 0) + 1
        return value[: token[0]] + REDACTED + value[token[1] :]
    if counts is not None:
        counts["credential_field"] = counts.get("credential_field", 0) + 1
    return REDACTED


def _has_scheme_prefix(value: str, end: int) -> bool:
    prefix = value[:end]
    if not prefix or not prefix[-1].isspace():
        return False
    candidate = prefix.strip().lstrip("([{<\"'`")
    parts = candidate.split()
    return bool(parts) and all(_normalize_scheme_candidate(part) in _SCHEME_NAMES for part in parts)


def _redact_pair_payload(
    value: Any, counts: dict[str, int], secrets: set[str], *, preserve_scheme: bool = False
) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return {
            key: _redact_pair_payload(child, counts, secrets, preserve_scheme=preserve_scheme)
            for key, child in value.items()
        }
    if isinstance(value, list):
        result = list(value)
        first = (
            1
            if result
            and isinstance(result[0], str)
            and _normalize_scheme_candidate(result[0]) in _SCHEME_NAMES
            else 0
        )
        for index in range(first, len(result)):
            result[index] = _redact_pair_payload(result[index], counts, secrets)
        return result
    if preserve_scheme:
        return _scheme_redacted_value(value, counts)
    counts["credential_field"] = counts.get("credential_field", 0) + 1
    return REDACTED


def _alternating_list_shape(value: list[Any]) -> bool:
    if not value or len(value) % 2:
        return False
    if all(isinstance(item, str) for item in value):
        return True
    keys = [next(iter(item)) for item in value if isinstance(item, dict) and len(item) == 1]
    return len(keys) == len(value) and len(set(keys)) == 1


def _bracketed_pair_matches(text: str) -> list[tuple[int, int, str]]:
    found: list[tuple[int, int, str]] = []
    for group in re.finditer(r"\[([^\]\r\n]*)\]", text):
        if any(char in group.group(1) for char in "{}:"):
            continue
        pieces = group.group(1).split(",")
        for index in range(0, len(pieces) - 1, 2):
            name = pieces[index].strip().strip("\"'")
            value = pieces[index + 1].strip().strip("\"'")
            if _alternating_sensitive_name(name, value):
                relative = group.group(1).find(
                    pieces[index + 1], sum(len(p) + 1 for p in pieces[: index + 1])
                )
                start = (
                    group.start(1)
                    + relative
                    + len(pieces[index + 1])
                    - len(pieces[index + 1].lstrip())
                )
                found.append((start, start + len(value), value))
    return found


def _header_pair_value_redacted(value: Any) -> bool:
    if value == REDACTED or value is None or isinstance(value, bool):
        return True
    if isinstance(value, dict):
        return all(_sensitive_field_value_redacted(child) for child in value.values())
    if not isinstance(value, list):
        return False
    first = (
        1
        if value
        and isinstance(value[0], str)
        and _normalize_scheme_candidate(value[0]) in _SCHEME_NAMES
        else 0
    )
    return all(
        item in (REDACTED, None, True, False)
        or (isinstance(item, dict) and not has_unredacted_fields(item))
        or (isinstance(item, list) and _header_pair_value_redacted(item))
        for item in value[first:]
    )


def _is_obs_key_enum(value: str) -> bool:
    return value in _OBS_KEY_NAMES or bool(re.fullmatch(r"OBS_KEY_0x[0-9A-F]{2}", value))


def _sensitive_field_value_redacted(value: Any) -> bool:
    if value in (None, "", REDACTED) or isinstance(value, bool):
        return True
    if isinstance(value, str):
        if value.casefold() in {"null", "undefined", "none", "nil", "true", "false"}:
            return True
        token = resolve_credential_token(value, 0)
        if token is not None and token[0] > 0:
            prefix = value[: token[0]]
            if any(_scheme_word(part) for part in re.findall(r"[^\s]+", prefix)):
                return (
                    _clean_credential_literal(_before_named_parameter(value[token[0] : token[1]]))
                    == REDACTED
                )
    if isinstance(value, dict):
        return all(_sensitive_field_value_redacted(child) for child in value.values())
    if isinstance(value, list):
        first = (
            1
            if value
            and isinstance(value[0], str)
            and _normalize_scheme_candidate(value[0]) in _SCHEME_NAMES
            else 0
        )
        return all(_sensitive_field_value_redacted(child) for child in value[first:])
    return False


def _before_named_parameter(value: str) -> str:
    match = re.search(r"&[A-Za-z][A-Za-z0-9_-]{1,79}[=:]", value)
    if match is None:
        return value
    name = match.group(0)[1:-1].rstrip("=").casefold()
    if name not in {"expires_in", "token_type", "scope", "region", "state", "expires"}:
        return value
    return value[: match.start()]


def _cookie_pair_promotable(name: str, value: str) -> bool:
    if name.casefold() in {
        "domain",
        "path",
        "expires",
        "max-age",
        "samesite",
        "secure",
        "httponly",
        "priority",
        "partitioned",
    }:
        return False
    del name
    return any(
        not _never_promote_literal(literal)
        and not _is_benign_shape(literal)
        and _looks_like_key_material(literal)
        for literal in _credential_literal_candidates(value)
    )


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
            r"(?:^|[&;]|/(?=[A-Za-z0-9_.-]+=))([A-Za-z0-9_.-]+)[ \t]*=[ \t]*([^\s]*)",
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


def _rtmp_segment_spans(text: str) -> list[tuple[int, int]]:
    """Find key-like RTMP path segments, including a key used as the app path."""
    spans: list[tuple[int, int]] = []
    for url in _RTMP_URL.finditer(text):
        scheme_end = url.start() + url.group(0).find("://") + 3
        slash = text.find("/", scheme_end, url.end())
        if slash < 0:
            continue
        path_end = url.end()
        for marker in ("?", "#"):
            found = text.find(marker, slash, path_end)
            if found >= 0:
                path_end = min(path_end, found)
        cursor = slash + 1
        for segment in text[cursor:path_end].split("/"):
            end = cursor + len(segment)
            clean = "" if segment.startswith(REDACTED) else _rtmp_key(segment)
            clean_end = cursor + len(clean)
            delimiter = re.search(r"&(?=[A-Za-z0-9_.-]{2,}=)", segment)
            if delimiter:
                clean = segment[: delimiter.start()].rstrip(".,;:!?)]}")
                clean_end = cursor + len(clean)
            if clean and clean != REDACTED and _looks_like_rtmp_in_place(clean):
                spans.append((cursor, clean_end))
            cursor = end + 1
    return spans


def _redact_rtmp_segments(text: str, counts: dict[str, int]) -> str:
    for start, end in reversed(_rtmp_segment_spans(text)):
        if text[start:end] != REDACTED:
            text = text[:start] + REDACTED + text[end:]
            counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
    return text


def _looks_like_key_material(value: str) -> bool:
    return len(value) >= 8 and any(not character.isalpha() for character in value)


def _never_promote_literal(value: str) -> bool:
    cleaned = _clean_credential_literal(value)
    folded = cleaned.casefold()
    return (
        not cleaned
        or cleaned == REDACTED
        or folded in {"null", "undefined", "none", "nil", "true", "false"}
        or _scheme_word(cleaned)
        or cleaned in _OBS_KEY_NAMES
        or _is_rtmp_quality_or_resolution(cleaned)
    )


def _promotable_free_text(value: str, *, explicit_auth: bool = False) -> bool:
    cleaned = _clean_credential_literal(value)
    return not _never_promote_literal(cleaned) and (
        explicit_auth or _looks_like_key_material(cleaned)
    )


_HOSTNAME_SHAPE = re.compile(r"^[A-Za-z0-9-]{1,30}(?:\.[A-Za-z0-9-]{1,30})+$")
_MODULE_NAME_SHAPES = frozenset(
    {
        "jim_nvenc_h264",
        "jim_nvenc_hevc",
        "ffmpeg_aac",
        "obs_x264",
        "obs_nvenc",
        "obs_qsv11",
        "obs_amf",
    }
)


def _is_hostname_or_module_like(candidate: str, *, derived: bool = True) -> bool:
    if _HOSTNAME_SHAPE.fullmatch(candidate) and len(candidate) <= 40:
        labels = candidate.split(".")
        final = labels[-1]
        mixed_token_label = any(
            any(char.islower() for char in label)
            and any(char.isupper() for char in label)
            and any(char.isdigit() for char in label)
            for label in labels
        )
        if final.isalpha() and 2 <= len(final) <= 24 and not mixed_token_label:
            return True
    return derived and candidate.casefold() in _MODULE_NAME_SHAPES


_SCHEME_TRAILING_PUNCTUATION = ".,;:=([{)]}>#!?'\"`"


def _normalize_scheme_candidate(token: str) -> str:
    candidate = _unquote(token).strip("\"'`")
    if candidate[:1] in "([{<\"'`":
        candidate = candidate[1:]
    return candidate.rstrip(_SCHEME_TRAILING_PUNCTUATION).casefold()


def _clean_credential_literal(token: str) -> str:
    if re.search(
        r"(?i)(?:%22|&quot;|&#0*34;|&#x0*22;|%27|&apos;|&#0*39;|&#x0*27;|[\"'])"
        + re.escape(REDACTED)
        + r"(?:%22|&quot;|&#0*34;|&#x0*22;|%27|&apos;|&#0*39;|&#x0*27;|[\"'])"
        + r"(?=$|[,;)}\] \t])",
        token,
    ):
        return REDACTED
    wrapped = token.strip()
    for _ in range(8):
        if _unquote(wrapped) == REDACTED:
            return REDACTED
        if not wrapped or wrapped[-1] not in ",.;:!?)]}":
            break
        wrapped = wrapped[:-1]
    unquoted = _unquote(token)
    marker_candidate = unquoted.lstrip("><=([{\"'`\u201c\u2018").rstrip(
        ".,;:)]}>!?\"'`\u201c\u201d\u2018\u2019"
    )
    if unquoted == REDACTED or (unquoted != "REDACTED" and marker_candidate == "REDACTED"):
        return REDACTED
    if unquoted.startswith(REDACTED) and all(
        char in ".,;:)]" for char in unquoted[len(REDACTED) :]
    ):
        return REDACTED
    if not unquoted or (
        unquoted[0] not in "\\><=([{\"'`\u201c\u2018"
        and unquoted[-1] not in "\\.,;:)]}>!?\"'`\u201c\u201d\u2018\u2019"
    ):
        return unquoted
    return unquoted.lstrip("\\><=([{\"'`\u201c\u2018").rstrip(
        "\\.,;:)]}>!?\"'`\u201c\u201d\u2018\u2019"
    )


@lru_cache(maxsize=4096)
def _credential_literal_candidates(token: str) -> set[str]:
    """Return a full token plus a bounded set of safe separator components."""
    cleaned = _clean_credential_literal(token)
    if not cleaned or cleaned == REDACTED:
        return set()
    candidates = {cleaned}
    if not _CREDENTIAL_COMPONENT_SEPARATOR_RE.search(cleaned) and "=" not in cleaned:
        return candidates
    split = _CREDENTIAL_COMPONENT_SEPARATOR_RE.split(re.sub(r"%[0-9a-fA-F]{2}", "&", cleaned))
    for part in split:
        component = _clean_credential_literal(part)
        components = [component]
        if "=" in component:
            _left, *right = component.split("=")
            components = right
        for component_candidate in components:
            candidate = _clean_credential_literal(component_candidate)
            if (
                len(candidate) >= 4
                and _looks_like_key_material(candidate)
                and not _is_hostname_or_module_like(candidate)
                and not _is_benign_shape(candidate)
                and not _is_parameter_identifier(candidate)
            ):
                candidates.add(candidate)
                if len(candidates) >= 8:
                    break
        if len(candidates) >= 8:
            break
    return candidates


_PARAMETER_IDENTIFIERS = frozenset(
    {
        "token_type",
        "expires_in",
        "session_id",
        "access_token",
        "refresh_token",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "region",
        "server",
        "bandwidthtest",
        "response_type",
        "grant_type",
        "code_challenge",
        "expires",
        "code_verifier",
        "client_secret",
        "redirect",
        "error_description",
    }
)


def _is_parameter_identifier(value: str) -> bool:
    if value.casefold() in _PARAMETER_IDENTIFIERS:
        return True
    if re.fullmatch(r"live_\d{5,}_[A-Za-z0-9]{10,}", value):
        return False
    if re.fullmatch(r"[a-z0-9]{4}(?:-[a-z0-9]{4}){3,4}", value):
        return False
    if (
        len(value) >= 12
        and any(char.isdigit() for char in value)
        and any(char.isalpha() for char in value)
    ):
        return False
    if any(char.isupper() for char in value) and any(char.isdigit() for char in value):
        return False
    return (
        bool(re.fullmatch(r"[a-z][a-z_]*(?:-[a-z]+)?(?:[_-][a-z]+){0,2}", value))
        and len(value) < 20
    )


def _is_benign_shape(value: str) -> bool:
    return bool(
        re.fullmatch(r"\d+(?:\.\d+)+(?:[-+][\w.]+)?", value)
        or re.fullmatch(r"[a-z]{2,3}(?:[-_][A-Za-z]{2,4})?", value, re.I)
        or re.fullmatch(r"[A-Za-z]+(?:/[A-Za-z_+-]+)+", value)
        or re.fullmatch(r"\d{1,7}", value)
        or re.fullmatch(r"\d{4}-\d\d-\d\d(?:[T ][\d:.+-]+Z?)?", value)
        or value.casefold() in {"true", "false", "null", "none", "undefined"}
        or _is_hostname_or_module_like(value)
    )


def _continuation_literal_is_promotable(text: str, start: int, end: int) -> bool:
    separators = "\r\n\u2028\u2029\u0085\x0b\x0c"
    line_start = max((text.rfind(char, 0, start) for char in separators), default=-1) + 1
    next_separator = _LINE_SEPARATOR_RE.search(text, end)
    line_end = next_separator.start() if next_separator is not None else len(text)
    before = text[line_start:start].strip()
    after = _clean_credential_literal(text[end:line_end])
    literal = _clean_credential_literal(text[start:end])
    scheme_prefix_only = all(_scheme_word(part) for part in before.split())
    return (
        scheme_prefix_only
        and not after
        and _looks_like_key_material(literal)
        and not re.fullmatch(r"\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?:?", literal)
        and "=" not in literal
        and "://" not in literal
        and literal not in _OBS_KEY_NAMES
        and not _is_rtmp_quality_or_resolution(literal)
    )


def _scheme_word(value: str) -> bool:
    return _normalize_scheme_candidate(value) in _SCHEME_NAMES


def _yaml_block_marker(value: str) -> bool:
    return bool(re.fullmatch(r"[|>][+-]?[0-9]?", value))


def resolve_credential_token(text: str, label_end: int) -> tuple[int, int] | None:  # noqa: PLR0911, PLR0912, PLR0915
    """Find the credential token following a sensitive label and optional schemes."""
    position = label_end
    skipped_scheme = False

    line_separators = "\r\n\u2028\u2029\u0085\x0b\x0c"

    def next_token(start: int) -> tuple[int, int] | None:
        cursor = start
        while cursor < len(text) and text[cursor] in " \t":
            cursor += 1
        while cursor < len(text) and text[cursor] in line_separators:
            if text.startswith("\r\n", cursor):
                cursor += 2
            else:
                cursor += 1
            line_start = cursor
            while cursor < len(text) and text[cursor] in " \t":
                cursor += 1
            if cursor < len(text) and text[cursor] in "\r\n":
                continue
            if cursor == line_start:
                next_separator = _LINE_SEPARATOR_RE.search(text, cursor)
                line_end = next_separator.start() if next_separator is not None else len(text)
                if any(char.isspace() for char in text[cursor:line_end]):
                    return None
            break
        if cursor >= len(text):
            return None
        end = cursor
        while end < len(text) and not text[end].isspace():
            end += 1
        if end == cursor:
            return None
        return cursor, end

    token = next_token(position)
    if token is None:
        return None
    start, end = token
    # YAML block markers are empty same-line values. The block's first indented
    # content line is resolved by the same continuation rule.
    if _yaml_block_marker(text[start:end]):
        token = next_token(end)
        if token is None:
            return None
        start, end = token
    candidate = text[start:end]
    next_label = candidate[:-1] if candidate.endswith((":", "=")) else ""
    if next_label and _is_sensitive_key(next_label):
        if not _scheme_word(candidate):
            return None
        has_line_break = any(char in text[position:start] for char in line_separators)
        if has_line_break:
            following = next_token(end)
            if following is None:
                return None
            following_candidate = text[following[0] : following[1]]
            following_label = (
                following_candidate[:-1] if following_candidate.endswith((":", "=")) else ""
            )
            if following_label and _is_sensitive_key(following_label):
                return None
    skipped_schemes = 0
    while _scheme_word(text[start:end]) and skipped_schemes < 4:
        skipped_scheme = True
        skipped_schemes += 1
        token = next_token(end)
        if token is None:
            return None
        start, end = token
    if skipped_scheme:
        if end > start + 1 and text[start] in "\"'`" and text[end - 1] == text[start]:
            start += 1
            end -= 1
        elif end > start and text[end - 1] in "\"'`":
            end -= 1
    return (start, end) if not skipped_scheme or start < end else None


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


def _looks_like_rtmp_in_place(value: str) -> bool:
    if value.casefold() in _RTMP_APPLICATION_NAMES:
        return False
    return (len(value) >= 4 and any(not char.isalpha() for char in value)) or (
        value.isalpha() and len(value) >= 8
    )


def _looks_like_rtmp_harvest(value: str) -> bool:
    if value.casefold() in _RTMP_APPLICATION_NAMES:
        return False
    if _is_rtmp_quality_or_resolution(value):
        return False
    return (
        len(value) >= 16
        or (any(char.isdigit() for char in value) and any(char.isalpha() for char in value))
        or bool(re.fullmatch(r"(?i)[a-f]{8,}", value))
    )


def _is_rtmp_quality_or_resolution(value: str) -> bool:
    return bool(re.fullmatch(r"(?i)(?:\d{3,4}[pi]\d{0,3}|\d{2,4}x\d{2,4})", value))


def _rtmp_harvest_spans(text: str) -> list[tuple[int, int]]:
    """Find key-like RTMP path segments suitable for cross-file scanning."""
    spans: list[tuple[int, int]] = []
    for url in _RTMP_URL.finditer(text):
        scheme_end = url.start() + url.group(0).find("://") + 3
        slash = text.find("/", scheme_end, url.end())
        if slash < 0:
            continue
        path_end = min(
            (
                position
                for marker in ("?", "#")
                if (position := text.find(marker, slash, url.end())) >= 0
            ),
            default=url.end(),
        )
        cursor = slash + 1
        for segment in text[cursor:path_end].split("/"):
            segment_start = cursor
            clean = _rtmp_key(segment)
            if clean and _looks_like_rtmp_harvest(clean):
                spans.append((segment_start, segment_start + len(clean)))
            cursor += len(segment) + 1
    return spans


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
    return (
        key.endswith("Key")
        and re.sub(r"[^a-z0-9]", "", key.casefold()) != "key"
        and not _is_explicit_camel_key(key)
    )


def _hotkey_key_exempt(  # noqa: PLR0911
    key: str, context: tuple[str, ...], value: Any
) -> bool:
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
    if value == "":
        return True
    if not isinstance(value, str):
        return False
    return _is_obs_key_enum(value)


# Identifier names from OBS_HOTKEY and OBS_MOUSE_BUTTON entries in
# obsproject/obs-studio libobs/obs-hotkeys.h.
_OBS_KEY_NAMES = frozenset(
    {
        "OBS_KEY_0",
        "OBS_KEY_1",
        "OBS_KEY_2",
        "OBS_KEY_3",
        "OBS_KEY_4",
        "OBS_KEY_5",
        "OBS_KEY_6",
        "OBS_KEY_7",
        "OBS_KEY_8",
        "OBS_KEY_9",
        "OBS_KEY_A",
        "OBS_KEY_AACUTE",
        "OBS_KEY_ACIRCUMFLEX",
        "OBS_KEY_ACUTE",
        "OBS_KEY_ADDFAVORITE",
        "OBS_KEY_ADIAERESIS",
        "OBS_KEY_AE",
        "OBS_KEY_AGRAVE",
        "OBS_KEY_ALT",
        "OBS_KEY_ALTGR",
        "OBS_KEY_AMPERSAND",
        "OBS_KEY_APOSTROPHE",
        "OBS_KEY_APPLICATIONLEFT",
        "OBS_KEY_APPLICATIONRIGHT",
        "OBS_KEY_ARING",
        "OBS_KEY_ASCIICIRCUM",
        "OBS_KEY_ASCIITILDE",
        "OBS_KEY_ASTERISK",
        "OBS_KEY_AT",
        "OBS_KEY_ATILDE",
        "OBS_KEY_AUDIOCYCLETRACK",
        "OBS_KEY_AUDIOFORWARD",
        "OBS_KEY_AUDIORANDOMPLAY",
        "OBS_KEY_AUDIOREPEAT",
        "OBS_KEY_AUDIOREWIND",
        "OBS_KEY_AWAY",
        "OBS_KEY_B",
        "OBS_KEY_BACK",
        "OBS_KEY_BACKFORWARD",
        "OBS_KEY_BACKSLASH",
        "OBS_KEY_BACKSLASH_RT102",
        "OBS_KEY_BACKSPACE",
        "OBS_KEY_BACKTAB",
        "OBS_KEY_BAR",
        "OBS_KEY_BASSBOOST",
        "OBS_KEY_BASSDOWN",
        "OBS_KEY_BASSUP",
        "OBS_KEY_BATTERY",
        "OBS_KEY_BLUETOOTH",
        "OBS_KEY_BOOK",
        "OBS_KEY_BRACELEFT",
        "OBS_KEY_BRACERIGHT",
        "OBS_KEY_BRACKETLEFT",
        "OBS_KEY_BRACKETRIGHT",
        "OBS_KEY_BRIGHTNESSADJUST",
        "OBS_KEY_BROKENBAR",
        "OBS_KEY_C",
        "OBS_KEY_CALCULATOR",
        "OBS_KEY_CALENDAR",
        "OBS_KEY_CALL",
        "OBS_KEY_CAMERA",
        "OBS_KEY_CAMERAFOCUS",
        "OBS_KEY_CANCEL",
        "OBS_KEY_CAPSLOCK",
        "OBS_KEY_CCEDILLA",
        "OBS_KEY_CD",
        "OBS_KEY_CEDILLA",
        "OBS_KEY_CENT",
        "OBS_KEY_CLEAR",
        "OBS_KEY_CLEARGRAB",
        "OBS_KEY_CLOSE",
        "OBS_KEY_CODEINPUT",
        "OBS_KEY_COLON",
        "OBS_KEY_COMMA",
        "OBS_KEY_COMMUNITY",
        "OBS_KEY_CONTEXT1",
        "OBS_KEY_CONTEXT2",
        "OBS_KEY_CONTEXT3",
        "OBS_KEY_CONTEXT4",
        "OBS_KEY_CONTRASTADJUST",
        "OBS_KEY_CONTROL",
        "OBS_KEY_COPY",
        "OBS_KEY_COPYRIGHT",
        "OBS_KEY_CURRENCY",
        "OBS_KEY_CUT",
        "OBS_KEY_D",
        "OBS_KEY_DEAD_ABOVEDOT",
        "OBS_KEY_DEAD_ABOVERING",
        "OBS_KEY_DEAD_ACUTE",
        "OBS_KEY_DEAD_BELOWDOT",
        "OBS_KEY_DEAD_BREVE",
        "OBS_KEY_DEAD_CARON",
        "OBS_KEY_DEAD_CEDILLA",
        "OBS_KEY_DEAD_CIRCUMFLEX",
        "OBS_KEY_DEAD_DIAERESIS",
        "OBS_KEY_DEAD_DOUBLEACUTE",
        "OBS_KEY_DEAD_GRAVE",
        "OBS_KEY_DEAD_HOOK",
        "OBS_KEY_DEAD_HORN",
        "OBS_KEY_DEAD_IOTA",
        "OBS_KEY_DEAD_MACRON",
        "OBS_KEY_DEAD_OGONEK",
        "OBS_KEY_DEAD_SEMIVOICED_SOUND",
        "OBS_KEY_DEAD_TILDE",
        "OBS_KEY_DEAD_VOICED_SOUND",
        "OBS_KEY_DEGREE",
        "OBS_KEY_DELETE",
        "OBS_KEY_DIAERESIS",
        "OBS_KEY_DIRECTION_L",
        "OBS_KEY_DIRECTION_R",
        "OBS_KEY_DISPLAY",
        "OBS_KEY_DIVISION",
        "OBS_KEY_DOCUMENTS",
        "OBS_KEY_DOLLAR",
        "OBS_KEY_DOS",
        "OBS_KEY_DOWN",
        "OBS_KEY_E",
        "OBS_KEY_EACUTE",
        "OBS_KEY_ECIRCUMFLEX",
        "OBS_KEY_EDIAERESIS",
        "OBS_KEY_EGRAVE",
        "OBS_KEY_EISU_SHIFT",
        "OBS_KEY_EISU_TOGGLE",
        "OBS_KEY_EJECT",
        "OBS_KEY_END",
        "OBS_KEY_ENTER",
        "OBS_KEY_EQUAL",
        "OBS_KEY_ESCAPE",
        "OBS_KEY_ETH",
        "OBS_KEY_EXCEL",
        "OBS_KEY_EXCLAM",
        "OBS_KEY_EXCLAMDOWN",
        "OBS_KEY_EXECUTE",
        "OBS_KEY_EXPLORER",
        "OBS_KEY_F",
        "OBS_KEY_F1",
        "OBS_KEY_F10",
        "OBS_KEY_F11",
        "OBS_KEY_F12",
        "OBS_KEY_F13",
        "OBS_KEY_F14",
        "OBS_KEY_F15",
        "OBS_KEY_F16",
        "OBS_KEY_F17",
        "OBS_KEY_F18",
        "OBS_KEY_F19",
        "OBS_KEY_F2",
        "OBS_KEY_F20",
        "OBS_KEY_F21",
        "OBS_KEY_F22",
        "OBS_KEY_F23",
        "OBS_KEY_F24",
        "OBS_KEY_F25",
        "OBS_KEY_F26",
        "OBS_KEY_F27",
        "OBS_KEY_F28",
        "OBS_KEY_F29",
        "OBS_KEY_F3",
        "OBS_KEY_F30",
        "OBS_KEY_F31",
        "OBS_KEY_F32",
        "OBS_KEY_F33",
        "OBS_KEY_F34",
        "OBS_KEY_F35",
        "OBS_KEY_F4",
        "OBS_KEY_F5",
        "OBS_KEY_F6",
        "OBS_KEY_F7",
        "OBS_KEY_F8",
        "OBS_KEY_F9",
        "OBS_KEY_FAVORITES",
        "OBS_KEY_FINANCE",
        "OBS_KEY_FIND",
        "OBS_KEY_FLIP",
        "OBS_KEY_FORWARD",
        "OBS_KEY_FRONT",
        "OBS_KEY_G",
        "OBS_KEY_GAME",
        "OBS_KEY_GO",
        "OBS_KEY_GREATER",
        "OBS_KEY_GUILLEMOTLEFT",
        "OBS_KEY_GUILLEMOTRIGHT",
        "OBS_KEY_H",
        "OBS_KEY_HANGUL",
        "OBS_KEY_HANGUL_BANJA",
        "OBS_KEY_HANGUL_END",
        "OBS_KEY_HANGUL_HANJA",
        "OBS_KEY_HANGUL_JAMO",
        "OBS_KEY_HANGUL_JEONJA",
        "OBS_KEY_HANGUL_POSTHANJA",
        "OBS_KEY_HANGUL_PREHANJA",
        "OBS_KEY_HANGUL_ROMAJA",
        "OBS_KEY_HANGUL_SPECIAL",
        "OBS_KEY_HANGUL_START",
        "OBS_KEY_HANGUP",
        "OBS_KEY_HANKAKU",
        "OBS_KEY_HELP",
        "OBS_KEY_HENKAN",
        "OBS_KEY_HIBERNATE",
        "OBS_KEY_HIRAGANA",
        "OBS_KEY_HIRAGANA_KATAKANA",
        "OBS_KEY_HISTORY",
        "OBS_KEY_HOME",
        "OBS_KEY_HOMEPAGE",
        "OBS_KEY_HOTLINKS",
        "OBS_KEY_HYPER_L",
        "OBS_KEY_HYPER_R",
        "OBS_KEY_HYPHEN",
        "OBS_KEY_I",
        "OBS_KEY_IACUTE",
        "OBS_KEY_ICIRCUMFLEX",
        "OBS_KEY_IDIAERESIS",
        "OBS_KEY_IGRAVE",
        "OBS_KEY_INSERT",
        "OBS_KEY_ITOUCH",
        "OBS_KEY_J",
        "OBS_KEY_K",
        "OBS_KEY_KANA_LOCK",
        "OBS_KEY_KANA_SHIFT",
        "OBS_KEY_KANJI",
        "OBS_KEY_KATAKANA",
        "OBS_KEY_KEYBOARDBRIGHTNESSDOWN",
        "OBS_KEY_KEYBOARDBRIGHTNESSUP",
        "OBS_KEY_KEYBOARDLIGHTONOFF",
        "OBS_KEY_L",
        "OBS_KEY_LASTNUMBERREDIAL",
        "OBS_KEY_LAUNCH0",
        "OBS_KEY_LAUNCH1",
        "OBS_KEY_LAUNCH2",
        "OBS_KEY_LAUNCH3",
        "OBS_KEY_LAUNCH4",
        "OBS_KEY_LAUNCH5",
        "OBS_KEY_LAUNCH6",
        "OBS_KEY_LAUNCH7",
        "OBS_KEY_LAUNCH8",
        "OBS_KEY_LAUNCH9",
        "OBS_KEY_LAUNCHA",
        "OBS_KEY_LAUNCHB",
        "OBS_KEY_LAUNCHC",
        "OBS_KEY_LAUNCHD",
        "OBS_KEY_LAUNCHE",
        "OBS_KEY_LAUNCHF",
        "OBS_KEY_LAUNCHG",
        "OBS_KEY_LAUNCHH",
        "OBS_KEY_LAUNCHMAIL",
        "OBS_KEY_LAUNCHMEDIA",
        "OBS_KEY_LEFT",
        "OBS_KEY_LESS",
        "OBS_KEY_LIGHTBULB",
        "OBS_KEY_LOGOFF",
        "OBS_KEY_M",
        "OBS_KEY_MACRON",
        "OBS_KEY_MAILFORWARD",
        "OBS_KEY_MARKET",
        "OBS_KEY_MASCULINE",
        "OBS_KEY_MASSYO",
        "OBS_KEY_MEDIALAST",
        "OBS_KEY_MEDIANEXT",
        "OBS_KEY_MEDIAPAUSE",
        "OBS_KEY_MEDIAPLAY",
        "OBS_KEY_MEDIAPREVIOUS",
        "OBS_KEY_MEDIARECORD",
        "OBS_KEY_MEDIASTOP",
        "OBS_KEY_MEDIATOGGLEPLAYPAUSE",
        "OBS_KEY_MEETING",
        "OBS_KEY_MEMO",
        "OBS_KEY_MENU",
        "OBS_KEY_MENUKB",
        "OBS_KEY_MENUPB",
        "OBS_KEY_MESSENGER",
        "OBS_KEY_META",
        "OBS_KEY_MINUS",
        "OBS_KEY_MODE_SWITCH",
        "OBS_KEY_MONBRIGHTNESSDOWN",
        "OBS_KEY_MONBRIGHTNESSUP",
        "OBS_KEY_MOUSE1",
        "OBS_KEY_MOUSE10",
        "OBS_KEY_MOUSE11",
        "OBS_KEY_MOUSE12",
        "OBS_KEY_MOUSE13",
        "OBS_KEY_MOUSE14",
        "OBS_KEY_MOUSE15",
        "OBS_KEY_MOUSE16",
        "OBS_KEY_MOUSE17",
        "OBS_KEY_MOUSE18",
        "OBS_KEY_MOUSE19",
        "OBS_KEY_MOUSE2",
        "OBS_KEY_MOUSE20",
        "OBS_KEY_MOUSE21",
        "OBS_KEY_MOUSE22",
        "OBS_KEY_MOUSE23",
        "OBS_KEY_MOUSE24",
        "OBS_KEY_MOUSE25",
        "OBS_KEY_MOUSE26",
        "OBS_KEY_MOUSE27",
        "OBS_KEY_MOUSE28",
        "OBS_KEY_MOUSE29",
        "OBS_KEY_MOUSE3",
        "OBS_KEY_MOUSE4",
        "OBS_KEY_MOUSE5",
        "OBS_KEY_MOUSE6",
        "OBS_KEY_MOUSE7",
        "OBS_KEY_MOUSE8",
        "OBS_KEY_MOUSE9",
        "OBS_KEY_MU",
        "OBS_KEY_MUHENKAN",
        "OBS_KEY_MULTIPLECANDIDATE",
        "OBS_KEY_MULTIPLY",
        "OBS_KEY_MULTI_KEY",
        "OBS_KEY_MUSIC",
        "OBS_KEY_MYSITES",
        "OBS_KEY_N",
        "OBS_KEY_NEWS",
        "OBS_KEY_NO",
        "OBS_KEY_NOBREAKSPACE",
        "OBS_KEY_NONE",
        "OBS_KEY_NOTSIGN",
        "OBS_KEY_NTILDE",
        "OBS_KEY_NUM0",
        "OBS_KEY_NUM1",
        "OBS_KEY_NUM2",
        "OBS_KEY_NUM3",
        "OBS_KEY_NUM4",
        "OBS_KEY_NUM5",
        "OBS_KEY_NUM6",
        "OBS_KEY_NUM7",
        "OBS_KEY_NUM8",
        "OBS_KEY_NUM9",
        "OBS_KEY_NUMASTERISK",
        "OBS_KEY_NUMBERSIGN",
        "OBS_KEY_NUMCOMMA",
        "OBS_KEY_NUMEQUAL",
        "OBS_KEY_NUMLOCK",
        "OBS_KEY_NUMMINUS",
        "OBS_KEY_NUMPERIOD",
        "OBS_KEY_NUMPLUS",
        "OBS_KEY_NUMSLASH",
        "OBS_KEY_O",
        "OBS_KEY_OACUTE",
        "OBS_KEY_OCIRCUMFLEX",
        "OBS_KEY_ODIAERESIS",
        "OBS_KEY_OFFICEHOME",
        "OBS_KEY_OGRAVE",
        "OBS_KEY_ONEHALF",
        "OBS_KEY_ONEQUARTER",
        "OBS_KEY_ONESUPERIOR",
        "OBS_KEY_OOBLIQUE",
        "OBS_KEY_OPEN",
        "OBS_KEY_OPENURL",
        "OBS_KEY_OPTION",
        "OBS_KEY_ORDFEMININE",
        "OBS_KEY_OTILDE",
        "OBS_KEY_P",
        "OBS_KEY_PAGEDOWN",
        "OBS_KEY_PAGEUP",
        "OBS_KEY_PARAGRAPH",
        "OBS_KEY_PARENLEFT",
        "OBS_KEY_PARENRIGHT",
        "OBS_KEY_PASTE",
        "OBS_KEY_PAUSE",
        "OBS_KEY_PERCENT",
        "OBS_KEY_PERIOD",
        "OBS_KEY_PERIODCENTERED",
        "OBS_KEY_PHONE",
        "OBS_KEY_PICTURES",
        "OBS_KEY_PLAY",
        "OBS_KEY_PLUS",
        "OBS_KEY_PLUSMINUS",
        "OBS_KEY_POWERDOWN",
        "OBS_KEY_POWEROFF",
        "OBS_KEY_PREVIOUSCANDIDATE",
        "OBS_KEY_PRINT",
        "OBS_KEY_PRINTER",
        "OBS_KEY_PROPS",
        "OBS_KEY_Q",
        "OBS_KEY_QUESTION",
        "OBS_KEY_QUESTIONDOWN",
        "OBS_KEY_QUOTE",
        "OBS_KEY_QUOTEDBL",
        "OBS_KEY_QUOTELEFT",
        "OBS_KEY_R",
        "OBS_KEY_REDO",
        "OBS_KEY_REFRESH",
        "OBS_KEY_REGISTERED",
        "OBS_KEY_RELOAD",
        "OBS_KEY_REPLY",
        "OBS_KEY_RETURN",
        "OBS_KEY_RIGHT",
        "OBS_KEY_ROMAJI",
        "OBS_KEY_ROTATEWINDOWS",
        "OBS_KEY_ROTATIONKB",
        "OBS_KEY_ROTATIONPB",
        "OBS_KEY_S",
        "OBS_KEY_SAVE",
        "OBS_KEY_SCREENSAVER",
        "OBS_KEY_SCROLLLOCK",
        "OBS_KEY_SEARCH",
        "OBS_KEY_SECTION",
        "OBS_KEY_SELECT",
        "OBS_KEY_SEMICOLON",
        "OBS_KEY_SEND",
        "OBS_KEY_SHIFT",
        "OBS_KEY_SHOP",
        "OBS_KEY_SINGLECANDIDATE",
        "OBS_KEY_SLASH",
        "OBS_KEY_SLEEP",
        "OBS_KEY_SPACE",
        "OBS_KEY_SPELL",
        "OBS_KEY_SPLITSCREEN",
        "OBS_KEY_SSHARP",
        "OBS_KEY_STANDBY",
        "OBS_KEY_STERLING",
        "OBS_KEY_STOP",
        "OBS_KEY_SUBTITLE",
        "OBS_KEY_SUPPORT",
        "OBS_KEY_SUSPEND",
        "OBS_KEY_SYSREQ",
        "OBS_KEY_T",
        "OBS_KEY_TAB",
        "OBS_KEY_TASKPANE",
        "OBS_KEY_TERMINAL",
        "OBS_KEY_THORN",
        "OBS_KEY_THREEQUARTERS",
        "OBS_KEY_THREESUPERIOR",
        "OBS_KEY_TIME",
        "OBS_KEY_TODOLIST",
        "OBS_KEY_TOGGLECALLHANGUP",
        "OBS_KEY_TOOLS",
        "OBS_KEY_TOPMENU",
        "OBS_KEY_TOUROKU",
        "OBS_KEY_TRAVEL",
        "OBS_KEY_TREBLEDOWN",
        "OBS_KEY_TREBLEUP",
        "OBS_KEY_TWOSUPERIOR",
        "OBS_KEY_U",
        "OBS_KEY_UACUTE",
        "OBS_KEY_UCIRCUMFLEX",
        "OBS_KEY_UDIAERESIS",
        "OBS_KEY_UGRAVE",
        "OBS_KEY_UNDERSCORE",
        "OBS_KEY_UNDO",
        "OBS_KEY_UP",
        "OBS_KEY_UWB",
        "OBS_KEY_V",
        "OBS_KEY_VIDEO",
        "OBS_KEY_VIEW",
        "OBS_KEY_VK_ACCEPT",
        "OBS_KEY_VK_APPS",
        "OBS_KEY_VK_ATTN",
        "OBS_KEY_VK_BROWSER_BACK",
        "OBS_KEY_VK_BROWSER_FAVORITES",
        "OBS_KEY_VK_BROWSER_FORWARD",
        "OBS_KEY_VK_BROWSER_HOME",
        "OBS_KEY_VK_BROWSER_REFRESH",
        "OBS_KEY_VK_BROWSER_SEARCH",
        "OBS_KEY_VK_BROWSER_STOP",
        "OBS_KEY_VK_CANCEL",
        "OBS_KEY_VK_CRSEL",
        "OBS_KEY_VK_EREOF",
        "OBS_KEY_VK_EXECUTE",
        "OBS_KEY_VK_EXSEL",
        "OBS_KEY_VK_FINAL",
        "OBS_KEY_VK_HELP",
        "OBS_KEY_VK_ICO_00",
        "OBS_KEY_VK_ICO_CLEAR",
        "OBS_KEY_VK_ICO_HELP",
        "OBS_KEY_VK_JUNJA",
        "OBS_KEY_VK_LAUNCH_APP1",
        "OBS_KEY_VK_LAUNCH_APP2",
        "OBS_KEY_VK_LAUNCH_MAIL",
        "OBS_KEY_VK_LAUNCH_MEDIA_SELECT",
        "OBS_KEY_VK_LCONTROL",
        "OBS_KEY_VK_LMENU",
        "OBS_KEY_VK_LSHIFT",
        "OBS_KEY_VK_LWIN",
        "OBS_KEY_VK_MEDIA_NEXT_TRACK",
        "OBS_KEY_VK_MEDIA_PLAY_PAUSE",
        "OBS_KEY_VK_MEDIA_PREV_TRACK",
        "OBS_KEY_VK_MEDIA_STOP",
        "OBS_KEY_VK_MODECHANGE",
        "OBS_KEY_VK_NONAME",
        "OBS_KEY_VK_OEM_8",
        "OBS_KEY_VK_OEM_ATTN",
        "OBS_KEY_VK_OEM_AUTO",
        "OBS_KEY_VK_OEM_AX",
        "OBS_KEY_VK_OEM_CLEAR",
        "OBS_KEY_VK_OEM_COPY",
        "OBS_KEY_VK_OEM_CUSEL",
        "OBS_KEY_VK_OEM_ENLW",
        "OBS_KEY_VK_OEM_FINISH",
        "OBS_KEY_VK_OEM_FJ_JISHO",
        "OBS_KEY_VK_OEM_FJ_LOYA",
        "OBS_KEY_VK_OEM_FJ_ROYA",
        "OBS_KEY_VK_OEM_JUMP",
        "OBS_KEY_VK_OEM_PA1",
        "OBS_KEY_VK_OEM_PA2",
        "OBS_KEY_VK_OEM_PA3",
        "OBS_KEY_VK_OEM_RESET",
        "OBS_KEY_VK_OEM_WSCTRL",
        "OBS_KEY_VK_PA1",
        "OBS_KEY_VK_PACKET",
        "OBS_KEY_VK_PLAY",
        "OBS_KEY_VK_PRINT",
        "OBS_KEY_VK_PROCESSKEY",
        "OBS_KEY_VK_RCONTROL",
        "OBS_KEY_VK_RMENU",
        "OBS_KEY_VK_RSHIFT",
        "OBS_KEY_VK_RWIN",
        "OBS_KEY_VK_SELECT",
        "OBS_KEY_VK_SEPARATOR",
        "OBS_KEY_VK_SLEEP",
        "OBS_KEY_VK_VOLUME_DOWN",
        "OBS_KEY_VK_VOLUME_MUTE",
        "OBS_KEY_VK_VOLUME_UP",
        "OBS_KEY_VK_ZOOM",
        "OBS_KEY_VOICEDIAL",
        "OBS_KEY_VOLUMEDOWN",
        "OBS_KEY_VOLUMEMUTE",
        "OBS_KEY_VOLUMEUP",
        "OBS_KEY_W",
        "OBS_KEY_WAKEUP",
        "OBS_KEY_WEBCAM",
        "OBS_KEY_WLAN",
        "OBS_KEY_WORD",
        "OBS_KEY_WWW",
        "OBS_KEY_X",
        "OBS_KEY_XFER",
        "OBS_KEY_Y",
        "OBS_KEY_YACUTE",
        "OBS_KEY_YDIAERESIS",
        "OBS_KEY_YEN",
        "OBS_KEY_YES",
        "OBS_KEY_Z",
        "OBS_KEY_ZENKAKU",
        "OBS_KEY_ZENKAKU_HANKAKU",
        "OBS_KEY_ZOOM",
        "OBS_KEY_ZOOMIN",
        "OBS_KEY_ZOOMOUT",
    }
)


class CredentialSecrets(set[str]):
    """Collected credential literals with their weaker matching provenance."""

    def __init__(self, values: set[str], weak: set[str], strong: set[str] | None = None) -> None:
        super().__init__(values)
        self.weak = weak
        self.strong = strong if strong is not None else values - weak


def _strong_credential_values(value: Any, context: tuple[str, ...] = ()) -> set[str]:
    """Collect literals that came from explicit credential fields or assignments."""
    values: set[str] = set()
    if isinstance(value, dict):
        pair = _header_pair_keys(value)
        if pair is not None:
            for pair_value_key in _header_pair_value_keys(value, pair[0]):
                values.update(_credential_literals(value[pair_value_key]))
        for key, child in value.items():
            if pair is not None and key == pair[0]:
                continue
            child_context = context + ((key,) if isinstance(key, str) else ())
            if isinstance(key, str) and _is_sensitive_key(key, context, child):
                if not _is_weak_camel_key(key):
                    values.update(_credential_literals(child))
            else:
                values.update(_strong_credential_values(child, child_context))
    elif isinstance(value, list):
        for child in value:
            values.update(_strong_credential_values(child, context))
    elif isinstance(value, str):
        values.update(_strong_embedded_secrets(value))
    return {literal for literal in values if not _never_promote_literal(literal)}


def _weak_credential_values(value: Any) -> set[str]:
    weak: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                isinstance(key, str)
                and _is_weak_camel_key(key)
                and _is_sensitive_key(key, value=child)
            ):
                for literal in _credential_literals(child):
                    if _looks_like_key_material(literal):
                        weak.add(literal)
            weak.update(_weak_credential_values(child))
    elif isinstance(value, list):
        for child in value:
            weak.update(_weak_credential_values(child))
    elif isinstance(value, str):
        weak.update(
            literal
            for start, end in _rtmp_harvest_spans(value)
            for literal in _credential_literal_candidates(value[start:end])
            if _looks_like_rtmp_harvest(literal)
        )
    return weak


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
    if _is_weak_camel_key(key) and not _looks_like_key_material(
        value if isinstance(value, str) else ""
    ):
        return False
    if normalized == "key":
        if context and context[-1] == "__obsbasic_hotkey_binding__":
            return not _hotkey_key_exempt(key, context, value)
        return not _hotkey_key_exempt(key, context, value)
    if normalized in _CREDENTIAL_NAMES or normalized in {
        "setcookie",
        "setcookie2",
        "cookie2",
        "pass",
        "oauth",
        "bearer",
        "auth",
        "wspass",
        "authcode",
        "refresh",
    }:
        return True
    if normalized in {
        "authorization",
        "authentication",
        "wwwauthenticate",
        "proxyauthenticate",
    } or ("-" in key and normalized.endswith("authorization")):
        return True
    if context and context[-1] == "__url_query__" and normalized in {"auth", "sig"}:
        return True
    # Credential suffixes apply regardless of lowercase compound prefixes.
    if normalized.endswith(("password", "passwd", "secret", "token", "oauth", "jwt")):
        return True
    if normalized.endswith("pw") and (
        len(normalized) == 2 or re.search(r"[_-]pw$", key, re.I) or re.search(r"[a-z]Pw$", key)
    ):
        return True
    if normalized.endswith("pass") and (
        len(normalized) == 4 or re.search(r"[_-]pass$", key, re.I) or re.search(r"[a-z]Pass$", key)
    ):
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
        ("\u201c", "\u201d"),
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
        ("\u201c", "\u201d"),
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


def _sub_overlapping_assignments(text: str, replace: Any) -> str:  # noqa: PLR0912
    """Replace credential assignments even when they start inside another value."""
    pattern = _LOG_PATTERNS[0]
    fragments = _json_fragments(text)
    if fragments:
        full_scan = _mask_urls(text)
        covered = [
            (match.start(1), match.end(2))
            for match in pattern.finditer(full_scan)
            if _is_sensitive_key(_log_match_key(match), value=_unquote(match.group(2)))
        ]
        filtered_fragments: list[tuple[int, int, Any, tuple[str, ...]]] = []
        covered_index = 0
        furthest_covered_end = -1
        for fragment in fragments:
            while covered_index < len(covered) and covered[covered_index][0] < fragment[0]:
                furthest_covered_end = max(furthest_covered_end, covered[covered_index][1])
                covered_index += 1
            if furthest_covered_end <= fragment[1]:
                filtered_fragments.append(fragment)
        fragments = filtered_fragments
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
        tail = value[len(REDACTED) :]
        if re.fullmatch(r"[<>\"'`.,;:!?)]}]*", tail):
            return REDACTED, tail
        next_parameter = re.search(r"[&;](?=[A-Za-z0-9_.-]+=)", tail)
        if next_parameter:
            return REDACTED, tail[next_parameter.start() :]
        return REDACTED, tail
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
    delimiter = re.search(r"[<>\"'`]", value)
    if delimiter:
        cursor = delimiter.start()
        while cursor < len(value):
            if value[cursor] in "<>\"'`" and re.fullmatch(r"[<>\"'`.,;:!?)]}]*", value[cursor:]):
                following = value[cursor:] + following
                value = value[:cursor]
                break
            cursor += 1
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
        or bool(re.fullmatch(r"[<>\"'`.,;:!?)]}]*", following))
    )


def _query_value_line_tail(text: str, end: int) -> str:
    boundaries = [
        position for position in (text.find("\n", end), text.find("\r", end)) if position >= 0
    ]
    line_end = min(boundaries) if boundaries else len(text)
    return text[end:line_end]


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
    token = resolve_credential_token(match.string, match.start(2))
    if token is None or token[0] == match.start(2):
        return False
    prefix = match.string[match.start(2) : token[0]]
    return any(_scheme_word(part) for part in re.findall(r"[^\s]+", prefix)) and (
        _clean_credential_literal(_before_named_parameter(match.string[token[0] : token[1]]))
        == REDACTED
    )


def _authorization_scheme(match: re.Match[str]) -> bool:
    if match.re is _LOG_PATTERNS[-1]:
        scheme = _normalize_scheme_candidate(match.group(1).split()[-1])
    else:
        pieces = _unquote(match.group(2)).split(None, 1)
        scheme = _normalize_scheme_candidate(pieces[0]) if pieces else ""
    return scheme in _SCHEME_NAMES


def _scheme_prefixed_value_is_redacted(match: re.Match[str]) -> bool:
    """Recognize a preserved scheme followed by a redacted credential token."""
    token = resolve_credential_token(match.string, match.start(2))
    if token is None or token[0] == match.start(2):
        return False
    start, end = token
    return _clean_credential_literal(_before_named_parameter(match.string[start:end])) == REDACTED


def _resolved_value_has_scheme(match: re.Match[str]) -> bool:
    token = resolve_credential_token(match.string, match.start(2))
    if token is None or token[0] == match.start(2):
        return False
    return any(
        _scheme_word(part)
        for part in re.findall(r"[^\s]+", match.string[match.start(2) : token[0]])
    )


def _redact_authorization_remainders(  # noqa: PLR0912, PLR0915
    text: str, counts: dict[str, int]
) -> str:
    header = re.compile(
        r"(?i)(?<![\w.-])(?:[A-Za-z0-9_.]+-)*(?:authorization|authentication)"
        r"[\"']?[ \t]*[=:][ \t]*([\"'`]?)"
    )
    replacements: list[tuple[int, int, str]] = []
    lines = list(re.finditer(r"[^\r\n]*(?:\r?\n|\r|$)", text))
    for line_index, line in enumerate(lines):
        body = line.group(0).rstrip("\r\n")
        line_start, line_end = line.start(), line.start() + len(body)
        covered_end = line_start
        for match in header.finditer(body):
            start = line_start + match.start()
            if start < covered_end:
                continue
            value_start = line_start + match.end()
            value = text[value_start:line_end]
            if _yaml_block_marker(value.strip()):
                continue
            resolved = resolve_credential_token(text, value_start)
            if resolved is not None and resolved[0] > value_start:
                token_start, token_end = resolved
                prefix = text[value_start:token_start]
                if (
                    any(_scheme_word(part) for part in re.findall(r"[^\s]+", prefix))
                    and _clean_credential_literal(text[token_start:token_end]) == REDACTED
                ):
                    tail = text[token_end:line_end]
                    if tail.strip(" \t\"'`)}],.;"):
                        replacements.append((token_end, line_end, ""))
                    covered_end = line_end
                    continue
            leading = len(value) - len(value.lstrip())
            stripped = value.strip()
            if not stripped:
                following_index = line_index + 1
                while following_index < len(lines):
                    following = lines[following_index]
                    next_body = following.group(0).rstrip("\r\n")
                    if next_body.strip():
                        next_value = next_body.strip()
                        if next_body[: len(next_body) - len(next_body.lstrip())] or not re.search(
                            r"\s", next_value
                        ):
                            replacements.append(
                                (following.start(), following.start() + len(next_body), REDACTED)
                            )
                        break
                    following_index += 1
                continue
            if stripped == REDACTED:
                continue
            opening_consumed = bool(match.group(1))
            quote_char = match.group(1) or (stripped[0] if stripped[0] in "\"'`" else "")
            quoted_end = -1
            if quote_char:
                escaped = False
                quote_content_start = value_start + leading + (0 if opening_consumed else 1)
                for pos in range(quote_content_start, line_end):
                    char = text[pos]
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == quote_char:
                        quoted_end = pos
                        break
            if quote_char and quoted_end >= 0:
                inside_start = value_start + leading + (0 if opening_consumed else 1)
                inside = text[inside_start:quoted_end]
                after_start = quoted_end + 1
                tail = text[after_start:line_end].strip()
                inside_parts = inside.split(None, 1)
                if (
                    inside_parts
                    and _normalize_scheme_candidate(inside_parts[0]) in _SCHEME_NAMES
                    and not inside_parts[1:]
                    and tail
                ):
                    replacement = value[:leading] + inside + quote_char + " " + REDACTED
                    replacements.append((value_start, line_end, replacement))
                elif inside.strip() != REDACTED:
                    if (
                        inside_parts
                        and _normalize_scheme_candidate(inside_parts[0]) in _SCHEME_NAMES
                        and len(inside_parts) > 1
                    ):
                        clean_inside = inside_parts[0] + " " + REDACTED
                    else:
                        clean_inside = REDACTED
                    replacement_start = value_start + leading - (1 if opening_consumed else 0)
                    replacements.append(
                        (
                            replacement_start,
                            quoted_end + 1,
                            quote_char + clean_inside + quote_char,
                        )
                    )
                covered_end = line_end
                continue
            pieces = stripped.split(None, 1)
            first = _normalize_scheme_candidate(pieces[0]) if pieces else ""
            scheme_text = pieces[0].strip("\"'`") if pieces else ""
            if first in _SCHEME_NAMES and len(pieces) > 1:
                if pieces[1].strip().strip("\"'`") == REDACTED:
                    covered_end = line_end
                    continue
                replacement = value[:leading] + scheme_text + " " + REDACTED
            elif first in _SCHEME_NAMES:
                replacement = value[:leading] + scheme_text
            else:
                replacement = REDACTED
            if replacement != value:
                replacements.append((value_start, line_end, replacement))
            covered_end = line_end
            if first in _SCHEME_NAMES and len(pieces) == 1:
                following_index = line_index + 1
                while following_index < len(lines):
                    following = lines[following_index]
                    next_body = following.group(0).rstrip("\r\n")
                    if next_body.strip():
                        next_value = next_body.strip()
                        if next_body[: len(next_body) - len(next_body.lstrip())] or not re.search(
                            r"\s", next_value
                        ):
                            replacements.append(
                                (following.start(), following.start() + len(next_body), REDACTED)
                            )
                        break
                    following_index += 1
    for start, end, replacement in reversed(replacements):
        if text[start:end] != replacement:
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


@lru_cache(maxsize=2)
def _free_text_credential_spans(  # noqa: PLR0912
    text: str,
) -> list[tuple[int, int, str, bool]]:
    """Return sensitive free-text credentials, including scheme and next-line forms."""
    found: list[tuple[int, int, str, bool]] = []
    assignment = re.compile(
        rf"(?i)(?<![A-Za-z0-9_.-])({_SENSITIVE_FREE_NAME})"
        r"[ \t]*[=:][ \t]*([^\r\n]*)"
    )
    json_spans = [(start, end) for start, end, _value, _context in _json_fragments(text)]
    json_starts = [start for start, _end in json_spans]
    lines = list(re.finditer(r"[^\r\n]*(?:\r?\n|\r|$)", text))
    for line in lines:
        body = line.group(0).rstrip("\r\n")
        for match in assignment.finditer(body):
            absolute_start = line.start() + match.start()
            if _is_url_query_assignment(text, absolute_start):
                continue
            fragment_index = bisect_right(json_starts, absolute_start) - 1
            if fragment_index >= 0 and absolute_start < json_spans[fragment_index][1]:
                continue
            key = _clean_log_key(match.group(1))
            if not key or not _is_sensitive_key(key):
                continue
            auth = _is_whole_authorization_header(key)
            cookie = _is_cookie_header_name(key)
            token = resolve_credential_token(text, line.start() + match.start(2))
            cookie_value = text[line.start() + match.start(2) : line.start() + len(body)]
            has_cookie_pairs = cookie and _COOKIE_PAIR.match(cookie_value) is not None
            if token is not None and not has_cookie_pairs:
                start, end = token
                end = start + len(_before_named_parameter(text[start:end]))
                raw = text[start:end]
                literal = _clean_credential_literal(raw)
                if literal and literal != REDACTED:
                    prefix = text[line.start() + match.start(2) : start]
                    scheme_credential = any(
                        _scheme_word(part) for part in re.findall(r"[^\s]+", prefix)
                    )
                    continuation = any(char in prefix for char in "\r\n\u2028\u2029\u0085\x0b\x0c")
                    if continuation and not _continuation_literal_is_promotable(text, start, end):
                        literal = ""
                    challenge = re.sub(r"[^a-z0-9]", "", key.casefold()) in {
                        "wwwauthenticate",
                        "proxyauthenticate",
                    }
                    challenge_credential = not challenge or (
                        _looks_like_key_material(literal)
                        and not re.match(r"(?i)^[A-Za-z0-9_.-]+=", literal)
                    )
                    if (
                        scheme_credential or continuation or (cookie and not has_cookie_pairs)
                    ) and challenge_credential:
                        found.append((start, end, literal, (auth or cookie) and scheme_credential))
            if has_cookie_pairs:
                line_end = line.start() + len(body)
                header_value_start = line.start() + match.start(2)
                for pair in _COOKIE_PAIR.finditer(text[header_value_start:line_end]):
                    start = header_value_start + pair.start(2)
                    end = header_value_start + pair.end(2)
                    if _cookie_pair_promotable(pair.group(1), pair.group(2)):
                        for literal in _credential_literal_candidates(text[start:end]):
                            found.append((start, end, literal, True))
    return list(dict.fromkeys(found))


def _redact_free_text_credential_spans(text: str, counts: dict[str, int]) -> str:
    spans = _free_text_credential_spans(text)
    if not spans:
        return text
    replacements: list[tuple[int, int, str]] = []
    for start, end, _literal, _explicit_auth in spans:
        if _clean_credential_literal(text[start:end]) != REDACTED:
            replacements.append((start, end, _redact_token_preserving_delimiters(text[start:end])))
    if not replacements:
        return text
    pieces: list[str] = []
    cursor = 0
    for start, end, replacement in sorted(replacements):
        if start < cursor:
            continue
        pieces.extend((text[cursor:start], replacement))
        cursor = end
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
    pieces.append(text[cursor:])
    return "".join(pieces)


def _redact_bracketed_pairs(text: str, counts: dict[str, int]) -> str:
    replacements: list[tuple[int, int, str]] = []
    for start, end, value in _bracketed_pair_matches(text):
        replacement = _scheme_redacted_value(value, counts)
        replacements.append((start, end, replacement))
    for start, end, replacement in reversed(replacements):
        text = text[:start] + replacement + text[end:]
    return text


def _redact_token_preserving_delimiters(raw: str) -> str:
    cleaned = _clean_credential_literal(raw)
    if cleaned == REDACTED:
        return raw
    position = raw.find(cleaned)
    if position < 0:
        return _quoted_redacted(raw)
    return raw[:position] + REDACTED + raw[position + len(cleaned) :]


def _embedded_secrets(text: str) -> set[str]:  # noqa: PLR0912
    values: set[str] = set()
    if _BROKEN_BACKSLASH_ASSIGNMENT.fullmatch(text):
        return values
    if _REPEATED_NUMERIC_KEY_LINES.fullmatch(text):
        return values
    if _REPEATED_QUOTED_KEY_LINES.fullmatch(text):
        return {
            literal
            for match in _QUOTED_KEY_LINE.finditer(text)
            if len(match.group("value")) >= 4
            and not match.group("value").isdigit()
            and match.group("value") != REDACTED
            for literal in _credential_literal_candidates(match.group("value"))
        }
    if _has_sensitive_query_assignment(text):
        for match in _URL_QUERY_SECRET.finditer(text):
            value = _query_value_parts(match.group(3))[0]
            if _is_sensitive_key(match.group(2), ("__url_query__",)):
                values.update(
                    literal
                    for literal in _credential_literal_candidates(value)
                    if _promotable_free_text(literal)
                )
    if "://" in text:
        values.update(
            literal
            for match in _URL_USERINFO.finditer(text)
            for literal in _credential_literal_candidates(match.group(3)[:-1])
            if match.group(3) != f"{REDACTED}@" and _userinfo_candidate(match)
        )
        values.update(
            literal
            for start, end in _rtmp_harvest_spans(text)
            for literal in _credential_literal_candidates(text[start:end])
            if _looks_like_rtmp_harvest(literal)
        )
    if "streamlabs.com/" in text.casefold():
        values.update(
            literal
            for match in _STREAMLABS_WIDGET_TOKEN.finditer(text)
            for literal in _credential_literal_candidates(match.group(2))
        )
    for start, end in _fragment_secret_spans(text):
        values.update(
            literal
            for literal in _credential_literal_candidates(text[start:end])
            if _promotable_free_text(literal)
        )
    for pattern in (_STREAMELEMENTS_TOKEN, _DISCORD_WEBHOOK_TOKEN, _SLACK_WEBHOOK_TOKEN):
        values.update(
            literal
            for match in pattern.finditer(text)
            for literal in _credential_literal_candidates(match.group(2))
        )
    for header in _COOKIE_HEADER.finditer(text):
        for pair in _COOKIE_PAIR.finditer(header.group(2)):
            if _cookie_pair_promotable(pair.group(1), pair.group(2)):
                values.update(_credential_literal_candidates(pair.group(2)))
    if _SENSITIVE_NAME_HINT.search(text):
        for _start, _end, value in _bracketed_pair_matches(text):
            values.update(_credential_literals(value))
        for match in _CLI_ASSIGNMENT.finditer(_mask_urls(text)):
            option = re.match(r"--?([A-Za-z0-9_.-]+)", match.group(1))
            if option and _is_sensitive_key(option.group(1)):
                values.update(
                    value
                    for value in _credential_literal_candidates(match.group(2))
                    if _promotable_free_text(value)
                )
        values.update(
            literal
            for _name, value, _start, _end, noncredential in _comment_assignments(text)
            if not noncredential
            for literal in _credential_literal_candidates(value)
            if _promotable_free_text(literal)
        )
        values.update(
            candidate
            for _start, _end, literal, explicit_auth in _free_text_credential_spans(text)
            for candidate in _credential_literal_candidates(literal)
            if _promotable_free_text(candidate, explicit_auth=explicit_auth)
        )
    for pattern in _LOG_PATTERNS if _SENSITIVE_NAME_HINT.search(text) else ():
        if pattern is _LOG_PATTERNS[-1] and not re.search(
            r"(?i)(?:authorization|authentication|www-authenticate|proxy-authenticate)", text
        ):
            continue

        def collect(match: re.Match[str], pattern: re.Pattern[str] = pattern) -> str:
            if _is_challenge_realm_match(match):
                return match.group(0)
            if pattern is _LOG_PATTERNS[0] and _is_url_query_assignment(
                match.string, match.start(1)
            ):
                return match.group(0)
            if (
                pattern is _LOG_PATTERNS[-1]
                or _log_match_key(match).casefold() != "key"
                or not is_noncredential_log_match(text, match)
            ) and (
                pattern is _LOG_PATTERNS[-1]
                or _is_sensitive_key(_log_match_key(match), value=_unquote(match.group(2)))
            ):
                if (
                    pattern is _LOG_PATTERNS[0]
                    and _is_auth_header_name(_log_match_key(match))
                    and _authorization_scheme(match)
                ):
                    return match.group(0)
                if pattern is _LOG_PATTERNS[-1] and not _authorization_scheme(match):
                    return match.group(0)
                if _is_cookie_header_name(_log_match_key(match)) and _COOKIE_PAIR.match(
                    match.group(2)
                ):
                    return match.group(0)
                literals = _credential_literal_candidates(match.group(2))
                match_key = _log_match_key(match).casefold()
                explicit_auth = False
                if _is_auth_header_name(match_key):
                    resolved = resolve_credential_token(match.string, match.start(2))
                    if resolved is not None:
                        explicit_auth = any(
                            _scheme_word(part)
                            for part in re.findall(
                                r"[^\s]+", match.string[match.start(2) : resolved[0]]
                            )
                        )
                for literal in literals:
                    if _promotable_free_text(literal, explicit_auth=explicit_auth):
                        key = _log_match_key(match)
                        if _is_weak_camel_key(key) and not _looks_like_key_material(literal):
                            continue
                        values.add(literal)
            return match.group(0)

        scan_text = _mask_urls(text)
        for start, end in _outside_json_segments(scan_text):
            for match in pattern.finditer(scan_text[start:end]):
                collect(match)
    for _start, _end, value, context in _json_fragments(text):
        values.update(_credential_values(value, context))
    return {value for value in values if value and not _never_promote_literal(value)}


def _strong_embedded_secrets(text: str) -> set[str]:  # noqa: PLR0912
    """Keep explicit assignment provenance when a value also appears in a weak source."""
    weak = _weak_credential_values(text)
    values = _embedded_secrets(text) - weak
    for pattern in _LOG_PATTERNS:
        if pattern is _LOG_PATTERNS[-1] and not re.search(
            r"(?i)(?:authorization|authentication|www-authenticate|proxy-authenticate)", text
        ):
            continue
        for match in pattern.finditer(_mask_urls(text)):
            if _is_challenge_realm_match(match):
                continue
            key = _log_match_key(match)
            literals = _credential_literal_candidates(match.group(2))
            if _is_cookie_header_name(key) and _COOKIE_PAIR.match(match.group(2)):
                continue
            explicit_auth = False
            if _is_auth_header_name(key):
                resolved = resolve_credential_token(match.string, match.start(2))
                explicit_auth = resolved is not None and any(
                    _scheme_word(part)
                    for part in re.findall(r"[^\s]+", match.string[match.start(2) : resolved[0]])
                )
            if _is_sensitive_key(key, value=match.group(2)) and not _is_weak_camel_key(key):
                values.update(
                    literal
                    for literal in literals
                    if not _never_promote_literal(literal)
                    and _promotable_free_text(literal, explicit_auth=explicit_auth)
                )
    for header in _COOKIE_HEADER.finditer(text):
        for pair in _COOKIE_PAIR.finditer(header.group(2)):
            if _cookie_pair_promotable(pair.group(1), pair.group(2)):
                values.update(_credential_literal_candidates(pair.group(2)))
    if _has_sensitive_query_assignment(text):
        for match in _URL_QUERY_SECRET.finditer(text):
            value = _query_value_parts(match.group(3))[0]
            if _is_sensitive_key(match.group(2), ("__url_query__",)):
                values.update(
                    literal
                    for literal in _credential_literal_candidates(value)
                    if _promotable_free_text(literal)
                )
    for match in _URL_USERINFO.finditer(text):
        if (
            _userinfo_candidate(match)
            and match.group(3) != f"{REDACTED}@"
            and not _never_promote_literal(match.group(3)[:-1])
        ):
            values.update(_credential_literal_candidates(match.group(3)[:-1]))
    for _start, _end, value, context in _json_fragments(text):
        values.update(_strong_credential_values(value, context))
    return {literal for literal in values if not _never_promote_literal(literal)}


def _rtmp_key(value: str) -> str:
    """Drop sentence punctuation accidentally attached to a URL path segment."""
    return value.rstrip(".,;:!?)]}>\\\"'`\u201d\u2019")


@lru_cache(maxsize=2)
def _json_fragments(text: str) -> list[tuple[int, int, Any, tuple[str, ...]]]:  # noqa: PLR0912, PLR0915
    """Find valid JSON object/array fragments in otherwise free-form text."""
    if not (_JSON_OBJECT_START.search(text) or _JSON_ARRAY_START.search(text)):
        return []
    decoder = json.JSONDecoder()
    fragments: list[tuple[int, int, Any, tuple[str, ...]]] = []
    line_starts = [0, *(match.end() for match in re.finditer("\n", text))]
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
        opening_match = _JSON_OPENING.search(text, index)
        if opening_match is None:
            break
        start = opening_match.start()
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
            line_start = line_starts[bisect_right(line_starts, assignment_end) - 1]
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
        line_start = line_starts[bisect_right(line_starts, assignment_end) - 1]
        assignment_prefix = text[max(line_start, assignment_end - 1024) : assignment_end]
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
        values = set(_credential_literal_candidates(value))
        match = re.match(r"(?is)^\s*(?:[\"'`([{<])?([A-Za-z][A-Za-z0-9_-]*)\s+", value)
        if match and _scheme_word(match.group(1)):
            token = resolve_credential_token(value, match.end())
            if token is not None:
                values.update(_credential_literal_candidates(value[token[0] : token[1]]))
        return values
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


def _credential_values(value: Any, context: tuple[str, ...] = ()) -> set[str]:  # noqa: PLR0912
    """Collect credential literals transiently so duplicate values can be checked."""
    values: set[str] = set()
    if isinstance(value, dict):
        pair = _header_pair_keys(value)
        if pair is not None:
            for pair_value_key in _header_pair_value_keys(value, pair[0]):
                values.update(_credential_literals(value[pair_value_key]))
        for key, child in value.items():
            if pair is not None and key == pair[0]:
                continue
            child_context = context + ((key,) if isinstance(key, str) else ())
            if isinstance(key, str) and _is_sensitive_key(key, context, child):
                literals = _credential_literals(child)
                if _is_weak_camel_key(key):
                    literals = {item for item in literals if _looks_like_key_material(item)}
                values.update(
                    literal for literal in literals if not _never_promote_literal(literal)
                )
            else:
                values.update(_credential_values(child, child_context))
    elif isinstance(value, list):
        if _header_pair_list(value):
            values.update(_credential_literals(value[1]))
            return {literal for literal in values if not _never_promote_literal(literal)}
        if _alternating_list_shape(value):
            index = 0
            while index + 1 < len(value):
                name = _alternating_list_name(value[index])
                candidate = (
                    _alternating_list_name(value[index + 1])
                    if isinstance(value[index + 1], dict)
                    else value[index + 1]
                )
                if name is not None and _alternating_sensitive_name(name, candidate):
                    values.update(_credential_literals(candidate))
                    index += 2
                else:
                    values.update(_credential_values(value[index], context))
                    index += 1
            if index < len(value):
                values.update(_credential_values(value[index], context))
            return {literal for literal in values if not _never_promote_literal(literal)}
        for child in value:
            values.update(_credential_values(child, context))
    elif isinstance(value, str):
        values.update(_embedded_secrets(value))
    return {literal for literal in values if not _never_promote_literal(literal)}


@lru_cache(maxsize=128)
def _compiled_local_literals(
    strong: tuple[str, ...], weak: tuple[str, ...]
) -> re.Pattern[str] | None:
    buckets: dict[str, set[str]] = {
        "strong_embedded": set(),
        "weak_embedded": set(),
        "strong_bounded": set(),
        "weak_bounded": set(),
        "numeric": set(),
    }
    for literal in sorted(set(strong) | set(weak), key=len, reverse=True):
        if (
            _never_promote_literal(literal)
            or len(literal) < 4
            or (literal.isdigit() and len(literal) < 6)
        ):
            continue
        is_weak = literal in weak and literal not in strong
        numeric = bool(re.fullmatch(r"-?\d+(?:\.\d+)?", literal))
        long_key = len(literal) >= 12 and any(char.isdigit() for char in literal)
        if numeric:
            bucket = "numeric"
        elif long_key:
            bucket = "weak_embedded" if is_weak else "strong_embedded"
        else:
            bucket = "weak_bounded" if is_weak else "strong_bounded"
        buckets[bucket].add(literal)

    def trie(values: set[str]) -> str:
        root: dict[str, Any] = {}
        for value in values:
            node = root
            for character in value:
                node = node.setdefault(character, {})
            node[""] = None

        rendered: dict[int, str] = {}
        stack = [(root, False)]
        while stack:
            node, ready = stack.pop()
            if not ready:
                stack.append((node, True))
                stack.extend((child, False) for key, child in node.items() if key)
                continue
            choices = [re.escape(key) + rendered[id(child)] for key, child in node.items() if key]
            if "" in node:
                choices.append("")
            rendered[id(node)] = (
                choices[0] if len(choices) == 1 else "(?:" + "|".join(choices) + ")"
            )
        return rendered[id(root)]

    alternatives: list[str] = []
    for bucket in ("strong_embedded", "weak_embedded", "strong_bounded", "weak_bounded", "numeric"):
        values = buckets[bucket]
        if not values:
            continue
        body = trie(values)
        if bucket.startswith("strong_"):
            body = "(?i:" + body + ")"
        if bucket.endswith("bounded"):
            body = r"(?<![A-Za-z0-9])" + body + r"(?![A-Za-z0-9])"
        elif bucket == "numeric":
            body = r"(?<![A-Za-z0-9.-])" + body + r"(?![A-Za-z0-9.-])"
        alternatives.append(body)
    return re.compile("(?:" + "|".join(alternatives) + ")") if alternatives else None


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
    strong = tuple(getattr(secrets, "strong", secrets))
    weak = tuple(getattr(secrets, "weak", ()))
    pattern = _compiled_local_literals(strong, weak)
    return pattern.sub(REDACTED, text) if pattern else text


def _redact_embedded(  # noqa: PLR0912, PLR0915
    text: str, counts: dict[str, int], secrets: set[str] | None = None, *, ini_mode: bool = False
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

    text, escaped_json = _protect_escaped_json(text, counts, secrets or set())
    text = _redact_bracketed_pairs(text, counts)
    if not ini_mode:
        text = _redact_free_text_credential_spans(text, counts)

    def replace(match: re.Match[str], *, check_noncredential: bool = True) -> str:
        raw_value = match.group(2)
        trimmed_value = _before_named_parameter(raw_value)
        trailing_parameters = raw_value[len(trimmed_value) :]
        raw_value = trimmed_value
        literal = _unquote(raw_value)
        if _yaml_block_marker(literal):
            return match.group(1) + match.group(2)
        if _resolved_value_has_scheme(match):
            return match.group(1) + match.group(2)
        if literal == REDACTED or literal.casefold() in {
            "null",
            "undefined",
            "none",
            "nil",
            "true",
            "false",
        }:
            return match.group(1) + match.group(2)
        if _scheme_word(literal):
            return match.group(1) + match.group(2)
        if (
            check_noncredential
            and _log_match_key(match).casefold() == "key"
            and is_noncredential_log_match(text, match)
        ):
            return match.group(1) + match.group(2)
        counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
        return f"{match.group(1)}{_quoted_redacted(raw_value)}{trailing_parameters}"

    def replace_log(match: re.Match[str], pattern: re.Pattern[str]) -> str:  # noqa: PLR0911
        key = _log_match_key(match)
        if _is_challenge_realm_match(match):
            return match.group(0)
        if _yaml_block_marker(_unquote(match.group(2))):
            return match.group(1) + match.group(2)
        if _scheme_word(_unquote(match.group(2))) or _resolved_value_has_scheme(match):
            return match.group(1) + match.group(2)
        if _is_auth_header_name(key) and _authorization_has_scheme(match):
            return match.group(1) + match.group(2)
        if pattern is _LOG_PATTERNS[-1] and not _authorization_scheme(match):
            return match.group(0)
        if pattern is _LOG_PATTERNS[0] and _is_url_query_assignment(match.string, match.start(1)):
            return match.group(1) + match.group(2)
        if pattern is not _LOG_PATTERNS[-1] and not _is_sensitive_key(
            key, value=_unquote(match.group(2))
        ):
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

    if re.search(r"(?i)(?:authorization|authentication|www-authenticate|proxy-authenticate)", text):
        text = _redact_authorization_remainders(text, counts)

    if "://" in text:
        text = _sub_outside_json(
            text, _RTMP_URL, lambda match: _redact_rtmp_segments(match.group(0), counts)
        )

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
        if not _userinfo_candidate(match):
            return match.group(0)
        if match.group(3) == f"{REDACTED}@":
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
    if (
        ".discord.com/api" in text.casefold()
        or ".discordapp.com/api" in text.casefold()
        or "https://discord.com/api" in text.casefold()
        or "https://discordapp.com/api" in text.casefold()
    ):

        def redact_discord(match: re.Match[str]) -> str:
            counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
            return f"{match.group(1)}{REDACTED}"

        text = _sub_outside_json(text, _DISCORD_WEBHOOK_TOKEN, redact_discord)
    if any(
        f"hooks.slack.com/{path}/" in text.casefold()
        for path in ("services", "workflows", "triggers")
    ):

        def redact_slack(match: re.Match[str]) -> str:
            counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
            return f"{match.group(1)}{REDACTED}"

        text = _sub_outside_json(text, _SLACK_WEBHOOK_TOKEN, redact_slack)
    if _COOKIE_HEADER.search(text):

        def redact_cookie(match: re.Match[str]) -> str:
            if _yaml_block_marker(match.group(2).strip()):
                return match.group(0)
            value_start = match.start(2)
            resolved = resolve_credential_token(text, value_start)
            if resolved is not None and resolved[0] > value_start:
                token_start, token_end = resolved
                prefix = text[value_start:token_start]
                if any(_scheme_word(part) for part in re.findall(r"[^\s]+", prefix)):
                    if token_start < match.end(2):
                        return match.group(1) + text[value_start:token_end]
                    return match.group(0)
            value = match.group(2)
            if value.strip() and value.strip() != REDACTED:
                counts["credential_pattern"] = counts.get("credential_pattern", 0) + 1
            return match.group(1) + REDACTED

        text = _COOKIE_HEADER.sub(redact_cookie, text)
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
        if pattern is _LOG_PATTERNS[-1] and not re.search(
            r"(?i)(?:authorization|authentication|www-authenticate|proxy-authenticate)", text
        ):
            continue

        def replace_match(match: re.Match[str], pattern: re.Pattern[str] = pattern) -> str:
            return replace_log(match, pattern)

        if pattern is _LOG_PATTERNS[0]:
            text = _sub_overlapping_assignments(text, replace_match)
        else:
            text = _sub_outside_json(text, pattern, replace_match)
    if escaped_json:
        marker_pattern = re.compile("|".join(re.escape(marker) for marker in escaped_json))
        text = marker_pattern.sub(lambda match: escaped_json[match.group(0)], text)
    return text


def _redact_escaped_json(text: str, counts: dict[str, int], secrets: set[str]) -> str:
    """Redact JSON objects whose property quotes are escaped in a log string."""
    if r"\"" not in text:
        return text
    pattern = re.compile(r"\{(?:\\.|[^{}])*\}")
    valid_json_spans = [(start, end) for start, end, _value, _context in _json_fragments(text)]
    pieces: list[str] = []
    cursor = 0
    for match in pattern.finditer(text):
        if any(start <= match.start() < end for start, end in valid_json_spans):
            continue
        raw = match.group(0)
        if r"\"" not in raw:
            continue
        try:
            value = json.loads(raw.replace(r"\"", '"'))
        except json.JSONDecodeError, RecursionError, MemoryError:
            continue
        before = sum(counts.values())
        clean = _redact_object(value, counts, secrets)
        if sum(counts.values()) == before:
            continue
        encoded = json.dumps(clean, ensure_ascii=False, separators=(",", ":")).replace('"', r"\"")
        pieces.extend((text[cursor : match.start()], encoded))
        cursor = match.end()
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


def _protect_escaped_json(
    text: str, counts: dict[str, int], secrets: set[str]
) -> tuple[str, dict[str, str]]:
    if r"\"" not in text:
        return text, {}
    pattern = re.compile(r"\{(?:\\.|[^{}])*\}")
    valid_json_spans = [(start, end) for start, end, _value, _context in _json_fragments(text)]
    pieces: list[str] = []
    protected: dict[str, str] = {}
    cursor = 0
    for index, match in enumerate(pattern.finditer(text)):
        if any(start <= match.start() < end for start, end in valid_json_spans):
            continue
        if r"\"" not in match.group(0):
            continue
        redacted = _redact_escaped_json(match.group(0), counts, secrets)
        marker = f"\x00ESCAPED_JSON_{index}\x00"
        pieces.extend((text[cursor : match.start()], marker))
        protected[marker] = redacted
        cursor = match.end()
    if not protected:
        return text, protected
    pieces.append(text[cursor:])
    return "".join(pieces), protected


def _redact_object(  # noqa: PLR0911, PLR0912
    value: Any,
    counts: dict[str, int],
    secrets: set[str],
    context: tuple[str, ...] = (),
) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        pair = _header_pair_keys(value)
        pair_values = _header_pair_value_keys(value, pair[0]) if pair is not None else set()
        for key, child in value.items():
            if pair is not None and key in pair_values:
                result[key] = _redact_pair_payload(child, counts, secrets)
                continue
            if pair is not None and key == pair[0]:
                result[key] = child
                continue
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
        if _header_pair_list(value):
            name, child = value[0], value[1]
            return [
                name,
                _redact_pair_payload(child, counts, secrets, preserve_scheme=True),
                *value[2:],
            ]
        if _alternating_list_shape(value):
            list_result = list(value)
            index = 0
            while index + 1 < len(list_result):
                name = _alternating_list_name(list_result[index])
                next_item = list_result[index + 1]
                if name is not None and _alternating_sensitive_name(
                    name, _alternating_list_name(next_item) or next_item
                ):
                    if isinstance(next_item, dict) and len(next_item) == 1:
                        item_key = next(iter(next_item))
                        next_item = {
                            item_key: _redact_pair_payload(
                                next_item[item_key], counts, secrets, preserve_scheme=True
                            )
                        }
                        list_result[index + 1] = next_item
                    else:
                        list_result[index + 1] = _redact_pair_payload(
                            next_item, counts, secrets, preserve_scheme=True
                        )
                    index += 2
                else:
                    list_result[index] = _redact_object(
                        list_result[index], counts, secrets, context
                    )
                    index += 1
            if index < len(list_result):
                list_result[index] = _redact_object(list_result[index], counts, secrets, context)
            return list_result
        return [_redact_object(child, counts, secrets, context) for child in value]
    if isinstance(value, str):
        if value in secrets:
            # Secret literals are collected across the whole document so that
            # duplicate values under otherwise benign keys are scrubbed too.
            # Count each replacement just like a sensitive-key replacement.
            if value != REDACTED:
                counts["credential_field"] = counts.get("credential_field", 0) + 1
            return REDACTED
        token = resolve_credential_token(value, 0)
        if (
            token is not None
            and token[0] > 0
            and value[token[0] : token[1]] not in {":", "="}
            and _has_scheme_prefix(value, token[0])
        ):
            counts["credential_field"] = counts.get("credential_field", 0) + 1
            value = value[: token[0]] + REDACTED + value[token[1] :]
        return _scrub_text(_redact_embedded(value, counts, secrets), secrets)
    return value


def has_unredacted_fields(value: Any, context: tuple[str, ...] = ()) -> bool:  # noqa: PLR0911, PLR0912
    """Check parsed JSON for recognized credential keys with remaining values."""
    if isinstance(value, dict):
        pair = _header_pair_keys(value)
        if pair is not None and any(
            not _sensitive_field_value_redacted(value[key])
            for key in _header_pair_value_keys(value, pair[0])
        ):
            return True
        for key, child in value.items():
            if pair is not None and key == pair[0]:
                continue
            if (
                isinstance(key, str)
                and _is_sensitive_key(key, context, child)
                and not _sensitive_field_value_redacted(child)
            ):
                return True
            child_context = context + ((key,) if isinstance(key, str) else ())
            if has_unredacted_fields(child, child_context):
                return True
    elif isinstance(value, list):
        if _header_pair_list(value) and not _sensitive_field_value_redacted(value[1]):
            return True
        if _alternating_list_shape(value):
            index = 0
            while index + 1 < len(value):
                name = _alternating_list_name(value[index])
                next_value = value[index + 1]
                plain_next = (
                    _alternating_list_name(next_value)
                    if isinstance(next_value, dict)
                    else next_value
                )
                if name is not None and _alternating_sensitive_name(name, plain_next):
                    if not _sensitive_field_value_redacted(plain_next):
                        return True
                    index += 2
                else:
                    if has_unredacted_fields(value[index], context) or has_unredacted_fields(
                        next_value, context
                    ):
                        return True
                    index += 2
            return False
        return any(has_unredacted_fields(child, context) for child in value)
    elif isinstance(value, str):
        return has_unredacted_embedded_json(value)
    return False


def has_unredacted_embedded_json(text: str) -> bool:  # noqa: PLR0911, PLR0912
    """Check JSON-like credential assignments embedded in other text."""
    if _is_repeated_redacted_key_log(text) or _is_repeated_redacted_quoted_key_log(text):
        return False
    if _redact_escaped_json(text, {}, set()) != text:
        return True
    text, _escaped_json = _protect_escaped_json(text, {}, set())
    if any(has_unredacted_fields(value, context) for _, _, value, context in _json_fragments(text)):
        return True
    if _rtmp_segment_spans(text):
        return True
    if any(_unquote(text[start:end]) != REDACTED for start, end in _fragment_secret_spans(text)):
        return True
    if _has_sensitive_query_assignment(text) and any(
        _is_sensitive_key(match.group(2), ("__url_query__",))
        and _unquote(_query_value_parts(match.group(3))[0]).casefold()
        not in {"null", "undefined", "none", "nil", "true", "false"}
        and not _query_value_is_redacted(
            match.group(3) + _query_value_line_tail(text, match.end(3))
        )
        for match in _URL_QUERY_SECRET.finditer(text)
    ):
        return True
    if any(
        match.group(3) != f"{REDACTED}@" and _userinfo_candidate(match)
        for match in _URL_USERINFO.finditer(text)
    ):
        return True
    if any(
        _clean_credential_literal(text[start:end]) != REDACTED
        for start, end, _literal, _ungated in _free_text_credential_spans(text)
    ):
        return True
    if _SENSITIVE_NAME_HINT.search(text) and any(
        _unquote(value) != REDACTED and not noncredential
        for _name, value, _start, _end, noncredential in _comment_assignments(text)
    ):
        return True
    for pattern in _LOG_PATTERNS if _SENSITIVE_NAME_HINT.search(text) else ():
        if pattern is _LOG_PATTERNS[-1] and not re.search(
            r"(?i)(?:authorization|authentication|www-authenticate|proxy-authenticate)", text
        ):
            continue
        for start, end in _outside_json_segments(text):
            segment = text[start:end]
            scan_segment = _mask_urls(segment)
            if any(
                not _is_challenge_realm_match(match)
                and not (
                    re.sub(r"[^a-z0-9]", "", _log_match_key(match).casefold())
                    in {"wwwauthenticate", "proxyauthenticate"}
                    and _scheme_word(_unquote(match.group(2)))
                )
                and _unquote(_before_named_parameter(match.group(2))) != REDACTED
                and not (
                    _yaml_block_marker(_unquote(match.group(2)))
                    and resolve_credential_token(match.string, match.start(2)) is None
                )
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
                    and _is_auth_header_name(_log_match_key(match))
                    and _authorization_has_scheme(match)
                )
                and not _scheme_prefixed_value_is_redacted(match)
                and (
                    pattern is _LOG_PATTERNS[-1]
                    or _is_sensitive_key(_log_match_key(match), value=_unquote(match.group(2)))
                )
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
            if secret.casefold() not in {"null", "undefined", "none", "nil", "true", "false"}:
                secrets.update(_credential_literal_candidates(secret))
            end = _ini_continuation_end(lines, index, match.group(2))
            secrets.update(
                literal
                for pos in range(index + 1, end)
                if lines[pos].strip()
                for literal in _credential_literal_candidates(lines[pos].strip())
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
        weak_secrets = _weak_credential_values(raw)
        strong_secrets = _strong_credential_values(raw, (path.name,))
        clean = _redact_object(raw, counts, secrets, (path.name,))
        path.write_text(json.dumps(clean, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif is_ini:
        text = read_text_safely(path)
        secrets = _ini_secret_values(text, path.name) | _embedded_secrets(text)
        weak_secrets = _weak_credential_values(text)
        strong_secrets = _strong_embedded_secrets(text)
        for match in re.finditer(r"(?im)^\s*([A-Za-z0-9_.-]+)\s*[=:]\s*([^\r\n]+)", text):
            value = _unquote(match.group(2))
            if _is_sensitive_key(match.group(1), (path.name,), value) and not _is_weak_camel_key(
                match.group(1)
            ):
                strong_secrets.update(_credential_literal_candidates(value))
            if _is_weak_camel_key(match.group(1)) and _looks_like_key_material(value):
                weak_secrets.add(value)
        clean = _redact_ini(text, path.name, counts, secrets)
        clean = _scrub_text(_redact_embedded(clean, counts, secrets, ini_mode=True), secrets)
        path.write_text(clean, encoding="utf-8", newline="")
    elif suffix == ".txt":
        text = read_text_safely(path)
        secrets = _embedded_secrets(text)
        weak_secrets = _weak_credential_values(text)
        strong_secrets = _strong_embedded_secrets(text)
        text = _redact_embedded(text, counts, secrets)
        # Supported UTF-16 input is deliberately normalized to UTF-8 in staging.
        path.write_text(_scrub_text(text, secrets), encoding="utf-8")
    else:
        secrets = set()
        weak_secrets = set()
        strong_secrets = set()
    return counts, sum(counts.values()), CredentialSecrets(secrets, weak_secrets, strong_secrets)


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
