"""
Redaction for audit event payloads.

``redact()`` is a pure function: it never mutates its input and returns a new
structure that is safe to store as JSON. Two things get replaced with
``REDACTED``:

1. The value of any key whose name looks sensitive (password, token, secret,
   authorization, api key, cookie, ...), whatever the value is.
2. Any string value that looks like a credential, even under an innocent key:
   JWTs, ``Bearer ...`` headers, well known token prefixes, PEM private keys,
   inline ``password=...`` pairs and long opaque strings.

It is deliberately on the cautious side. A false positive costs one field in an
audit row, a false negative leaves a secret in a table that admins can read and
that gets archived to disk.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"

MAX_DEPTH = 8
MAX_STRING_LENGTH = 500

# Compared against the key lower-cased with everything but letters and digits
# removed, so "API-Key", "api_key" and "apiKey" all become "apikey".
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "authorization",
    "apikey",
    "cookie",
    "credential",
    "privatekey",
    "csrf",
    "sessionid",
)
# Too short to match as a substring without catching normal words.
_SENSITIVE_KEY_EXACT = frozenset({"key", "auth", "pwd", "otp", "jwt", "signature"})

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# One unbroken run of token characters. Only applied to a whole string value.
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_\-+/=]{32,}$")

# (pattern, replacement) applied to any string, inside free text as well.
_INLINE_PATTERNS = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
            re.DOTALL,
        ),
        REDACTED,
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
        REDACTED,
    ),
    (
        re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]{8,}=*", re.IGNORECASE),
        r"\1 " + REDACTED,
    ),
    (
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
            r"|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,})"
        ),
        REDACTED,
    ),
    (
        re.compile(r"""(?ix)
            \b(password|passwd|secret|token|api[_-]?key|access[_-]?token)
            (\s*[=:]\s*)
            ["']?[^\s"'&,;]+["']?
            """),
        r"\1\2" + REDACTED,
    ),
)


def is_sensitive_key(key: Any) -> bool:
    """True when a mapping key name suggests the value is a secret."""
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    if not normalized:
        return False
    if normalized in _SENSITIVE_KEY_EXACT:
        return True
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _looks_opaque(value: str) -> bool:
    candidate = value.strip()
    if not _OPAQUE_RE.match(candidate) or _UUID_RE.match(candidate):
        return False
    # Must mix letters and digits, so long slugs and plain words are left alone.
    return any(c.isdigit() for c in candidate) and any(c.isalpha() for c in candidate)


def redact_string(value: str) -> str:
    """Redact credential-looking parts of one string and cap its length."""
    if _looks_opaque(value):
        return REDACTED
    for pattern, replacement in _INLINE_PATTERNS:
        value = pattern.sub(replacement, value)
    if len(value) > MAX_STRING_LENGTH:
        value = value[:MAX_STRING_LENGTH] + "..."
    return value


def redact(value: Any, _depth: int = 0) -> Any:
    """
    Return a redacted, JSON-safe copy of ``value``.

    Dicts (any Mapping), lists, tuples and sets are walked recursively. Values
    that are not JSON types are converted with ``str()`` and then treated like
    any other string. Structures deeper than ``MAX_DEPTH`` are cut off.
    """
    if _depth > MAX_DEPTH:
        return TRUNCATED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, Mapping):
        cleaned = {}
        for key, item in value.items():
            if is_sensitive_key(key):
                cleaned[str(key)] = REDACTED
            else:
                cleaned[str(key)] = redact(item, _depth + 1)
        return cleaned
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact(item, _depth + 1) for item in value]
    return redact_string(str(value))
