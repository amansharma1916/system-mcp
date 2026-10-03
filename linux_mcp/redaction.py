"""Secret redaction for anything that leaves the process (audit log, logs).

Defence in depth, not a guarantee: it catches common credential shapes and
secret-looking key names. The audit log records *what was run*, not the contents
of files, so the highest-value secrets are never in scope in the first place.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

REDACTED = "[redacted]"
"""What a redacted value is replaced with."""

_SECRET_WORDS = frozenset(
    {"token", "key", "secret", "password", "passwd", "credential", "credentials"}
)
"""Whole words that mark a field name as secret.

Matched as *tokens*, not substrings, so ``monkey``, ``keyboard`` and ``keyring``
are not mistaken for secrets while ``api_key``, ``apiKey`` and ``github_token``
are. ``apiKey`` is handled by splitting camelCase before tokenising.
"""

_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+")


def _tokens(name: str) -> list[str]:
    """Split a field name into lowercase words, respecting camelCase."""
    spaced = _CAMEL_BOUNDARY.sub(r"\1 \2", name)
    return [token.lower() for token in _WORD_SPLIT.split(spaced) if token]


_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bpassword\s*[=:]\s*\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}"),
)


def is_secret_key(name: str) -> bool:
    """True when a mapping key's *name* suggests its value is a secret."""
    return any(token in _SECRET_WORDS for token in _tokens(name))


def redact_value(value: str) -> str:
    """Replace secret-looking substrings inside *value*."""
    for pattern in _SECRET_VALUE_PATTERNS:
        value = pattern.sub(REDACTED, value)
    return value


def redact_any(value: object) -> object:
    """Recursively redact *value*: mappings by key name, strings by shape."""
    if isinstance(value, Mapping):
        return redact_mapping(value)
    if isinstance(value, str):
        return redact_value(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [redact_any(item) for item in value]
    return value


def redact_mapping(data: Mapping[str, object]) -> dict[str, object]:
    """Redact every entry of *data*, by key name first, then by value shape."""
    result: dict[str, object] = {}
    for key, value in data.items():
        name = str(key)
        result[name] = REDACTED if is_secret_key(name) else redact_any(value)
    return result
