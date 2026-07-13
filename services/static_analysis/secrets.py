"""Secret / key detection (Task 8).

A regex pass OVER THE ALREADY-EXTRACTED STRINGS from the string-extraction step —
NOT a second extraction pipeline (analysis-modules-rbac.md). Flags private-key
headers and common hardcoded-credential patterns. Emits ``{type, context}`` (the
matched string, truncated) so an analyst can see WHY it fired without leaking a
full key blob into the event.
"""
from __future__ import annotations

import re
from typing import Iterable, List

_CONTEXT_MAX = 200

# type-code -> compiled pattern. Order is stable; a string may fire several.
_PATTERNS = [
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+")),
    ("private_key_pem_body", re.compile(r"\bMII[A-Za-z0-9+/]{20,}")),  # DER/base64 key body
    ("hardcoded_credential", re.compile(r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret|token|auth)\b\s*[=:]\s*\S+")),
    ("connection_string_password", re.compile(r"(?i)://[^:@/\s]+:[^@/\s]+@")),
]


def _truncate(s: str) -> str:
    return s if len(s) <= _CONTEXT_MAX else s[:_CONTEXT_MAX]


def scan_strings(strings: Iterable[str]) -> List[dict]:
    """Return ``[{type, context}, ...]`` for every secret pattern hit."""
    findings: List[dict] = []
    for s in strings:
        for type_code, pattern in _PATTERNS:
            if pattern.search(s):
                findings.append({"type": type_code, "context": _truncate(s)})
    return findings
