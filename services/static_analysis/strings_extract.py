"""Multi-encoding string extraction (Task 8).

Extracts printable runs in THREE encodings explicitly — not just the default
``strings(1)`` ASCII pass — because firmware routinely embeds wide-char strings:

  * ASCII      — runs of printable single bytes;
  * UTF-16LE   — printable byte followed by 0x00 (``H\x00e\x00l\x00l\x00o\x00``);
  * UTF-16BE   — 0x00 followed by a printable byte.

The null bytes in a UTF-16 run break ASCII runs shorter than ``min_len``, so a
wide string is captured by the UTF-16 pass (decoded correctly, not garbled) rather
than as a stream of one-character ASCII fragments. Results are de-duplicated with
first-seen order preserved; this SAME list feeds the secret-detection and
version-candidate passes (no second extraction pipeline).
"""
from __future__ import annotations

import re
from typing import List

DEFAULT_MIN_LEN = 4

# Printable ASCII byte class (space through tilde).
_PRINTABLE = rb"\x20-\x7e"


def _compile(min_len: int):
    ascii_re = re.compile(rb"[%b]{%d,}" % (_PRINTABLE, min_len))
    utf16le_re = re.compile(rb"(?:[%b]\x00){%d,}" % (_PRINTABLE, min_len))
    utf16be_re = re.compile(rb"(?:\x00[%b]){%d,}" % (_PRINTABLE, min_len))
    return ascii_re, utf16le_re, utf16be_re


def extract_strings(data: bytes, *, min_len: int = DEFAULT_MIN_LEN) -> List[str]:
    """Return de-duplicated printable strings across ASCII + UTF-16LE + UTF-16BE."""
    ascii_re, utf16le_re, utf16be_re = _compile(min_len)

    ordered: List[str] = []
    seen: set[str] = set()

    def _add(s: str) -> None:
        if s and s not in seen:
            seen.add(s)
            ordered.append(s)

    for m in ascii_re.finditer(data):
        _add(m.group().decode("ascii", errors="replace"))
    for m in utf16le_re.finditer(data):
        _add(m.group().decode("utf-16-le", errors="replace"))
    for m in utf16be_re.finditer(data):
        _add(m.group().decode("utf-16-be", errors="replace"))

    return ordered
