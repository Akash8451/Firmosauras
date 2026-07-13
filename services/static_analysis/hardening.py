"""Binary hardening flags via direct ELF header parsing (Task 8).

Emits the small structured object SCHEMA.md §2 expects —
``{"nx": bool, "pie": bool, "relro": "none|partial|full", "canary": bool}`` —
appended to ``firmware.analyzed`` (NOT a new Kafka topic; analysis-modules-rbac.md).

Detection (checksec-equivalent, no external tool):
  * NX     — ``PT_GNU_STACK`` present and NOT executable (no ``PF_X``).
  * PIE    — ELF type ``ET_DYN`` (position-independent executable / shared object).
  * RELRO  — ``PT_GNU_RELRO`` present → at least ``partial``; upgraded to ``full``
             when the dynamic section requests immediate binding (``DT_BIND_NOW`` or
             ``DF_BIND_NOW`` / ``DF_1_NOW``).
  * canary — the stack-protector symbol ``__stack_chk_fail`` appears in the
             already-extracted strings (reuses the string pass, no re-scan).

Non-ELF sub-blobs (config files, images) return the all-off default; the field is
always present so the contract never breaks.
"""
from __future__ import annotations

import struct
from typing import Iterable

# Program header types.
_PT_DYNAMIC = 0x2
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PF_X = 0x1

# ELF e_type.
_ET_DYN = 3

# Dynamic tags / flags for RELRO "full" detection.
_DT_BIND_NOW = 24
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6FFFFFFB
_DF_BIND_NOW = 0x8
_DF_1_NOW = 0x1

CANARY_SYMBOL = "__stack_chk_fail"

DEFAULT_FLAGS = {"nx": False, "pie": False, "relro": "none", "canary": False}


def is_elf(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == b"\x7fELF"


def analyze_hardening(data: bytes, strings: Iterable[str]) -> dict:
    """Return the hardening-flags object for a blob (defaults if not an ELF)."""
    canary = any(CANARY_SYMBOL in s for s in strings)
    if not is_elf(data):
        flags = dict(DEFAULT_FLAGS)
        flags["canary"] = canary
        return flags
    try:
        return _parse_elf(data, canary)
    except (struct.error, IndexError, ValueError):
        # Malformed/truncated ELF — degrade to defaults rather than crash the stage.
        flags = dict(DEFAULT_FLAGS)
        flags["canary"] = canary
        return flags


def _parse_elf(data: bytes, canary: bool) -> dict:
    ei_class = data[4]   # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]    # 1 = little-endian, 2 = big-endian
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2

    e_type = struct.unpack_from(endian + "H", data, 16)[0]
    pie = e_type == _ET_DYN

    if is64:
        e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
    else:
        e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 44)[0]

    nx = False
    relro = "none"
    dyn_segment: tuple[int, int] | None = None  # (offset, filesz)

    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        if base + e_phentsize > len(data):
            break
        if is64:
            p_type, p_flags = struct.unpack_from(endian + "II", data, base)
            p_offset = struct.unpack_from(endian + "Q", data, base + 8)[0]
            p_filesz = struct.unpack_from(endian + "Q", data, base + 32)[0]
        else:
            p_type = struct.unpack_from(endian + "I", data, base)[0]
            p_offset = struct.unpack_from(endian + "I", data, base + 4)[0]
            p_filesz = struct.unpack_from(endian + "I", data, base + 16)[0]
            p_flags = struct.unpack_from(endian + "I", data, base + 24)[0]

        if p_type == _PT_GNU_STACK:
            nx = not bool(p_flags & _PF_X)
        elif p_type == _PT_GNU_RELRO:
            relro = "partial"
        elif p_type == _PT_DYNAMIC:
            dyn_segment = (p_offset, p_filesz)

    # Upgrade RELRO to "full" if the dynamic section requests immediate binding.
    if relro == "partial" and dyn_segment is not None and _has_bind_now(data, dyn_segment, endian, is64):
        relro = "full"

    return {"nx": nx, "pie": pie, "relro": relro, "canary": canary}


def _has_bind_now(data: bytes, dyn_segment: tuple[int, int], endian: str, is64: bool) -> bool:
    offset, filesz = dyn_segment
    entry_size = 16 if is64 else 8
    tag_fmt = endian + ("q" if is64 else "i")
    val_fmt = endian + ("Q" if is64 else "I")
    end = min(offset + filesz, len(data))
    pos = offset
    while pos + entry_size <= end:
        d_tag = struct.unpack_from(tag_fmt, data, pos)[0]
        d_val = struct.unpack_from(val_fmt, data, pos + (8 if is64 else 4))[0]
        if d_tag == 0:  # DT_NULL terminates the dynamic array
            break
        if d_tag == _DT_BIND_NOW:
            return True
        if d_tag == _DT_FLAGS and (d_val & _DF_BIND_NOW):
            return True
        if d_tag == _DT_FLAGS_1 and (d_val & _DF_1_NOW):
            return True
        pos += entry_size
    return False
