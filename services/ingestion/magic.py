"""Magic-byte format detection + declared-size pre-check (Task 6).

Triage rejects a firmware blob BEFORE the expensive unpack stage if:

  * its leading bytes match no known container/binary format ("bad magic"), or
  * its own header declares a payload far larger than the object actually is — a
    cheap decompression-bomb precursor caught at the door ("suspiciously small
    header claiming a large payload").

Format coverage is the common embedded-firmware set (squashfs, jffs2, ubi(fs),
cramfs, cpio, tar, gzip/xz/bzip2/lzma/zstd, zip, ELF, u-boot uImage, DTB, PE).
We parse an embedded declared size only for the formats that carry one plainly in
a fixed-offset header (u-boot uImage, squashfs) — enough to demonstrate the
pre-check without a full format parser.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

# Header bytes we ask the blob store for (enough for a squashfs superblock).
HEADER_BYTES = 512

# Actual-size floor: nothing smaller than this is a plausible firmware container.
MIN_BLOB_BYTES = 64

# If a header declares a payload more than this many times the actual object
# size, treat it as a decompression-bomb precursor.
DECLARED_SIZE_RATIO_LIMIT = 100


# (offset, magic, format-name). Order matters only for overlapping prefixes.
_MAGICS = [
    (0, b"\x7fELF", "elf"),
    (0, b"hsqs", "squashfs"),          # little-endian squashfs
    (0, b"sqsh", "squashfs"),          # big-endian squashfs
    (0, b"\x85\x19\x03\x20", "jffs2"), # jffs2 (little-endian marker 0x1985)
    (0, b"\x19\x85", "jffs2"),
    (0, b"UBI#", "ubi"),
    (0, b"UBI!", "ubifs"),
    (0, b"\x45\x3d\xcd\x28", "cramfs"),
    (0, b"\x27\x05\x19\x56", "uimage"),  # u-boot legacy image
    (0, b"\xd0\x0d\xfe\xed", "dtb"),     # device tree blob
    (0, b"PK\x03\x04", "zip"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"\x5d\x00\x00", "lzma"),
    (0, b"\x28\xb5\x2f\xfd", "zstd"),
    (0, b"\x30\x37\x30\x37\x30", "cpio"),  # ASCII cpio ("07070...")
    (0, b"\xc7\x71", "cpio"),              # binary cpio (0o070707 LE)
    (0, b"MZ", "pe"),
]


@dataclass(frozen=True)
class MagicResult:
    fmt: Optional[str]         # detected format name, or None if unknown
    declared_size: Optional[int]  # payload size the header claims, if parseable


def detect_format(header: bytes) -> Optional[str]:
    """Return the detected format name, or None for unknown magic."""
    for offset, magic, name in _MAGICS:
        if header[offset : offset + len(magic)] == magic:
            return name
    # tar: "ustar" appears at offset 257.
    if len(header) >= 262 and header[257:262] == b"ustar":
        return "tar"
    return None


def declared_size_from_header(header: bytes, fmt: Optional[str]) -> Optional[int]:
    """Parse a payload/total size embedded in the header, where the format has one.

    Implemented for the two formats that carry it plainly at a fixed offset:
      * u-boot uImage: big-endian ``ih_size`` at byte offset 12 (data size).
      * squashfs (little-endian ``hsqs``): ``bytes_used`` (8-byte LE) at offset 40.
    Returns None when the format doesn't embed one / the header is too short.
    """
    try:
        if fmt == "uimage" and len(header) >= 16:
            return struct.unpack(">I", header[12:16])[0]
        if fmt == "squashfs" and header[:4] == b"hsqs" and len(header) >= 48:
            return struct.unpack("<Q", header[40:48])[0]
    except struct.error:
        return None
    return None


@dataclass(frozen=True)
class PrecheckResult:
    ok: bool
    reason: Optional[str] = None  # reason code when ok is False


def precheck(header: bytes, actual_size: int) -> PrecheckResult:
    """Run the magic-byte + declared-size gate. Returns a reason code on rejection.

    Reason codes (used verbatim as the DLQ ``error`` field):
      * ``too_small``              — object smaller than any plausible container.
      * ``unknown_format``         — magic bytes match no known format.
      * ``declared_size_mismatch`` — header claims a payload >> the actual bytes.
    """
    if actual_size < MIN_BLOB_BYTES:
        return PrecheckResult(False, "too_small")

    fmt = detect_format(header)
    if fmt is None:
        return PrecheckResult(False, "unknown_format")

    declared = declared_size_from_header(header, fmt)
    if declared is not None and declared > actual_size * DECLARED_SIZE_RATIO_LIMIT:
        return PrecheckResult(False, "declared_size_mismatch")

    return PrecheckResult(True)
