"""Task 8 — Static analysis workers.

Covers the Task 8 checklist:
  * a fully-populated firmware.analyzed matching the schema (handler, rule 7);
  * UTF-16 (LE + BE) strings extracted, not garbled;
  * a planted private-key header is flagged;
  * version candidates extracted correctly per family;
plus per-section entropy flagging and ELF hardening-flag parsing.
"""
from __future__ import annotations

import json
import os
import pathlib
import struct

from shared import topics
from shared.contracts import FirmwareAnalyzed
from shared.redis_keys import completed_children

from services.ingestion import runtime as ingestion_runtime
from services.ingestion.blobstore import InMemoryBlobStore
from services.static_analysis import entropy, hardening, secrets, versions
from services.static_analysis.analyze import analyze
from services.static_analysis.strings_extract import extract_strings

from _sa_fakes import CapturingContext, FakeRedis

_SAMPLES = pathlib.Path(__file__).resolve().parents[3] / "sample_payloads"


# --------------------------------------------------------------------------- #
# ELF crafting helper (64-bit LE, ET_DYN, NX + partial RELRO).                 #
# --------------------------------------------------------------------------- #
def make_elf(*, extra: bytes = b"") -> bytes:
    e_ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9  # 64-bit, LE, v1
    header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3,      # e_type = ET_DYN (PIE)
        0x3E,   # e_machine = x86-64
        1,      # e_version
        0,      # e_entry
        64,     # e_phoff (right after the 64-byte header)
        0,      # e_shoff
        0,      # e_flags
        64,     # e_ehsize
        56,     # e_phentsize
        2,      # e_phnum
        0, 0, 0,  # e_shentsize, e_shnum, e_shstrndx
    )
    # PT_GNU_STACK, flags RW (no PF_X → NX enabled).
    ph1 = struct.pack("<IIQQQQQQ", 0x6474E551, 0x6, 0, 0, 0, 0, 0, 0)
    # PT_GNU_RELRO present → partial RELRO.
    ph2 = struct.pack("<IIQQQQQQ", 0x6474E552, 0x4, 0, 0, 0, 0, 0, 0)
    return header + ph1 + ph2 + extra


# --------------------------------------------------------------------------- #
# Multi-encoding strings.                                                      #
# --------------------------------------------------------------------------- #
def test_multi_encoding_strings_not_garbled():
    data = (
        b"HelloWorldASCII\x00\x00\x00\x00"
        + "WideStringLE".encode("utf-16-le")
        + b"\x00\x00\x00\x00"
        + "WideStringBE".encode("utf-16-be")
    )
    found = extract_strings(data)
    assert "HelloWorldASCII" in found     # ASCII
    assert "WideStringLE" in found        # UTF-16LE decoded correctly
    assert "WideStringBE" in found        # UTF-16BE decoded correctly


# --------------------------------------------------------------------------- #
# Secret detection over the extracted strings.                                 #
# --------------------------------------------------------------------------- #
def test_private_key_header_flagged():
    strings = ["harmless", "-----BEGIN RSA PRIVATE KEY-----", "also fine"]
    flags = secrets.scan_strings(strings)
    assert any(f["type"] == "private_key_header" for f in flags)


def test_hardcoded_credential_flagged():
    flags = secrets.scan_strings(["password = hunter2", "PATH=/usr/bin"])
    assert any(f["type"] == "hardcoded_credential" for f in flags)


# --------------------------------------------------------------------------- #
# Version candidates per family.                                               #
# --------------------------------------------------------------------------- #
def test_version_candidates_extracted():
    strings = [
        "BusyBox v1.31.1 (2020-04-14 15:22:11 UTC)",
        "OpenSSL 1.0.2n  7 Dec 2017",
        "libcurl/7.68.0",
        "Dropbear 2019.78",
        "uClibc 0.9.33",
        "Linux version 4.14.98 (gcc ...)",
    ]
    cands = versions.find_version_candidates(strings)
    got = {(c["product"], c["version"]) for c in cands}
    assert ("busybox", "1.31.1") in got
    assert ("openssl", "1.0.2n") in got
    assert ("libcurl", "7.68.0") in got
    assert ("dropbear", "2019.78") in got
    assert ("uclibc", "0.9.33") in got
    assert ("linux_kernel", "4.14.98") in got


# --------------------------------------------------------------------------- #
# Entropy.                                                                     #
# --------------------------------------------------------------------------- #
def test_entropy_flags_high_entropy_section():
    high = os.urandom(65536)          # ~8 bits/byte
    low = b"\x00" * 65536             # ~0 bits/byte
    sections = entropy.section_entropies(high + low, section_size=65536)
    assert len(sections) == 2
    assert sections[0]["flagged_packed"] is True
    assert sections[1]["flagged_packed"] is False
    assert 0.0 <= sections[0]["entropy"] <= 8.0


# --------------------------------------------------------------------------- #
# Hardening flags.                                                             #
# --------------------------------------------------------------------------- #
def test_hardening_elf_flags():
    data = make_elf(extra=b"__stack_chk_fail\x00")
    flags = hardening.analyze_hardening(data, ["__stack_chk_fail"])
    assert flags == {"nx": True, "pie": True, "relro": "partial", "canary": True}


def test_hardening_non_elf_defaults():
    flags = hardening.analyze_hardening(b"just a config file\n", ["no canary here"])
    assert flags == {"nx": False, "pie": False, "relro": "none", "canary": False}


# --------------------------------------------------------------------------- #
# Handler wiring (rule 7): fully-populated firmware.analyzed.                   #
# --------------------------------------------------------------------------- #
def _load_extracted() -> dict:
    with open(_SAMPLES / "firmware.extracted.json", "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_handler_emits_full_analyzed_on_contract():
    payload = _load_extracted()
    job_id = payload["job_id"]
    sub_blob_id = payload["sub_blob_id"]

    # A realistic sub-blob: an ELF with a version banner, a secret, and a canary.
    blob = make_elf(
        extra=(
            b"__stack_chk_fail\x00"
            b"BusyBox v1.31.1 (2020-04-14 15:22:11 UTC)\x00"
            b"-----BEGIN RSA PRIVATE KEY-----\x00"
            b"Linux version 4.14.98\x00"
        )
        + os.urandom(65536)  # a packed-looking high-entropy region
    )
    store = InMemoryBlobStore()
    store.put_bytes(payload["s3_key"], blob)
    ingestion_runtime.set_blobstore(store)
    try:
        from services.router.handlers.analysis import handle_analysis

        redis = FakeRedis()
        ctx = CapturingContext(redis, source_topic=topics.FIRMWARE_EXTRACTED, message_key=sub_blob_id)
        handle_analysis(payload, ctx)

        assert len(ctx.emitted) == 1
        topic, emitted = ctx.emitted[0]
        assert topic == topics.FIRMWARE_ANALYZED
        FirmwareAnalyzed.model_validate(emitted)  # on-contract
        assert emitted["job_id"] == job_id
        assert emitted["sub_blob_id"] == sub_blob_id

        # Fully populated: strings, versions, secrets, entropy, hardening.
        assert emitted["strings_found"]
        assert any(v["product"] == "busybox" and v["version"] == "1.31.1" for v in emitted["version_candidates"])
        assert any(s["type"] == "private_key_header" for s in emitted["secrets_flagged"])
        assert any(sec["flagged_packed"] for sec in emitted["entropy_sections"])
        assert emitted["hardening_flags"]["nx"] is True
        assert emitted["hardening_flags"]["canary"] is True

        # completed_children incremented (NOT matched_children).
        assert redis.get(completed_children(job_id)) == "1"
    finally:
        ingestion_runtime.reset()


def test_analyze_pure_function_shape():
    out = analyze("j", "s", make_elf(extra=b"BusyBox v1.31.1\x00"))
    FirmwareAnalyzed.model_validate(out)
    assert out["hardening_flags"]["pie"] is True
