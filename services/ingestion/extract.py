"""Extraction backends (Task 7).

An ``Extractor`` unpacks ONE container into a destination directory, enforcing the
per-container hostile-archive defenses (zip-slip, symlink, decompression ratio),
and returns the list of regular files it produced — or ``None`` if the input is
not a container it can open (a leaf blob).

  * ``NativeExtractor``        — zip / tar / gzip in-process (what the unit tests
    exercise for the four defenses on crafted archives).
  * ``BinwalkSandboxExtractor``— firmware images (squashfs, jffs2, ubifs, ...) via
    ``binwalk`` run inside the POSIX ``sandbox`` (setrlimit + timeout + SIGKILL).
  * ``CompositeExtractor``     — try native first, fall back to binwalk. This is
    the runtime default; tests inject ``NativeExtractor`` directly.

Recursion depth (layer 3) is enforced by the orchestration in ``unpack.py``; the
extractors enforce layers 1, 2 and the per-container half of layer 4.
"""
from __future__ import annotations

import gzip
import logging
import os
import stat
import tarfile
import zipfile
from typing import List, Optional, Protocol

from . import defenses
from .magic import detect_format

log = logging.getLogger("ingestion.extract")

# Chunk size for streaming single-stream decompressors.
_CHUNK = 1024 * 1024


class Extractor(Protocol):
    def extract(self, src_path: str, dest_dir: str) -> Optional[List[str]]: ...


def _read_header(path: str, n: int = 512) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def _collect_regular_files(root: str) -> List[str]:
    """All regular files under ``root``, skipping symlinks (never followed) and
    validating each stays within the sandbox root (zip-slip belt-and-braces)."""
    out: List[str] = []
    for base, _dirs, files in os.walk(root, followlinks=False):
        for name in files:
            fp = os.path.join(base, name)
            if os.path.islink(fp):
                # Layer 2: a symlink escaping the root is a violation.
                target = os.readlink(fp)
                defenses.check_symlink_target(root, os.path.relpath(fp, root), target)
                continue  # never follow, never treat as a sub-blob
            if defenses.is_within(root, fp):
                out.append(fp)
    return sorted(out)


# --------------------------------------------------------------------------- #
# Native in-process extractor (zip / tar / gzip).                              #
# --------------------------------------------------------------------------- #
class NativeExtractor:
    def extract(self, src_path: str, dest_dir: str) -> Optional[List[str]]:
        header = _read_header(src_path)
        fmt = detect_format(header)
        input_size = os.path.getsize(src_path)

        if fmt == "zip" and zipfile.is_zipfile(src_path):
            return self._extract_zip(src_path, dest_dir, input_size)
        if fmt == "tar" or tarfile.is_tarfile(src_path):
            return self._extract_tar(src_path, dest_dir, input_size)
        if fmt == "gzip":
            return self._extract_gzip(src_path, dest_dir, input_size)
        return None  # not a native container → leaf blob

    # -- zip -- #
    def _extract_zip(self, src_path: str, dest_dir: str, input_size: int) -> List[str]:
        os.makedirs(dest_dir, exist_ok=True)
        with zipfile.ZipFile(src_path) as zf:
            infos = zf.infolist()
            # Layer 4 (per-container): reject a bomb BEFORE writing anything.
            total = sum(zi.file_size for zi in infos if not zi.is_dir())
            defenses.check_ratio(total, input_size)

            for zi in infos:
                if zi.is_dir():
                    continue
                # Layer 1: zip-slip.
                target = defenses.safe_join(dest_dir, zi.filename)
                # Layer 2: symlink entries (unix mode in the high external_attr bits).
                mode = (zi.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    link_target = zf.read(zi).decode(errors="replace")
                    defenses.check_symlink_target(dest_dir, zi.filename, link_target)
                    continue  # validated-internal or not — never materialize/follow
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(zi) as src, open(target, "wb") as dst:
                    self._stream_copy(src, dst)
        return _collect_regular_files(dest_dir)

    # -- tar -- #
    def _extract_tar(self, src_path: str, dest_dir: str, input_size: int) -> List[str]:
        os.makedirs(dest_dir, exist_ok=True)
        with tarfile.open(src_path) as tf:
            members = tf.getmembers()
            total = sum(m.size for m in members if m.isreg())
            defenses.check_ratio(total, input_size)  # layer 4

            for m in members:
                # Layer 1: zip-slip on the member name.
                target = defenses.safe_join(dest_dir, m.name)
                if m.issym() or m.islnk():
                    # Layer 2: validate link target, then skip (never follow).
                    defenses.check_symlink_target(dest_dir, m.name, m.linkname)
                    continue
                if m.isdir():
                    os.makedirs(target, exist_ok=True)
                    continue
                if not m.isreg():
                    continue  # devices/fifos etc. are not sub-blobs
                os.makedirs(os.path.dirname(target), exist_ok=True)
                extracted = tf.extractfile(m)
                if extracted is None:
                    continue
                with extracted as src, open(target, "wb") as dst:
                    self._stream_copy(src, dst)
        return _collect_regular_files(dest_dir)

    # -- gzip (single stream) -- #
    def _extract_gzip(self, src_path: str, dest_dir: str, input_size: int) -> List[str]:
        os.makedirs(dest_dir, exist_ok=True)
        out_path = os.path.join(dest_dir, "decompressed.bin")
        written = 0
        cap = max(input_size, 1) * defenses.DECOMPRESSION_RATIO_LIMIT
        with gzip.open(src_path, "rb") as src, open(out_path, "wb") as dst:
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                # Layer 4: stream cap — a gzip bomb never fully materializes.
                if written > cap:
                    dst.close()
                    os.remove(out_path)
                    raise defenses.ZipBombError(
                        f"gzip stream {written} exceeds {defenses.DECOMPRESSION_RATIO_LIMIT}x cap",
                        layer=defenses.LAYER_DECOMPRESSION_RATIO,
                    )
                dst.write(chunk)
        return _collect_regular_files(dest_dir)

    @staticmethod
    def _stream_copy(src, dst) -> None:
        while True:
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            dst.write(chunk)


# --------------------------------------------------------------------------- #
# Firmware image extractor via binwalk in the POSIX sandbox.                   #
# --------------------------------------------------------------------------- #
class BinwalkSandboxExtractor:
    """Runs ``binwalk --extract`` under the setrlimit+timeout+SIGKILL sandbox.

    Only attempts formats binwalk understands (recognized firmware magic); returns
    ``None`` for unknown magic so the caller treats the blob as a leaf.
    """

    def extract(self, src_path: str, dest_dir: str) -> Optional[List[str]]:
        from . import sandbox  # lazy: POSIX-only

        header = _read_header(src_path)
        if detect_format(header) is None:
            return None
        os.makedirs(dest_dir, exist_ok=True)
        input_size = os.path.getsize(src_path)
        result = sandbox.run_sandboxed(
            ["binwalk", "--extract", "--directory", dest_dir, src_path],
            cwd=dest_dir,
            output_dir=dest_dir,
            input_size=input_size,
        )
        files = _collect_regular_files(dest_dir)
        # Nothing new produced (binwalk found no embedded files) → leaf blob.
        if not files:
            return None
        return files


# --------------------------------------------------------------------------- #
# Composite (runtime default).                                                 #
# --------------------------------------------------------------------------- #
class CompositeExtractor:
    def __init__(self, extractors: Optional[List[Extractor]] = None) -> None:
        self._extractors = extractors or [NativeExtractor(), BinwalkSandboxExtractor()]

    def extract(self, src_path: str, dest_dir: str) -> Optional[List[str]]:
        for ex in self._extractors:
            try:
                out = ex.extract(src_path, dest_dir)
            except defenses.ExtractionError:
                raise  # a tripped defense must propagate (→ DLQ), not fall through
            if out is not None:
                return out
        return None
