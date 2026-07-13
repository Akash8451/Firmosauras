"""Zip-bomb / hostile-archive defense primitives (Task 7).

FOUR INDEPENDENT layers — every one is enforced regardless of the others, because
a defense that can be bypassed by dodging a single check is not a defense:

  1. ``zip_slip``            — reject any entry whose resolved path escapes the
                               sandbox root (``../../etc/passwd`` style traversal).
  2. ``symlink``             — reject symlink entries whose target escapes the
                               sandbox root; never follow symlinks during walk.
  3. ``recursion_depth``     — hard cap on nested-archive depth (<= 8 levels).
  4. ``decompression_ratio`` — abort/kill if total output / input exceeds 100x.

These are pure helpers with no I/O so they can be unit-tested directly and reused
by both the in-process ``NativeExtractor`` and the ``binwalk`` subprocess sandbox.
"""
from __future__ import annotations

import os

# --- pinned limits (Task 7) ------------------------------------------------- #
RECURSION_DEPTH_CAP = 8
DECOMPRESSION_RATIO_LIMIT = 100
MEM_LIMIT_BYTES = 512 * 1024 * 1024   # RLIMIT_AS for the extraction subprocess
WALL_CLOCK_TIMEOUT_SECONDS = 60       # subprocess wall-clock timeout before SIGKILL

# --- layer names (used as DLQ reason codes) --------------------------------- #
LAYER_ZIP_SLIP = "zip_slip"
LAYER_SYMLINK = "symlink"
LAYER_RECURSION_DEPTH = "recursion_depth"
LAYER_DECOMPRESSION_RATIO = "decompression_ratio"
LAYER_SANDBOX_TIMEOUT = "sandbox_timeout"
LAYER_SANDBOX_OOM = "sandbox_oom"


class ExtractionError(Exception):
    """Base for any extraction failure that should route the job to the DLQ."""

    def __init__(self, message: str, *, layer: str) -> None:
        super().__init__(message)
        self.layer = layer


class ZipBombError(ExtractionError):
    """A hostile-archive defense tripped (any of the four layers)."""


def _norm(path: str) -> str:
    """Absolute, symlink-free-ish normalization for containment checks."""
    return os.path.normpath(os.path.abspath(path))


def is_within(root: str, candidate: str) -> bool:
    """True if ``candidate`` resolves to a path inside ``root`` (inclusive)."""
    root_n = _norm(root)
    cand_n = _norm(candidate)
    return cand_n == root_n or cand_n.startswith(root_n + os.sep)


def safe_join(root: str, member_name: str) -> str:
    """Join ``member_name`` under ``root``, raising on zip-slip traversal.

    Layer 1: an entry name that escapes the sandbox root (absolute path or
    ``..`` traversal) is rejected outright.
    """
    # An absolute member name is inherently an escape attempt.
    if os.path.isabs(member_name) or member_name.startswith(("/", "\\")):
        raise ZipBombError(f"absolute path entry {member_name!r}", layer=LAYER_ZIP_SLIP)
    target = os.path.join(root, member_name)
    if not is_within(root, target):
        raise ZipBombError(f"path traversal entry {member_name!r}", layer=LAYER_ZIP_SLIP)
    return target


def check_symlink_target(root: str, link_name: str, link_target: str) -> None:
    """Layer 2: reject a symlink whose (resolved) target escapes the sandbox root.

    Absolute targets, and relative targets that climb out of ``root`` from the
    link's own directory, are both rejected.
    """
    if os.path.isabs(link_target):
        raise ZipBombError(
            f"symlink {link_name!r} -> absolute {link_target!r}", layer=LAYER_SYMLINK
        )
    link_dir = os.path.dirname(os.path.join(root, link_name))
    resolved = os.path.normpath(os.path.join(link_dir, link_target))
    if not is_within(root, resolved):
        raise ZipBombError(
            f"symlink {link_name!r} escapes sandbox -> {link_target!r}", layer=LAYER_SYMLINK
        )


def check_depth(depth: int) -> None:
    """Layer 3: enforce the nested-archive recursion cap."""
    if depth > RECURSION_DEPTH_CAP:
        raise ZipBombError(
            f"recursion depth {depth} exceeds cap {RECURSION_DEPTH_CAP}",
            layer=LAYER_RECURSION_DEPTH,
        )


def check_ratio(output_bytes: int, input_bytes: int, *, limit: int = DECOMPRESSION_RATIO_LIMIT) -> None:
    """Layer 4: abort when decompressed output outgrows input beyond ``limit``x."""
    if input_bytes <= 0:
        return
    if output_bytes > input_bytes * limit:
        raise ZipBombError(
            f"decompression ratio {output_bytes}/{input_bytes} exceeds {limit}x",
            layer=LAYER_DECOMPRESSION_RATIO,
        )


def dir_size(path: str) -> int:
    """Total size of regular files under ``path`` (symlinks NOT followed)."""
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        for name in files:
            fp = os.path.join(root, name)
            try:
                if not os.path.islink(fp):
                    total += os.path.getsize(fp)
            except OSError:
                pass
    return total
