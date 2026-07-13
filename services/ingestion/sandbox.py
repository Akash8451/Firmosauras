"""POSIX subprocess sandbox for extraction backends (Task 7).

Runs an external extractor (``binwalk`` + backends) as a child process hardened
three independent ways — NO cgroups (hard-constraints: WSL2, no in-container
cgroup control), just the primitives the router container already has:

  * ADDRESS-SPACE CAP — ``resource.setrlimit(RLIMIT_AS, (512MiB, 512MiB))`` in a
    ``preexec_fn`` so the child (and its own children) cannot outgrow the memory
    budget; an allocation past the cap fails in-process (the OOM defense).
  * WALL-CLOCK TIMEOUT — a monitor loop SIGKILLs the whole process group after
    60s so a wedged/​malicious extractor cannot hang the worker.
  * DECOMPRESSION-RATIO WATCHDOG — the same loop measures the output directory and
    SIGKILLs the group the instant ``output / input`` exceeds 100x.

The child is started in its OWN session (``setsid``) so ``killpg`` reaps the whole
tree — no zombie extraction children (backend-architecture.md rule 6).

``resource``/``os.setsid``/``killpg`` are POSIX-only; the router runs in a Linux
container so that is the real path. On a non-POSIX host the import still succeeds
(``resource is None``) and ``run_sandboxed`` raises, so unit tests exercise the
in-process extractor + defenses instead.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

from . import defenses

try:  # POSIX-only; absent on Windows.
    import resource
except ImportError:  # pragma: no cover - Windows dev host
    resource = None  # type: ignore

log = logging.getLogger("ingestion.sandbox")

# Sentinel status values.
STATUS_OK = "ok"
STATUS_TIMEOUT = defenses.LAYER_SANDBOX_TIMEOUT
STATUS_RATIO = defenses.LAYER_DECOMPRESSION_RATIO
STATUS_ERROR = "error"


@dataclass
class SandboxResult:
    status: str
    returncode: Optional[int]
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and (self.returncode == 0)


def _preexec(mem_limit: int):
    """Return a preexec_fn that caps address space and starts a new session."""

    def _apply() -> None:  # pragma: no cover - runs only in the child, POSIX-only
        resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
        os.setsid()

    return _apply


def run_sandboxed(
    cmd: List[str],
    *,
    cwd: str,
    output_dir: str,
    input_size: int,
    mem_limit: int = defenses.MEM_LIMIT_BYTES,
    timeout: int = defenses.WALL_CLOCK_TIMEOUT_SECONDS,
    ratio_limit: int = defenses.DECOMPRESSION_RATIO_LIMIT,
    poll_interval: float = 0.1,
) -> SandboxResult:
    """Run ``cmd`` under the memory cap + timeout + ratio watchdog.

    Raises ``ZipBombError`` (layer ``decompression_ratio``) when the watchdog
    trips and ``ExtractionError`` (layer ``sandbox_timeout``) on wall-clock
    timeout — both after SIGKILLing the whole process group.
    """
    if resource is None:  # pragma: no cover - Windows dev host
        raise RuntimeError("run_sandboxed requires a POSIX host (resource/setsid)")

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=_preexec(mem_limit),
    )
    start = time.monotonic()

    def _killpg() -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass

    try:
        while proc.poll() is None:
            elapsed = time.monotonic() - start
            if elapsed > timeout:
                _killpg()
                proc.wait(timeout=5)
                raise defenses.ExtractionError(
                    f"extraction exceeded {timeout}s wall-clock", layer=defenses.LAYER_SANDBOX_TIMEOUT
                )
            produced = defenses.dir_size(output_dir)
            if input_size > 0 and produced > input_size * ratio_limit:
                _killpg()
                proc.wait(timeout=5)
                raise defenses.ZipBombError(
                    f"sandbox output {produced}/{input_size} exceeds {ratio_limit}x",
                    layer=defenses.LAYER_DECOMPRESSION_RATIO,
                )
            time.sleep(poll_interval)

        stdout, stderr = proc.communicate(timeout=5)
        return SandboxResult(
            status=STATUS_OK if proc.returncode == 0 else STATUS_ERROR,
            returncode=proc.returncode,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
        )
    finally:
        # Guarantee no lingering process group (zombie prevention, rule 6).
        if proc.poll() is None:
            _killpg()
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
