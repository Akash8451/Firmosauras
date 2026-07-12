"""Pytest config for the CVE-matching tests: ensure the repo root is importable
so `import services.cve_matching...` and `import shared...` resolve when tests are
run from anywhere.
"""
from __future__ import annotations

import pathlib
import sys

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
