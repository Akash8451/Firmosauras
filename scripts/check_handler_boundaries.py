"""CI reviewer check: handler boundary discipline.

backend-architecture.md rule 4 forbids handlers calling each other in-process —
all inter-stage communication must go through Kafka (`ctx.emit`). This static
check parses every stage handler module and fails if one references another
stage's `handle_*` function directly.

Usage:
    python scripts/check_handler_boundaries.py
"""
from __future__ import annotations

import ast
import pathlib
import sys

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_HANDLERS = _REPO_ROOT / "services" / "router" / "handlers"


def _handler_funcs(tree: ast.AST) -> set[str]:
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("handle_")
    }


def main() -> int:
    files = [p for p in sorted(_HANDLERS.glob("*.py")) if p.name != "__init__.py"]
    if not files:
        print(f"ERROR: no handler modules found in {_HANDLERS}", file=sys.stderr)
        return 1

    trees = {p: ast.parse(p.read_text(encoding="utf-8")) for p in files}
    # Map every handler function name to the file that defines it.
    owner: dict[str, pathlib.Path] = {}
    for p, tree in trees.items():
        for name in _handler_funcs(tree):
            owner[name] = p

    violations: list[str] = []
    for p, tree in trees.items():
        own = _handler_funcs(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else (
                    fn.attr if isinstance(fn, ast.Attribute) else None
                )
                if name and name in owner and name not in own:
                    violations.append(
                        f"{p.name}:{node.lineno} calls handler {name!r} "
                        f"(defined in {owner[name].name}) directly"
                    )

    if violations:
        print("handler-boundary check FAILED:", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        print("Handlers must communicate via ctx.emit (Kafka), never direct calls.",
              file=sys.stderr)
        return 1

    print(f"handler-boundary check OK: {len(files)} handler module(s), "
          f"no cross-handler calls.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
