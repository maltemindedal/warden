"""The output boundary of `src/warden`: only `_out.py` writes to the terminal.

ruff's `TID251` (see `pyproject.toml`) bans the names it can resolve: `sys.stdout`, `sys.stderr`,
`rich` and `argparse.ArgumentParser`. ruff 0.17.4 does not match a builtin such as `print`, so
this walk over the syntax tree covers those.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).parents[1] / "src" / "warden"

_SAY = "use warden._out.say(), which escapes project text and survives a cp1252 stdout"

BANNED_CALLS: dict[str, str] = {"print": _SAY, "input": _SAY, "breakpoint": _SAY}

BANNED_METHODS: dict[str, str] = {
    "reconfigure": "leave the stream alone: warden._out.say() makes each write encodable",
}
"""Matched by attribute name alone, on any object: no type is consulted."""


def violations(path: Path) -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in BANNED_CALLS:
            found.append(f"{path.name}:{node.lineno}: {func.id}(): {BANNED_CALLS[func.id]}")
        elif isinstance(func, ast.Attribute) and func.attr in BANNED_METHODS:
            found.append(f"{path.name}:{node.lineno}: .{func.attr}(): {BANNED_METHODS[func.attr]}")
    return found


@pytest.mark.parametrize("path", sorted(SRC.glob("*.py")), ids=lambda path: path.name)
def test_no_module_writes_to_the_terminal_except_through_the_output_sink(path: Path) -> None:
    """Four fixes (e98134d, a2a5b41, d6e4ffe, 81d5c60) were one mistake made the obvious way: a
    `print` of project text, raw. Outside `_out.py` that spelling is not available."""
    assert violations(path) == [], "\n" + "\n".join(violations(path))


def test_the_check_reports_a_print_and_names_the_replacement(tmp_path: Path) -> None:
    """The check must fail on the mistake it exists for, with the fix in the message."""
    bad = tmp_path / "bad.py"
    bad.write_text(
        'print(f"   Target: {root}")\nsys.stdout.reconfigure(errors="replace")\n', encoding="utf-8"
    )

    first, second = violations(bad)

    assert first.startswith("bad.py:1: print(): use warden._out.say()")
    assert second.startswith("bad.py:2: .reconfigure(): leave the stream alone: warden._out.say()")
