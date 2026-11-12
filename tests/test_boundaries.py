"""The two boundaries of `src/warden`: only `_out.py` writes to the terminal, and only `_fs.py`
touches the file system.

ruff's `TID251` (see `pyproject.toml`) bans the names it can resolve: `sys.stdout`, `rich`,
`os.open`, `os.path`, `shutil` and the rest of that table. ruff 0.17.4 does not match a builtin
such as `print` or `open`, nor a method on a `Path` instance, so a walk over the syntax tree
covers those.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).parents[1]
SRC = ROOT / "src" / "warden"

_SAY = "use warden._out.say(), which escapes project text and survives a cp1252 stdout"
_READ = (
    "use warden._fs.read_text() or read_bytes(), which return Absent, NotRegular, Unlocatable "
    "or Unreadable instead of raising, so a project file cannot end the run in a traceback"
)
_WRITE = (
    "get a warden._fs.WritableFile from owned_file() or as_given() and call write() or remove(), "
    "which raise only ProjectIOError and say what a symlink at the name means"
)
_LOOKUP = (
    "use warden._fs.resolved(), is_dir(), owned_dir() or WritableFile.present(), which raise "
    "only ProjectIOError"
)

BANNED_CALLS: dict[str, str] = {"print": _SAY, "input": _SAY, "breakpoint": _SAY, "open": _READ}

BANNED_METHODS: dict[str, str] = {
    "reconfigure": "leave the stream alone: warden._out.say() makes each write encodable",
    **dict.fromkeys(("read_text", "read_bytes", "iterdir", "glob", "rglob", "walk"), _READ),
    "open": f"to read, {_READ}; to write, {_WRITE}",
    **dict.fromkeys(
        (
            "write_text",
            "write_bytes",
            "unlink",
            "rmdir",
            "touch",
            "rename",
            "chmod",
            "mkdir",
            "symlink_to",
            "hardlink_to",
        ),
        _WRITE,
    ),
    **dict.fromkeys(
        (
            "exists",
            "is_file",
            "is_dir",
            "is_symlink",
            "is_fifo",
            "lstat",
            "stat",
            "resolve",
            "absolute",
            "readlink",
            "samefile",
            "expanduser",
        ),
        _LOOKUP,
    ),
}
"""Matched by attribute name alone, on any object but the `_fs` module itself: no type is
consulted, so a class in `src/warden` must not name a method like one of these."""

OWNERS: dict[str, frozenset[str]] = {
    "_out.py": frozenset({"print"}),
    "_fs.py": frozenset(BANNED_METHODS) - {"reconfigure"} | {"open"},
}
"""The one module that may use each name."""


def _fs_aliases(tree: ast.Module) -> frozenset[str]:
    """The names `warden._fs` is imported under: `fs.read_text(...)` is the boundary itself."""
    return frozenset(
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module is None
        for alias in node.names
        if alias.name == "_fs"
    )


def violations(path: Path) -> list[str]:
    allowed = OWNERS.get(path.name, frozenset())
    tree = ast.parse(path.read_text(encoding="utf-8"))
    boundary = _fs_aliases(tree)
    found: list[str] = []
    calls = (node for node in ast.walk(tree) if isinstance(node, ast.Call))
    for node in sorted(calls, key=lambda call: (call.lineno, call.col_offset)):
        func = node.func
        if isinstance(func, ast.Name) and func.id in BANNED_CALLS and func.id not in allowed:
            found.append(f"{path.name}:{node.lineno}: {func.id}(): {BANNED_CALLS[func.id]}")
        elif (
            isinstance(func, ast.Attribute)
            and func.attr in BANNED_METHODS
            and func.attr not in allowed
            and not (isinstance(func.value, ast.Name) and func.value.id in boundary)
        ):
            found.append(f"{path.name}:{node.lineno}: .{func.attr}(): {BANNED_METHODS[func.attr]}")
    return found


@pytest.mark.parametrize("path", sorted(SRC.glob("*.py")), ids=lambda path: path.name)
def test_only_the_boundary_modules_print_or_touch_the_file_system(path: Path) -> None:
    """Nine fixes were two mistakes made the obvious way: a `print` of project text, raw (e98134d,
    a2a5b41, d6e4ffe, 81d5c60), and a `Path` call on a project file that raised (2825ae7, b89314d,
    bf9bbd8 among them). Outside the two boundary modules neither spelling is available."""
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


def test_the_check_reports_an_unguarded_project_file_call_and_names_the_replacement(
    tmp_path: Path,
) -> None:
    """The lines are the ones b89314d, 2825ae7 and bf9bbd8 fixed: a read, a lookup and a write
    that each raised on a hostile project. A call on the `_fs` module is the fix, so it passes."""
    bad = tmp_path / "bad.py"
    bad.write_text(
        "from . import _fs as fs\n"
        'existing_lines = gitignore_path.read_text(encoding="utf-8").splitlines()\n'
        "if path.exists():\n"
        '    path.write_text(text, encoding="utf-8")\n'
        'with open(path, "a") as handle:\n'
        "    pass\n"
        "fs.read_text(path, accept=fs.Accept.ANYTHING, encoding='utf-8')\n"
        "fs.is_dir(path)\n",
        encoding="utf-8",
    )

    read, lookup, write, builtin = violations(bad)

    assert read.startswith("bad.py:2: .read_text(): use warden._fs.read_text() or read_bytes()")
    assert lookup.startswith("bad.py:3: .exists(): use warden._fs.resolved(), is_dir()")
    assert write.startswith("bad.py:4: .write_text(): get a warden._fs.WritableFile")
    assert builtin.startswith("bad.py:5: open(): use warden._fs.read_text()")


def _banned_api() -> dict[str, str]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    table = pyproject["tool"]["ruff"]["lint"]["flake8-tidy-imports"]["banned-api"]
    return {name: entry["msg"] for name, entry in cast(dict[str, dict[str, str]], table).items()}


@pytest.mark.parametrize("name", sorted(_banned_api()))
def test_ruff_reports_each_banned_name_inside_the_package_and_names_the_replacement(
    name: str,
) -> None:
    """A `banned-api` row that ruff does not match is a rule that looks enforced and is not:
    0.17.4 takes `builtins.print` without a complaint and never reports it. Each row is run
    through the locked ruff as an import in a module of `src/warden`."""
    module, _, attribute = name.rpartition(".")
    source = f"from {module} import {attribute} as banned\n" if module else f"import {name}\n"

    result = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--no-cache", "--select", "TID251"]
        + ["--stdin-filename", "src/warden/_probe.py", "-"],
        input=source,
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"`{name}` is banned: {_banned_api()[name]}" in result.stdout
    assert "warden._out" in result.stdout or "warden._fs" in result.stdout
