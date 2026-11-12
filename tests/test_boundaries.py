"""The two boundaries of `src/warden`: only `_out.py` writes to the terminal, and only `_fs.py`
touches the file system.

ruff's `TID251` (see `pyproject.toml`) bans the names it can resolve: `sys.stdout`, `sys.exit`,
`rich`, `logging`, `os.open`, `os.path`, `shutil` and the rest of that table. ruff 0.17.4 does
not match a builtin such as `print`, `open` or `SystemExit`, nor an attribute of a `Path`
instance, so a walk over the syntax tree covers those.

The walk looks at every reference, not only at calls: `map(Path.read_text, paths)`,
`reader = path.read_text` and `getattr(path, "read_text")` never call the method by name.
"""

from __future__ import annotations

import ast
import functools
import json
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path, PurePath
from typing import cast

import pytest

ROOT = Path(__file__).parents[1]
SRC = ROOT / "src" / "warden"

_SAY = "use warden._out.say(), which escapes project text and survives a cp1252 stdout"
_EXIT = (
    "return the status from main(), and say why with warden._out.error(), which escapes project "
    "text, writes `<prog>: error: <message>` to stderr and returns 1"
)
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

BANNED_NAMES: dict[str, str] = {
    **dict.fromkeys(("print", "input", "breakpoint"), _SAY),
    **dict.fromkeys(("exit", "quit", "SystemExit"), _EXIT),
    "open": _READ,
}
"""Builtins, wherever they are named: called, passed to `map` or bound to another name."""

_PATH_ONLY = frozenset(
    name for name in set(dir(Path)) - set(dir(PurePath)) if not name.startswith("_")
)
"""Every public name a `Path` has and a `PurePath` lacks: the ones that touch the disk. Derived
rather than listed, so a method nobody thought of (`is_socket`, `owner`, `cwd`, `home`) and one a
newer Python adds are banned as well."""

_READS = frozenset({"read_text", "read_bytes", "iterdir", "glob", "rglob", "walk"})
_WRITES = frozenset(
    {
        "write_text",
        "write_bytes",
        "unlink",
        "rmdir",
        "touch",
        "rename",
        "replace",
        "chmod",
        "lchmod",
        "mkdir",
        "symlink_to",
        "hardlink_to",
        "link_to",
        "copy",
        "copy_into",
        "move",
        "move_into",
    }
)
"""Only which replacement the message names. A name in neither set gets the lookup one."""


def _replacement(name: str) -> str:
    if name == "open":
        return f"to read, {_READ}; to write, {_WRITE}"
    if name in _READS:
        return _READ
    return _WRITE if name in _WRITES else _LOOKUP


BANNED_ATTRIBUTES: dict[str, str] = {
    "reconfigure": "leave the stream alone: warden._out.say() makes each write encodable",
    **{name: _replacement(name) for name in sorted(_PATH_ONLY | _READS | _WRITES)},
}
"""Matched by attribute name alone, on any object: no type is consulted, so a class in
`src/warden` must not name a method or a field like one of these."""

NOT_THE_PATH_METHOD: dict[str, Callable[[ast.Call | None], bool]] = {
    "replace": lambda call: call is not None and len(call.args) + len(call.keywords) >= 2,
    "copy": lambda call: call is not None and not call.args and not call.keywords,
    "cwd": lambda call: call is None,
}
"""The banned names `src/warden` also uses on something that is not a `Path`, with the shape
that tells that use apart. `call` is the call the attribute is the function of, or `None` when it
is only read. `str.replace(old, new)` takes two arguments where `Path.replace(target)` takes one,
`os.environ.copy()` takes none where `Path.copy(target)` (Python 3.14) takes one, and a scanner
command's `cwd` field is read where `Path.cwd()` is called."""

OWNERS: dict[str, frozenset[str]] = {
    "_fs.py": frozenset(BANNED_ATTRIBUTES) - {"reconfigure"},
    "__main__.py": frozenset({"SystemExit"}),
}
"""The one module that may use each name. `_out.py` needs none of them: it writes to the stream
it is handed."""

BOUNDARIES = ("_fs", "_out")


def _public_names(module: str) -> frozenset[str]:
    """What a boundary module defines for the others: its functions and classes."""
    tree = ast.parse((SRC / f"{module}.py").read_text(encoding="utf-8"))
    return frozenset(
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.ClassDef) and not node.name.startswith("_")
    )


def _boundary_aliases(tree: ast.Module) -> dict[str, ast.alias]:
    """The names the boundary modules are imported under (`from . import _fs as fs`)."""
    return {
        alias.asname or alias.name: alias
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module is None
        for alias in node.names
        if alias.name in BOUNDARIES
    }


def _bound_names(node: ast.AST) -> list[str]:
    """The names this one node binds, if it binds any."""
    match node:
        case ast.Name(id=name, ctx=ast.Store() | ast.Del()):
            return [name]
        case ast.arg(arg=name) | ast.ExceptHandler(name=str(name)):
            return [name]
        case ast.FunctionDef(name=name) | ast.AsyncFunctionDef(name=name) | ast.ClassDef(name=name):
            return [name]
        case ast.alias(name=name, asname=asname):
            return [asname or name.partition(".")[0]]
        case ast.MatchAs(name=str(name)) | ast.MatchStar(name=str(name)):
            return [name]
        case ast.MatchMapping(rest=str(name)):
            return [name]
        case ast.Global(names=names) | ast.Nonlocal(names=names):
            return names
        case _:
            return []


def _position(node: ast.AST) -> tuple[int, int]:
    return (cast(int, getattr(node, "lineno", 0)), cast(int, getattr(node, "col_offset", 0)))


def violations(path: Path) -> list[str]:
    allowed = OWNERS.get(path.name, frozenset())
    tree = ast.parse(path.read_text(encoding="utf-8"))
    aliases = _boundary_aliases(tree)
    fs_names = {name for name, alias in aliases.items() if alias.name == "_fs"}
    fs_exports = _public_names("_fs")
    called = {
        id(node.func): node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    def report(node: ast.AST, what: str, fix: str) -> None:
        found.append((_position(node), f"{path.name}:{_position(node)[0]}: {what}: {fix}"))

    found: list[tuple[tuple[int, int], str]] = []
    for node in ast.walk(tree):
        for name in _bound_names(node):
            if name in aliases and node is not aliases[name]:
                module = aliases[name].name
                report(
                    node,
                    f"`{name}` is bound again",
                    f"`{name}` is the name warden.{module} is imported under, so pick another "
                    f"name here: `{name}.<anything>` must always mean the boundary module",
                )
        match node:
            case ast.Name(id=name, ctx=ast.Load()) if name in BANNED_NAMES and name not in allowed:
                report(node, name, BANNED_NAMES[name])
            case ast.Attribute(value=value, attr=attr) if (
                attr in BANNED_ATTRIBUTES and attr not in allowed
            ):
                # `fs.read_text` is the boundary itself, but only for a name `_fs` defines:
                # `fs.exists` is not one, whatever `fs` is.
                through_fs = isinstance(value, ast.Name) and value.id in fs_names
                other_use = NOT_THE_PATH_METHOD.get(attr, lambda call: False)
                if not (through_fs and attr in fs_exports) and not other_use(called.get(id(node))):
                    report(node, f".{attr}", BANNED_ATTRIBUTES[attr])
            case ast.Call(
                func=ast.Name(id="getattr"), args=[_, ast.Constant(value=str(attr)), *_]
            ) if attr in BANNED_ATTRIBUTES and attr not in allowed:
                report(node, f'getattr(..., "{attr}")', BANNED_ATTRIBUTES[attr])
            case _:
                pass
    return [line for _, line in sorted(found)]


@pytest.mark.parametrize("path", sorted(SRC.glob("*.py")), ids=lambda path: path.name)
def test_only_the_boundary_modules_print_or_touch_the_file_system(path: Path) -> None:
    """Nine fixes were two mistakes made the obvious way: a `print` of project text, raw (e98134d,
    a2a5b41, d6e4ffe, 81d5c60), and a `Path` call on a project file that raised (2825ae7, b89314d,
    bf9bbd8 among them). Outside the two boundary modules neither spelling is available."""
    assert violations(path) == [], "\n" + "\n".join(violations(path))


def _violations_of(tmp_path: Path, source: str) -> list[str]:
    bad = tmp_path / "bad.py"
    bad.write_text(source, encoding="utf-8")
    return violations(bad)


def test_the_check_reports_a_print_and_names_the_replacement(tmp_path: Path) -> None:
    """The check must fail on the mistake it exists for, with the fix in the message."""
    first, second = _violations_of(
        tmp_path, 'print(f"   Target: {root}")\nsys.stdout.reconfigure(errors="replace")\n'
    )

    assert first.startswith("bad.py:1: print: use warden._out.say()")
    assert second.startswith("bad.py:2: .reconfigure: leave the stream alone: warden._out.say()")


def test_the_check_reports_an_unguarded_project_file_call_and_names_the_replacement(
    tmp_path: Path,
) -> None:
    """The lines are the ones b89314d, 2825ae7 and bf9bbd8 fixed: a read, a lookup and a write
    that each raised on a hostile project. A call on the `_fs` module is the fix, so it passes."""
    read, lookup, write, builtin = _violations_of(
        tmp_path,
        "from . import _fs as fs\n"
        'existing_lines = gitignore_path.read_text(encoding="utf-8").splitlines()\n'
        "if path.exists():\n"
        '    path.write_text(text, encoding="utf-8")\n'
        'with open(path, "a") as handle:\n'
        "    pass\n"
        "fs.read_text(path, accept=fs.Accept.ANYTHING, encoding='utf-8')\n"
        "fs.is_dir(path)\n",
    )

    assert read.startswith("bad.py:2: .read_text: use warden._fs.read_text() or read_bytes()")
    assert lookup.startswith("bad.py:3: .exists: use warden._fs.resolved(), is_dir()")
    assert write.startswith("bad.py:4: .write_text: get a warden._fs.WritableFile")
    assert builtin.startswith("bad.py:5: open: use warden._fs.read_text()")


@pytest.mark.parametrize(
    ("line", "reported"),
    [
        ("texts = list(map(Path.read_text, paths))", ".read_text: use warden._fs.read_text()"),
        ("ok = sorted(paths, key=Path.exists)", ".exists: use warden._fs.resolved()"),
        ("reader = path.read_text", ".read_text: use warden._fs.read_text()"),
        ('getattr(path, "read_text")()', 'getattr(..., "read_text"): use warden._fs.read_text()'),
        ("here = Path.cwd()", ".cwd: use warden._fs.resolved()"),
        ("home = Path.home()", ".home: use warden._fs.resolved()"),
        ("tmp.replace(target)", ".replace: get a warden._fs.WritableFile"),
        ("path.is_socket()", ".is_socket: use warden._fs.resolved()"),
        ("path.owner()", ".owner: use warden._fs.resolved()"),
        ("show = print", "print: use warden._out.say()"),
        ('raise SystemExit(f"bad {name}")', "SystemExit: return the status from main()"),
        ('exit(f"bad {name}")', "exit: return the status from main()"),
    ],
)
def test_the_check_reports_a_banned_name_however_it_is_reached(
    line: str, reported: str, tmp_path: Path
) -> None:
    """A review walked around the first version of this check, which matched calls by a list of
    method names: a method passed as a value, bound to a name or fetched with `getattr` was never
    called by name, and `cwd`, `home`, `replace`, `is_socket` and `owner` were not on the list.
    Nor was a `SystemExit` with a message, which Python prints to stderr as it is."""
    (found,) = _violations_of(tmp_path, line + "\n")

    assert found.startswith(f"bad.py:1: {reported}")


@pytest.mark.parametrize(
    "line",
    [
        'slashed = entry.replace(os.sep, "/")',
        "environment = os.environ.copy()",
        "runner(command.args, cwd=command.cwd)",
    ],
)
def test_the_check_tells_a_path_method_from_the_other_use_of_its_name(
    line: str, tmp_path: Path
) -> None:
    """`replace`, `copy` and `cwd` are names `src/warden` uses on a `str`, a `dict` and a scanner
    command. Each is told from the `Path` method by its shape, not let through by its name."""
    assert _violations_of(tmp_path, line + "\n") == []


def test_the_fs_alias_only_passes_what_fs_defines_and_cannot_be_bound_again(
    tmp_path: Path,
) -> None:
    """`fs.<method>` used to pass for any `fs`, so `fs = project_root` followed by
    `fs.read_text()` read the project file raw, and `fs.exists()` passed although `_fs` has no
    such function. `config.py` named a local list `out`, the name `_out` is imported under."""
    rebound, not_exported, parameter, loop = _violations_of(
        tmp_path,
        "from . import _fs as fs\n"
        "from . import _out as out\n"
        "fs = project_root\n"
        "fs.read_text()\n"
        "fs.exists()\n"
        "def strip(out: list[str]) -> None:\n"
        "    for fs in out:\n"
        "        pass\n",
    )

    assert rebound.startswith("bad.py:3: `fs` is bound again: `fs` is the name warden._fs is")
    assert not_exported.startswith("bad.py:5: .exists: use warden._fs.resolved()")
    assert parameter.startswith("bad.py:6: `out` is bound again: `out` is the name warden._out is")
    assert loop.startswith("bad.py:7: `fs` is bound again")


def _banned_api() -> dict[str, str]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    table = pyproject["tool"]["ruff"]["lint"]["flake8-tidy-imports"]["banned-api"]
    return {name: entry["msg"] for name, entry in cast(dict[str, dict[str, str]], table).items()}


def _ruff_hits(source: str) -> dict[int, list[str]]:
    """What the locked ruff's `TID251` reports for `source` as a module of `src/warden` that owns
    no banned name: each message, by line."""
    result = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--no-cache", "--select", "TID251"]
        + ["--output-format", "json", "--stdin-filename", "src/warden/_probe.py", "-"],
        input=source,
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=ROOT,
        check=False,
    )
    assert result.returncode in (0, 1), result.stdout + result.stderr
    hits: dict[int, list[str]] = {}
    for hit in cast(list[dict[str, object]], json.loads(result.stdout)):
        row = cast(dict[str, int], hit["location"])["row"]
        hits.setdefault(row, []).append(cast(str, hit["message"]))
    return hits


def _import_of(name: str) -> str:
    module, _, attribute = name.rpartition(".")
    return f"from {module} import {attribute} as banned" if module else f"import {name}"


@functools.cache
def _hits_for_every_row() -> dict[int, list[str]]:
    """One ruff run over a module that imports each banned name on a line of its own."""
    return _ruff_hits("".join(f"{_import_of(name)}\n" for name in sorted(_banned_api())))


@pytest.mark.parametrize(("line", "name"), list(enumerate(sorted(_banned_api()), start=1)))
def test_ruff_reports_each_banned_name_inside_the_package_and_names_the_replacement(
    line: int, name: str
) -> None:
    """A `banned-api` row that ruff does not match is a rule that looks enforced and is not:
    0.17.4 takes `builtins.print` without a complaint and never reports it. Each row is run
    through the locked ruff as an import in a module of `src/warden`, and names the one boundary
    module that owns it."""
    message = _banned_api()[name]

    assert _hits_for_every_row().get(line) == [f"`{name}` is banned: {message}"]
    assert ("warden._out" in message) != ("warden._fs" in message), message


def _other_boundarys_names(module: str, source: str) -> list[str]:
    """The `TID251` hits in `source` that belong to the boundary module `module` is not."""
    return [
        f"{module}.py:{line}: {message}"
        for line, messages in sorted(_ruff_hits(source).items())
        for message in messages
        if f"warden.{module}" not in message
    ]


@pytest.mark.parametrize("module", BOUNDARIES)
def test_a_boundary_module_uses_only_the_banned_names_it_owns(module: str) -> None:
    """`pyproject.toml` can only switch `TID251` off for a whole file, so `_out.py` could list a
    directory and `_fs.py` could print. Each is linted here as a module with no exemption, and
    every hit must be a name whose message sends the reader to that same module."""
    source = (SRC / f"{module}.py").read_text(encoding="utf-8")

    assert _other_boundarys_names(module, source) == []


def test_the_ownership_check_reports_the_other_boundarys_name() -> None:
    """The check above must fail on the mistake it exists for: `_out.py` touching the disk."""
    found = _other_boundarys_names("_out", "import sys\nimport shutil\nsys.stdout.write('')\n")

    assert found == [
        "_out.py:2: `shutil` is banned: Use warden._fs: it is the only module that touches "
        "the file system."
    ]
