"""The only module that writes to the terminal.

Every function here makes its text safe in two ways before it reaches the stream, whatever the
caller passed and whichever entry point is running:

- control-safe: a character Python's `repr` would escape (`str.isprintable()` is false: C0 and C1
  controls, ESC, tab, bidi and zero-width format characters, lone surrogates, line separators,
  every space but U+0020) is written as its `\\xNN` or `\\uNNNN` escape. Every other character is
  written as it is, so an ordinary path stays byte-identical: `C:\\proj\\[2024]`, `[/red]` and
  `:warning:` are untouched.
- encoding-safe: what the stream's encoding cannot hold is written as `\\uNNNN`. No stream is
  reconfigured, so nothing depends on which `main` ran first.

`neutral` is idempotent and the identity on printable text, so text a lower layer already quoted
with `shown` passes through unchanged. Callers therefore never ask "is this string safe?": they
build a line the obvious way, with an f-string, and hand it over.

Imports the standard library and rich, and nothing else in the package.
`tests/test_boundaries.py` and ruff's `TID251` keep `print`, `sys.stdout`, `sys.stderr`, rich and
`argparse.ArgumentParser` out of every other module.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import IO, TYPE_CHECKING, Literal, NoReturn, TextIO, cast

from rich.console import Console
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from typing_extensions import override
else:  # `typing.override` needs Python 3.12, and Warden does not depend on typing_extensions

    def override(method):
        return method


def neutral(text: str) -> str:
    """`text` with each non-printable character replaced by its backslash escape. Linear time.

    `neutral(neutral(t)) == neutral(t)`, and `neutral(t) == t` when `t.isprintable()`. The result
    holds no newline, so one call to `say` is one line on the terminal.
    """
    if text.isprintable():
        return text
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in text
    )


def shown(text: str, limit: int = 120) -> str:
    """Text quoted from a project file: its `repr`, cut to `limit`.

    It marks where file text starts and ends inside a sentence and caps its length. It is not what
    makes a line safe to print: `say` does that for every line.
    """
    return repr(text[:limit]) + ("..." if len(text) > limit else "")


def _encodable(text: str, stream: TextIO) -> str:
    """`text` with what `stream` cannot encode written as a backslash escape."""
    encoding = cast(str | None, getattr(stream, "encoding", None))
    if encoding is None:
        return text
    return text.encode(encoding, "backslashreplace").decode(encoding)


def _write_line(stream: TextIO | None, line: str) -> None:
    if stream is None:  # no console at all (pythonw): `print` writes nothing there either
        return
    stream.write(_encodable(neutral(line), stream) + "\n")


def say(line: str = "") -> None:
    """Write one line to stdout. `say()` writes an empty line.

    `sys.stdout` is looked up on each call, so `capsys` and a test that swaps the stream both see
    it. A newline inside `line` is escaped like any control character: write two lines with two
    calls. Never raises `UnicodeEncodeError`.
    """
    _write_line(sys.stdout, line)


def say_err(line: str) -> None:
    """`say`, to stderr. For `warden-config`, whose stdout is one JSON document."""
    _write_line(sys.stderr, line)


def error(prog: str, message: str) -> Literal[1]:
    """Write `<prog>: error: <message>` to stderr and return the exit status of a failed run."""
    say_err(f"{prog}: error: {message}")
    return 1


def _json_escape(char: str) -> str:
    code = ord(char)
    if code < 0x10000:
        return f"\\u{code:04x}"
    code -= 0x10000
    return f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}"


def _fits(char: str, encoding: str | None) -> bool:
    if char.isascii() or encoding is None:
        return True
    try:
        char.encode(encoding)
    except UnicodeEncodeError:
        return False
    return True


def json_document(data: object) -> None:
    """Write `data` to stdout as one line of JSON that parses back to the same value.

    Printable text the stream can encode stays readable (`ensure_ascii=False`). A character that
    is not printable, or that the stream cannot encode, is written as a JSON `\\uXXXX` escape, a
    surrogate pair past the BMP: `backslashreplace` would write `\\U0001f600` and `\\xa0`, which
    are not JSON. `json.dumps` puts such a character only inside a string, where the escape is
    valid.
    """
    stream = sys.stdout
    if stream is None:
        return
    encoding = cast(str | None, getattr(stream, "encoding", None))
    text = json.dumps(data, ensure_ascii=False)
    stream.write(
        "".join(
            char if char.isprintable() and _fits(char, encoding) else _json_escape(char)
            for char in text
        )
        + "\n"
    )


@dataclass(frozen=True, slots=True)
class Span:
    """A run of text and the rich style name it is drawn in. `text` is escaped like any other."""

    text: str
    style: str = ""


class _Stdout:
    """The live `sys.stdout`, with every write made encodable, for rich to write through."""

    def write(self, text: str) -> int:
        return cast(int, sys.stdout.write(_encodable(text, sys.stdout)))

    def __getattr__(self, name: str) -> object:
        return getattr(sys.stdout, name)


def _console() -> Console:
    # Built per call, so rich reads FORCE_COLOR, NO_COLOR, COLUMNS and the terminal on each run.
    return Console(file=cast(IO[str], _Stdout()))


def _plain(parts: Sequence[str | Span]) -> Text:
    text = Text()
    for part in parts:
        if isinstance(part, Span):
            text.append(neutral(part.text), style=part.style)
        else:
            text.append(neutral(part))
    return text


def say_styled(*parts: str | Span) -> None:
    """Write one line to stdout through rich.

    Each part is appended as plain text, never parsed as markup or emoji codes: a path named like
    markup (`[/red]`), like an emoji code (`:warning:`) or ending in a backslash prints as written.
    rich's repr highlighter, which colours a path on a terminal, then runs over the line.
    """
    console = _console()
    console.print(console.highlighter(_plain(parts)))


Justify = Literal["left", "right"]


def table(columns: Sequence[tuple[str, Justify]], rows: Sequence[Sequence[str | Span]]) -> None:
    """Write a rich table with a bold header. Every cell is plain text, escaped, not highlighted."""
    grid = Table(show_header=True, header_style="bold")
    for header, justify in columns:
        grid.add_column(_plain([header]), justify=justify)
    for row in rows:
        grid.add_row(*(_plain([cell]) for cell in row))
    _console().print(grid)


class ArgumentParser(argparse.ArgumentParser):
    """argparse, with the error line it prints sent through `say_err`.

    argparse echoes argv into its own messages (`unrecognized arguments: ...`), and a caller's
    `parser.error` echoes a path, and argparse writes both to stderr itself.
    """

    @override
    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message is not None:
            say_err(message.removesuffix("\n"))
        sys.exit(status)
