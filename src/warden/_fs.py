"""The only module that touches the file system.

The scanned project is hostile input, and so is every name in it: a symlink, a named pipe, a
directory where a file belongs, a path too long to look up, bytes that are not text. Two rules
keep any of that from ending a run in a traceback:

- A read returns a value. `read_text`, `read_bytes` and `append_line` never raise for anything
  the file system or the file's bytes can do. They return one of a closed set of outcomes, and a
  caller `match`es on it with a last arm of `assert_never`, so ty rejects one that uses the text
  without saying what the other outcomes mean. Whether an outcome is a warning (the config,
  `.gitignore`) or fails the audit closed (a report that cannot be located) is written in the
  caller's `match`, where a reviewer can see it.
- Everything else raises one type. A lookup, a write, a delete or a directory Warden needs either
  works or raises `ProjectIOError`.

`tests/test_boundaries.py` and ruff's `TID251` keep `open`, the `Path` methods that touch the
disk, the `os` functions that do, `os.path` and `shutil` out of every other module.

Imports the standard library only.
"""

from __future__ import annotations

import enum
import errno
import io
import os
import stat
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Literal, cast


class ProjectIOError(Exception):
    """A path Warden needs that the file system would not give it. `str()` is `<path>: <reason>`,
    the form `warden: error: cannot prepare the report paths: ...` prints."""

    def __init__(self, path: Path, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


def _reason(error: OSError) -> str:
    """`strerror` alone when there is one: `str(error)` repeats the path, which the project
    controls."""
    return error.strerror or str(error)


@contextmanager
def _contained(path: Path) -> Generator[None]:
    """Re-raise as `ProjectIOError` what a path operation raises for hostile input: `OSError`
    (every errno), `RuntimeError` (a symlink loop in `resolve()` before Python 3.13) and
    `ValueError` (a NUL byte in the path)."""
    try:
        yield
    except OSError as error:
        named = error.filename
        where = Path(named) if isinstance(named, str) else path
        raise ProjectIOError(where, _reason(error)) from None
    except RuntimeError:
        raise ProjectIOError(path, "symbolic link loop") from None
    except ValueError as error:
        raise ProjectIOError(path, str(error)) from None


_NOT_THERE = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})
_NOT_THERE_ON_WINDOWS = frozenset({21, 123, 1921})
"""What `Path.exists()` reads as "nothing has this name" on every supported Python. Any other
error means the lookup itself failed."""


def _looked_up(path: Path, *, follow: bool) -> os.stat_result | None:
    """The file's status, or `None` when nothing has this name. Raises `ProjectIOError` when the
    lookup fails, so "not there" is never concluded from an error."""
    try:
        return os.stat(path, follow_symlinks=follow)
    except OSError as error:
        if error.errno in _NOT_THERE or getattr(error, "winerror", None) in _NOT_THERE_ON_WINDOWS:
            return None
        raise ProjectIOError(path, _reason(error)) from None
    except ValueError:  # a NUL byte: no file has such a name
        return None


Kind = Literal["a symbolic link", "a directory", "a named pipe", "a special file"]


def _kind(mode: int) -> Kind:
    """What sits at a name, in Warden's own words: safe to print."""
    if stat.S_ISLNK(mode):
        return "a symbolic link"
    if stat.S_ISDIR(mode):
        return "a directory"
    if stat.S_ISFIFO(mode):
        return "a named pipe"
    return "a special file"


class Accept(enum.Enum):
    """Which kinds of file a read will open. There is no default: the caller says where the
    path came from by choosing one."""

    REGULAR_NO_LINK = enum.auto()
    """A regular file that is not a symlink. For a name inside the project, which the project
    controls: `.warden.yaml`, which could otherwise point at any file the user can read and have
    its lines quoted in a warning, and `.gitignore`, which Warden appends to."""
    ANYTHING = enum.auto()
    """Whatever is there, through symlinks, a pipe included. For a path the user typed
    (`--config`) and for a report a scanner wrote into the directory Warden owns."""


@dataclass(frozen=True, slots=True)
class Text:
    text: str


@dataclass(frozen=True, slots=True)
class Bytes:
    data: bytes


@dataclass(frozen=True, slots=True)
class Absent:
    """Nothing has this name."""


@dataclass(frozen=True, slots=True)
class NotRegular:
    """Something has this name and `accept` rules it out. It was not read."""

    kind: Kind
    """Warden's own words, safe to print. A symlink is never followed to find out more, so one
    that dangles or loops is `a symbolic link` too."""


@dataclass(frozen=True, slots=True)
class Unlocatable:
    """The lookup failed (EACCES on a parent, ENAMETOOLONG), so Warden cannot tell whether there
    is a file. Kept apart from `Unreadable` because a report in this state fails the audit closed
    (2825ae7), while a config in this state falls back to the defaults."""

    reason: str


@dataclass(frozen=True, slots=True)
class Unreadable:
    """There is a file, and opening, reading or decoding it failed."""

    reason: str
    """`strerror` or the codec's message. Never holds the path or the file's content."""


Problem = Absent | NotRegular | Unlocatable | Unreadable

_NO_FOLLOW = cast(int, getattr(os, "O_NOFOLLOW", 0))
_NO_BLOCK = cast(int, getattr(os, "O_NONBLOCK", 0))
_BINARY = cast(int, getattr(os, "O_BINARY", 0))
"""Windows has neither of the first two, and needs the third. The checks on the status and on
the open descriptor below still hold there."""


@contextmanager
def _opened(path: Path, flags: int, mode: Literal["rb", "ab"]) -> Generator[IO[bytes]]:
    descriptor = os.open(path, flags | _BINARY)
    try:
        handle = os.fdopen(descriptor, mode)
    except OSError:  # a directory, which opens but cannot be read: nothing owns the descriptor
        os.close(descriptor)
        raise
    with handle:
        yield handle


def read_bytes(path: Path, *, accept: Accept, max_bytes: int | None) -> Bytes | Problem:
    """The file's bytes, or why there are none. Never raises for what the file system does.

    `max_bytes` has no default either: a file the project supplies is as large as the project
    likes, so the caller says how much of one it will hold. A longer file is `Unreadable`, and
    no more than `max_bytes + 1` bytes of it are read, so `/dev/zero` ends too. `None` reads
    it all.

    Unless `accept` is `ANYTHING`, the kind is checked on the open descriptor, which is opened
    without blocking, so a named pipe cannot hang the run and a swap after the check changes
    nothing.
    """
    follow = accept is not Accept.REGULAR_NO_LINK
    try:
        status = _looked_up(path, follow=follow)
    except ProjectIOError as error:
        return Unlocatable(error.reason)
    if status is None:
        return Absent()
    regular_only = accept is not Accept.ANYTHING
    if regular_only and not stat.S_ISREG(status.st_mode):
        return NotRegular(_kind(status.st_mode))
    flags = os.O_RDONLY | (0 if follow else _NO_FOLLOW) | (_NO_BLOCK if regular_only else 0)
    try:
        with _opened(path, flags, "rb") as handle:
            opened = os.fstat(handle.fileno()).st_mode
            if regular_only and not stat.S_ISREG(opened):
                return NotRegular(_kind(opened))
            if max_bytes is None:
                return Bytes(handle.read())
            data = handle.read(max_bytes + 1)
            if len(data) > max_bytes:
                return Unreadable(f"larger than {max_bytes} bytes")
            return Bytes(data)
    except OSError as error:
        if error.errno == errno.ELOOP and not follow:
            return NotRegular("a symbolic link")
        return Unreadable(_reason(error))


def _looked_up_or_none(path: Path) -> os.stat_result | None:
    try:
        return _looked_up(path, follow=False)
    except ProjectIOError:
        return None


def read_text(
    path: Path, *, accept: Accept, max_bytes: int | None, encoding: str
) -> Text | Problem:
    """`read_bytes`, decoded as `Path.read_text` decodes: a line ending is read as `\\n`. Bytes
    that are not `encoding` are `Unreadable`."""
    outcome = read_bytes(path, accept=accept, max_bytes=max_bytes)
    if not isinstance(outcome, Bytes):
        return outcome
    try:
        with io.TextIOWrapper(io.BytesIO(outcome.data), encoding=encoding) as text:
            return Text(text.read())
    except UnicodeDecodeError as error:
        return Unreadable(str(error))


@dataclass(frozen=True, slots=True)
class Appended:
    """The line was not in the file, and is now its last line."""


@dataclass(frozen=True, slots=True)
class AlreadyThere:
    """A line equal to it, once stripped, was in the file. Nothing was written."""


@dataclass(frozen=True, slots=True)
class Unwritable:
    """The file was read, the line was not in it, and appending failed."""

    reason: str


AppendOutcome = Appended | AlreadyThere | Unwritable | Problem


def append_line(path: Path, line: str) -> AppendOutcome:
    """Append `line` to the project's own text file unless it is already there.

    A best-effort edit, so it returns what happened and never raises. The file is read as
    `REGULAR_NO_LINK`: a symlink or a special file is not written through, and a file that is
    absent is not created. One that holds a NUL byte is `Unreadable("not a text file")`. The
    bytes are otherwise left alone (git reads them as bytes, in whatever encoding), and the
    newline the last line lacks is added first.
    """
    outcome = read_bytes(path, accept=Accept.REGULAR_NO_LINK, max_bytes=None)
    if not isinstance(outcome, Bytes):
        return outcome
    if b"\x00" in outcome.data:
        return Unreadable("not a text file")
    lines = outcome.data.decode("utf-8", errors="replace").splitlines()
    if any(existing.strip() == line for existing in lines):
        return AlreadyThere()
    lead = "\n" if lines and lines[-1].strip() else ""
    return _append(path, f"{lead}{line}\n".encode())


def _append(path: Path, data: bytes) -> Appended | NotRegular | Unwritable:
    """Write `data` at the end of the regular file at `path`, which is not created.

    The name was a regular file when `append_line` read it, and the project can swap it since.
    A symlink is not followed, and the open does not block, so a named pipe put there with no
    reader fails it instead of hanging the run. The kind is then checked on the open descriptor
    before anything is written, as `read_bytes` checks it.
    """
    try:
        with _opened(path, os.O_WRONLY | os.O_APPEND | _NO_FOLLOW | _NO_BLOCK, "ab") as handle:
            opened = os.fstat(handle.fileno()).st_mode
            if not stat.S_ISREG(opened):
                return NotRegular(_kind(opened))
            handle.write(data)
    except OSError as error:
        return Unwritable(_reason(error))
    return Appended()


def resolved(path: str | Path) -> Path:
    """`Path(path).resolve()`. Raises only `ProjectIOError`.

    A symlink loop raises on every Python: `resolve()` itself raises for one only before 3.13.
    """
    given = Path(path)
    try:
        os.stat(given)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ProjectIOError(given, "symbolic link loop") from None
    except ValueError:  # a NUL byte, which `resolve()` reports below
        pass
    with _contained(given):
        return given.resolve()


def is_dir(path: Path) -> bool:
    """Whether `path` is a directory, following links. A lookup that fails is `False`."""
    try:
        status = _looked_up(path, follow=True)
    except ProjectIOError:
        return False
    return status is not None and stat.S_ISDIR(status.st_mode)


def owned_dir(path: Path) -> Path:
    """Make `path` a real directory that Warden owns: a symlink there is replaced rather than
    followed, and missing parents are created. Running it twice is the same as running it once."""
    with _contained(path):
        if path.is_symlink():
            path.unlink()
        path.mkdir(parents=True, exist_ok=True)
    return path


class _OnLink(enum.Enum):
    REPLACE = enum.auto()
    FOLLOW = enum.auto()


@dataclass(frozen=True, slots=True)
class WritableFile:
    """A path Warden may write, with the decision about a symlink or pipe sitting there already
    made. The only way to write or delete a file: build one with `owned_file` or `as_given`.
    Building one touches nothing on disk."""

    path: Path
    _on_link: _OnLink

    def present(self) -> bool:
        """Whether something has this name, following links. Raises `ProjectIOError` when the
        lookup itself fails, so "no report" is never concluded from an error."""
        return _looked_up(self.path, follow=True) is not None

    def make_way(self) -> None:
        """Apply the link policy now. An owned name that is a symlink or a named pipe is
        unlinked, since writing would follow the one and block forever on the other; a regular
        file is left for `write` to replace. A name taken as given is left alone. `write` calls
        this first, so calling it early only moves the failure earlier."""
        if self._on_link is _OnLink.FOLLOW:
            return
        status = _looked_up_or_none(self.path)
        if status is not None and (stat.S_ISLNK(status.st_mode) or stat.S_ISFIFO(status.st_mode)):
            with _contained(self.path):
                self.path.unlink()

    def write(self, text: str) -> None:
        """Create missing parents, then write `text` as UTF-8. A lone surrogate, which has no
        UTF-8 encoding, is written as its `\\udcff` escape rather than raising halfway through
        and leaving the file empty (bf9bbd8)."""
        with _contained(self.path):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.make_way()
        with _contained(self.path):
            self.path.write_text(text, encoding="utf-8", errors="backslashreplace")

    def remove(self) -> None:
        """Delete the name if it is there. A symlink is unlinked, never followed."""
        with _contained(self.path):
            self.path.unlink(missing_ok=True)


def owned_file(path: Path) -> WritableFile:
    """A name Warden owns inside the project (`security_audit.json`): a symlink or named pipe
    the project put there is replaced by the regular file Warden writes."""
    return WritableFile(path, _OnLink.REPLACE)


def as_given(path: Path) -> WritableFile:
    """A path written where it leads, through a symlink: one the user typed
    (`warden-aggregate <dir> <output>`), or the report a scanner just wrote into the directory
    Warden owns, which is read and rewritten in place."""
    return WritableFile(path, _OnLink.FOLLOW)
