from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import assert_never, cast

from . import _fs as fs


@dataclass(slots=True, frozen=True)
class LoadedJson:
    """What reading a JSON file produced: its data, or why it could not be read."""

    data: object | None = None
    error: str | None = None
    found: bool = False
    """Whether the file was there: an absent file and one holding `null` both have no data."""


class JsonLimitError(Exception):
    """A file that is JSON, but more than this Python can parse.

    `json.loads` gives up on nesting past the interpreter's recursion limit (around 1,000 levels on
    Python 3.11, around 10,000 from 3.12) and on an integer of more than 4,300 digits. A report it
    gives up on may hold findings, so this is raised rather than returned: a caller that does not
    expect it stops the audit, which fails closed, instead of passing without those findings.
    """


def as_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return None


def iter_list_items(value: object) -> Iterator[object]:
    if isinstance(value, list):
        yield from cast(list[object], value)


def iter_mappings(value: object) -> Iterator[Mapping[str, object]]:
    for item in iter_list_items(value):
        narrowed = as_mapping(item)
        if narrowed is not None:
            yield narrowed


def get_string(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value.strip() else None


def get_int(mapping: Mapping[str, object], key: str) -> int | None:
    value = mapping.get(key)
    # A bool is an int, but JSON `true` is not a number worth reporting.
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().isdecimal():
        try:
            return int(value.strip())
        except ValueError:  # more digits than int() will convert
            return None
    return None


def write_json(target: fs.WritableFile, data: object) -> None:
    """Write `data` as indented JSON, with non-ASCII text left readable rather than escaped.

    A lone surrogate, which a report can hold as a `\\udcff` escape, has no UTF-8 encoding.
    `WritableFile.write` writes it back as the same escape, which reads back as the same string:
    `json.dumps` only puts one inside a string, where that escape is valid JSON.
    """
    target.write(json.dumps(data, indent=2, ensure_ascii=False))


def load_json(path: str | Path) -> LoadedJson:
    """A file that is absent is not an error; one that is present but unreadable is.

    One that is valid JSON but more than this Python can parse raises `JsonLimitError`, and one
    that cannot be looked up raises `fs.ProjectIOError`: either may hold findings, so the audit
    fails rather than pass without them.
    """
    file_path = Path(path)
    # A report is read through a symlink, as the scanner wrote it: the directory is Warden's own,
    # and refusing one could only drop findings.
    match fs.read_text(file_path, accept=fs.Accept.ANYTHING, max_bytes=None, encoding="utf-8"):
        case fs.Absent():
            return LoadedJson()
        case fs.Unlocatable(reason):
            raise fs.ProjectIOError(file_path, reason)
        case fs.NotRegular(kind):
            return LoadedJson(error=f"it is {kind}", found=True)
        case fs.Unreadable(reason):
            # The caller names the report file, and `reason` never repeats its path, which the
            # project controls.
            return LoadedJson(error=reason, found=True)
        case fs.Text(text):
            try:
                return LoadedJson(data=cast(object, json.loads(text)), found=True)
            except json.JSONDecodeError as error:
                return LoadedJson(error=str(error), found=True)
            except (RecursionError, ValueError) as error:
                # A decode error is a `ValueError` too, so what is left is the integer limit.
                raise JsonLimitError(
                    f"{file_path.name} is more JSON than Python can parse ({error})"
                ) from None
        case _ as unreachable:
            assert_never(unreachable)
