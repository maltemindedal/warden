from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast


@dataclass(slots=True, frozen=True)
class LoadedJson:
    """What reading a JSON file produced: its data, or why it could not be read."""

    data: object | None = None
    error: str | None = None


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


def load_json(path: str | Path) -> LoadedJson:
    """A file that is absent is not an error; one that is present but unreadable is."""
    file_path = Path(path)
    if not file_path.exists():
        return LoadedJson()
    try:
        raw_data: object = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return LoadedJson(error=str(error))
    return LoadedJson(data=raw_data)
