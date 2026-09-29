from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path
from typing import cast

from ._models import CliOptions, ResolvedConfig
from ._scanners import SCANNERS
from ._text import shown

ScalarValue = str | int | bool
RawConfigValue = ScalarValue | list[str] | dict[str, ScalarValue]
RawConfig = dict[str, RawConfigValue]


CONFIG_FILENAME = ".warden.yaml"
_KNOWN_KEYS = frozenset({"target_url", "url", "exclude_dirs", "tools"})
_TOOL_WORDS = frozenset({"1", "true", "yes", "on", "0", "false", "no", "off"})
_MAX_WARNINGS = 10


def _closing_quote(line: str, start: int) -> int | None:
    """Where the quote opened at `start` closes, or `None`. Honours `\\` and a doubled `'`."""
    quote = line[start]
    index = start + 1
    while index < len(line):
        character = line[index]
        if character == "\\":
            index += 2
            continue
        if character == quote:
            if quote == "'" and line[index + 1 : index + 2] == "'":
                index += 2
                continue
            return index
        index += 1
    return None


def _strip_comment(line: str) -> str:
    """Cut the line at the first `#` that is not escaped and not inside a quoted value.

    A quote only opens a value where a value can start (after `:` or a list `-`), and only when
    it is closed on the same line; anywhere else it is an ordinary character. One pass, so a long
    line costs no more than its length, and a project controls the file.
    """
    out: list[str] = []
    first = last = ""  # the first and the last character of what is kept, ignoring spaces
    kept = 0  # how many characters that is

    def keep(text: str) -> None:
        nonlocal first, last, kept
        out.append(text)
        for character in text:
            if not character.isspace():
                first = character if kept == 0 else first
                last = character
                kept += 1

    index = 0
    while index < len(line):
        character = line[index]
        if character == "\\":
            keep(line[index : index + 2])
            index += 2
            continue
        if character in "\"'" and (last == ":" or (kept == 1 and first == "-")):
            closing = _closing_quote(line, index)
            if closing is not None:
                keep(line[index : closing + 1])
                index = closing + 1
                continue
        if character == "#":
            break
        keep(character)
        index += 1
    return "".join(out).rstrip("\r\n")


def _parse_scalar(raw: str) -> ScalarValue:
    value = raw.strip()
    if not value:
        return ""

    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]

    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    # `isdecimal`, not `isdigit`: `isdigit` is also true for characters such as "\u00b2" that
    # `int` rejects, and the ValueError would discard the whole config file.
    if lowered.isdecimal() or (lowered.startswith("-") and lowered[1:].isdecimal()):
        try:
            return int(lowered)
        except ValueError:  # more digits than int() will convert
            return value
    return value


def _split_key_value(text: str) -> tuple[str, str] | None:
    if ":" not in text:
        return None
    key, value = text.split(":", 1)
    return key.strip(), value.strip()


def _start_context(config: RawConfig, key: str) -> str:
    config[key] = [] if key == "exclude_dirs" else {}
    return key


def _parse_top_level_line(config: RawConfig, stripped: str) -> str | None:
    parsed = _split_key_value(stripped)
    if parsed is None:
        return None

    key, value = parsed
    if value == "":
        return _start_context(config, key)

    config[key] = _parse_scalar(value)
    return None


def _append_exclude_dir(config: RawConfig, stripped: str) -> None:
    if not stripped.startswith("-"):
        return

    item = _parse_scalar(stripped[1:].strip())
    if isinstance(item, str) and item:
        exclude_dirs = cast(list[str], config.setdefault("exclude_dirs", []))
        exclude_dirs.append(item)


def _assign_tool_override(config: RawConfig, stripped: str) -> None:
    parsed = _split_key_value(stripped)
    if parsed is None:
        return

    key, value = parsed
    tools = cast(dict[str, ScalarValue], config.setdefault("tools", {}))
    tools[key] = _parse_scalar(value)


def _parse_nested_line(config: RawConfig, context: str | None, stripped: str) -> None:
    if context == "exclude_dirs":
        _append_exclude_dir(config, stripped)
    elif context == "tools":
        _assign_tool_override(config, stripped)


def _parse_with_notes(text: str) -> tuple[RawConfig, list[str]]:
    """The parsed file, and what in it Warden did not understand (which is then ignored)."""
    config: RawConfig = {}
    notes: list[str] = []
    context: str | None = None

    for number, raw_line in enumerate(textwrap.dedent(text).splitlines(), start=1):
        line = _strip_comment(raw_line)
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if indent == 0:
            context = _parse_top_level_line(config, stripped)
            if context is None and _split_key_value(stripped) is None:
                notes.append(f"line {number} ({shown(stripped, 60)}) is not `key: value`: ignored")
            continue

        if context not in {"exclude_dirs", "tools"}:
            where = f"line {number} ({shown(stripped, 60)}) is indented"
            notes.append(f"{where} but not under `exclude_dirs:` or `tools:`: ignored")
        elif context == "exclude_dirs" and not stripped.startswith("-"):
            notes.append(f"line {number} ({shown(stripped, 60)}) is not a `- entry`: ignored")
        elif context == "tools" and _split_key_value(stripped) is None:
            notes.append(f"line {number} ({shown(stripped, 60)}) is not `tool: value`: ignored")
        _parse_nested_line(config, context, stripped)

    notes.extend(
        f"unknown key {shown(key, 60)} is ignored" for key in config if key not in _KNOWN_KEYS
    )
    return config, notes


def parse_minimal_yaml(text: str) -> RawConfig:
    return _parse_with_notes(text)[0]


def _coerce_string(value: RawConfigValue | None) -> str:
    return value if isinstance(value, str) else ""


def _extract_exclude_dirs(value: RawConfigValue | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if item.strip()]


def _tool_enabled(raw_value: ScalarValue | None) -> bool:
    """A key the config file does not mention leaves its scanner enabled."""
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, int):
        return bool(raw_value)
    if isinstance(raw_value, str):
        return raw_value.strip().lower() in {"1", "true", "yes", "on"}
    return True


def _extract_enabled_tools(value: RawConfigValue | None) -> frozenset[str]:
    overrides: dict[str, ScalarValue] = value if isinstance(value, dict) else {}
    return frozenset(
        scanner.key for scanner in SCANNERS if _tool_enabled(overrides.get(scanner.key))
    )


def _shape_notes(raw: RawConfig) -> list[str]:
    """Values that parsed but that Warden then ignores or reads differently from what was meant."""
    notes: list[str] = []
    if "target_url" in raw and not isinstance(raw["target_url"], str):
        notes.append("target_url is not a string: ignored")
    if "exclude_dirs" in raw and not isinstance(raw["exclude_dirs"], list):
        notes.append("exclude_dirs is not a list of `- entry` lines: ignored")
    tools = raw.get("tools")
    if "tools" in raw and not isinstance(tools, dict):
        notes.append("tools is not a mapping of `scanner: true|false`: ignored")
    elif isinstance(tools, dict):
        known = {scanner.key for scanner in SCANNERS}
        for name, value in tools.items():
            if name not in known:
                notes.append(f"unknown tool {shown(name, 60)} under tools is ignored")
            elif isinstance(value, str) and value.strip().lower() not in _TOOL_WORDS:
                notes.append(f"tools.{name} is {shown(value, 60)}, which counts as false: disabled")
    return notes


def _resolve_target_url(raw: RawConfig) -> str:
    """`target_url` wins whenever it is present, even when it is empty."""
    if "target_url" in raw:
        return _coerce_string(raw["target_url"])
    return _coerce_string(raw.get("url"))


def _capped(warnings: list[str]) -> list[str]:
    """A hostile file can be all mistakes; the first few say what is wrong."""
    if len(warnings) <= _MAX_WARNINGS:
        return warnings
    return [*warnings[:_MAX_WARNINGS], f"... and {len(warnings) - _MAX_WARNINGS} more."]


def resolve_config(
    *,
    project_root: str | Path,
    cli_url: str,
    config_path: str | Path | None = None,
) -> ResolvedConfig:
    root = Path(project_root).resolve()
    path = Path(config_path).resolve() if config_path is not None else root / CONFIG_FILENAME

    raw: RawConfig = {}
    warnings: list[str] = []
    try:
        # The project's own `.warden.yaml` is untrusted: a named pipe there blocks forever and
        # `/dev/zero` never ends, so only a regular file is read. A path passed with `--config` is
        # the user's own choice and is read as it always was, whatever kind of file it is.
        if path.exists() if config_path is not None else path.is_file():
            raw, notes = _parse_with_notes(path.read_text(encoding="utf-8-sig"))
            warnings.extend(f"{path.name}: {note}" for note in notes)
            warnings.extend(f"{path.name}: {note}" for note in _shape_notes(raw))
        elif config_path is not None:
            warnings.append(f"--config {shown(str(path))} does not exist: using the defaults.")
        elif os.path.lexists(path):
            warnings.append(f"{path.name} is not a regular file: using the defaults.")
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raw = {}
        reason = error.strerror if isinstance(error, OSError) and error.strerror else error
        warnings.append(f"{path.name} could not be read ({reason}): using the defaults.")

    resolved_url = cli_url.strip()
    if not resolved_url:
        resolved_url = _resolve_target_url(raw).strip()
        # On a CI runner the project's own `.warden.yaml` can be changed by whoever opens a pull
        # request, and `target_url` starts an active scan against whatever it names.
        if resolved_url and config_path is None and os.environ.get("GITHUB_WORKSPACE"):
            warnings.append(
                f"target_url in {CONFIG_FILENAME} is ignored because GITHUB_WORKSPACE is set "
                "(the file can come from a pull request): pass --url to scan it."
            )
            resolved_url = ""
    exclude_dirs = _extract_exclude_dirs(raw.get("exclude_dirs"))
    enabled_tools = _extract_enabled_tools(raw.get("tools"))

    # A URL is only meaningful while some scanner that targets one is still enabled.
    if not any(scanner.requires_url and scanner.key in enabled_tools for scanner in SCANNERS):
        resolved_url = ""

    return ResolvedConfig(
        url=resolved_url,
        exclude_dirs=exclude_dirs,
        enabled_tools=enabled_tools,
        warnings=tuple(_capped(warnings)),
    )


def _parse_args(argv: list[str] | None = None) -> CliOptions:
    parser = argparse.ArgumentParser(prog="warden-config")
    parser.add_argument("project_root", help="Project root directory")
    parser.add_argument("--cli-url", default="", help="URL passed via CLI (overrides config)")
    parser.add_argument("--config", default=None, help=f"Path to {CONFIG_FILENAME}")
    namespace = parser.parse_args(argv)

    return CliOptions(
        project_root=Path(cast(str, namespace.project_root)).resolve(),
        cli_url=cast(str, namespace.cli_url),
        config_path=(
            Path(config_path).resolve()
            if (config_path := cast(str | None, namespace.config)) is not None
            else None
        ),
    )


def main(argv: list[str] | None = None) -> int:
    options = _parse_args(argv)
    resolved = resolve_config(
        project_root=options.project_root,
        cli_url=options.cli_url,
        config_path=options.config_path,
    )

    for warning in resolved.warnings:
        print(f"Warning: {warning}", file=sys.stderr)
    print(
        json.dumps(
            {
                "url": resolved.url,
                "exclude_dirs": resolved.exclude_dirs,
                "tools": {
                    scanner.key: scanner.key in resolved.enabled_tools for scanner in SCANNERS
                },
            },
            ensure_ascii=False,
        )
    )
    return 0
