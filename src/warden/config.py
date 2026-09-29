from __future__ import annotations

import argparse
import json
import textwrap
from pathlib import Path
from typing import cast

from ._models import CliOptions, ResolvedConfig
from ._scanners import SCANNERS

ScalarValue = str | int | bool
RawConfigValue = ScalarValue | list[str] | dict[str, ScalarValue]
RawConfig = dict[str, RawConfigValue]


CONFIG_FILENAME = ".warden.yaml"


def _strip_comment(line: str) -> str:
    out: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            out.append(character)
            escaped = False
            continue
        if character == "\\":
            out.append(character)
            escaped = True
            continue
        if character == "#":
            break
        out.append(character)
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


def parse_minimal_yaml(text: str) -> RawConfig:
    config: RawConfig = {}
    context: str | None = None

    for raw_line in textwrap.dedent(text).splitlines():
        line = _strip_comment(raw_line)
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if indent == 0:
            context = _parse_top_level_line(config, stripped)
            continue

        _parse_nested_line(config, context, stripped)

    return config


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


def _resolve_target_url(raw: RawConfig) -> str:
    """`target_url` wins whenever it is present, even when it is empty."""
    if "target_url" in raw:
        return _coerce_string(raw["target_url"])
    return _coerce_string(raw.get("url"))


def resolve_config(
    *,
    project_root: str | Path,
    cli_url: str,
    config_path: str | Path | None = None,
) -> ResolvedConfig:
    root = Path(project_root).resolve()
    path = Path(config_path).resolve() if config_path is not None else root / CONFIG_FILENAME

    raw: RawConfig = {}
    try:
        # The project's own `.warden.yaml` is untrusted: a named pipe there blocks forever and
        # `/dev/zero` never ends, so only a regular file is read. A path passed with `--config` is
        # the user's own choice and is read as it always was, whatever kind of file it is.
        if path.exists() if config_path is not None else path.is_file():
            raw = parse_minimal_yaml(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, ValueError):
        raw = {}

    resolved_url = cli_url.strip() or _resolve_target_url(raw).strip()
    exclude_dirs = _extract_exclude_dirs(raw.get("exclude_dirs"))
    enabled_tools = _extract_enabled_tools(raw.get("tools"))

    # A URL is only meaningful while some scanner that targets one is still enabled.
    if not any(scanner.requires_url and scanner.key in enabled_tools for scanner in SCANNERS):
        resolved_url = ""

    return ResolvedConfig(url=resolved_url, exclude_dirs=exclude_dirs, enabled_tools=enabled_tools)


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
