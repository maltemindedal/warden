from __future__ import annotations

import argparse
import io
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

from . import aggregate, config, tooling
from ._models import CliOptions, ResolvedConfig
from ._scanners import SCANNERS, Scanner, rewrite_zap_target, url_problem
from ._text import shown

_MAX_TIMEOUT_SECONDS = 4_294_967
"""Windows takes a timeout in milliseconds as an unsigned 32-bit number, so nothing larger works."""

EXIT_INCOMPLETE = 3
"""`--strict`: no finding failed the build, but a scanner that ran left no usable report."""


def _parse_args(argv: list[str] | None = None) -> CliOptions:
    parser = argparse.ArgumentParser(prog="warden", description="Run the Warden security audit.")
    parser.add_argument(
        "-u",
        "--url",
        "-Url",
        "--Url",
        dest="url",
        default="",
        help="Optional DAST target URL",
    )
    parser.add_argument(
        "--project-root",
        default=".",
        help="Project root to scan (defaults to the current working directory)",
    )
    parser.add_argument("--config", default=None, help=f"Optional path to {config.CONFIG_FILENAME}")
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Exit 3 when a scanner that ran left no usable report, or no scanner ran, "
            "instead of passing"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Stop any single scanner that runs longer than this (default: no limit)",
    )
    namespace = parser.parse_args(argv)
    timeout = cast(float | None, namespace.timeout)
    if timeout is not None and not 0 < timeout <= _MAX_TIMEOUT_SECONDS:  # also rejects nan, inf
        parser.error(f"--timeout must be a number of seconds from 0 up to {_MAX_TIMEOUT_SECONDS}")
    project_root = Path(cast(str, namespace.project_root)).resolve()
    if not project_root.is_dir():
        parser.error(f"--project-root {project_root} is not an existing directory")
    config_path_value = cast(str | None, namespace.config)
    return CliOptions(
        project_root=project_root,
        cli_url=cast(str, namespace.url),
        config_path=Path(config_path_value).resolve() if config_path_value is not None else None,
        timeout=timeout,
        strict=cast(bool, namespace.strict),
    )


def _incomplete(tools: _ToolsRun, skipped_for_url: tuple[str, ...]) -> str | None:
    """What `--strict` holds against the run, or `None` if every scanner that was asked for ran."""
    missing = [*tools.unusable, *skipped_for_url]
    if missing:
        return f"{', '.join(missing)} did not produce a usable report, so the scan is incomplete."
    if not tools.attempted:
        return "no scanner ran, so the scan is incomplete."
    return None


def _describe(error: OSError) -> str:
    return (
        f"{error.filename}: {error.strerror}" if error.filename and error.strerror else str(error)
    )


def _fail(message: str) -> int:
    """A path the project controls that Warden cannot use: a failed run, not a traceback."""
    print(f"warden: error: {message}", file=sys.stderr)
    return 1


def _print_result(result: tooling.ToolRunResult) -> None:
    if result.returncode is None and result.warning is not None:
        print(f"   -> Warning: {result.warning}")
        return
    if result.succeeded or result.report_written:
        print("   -> Done.")
        return
    if result.warning is not None:
        print(f"   -> Warning: {result.warning}")
        return
    print(f"   -> Warning: {result.scanner.label} exited with status {result.returncode}.")


def _announce_zap_target(url: str) -> None:
    """A URL-targeting scanner runs in a container, where localhost is not the host."""
    target = rewrite_zap_target(url)
    if target != url:
        print(
            "      (Detected localhost: switching to "
            "'host.docker.internal' for Docker compatibility)"
        )
        print(f"      Targeting: {target}")


def _url_scanners(resolved: ResolvedConfig) -> tuple[str, ...]:
    """The enabled scanners that target the DAST URL rather than the project's files."""
    return tuple(
        scanner.label
        for scanner in SCANNERS
        if scanner.requires_url and scanner.key in resolved.enabled_tools
    )


def _skip_reason(scanner: Scanner, *, enabled: bool, url: str) -> str | None:
    """Why this scanner will not run, or `None` if it will."""
    if scanner.requires_url and not (enabled and url):
        return "no URL provided or disabled"
    if not scanner.requires_url and not enabled:
        return f"disabled in {config.CONFIG_FILENAME}"
    return None


@dataclass(slots=True, frozen=True)
class _ToolsRun:
    """Which scanners were started, and which of those left no usable report."""

    attempted: tuple[str, ...]
    unusable: tuple[str, ...]


def _run_enabled_tools(
    project_root: Path,
    report_dir: Path,
    resolved: ResolvedConfig,
    runner: tooling.CommandRunner,
    timeout: float | None,
) -> _ToolsRun:
    total = len(SCANNERS)
    attempted: list[str] = []
    unusable: list[str] = []

    print()
    for step, scanner in enumerate(SCANNERS, start=1):
        stage = f"[{step}/{total}]"
        enabled = scanner.key in resolved.enabled_tools
        reason = _skip_reason(scanner, enabled=enabled, url=resolved.url)
        if reason is not None:
            print(f"{stage} Skipping {scanner.label} ({reason}).")
            continue

        print(f"{stage} Running {scanner.label}...")
        if scanner.requires_url:
            _announce_zap_target(resolved.url)
        request = tooling.scan_request(
            scanner,
            project_root=project_root,
            report_dir=report_dir,
            exclude_dirs=resolved.exclude_dirs,
            url=resolved.url,
        )
        result = tooling.run_scanner(scanner, request, runner, timeout=timeout)
        _print_result(result)
        attempted.append(scanner.label)
        if not result.report_usable:
            unusable.append(scanner.label)
    return _ToolsRun(attempted=tuple(attempted), unusable=tuple(unusable))


def run_audit(options: CliOptions, *, runner: tooling.CommandRunner) -> int:
    resolved = config.resolve_config(
        project_root=options.project_root,
        cli_url=options.cli_url,
        config_path=options.config_path,
    )
    output_file = options.project_root / "security_audit.json"
    try:
        report_dir = tooling.prepare_report_dir(options.project_root)
        tooling.clear_output_file(output_file)
    except OSError as error:
        return _fail(f"cannot prepare the report paths: {_describe(error)}")

    print("STARTING SECURITY AUDIT")
    print(f"   Target: {options.project_root}")
    for warning in resolved.warnings:
        print(f"Warning: {warning}")
    skipped_for_url: tuple[str, ...] = ()
    if resolved.url:
        problem = url_problem(resolved.url)
        if problem is None:
            print(f"   DAST URL: {resolved.url}")
        else:
            skipped_for_url = _url_scanners(resolved)
            shown_url = shown(resolved.url)
            print(
                f"Warning: the DAST URL {shown_url} is not usable ({problem}): "
                f"skipping {', '.join(skipped_for_url)}."
            )
            resolved = replace(resolved, url="")

    tools = _run_enabled_tools(options.project_root, report_dir, resolved, runner, options.timeout)

    print("\n[*] Generating Final Report...")
    try:
        verdict = aggregate.generate_report(report_dir=report_dir, output_file=output_file)
    except OSError as error:
        return _fail(f"cannot read the reports or write {output_file.name}: {_describe(error)}")
    incomplete = _incomplete(tools, skipped_for_url) if options.strict else None
    if incomplete is not None:
        print(f"\nSTRICT: {incomplete}")
    if verdict.failed:
        print("\nAUDIT FAILED!")
        print(f"Report saved to: {output_file}")
        return 1
    if incomplete is not None:
        print("\nAUDIT INCOMPLETE!")
        print(f"Report saved to: {output_file}")
        return EXIT_INCOMPLETE

    print("\nAUDIT COMPLETE!")
    print(f"Report saved to: {output_file}")
    return 0


def _print_unencodable_text_escaped() -> None:
    """Warden echoes text the project supplied (a config warning, a URL), and a console that
    cannot encode it (a Windows code page on a redirected stdout) must not turn that into a
    traceback: print it as `\\uXXXX` instead, as Python already does for stderr."""
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="backslashreplace")


def main(
    argv: list[str] | None = None,
    *,
    runner: tooling.CommandRunner = tooling.run_subprocess,
) -> int:
    _print_unencodable_text_escaped()
    return run_audit(_parse_args(argv), runner=runner)
