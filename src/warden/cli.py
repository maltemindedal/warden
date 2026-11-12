from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

from . import _fs as fs
from . import _out as out
from . import aggregate, config, tooling
from ._json import JsonLimitError
from ._models import CliOptions, ResolvedConfig
from ._scanners import SCANNERS, Scanner, rewrite_zap_target, url_problem

_MAX_TIMEOUT_SECONDS = 4_294_967
"""Windows takes a timeout in milliseconds as an unsigned 32-bit number, so nothing larger works."""

EXIT_INCOMPLETE = 3
"""Strict, the default: no finding failed the build, but a scanner that ran left no usable
report."""

_OPT_OUT = "to accept an incomplete scan, pass --no-strict."


def _parse_args(argv: list[str] | None = None) -> CliOptions:
    parser = out.ArgumentParser(prog="warden", description="Run the Warden security audit.")
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
        type=out.path_argument,
        default=".",
        help="Project root to scan (defaults to the current working directory)",
    )
    parser.add_argument(
        "--config",
        type=out.path_argument,
        default=None,
        help=f"Optional path to {config.CONFIG_FILENAME}",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=True,
        help="Accepted for older pipelines; strict is the default",
    )
    parser.add_argument(
        "--no-strict",
        dest="strict",
        action="store_false",
        help=(
            "Pass with a warning when a scanner that ran left no usable report, or no scanner "
            "ran, instead of exiting 3"
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
    project_root = cast(Path, namespace.project_root)
    if not fs.is_dir(project_root):
        parser.error(f"--project-root {project_root} is not an existing directory")
    return CliOptions(
        project_root=project_root,
        cli_url=cast(str, namespace.url),
        config_path=cast(Path | None, namespace.config),
        timeout=timeout,
        strict=cast(bool, namespace.strict),
    )


def _incomplete(
    attempted: tuple[str, ...], tools_run: list[str], skipped_for_url: tuple[str, ...]
) -> str | None:
    """What strict mode holds against the run, or `None` if every scanner that was asked for ran.

    A scanner that was started counts as run exactly when the report lists it in `tools_run`, so
    the gate cannot pass on a report the aggregator did not read.
    """
    missing = [*(label for label in attempted if label not in tools_run), *skipped_for_url]
    if missing:
        names = ", ".join(missing)
        return f"{names} did not produce a usable report, so the scan is incomplete; {_OPT_OUT}"
    if not attempted:
        return f"no scanner ran, so the scan is incomplete; {_OPT_OUT}"
    return None


def _print_result(result: tooling.ToolRunResult) -> None:
    _print_status(result)
    if result.report_warning is not None:
        out.say(f"   -> Warning: {result.report_warning}")


def _print_status(result: tooling.ToolRunResult) -> None:
    if result.returncode is None and result.warning is not None:
        out.say(f"   -> Warning: {result.warning}")
        return
    if result.succeeded or result.report_written:
        out.say("   -> Done.")
        return
    if result.warning is not None:
        out.say(f"   -> Warning: {result.warning}")
        return
    out.say(f"   -> Warning: {result.scanner.label} exited with status {result.returncode}.")


def _announce_zap_target(url: str) -> None:
    """A URL-targeting scanner runs in a container, where localhost is not the host."""
    target = rewrite_zap_target(url)
    if target != url:
        out.say(
            "      (Detected localhost: switching to "
            "'host.docker.internal' for Docker compatibility)"
        )
        out.say(f"      Targeting: {target}")


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


def _run_enabled_tools(
    project_root: Path,
    report_dir: Path,
    resolved: ResolvedConfig,
    runner: tooling.CommandRunner,
    timeout: float | None,
) -> tuple[str, ...]:
    """Run each enabled scanner in turn; return the labels of those that were started."""
    total = len(SCANNERS)
    attempted: list[str] = []

    out.say()
    for step, scanner in enumerate(SCANNERS, start=1):
        stage = f"[{step}/{total}]"
        enabled = scanner.key in resolved.enabled_tools
        reason = _skip_reason(scanner, enabled=enabled, url=resolved.url)
        if reason is not None:
            out.say(f"{stage} Skipping {scanner.label} ({reason}).")
            continue

        out.say(f"{stage} Running {scanner.label}...")
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
    return tuple(attempted)


def run_audit(options: CliOptions, *, runner: tooling.CommandRunner) -> int:
    resolved = config.resolve_config(
        project_root=options.project_root,
        cli_url=options.cli_url,
        config_path=options.config_path,
    )
    output = fs.owned_file(options.project_root / "security_audit.json")
    output_file = output.path
    try:
        report_dir = tooling.prepare_report_dir(options.project_root)
        tooling.clear_output_file(output_file)
    except fs.ProjectIOError as error:
        return out.error("warden", f"cannot prepare the report paths: {error}")

    out.say("STARTING SECURITY AUDIT")
    out.say(f"   Target: {options.project_root}")
    for warning in resolved.warnings:
        out.say(f"Warning: {warning}")
    skipped_for_url: tuple[str, ...] = ()
    if resolved.url:
        problem = url_problem(resolved.url)
        if problem is None:
            out.say(f"   DAST URL: {resolved.url}")
        else:
            skipped_for_url = _url_scanners(resolved)
            shown_url = out.shown(resolved.url)
            out.say(
                f"Warning: the DAST URL {shown_url} is not usable ({problem}): "
                f"skipping {', '.join(skipped_for_url)}."
            )
            resolved = replace(resolved, url="")

    attempted = _run_enabled_tools(
        options.project_root, report_dir, resolved, runner, options.timeout
    )

    out.say()
    out.say("[*] Generating Final Report...")
    try:
        verdict, tools_run = aggregate.generate_report(report_dir=report_dir, output_file=output)
    except fs.ProjectIOError as error:
        return out.error("warden", f"cannot read the reports or write {output_file.name}: {error}")
    except JsonLimitError as error:
        return out.error("warden", f"{error}, {aggregate.FAILS_CLOSED}")
    incomplete = _incomplete(attempted, tools_run, skipped_for_url) if options.strict else None
    if incomplete is not None:
        out.say()
        out.say(f"STRICT: {incomplete}")
    if verdict.failed:
        out.say()
        out.say("AUDIT FAILED!")
        out.say(f"Report saved to: {output_file}")
        return 1
    if incomplete is not None:
        out.say()
        out.say("AUDIT INCOMPLETE!")
        out.say(f"Report saved to: {output_file}")
        return EXIT_INCOMPLETE

    out.say()
    out.say("AUDIT COMPLETE!")
    out.say(f"Report saved to: {output_file}")
    return 0


def main(
    argv: list[str] | None = None,
    *,
    runner: tooling.CommandRunner = tooling.run_subprocess,
) -> int:
    return run_audit(_parse_args(argv), runner=runner)
