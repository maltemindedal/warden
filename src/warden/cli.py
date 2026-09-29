from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import cast

from . import aggregate, config, tooling
from ._models import CliOptions, ResolvedConfig, ToolRunResult
from ._scanners import SCANNERS, Scanner, rewrite_zap_target


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
    namespace = parser.parse_args(argv)
    project_root = Path(cast(str, namespace.project_root)).resolve()
    if not project_root.is_dir():
        parser.error(f"--project-root {project_root} is not an existing directory")
    config_path_value = cast(str | None, namespace.config)
    return CliOptions(
        project_root=project_root,
        cli_url=cast(str, namespace.url),
        config_path=Path(config_path_value).resolve() if config_path_value is not None else None,
    )


def _describe(error: OSError) -> str:
    return (
        f"{error.filename}: {error.strerror}" if error.filename and error.strerror else str(error)
    )


def _fail(message: str) -> int:
    """A path the project controls that Warden cannot use: a failed run, not a traceback."""
    print(f"warden: error: {message}", file=sys.stderr)
    return 1


def _print_result(result: ToolRunResult) -> None:
    if tooling.tool_succeeded(result) or tooling.report_written(result):
        print("   -> Done.")
        return
    if result.warning is not None:
        print(f"   -> Warning: {result.warning}")
        return
    print(f"   -> Warning: {result.name} exited with status {result.returncode}.")


def _announce_zap_target(url: str) -> None:
    """A URL-targeting scanner runs in a container, where localhost is not the host."""
    target = rewrite_zap_target(url)
    if target != url:
        print(
            "      (Detected localhost: switching to "
            "'host.docker.internal' for Docker compatibility)"
        )
        print(f"      Targeting: {target}")


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
) -> None:
    total = len(SCANNERS)

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
        _print_result(tooling.run_scanner(scanner, request, runner))


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
    if resolved.url:
        print(f"   DAST URL: {resolved.url}")

    _run_enabled_tools(options.project_root, report_dir, resolved, runner)

    print("\n[*] Generating Final Report...")
    try:
        verdict = aggregate.generate_report(report_dir=report_dir, output_file=output_file)
    except OSError as error:
        return _fail(f"cannot read the reports or write {output_file.name}: {_describe(error)}")
    if verdict.failed:
        print("\nAUDIT FAILED!")
        print(f"Report saved to: {output_file}")
        return 1

    print("\nAUDIT COMPLETE!")
    print(f"Report saved to: {output_file}")
    return 0


def main(
    argv: list[str] | None = None,
    *,
    runner: tooling.CommandRunner = tooling.run_subprocess,
) -> int:
    return run_audit(_parse_args(argv), runner=runner)
