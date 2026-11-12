from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from fakes import RecordedCommand, RecordingRunner
from warden import cli
from warden._scanners import SCANNERS, ZAP_IMAGE, Scanner


def _every_command(tmp_path: Path) -> list[RecordedCommand]:
    """The command lines of one run with every option that adds arguments turned on.

    The URL only reaches `RecordingRunner`, so no ZAP scan is started.
    """
    project = tmp_path / "project"
    project.mkdir()
    (project / ".warden.yaml").write_text('exclude_dirs:\n  - "vendor"\n', encoding="utf-8")
    runner = RecordingRunner()
    cli.main(["--project-root", str(project), "--url", "https://example.com"], runner=runner)
    return runner.commands


def _command_of(scanner: Scanner, commands: list[RecordedCommand]) -> RecordedCommand:
    """Fails, rather than skips, for a scanner this run builds no command for."""
    return next(
        command
        for command in commands
        if any(Path(arg).name == scanner.report_file for arg in command.args)
    )


def _own_flags(args: list[str]) -> list[str]:
    """The flags the executable itself parses: those after the image belong to the container."""
    if ZAP_IMAGE in args:
        args = args[: args.index(ZAP_IMAGE)]
    return sorted({arg.split("=", 1)[0] for arg in args[2:] if arg.startswith("-")})


@pytest.mark.parametrize("scanner", SCANNERS, ids=[scanner.label for scanner in SCANNERS])
def test_every_flag_warden_passes_a_scanner_is_one_the_installed_tool_documents(
    tmp_path: Path, scanner: Scanner
) -> None:
    """`RecordingRunner` accepts any argv, so a flag the tool does not have passes every other
    test: Gitleaks got a nonexistent `--exclude-path` for each `exclude_dirs` entry, exited
    126, and the audit passed with secret scanning off (f5388bc). The tool's own
    `<subcommand> --help` is the authority on which flags exist."""
    args = _command_of(scanner, _every_command(tmp_path)).args
    executable = shutil.which(args[0])
    if executable is None:
        pytest.skip(f"{args[0]} is not on PATH")
    shown = subprocess.run(
        [executable, *args[1:2], "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert shown.returncode == 0, shown.stderr
    help_text = shown.stdout + shown.stderr

    unknown = [
        flag
        for flag in _own_flags(args)
        if re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", help_text) is None
    ]

    assert unknown == [], f"{' '.join(args[:2])} --help does not list {unknown}"
