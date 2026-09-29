from __future__ import annotations

import json
import os
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, cast

from ._json import as_mapping, get_string
from ._models import CommandResult, ToolRunResult
from ._scanners import SCANNERS, Scanner, ScanRequest


class CommandRunner(Protocol):
    """How a built command line reaches the operating system."""

    def __call__(
        self,
        args: list[str],
        *,
        cwd: Path,
        stderr_to_devnull: bool = False,
        env_overrides: dict[str, str] | None = None,
    ) -> CommandResult: ...


def tool_succeeded(result: ToolRunResult) -> bool:
    return result.returncode in result.accepted_returncodes


def report_written(result: ToolRunResult) -> bool:
    return result.report_path.exists()


def _clear_stale_reports(report_dir: Path) -> None:
    for scanner in SCANNERS:
        for filename in (scanner.report_file, *scanner.extra_artifacts):
            (report_dir / filename).unlink(missing_ok=True)


def _ignore_report_dir(root: Path) -> None:
    gitignore_path = root / ".gitignore"
    # A symlinked or special `.gitignore` is left alone: appending would write through the link.
    if gitignore_path.is_symlink() or not gitignore_path.is_file():
        return

    # Best effort: this only keeps the reports out of version control, so an unreadable or
    # unwritable `.gitignore` must not stop the audit. git reads the file as bytes, so a legacy
    # encoding is fine to append to; a file with NULs (UTF-16) is not text git can use at all.
    try:
        raw = gitignore_path.read_bytes()
        if b"\x00" in raw:
            print("Warning: could not add .security_reports/ to .gitignore: not a text file")
            return
        existing_lines = raw.decode("utf-8", errors="replace").splitlines()
        if any(line.strip() == ".security_reports/" for line in existing_lines):
            return

        with gitignore_path.open("a", encoding="utf-8") as handle:
            if existing_lines and existing_lines[-1].strip():
                handle.write("\n")
            handle.write(".security_reports/\n")
    except OSError as error:
        print(f"Warning: could not add .security_reports/ to .gitignore: {error.strerror or error}")


def prepare_report_dir(project_root: str | Path) -> Path:
    """Create `.security_reports/`, gitignore it, and drop any previous run's reports."""
    root = Path(project_root).resolve()
    report_dir = root / ".security_reports"
    # A project can ship this name as a symlink, and the reports below are deleted and written
    # through it. Replace the link with a real directory rather than follow it.
    if report_dir.is_symlink():
        report_dir.unlink()
    report_dir.mkdir(parents=True, exist_ok=True)
    _clear_stale_reports(report_dir)
    _ignore_report_dir(root)
    return report_dir


def clear_output_file(path: Path) -> None:
    """Remove a symlink or named pipe sitting where the report will be written.

    A project can ship `security_audit.json` as a symlink, and writing then follows it to a file
    elsewhere, or as a named pipe, and opening one for writing blocks forever. Warden owns the
    name, so either is replaced by the regular file it writes. Anything else is left alone.
    """
    try:
        mode = path.lstat().st_mode
    except OSError:
        return
    if stat.S_ISLNK(mode) or stat.S_ISFIFO(mode):
        path.unlink()


def run_subprocess(
    args: list[str],
    *,
    cwd: Path,
    stderr_to_devnull: bool = False,
    env_overrides: dict[str, str] | None = None,
) -> CommandResult:
    """The production `CommandRunner`: hand the command line to the operating system."""
    environment = os.environ.copy()
    if env_overrides is not None:
        environment.update(env_overrides)

    try:
        completed = subprocess.run(  # noqa: S603 - a list of arguments, never a shell string
            args,
            cwd=str(cwd),
            env=environment,
            check=False,
            stderr=subprocess.DEVNULL if stderr_to_devnull else None,
        )
    except FileNotFoundError:
        return CommandResult(returncode=None, warning=f"{args[0]} was not found on PATH.")
    except OSError as error:
        # Present but not runnable: not executable, wrong format, or a working directory that is
        # not one. Like a missing tool this is a warning, so the other scanners still run.
        return CommandResult(
            returncode=None, warning=f"{args[0]} could not be started: {error.strerror or error}"
        )
    except ValueError as error:
        # An argument the operating system cannot take, such as a NUL byte from `.warden.yaml`.
        return CommandResult(returncode=None, warning=f"{args[0]} could not be started: {error}")

    return CommandResult(returncode=completed.returncode)


def _excluded_prefixes(exclude_dirs: Sequence[str]) -> frozenset[str]:
    """Each entry as a directory below the project root; anything that is not one is dropped."""
    prefixes = (
        entry.strip().replace(os.sep, "/").removeprefix("./").rstrip("/") for entry in exclude_dirs
    )
    return frozenset(prefix for prefix in prefixes if prefix)


def _without_excluded(raw_data: object, path_key: str, exclude_dirs: Sequence[str]) -> object:
    """Drop the findings that sit at or under an excluded path, keep everything else.

    An entry matches that path and everything below it, anchored at the project root, and is a
    plain path rather than a glob. Finding paths are relative to it, as Gitleaks writes them, and
    a backslash separates parts only where the platform uses one. A finding is checked against the
    set of entries part by part, and only as far down as the deepest entry, so the cost grows with
    neither the number of entries nor how deep a path goes. A finding
    of an unexpected shape is kept: dropping one is never the safe way to be wrong.
    """
    prefixes = _excluded_prefixes(exclude_dirs)
    if not prefixes or not isinstance(raw_data, list):
        return raw_data
    # No entry is deeper than this, so no longer prefix of a path can match one.
    depth = max(prefix.count("/") for prefix in prefixes) + 1

    def excluded(finding: object) -> bool:
        mapping = as_mapping(finding)
        file = get_string(mapping, path_key) if mapping is not None else None
        if file is None:
            return False
        prefix: str | None = None
        for part in file.replace(os.sep, "/").split("/", depth)[:depth]:
            prefix = part if prefix is None else f"{prefix}/{part}"
            if prefix in prefixes:
                return True
        return False

    return [finding for finding in cast(list[object], raw_data) if not excluded(finding)]


def _prettify_json(
    path: Path, *, path_key: str | None = None, exclude_dirs: Sequence[str] = ()
) -> None:
    if not path.exists():
        return
    try:
        raw_data: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return
    if path_key is not None:
        raw_data = _without_excluded(raw_data, path_key, exclude_dirs)
    path.write_text(json.dumps(raw_data, indent=2, ensure_ascii=False), encoding="utf-8")


def scan_request(
    scanner: Scanner,
    *,
    project_root: str | Path,
    report_dir: str | Path,
    exclude_dirs: Sequence[str] = (),
    url: str = "",
) -> ScanRequest:
    """Everything `scanner.build_command` needs, with the paths already resolved."""
    resolved_report_dir = Path(report_dir).resolve()
    return ScanRequest(
        project_root=Path(project_root).resolve(),
        report_dir=resolved_report_dir,
        report_path=resolved_report_dir / scanner.report_file,
        exclude_dirs=tuple(exclude_dirs),
        url=url,
    )


def run_scanner(scanner: Scanner, request: ScanRequest, runner: CommandRunner) -> ToolRunResult:
    """Build this scanner's command line, run it, and normalise what came back."""
    command = scanner.build_command(request)
    result = runner(
        command.args,
        cwd=command.cwd,
        stderr_to_devnull=command.stderr_to_devnull,
        env_overrides=command.env_overrides,
    )
    _prettify_json(
        request.report_path, path_key=scanner.path_key, exclude_dirs=request.exclude_dirs
    )
    return ToolRunResult(
        name=scanner.label,
        returncode=result.returncode,
        report_path=request.report_path,
        accepted_returncodes=scanner.accepted_returncodes,
        warning=result.warning,
    )
