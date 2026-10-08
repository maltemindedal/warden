from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from ._json import LoadedJson, as_mapping, get_string, load_json
from ._models import CommandResult
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
        timeout: float | None = None,
    ) -> CommandResult: ...


@dataclass(slots=True, frozen=True)
class ToolRunResult:
    """What running one scanner came to: how it exited, and what it left as its report."""

    scanner: Scanner
    returncode: int | None
    report_path: Path
    report_written: bool
    report_usable: bool
    """Whether the report has the shape the scanner's parser reads, so its run counts.

    The exit status is not consulted: ZAP exits non-zero when it has alerts, and a clean Trivy
    report is an object with no `Results` in it, so only the shape of the file says it ran."""
    warning: str | None = None

    @property
    def succeeded(self) -> bool:
        """Whether the scanner exited with a status its record accepts."""
        return self.returncode in self.scanner.accepted_returncodes


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


_STOP_GRACE_SECONDS = 10
_OWN_SESSION = os.name == "posix"
"""A scanner is started as the leader of its own process group, so that the workers it starts
(Semgrep runs a separate `semgrep-core`) can be signalled with it. Windows has no such group here,
and only the scanner process itself is stopped there."""


def _signal_group(process: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    try:
        os.killpg(process.pid, sig)
    except (ProcessLookupError, PermissionError):
        pass  # nothing of it is left to signal


def _kill(process: subprocess.Popen[bytes]) -> None:
    """Kill the scanner and whatever it started, without waiting for either."""
    if _OWN_SESSION:
        _signal_group(process, signal.SIGKILL)
    process.kill()


def _stop(process: subprocess.Popen[bytes]) -> None:
    """Ask the scanner and its workers to stop, give them a moment, then kill what is left.

    However this is left, including by an interrupt while waiting, nothing is left running.
    """
    try:
        if _OWN_SESSION:
            _signal_group(process, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=_STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    finally:
        _kill(process)
        process.wait()


def run_subprocess(
    args: list[str],
    *,
    cwd: Path,
    stderr_to_devnull: bool = False,
    env_overrides: dict[str, str] | None = None,
    timeout: float | None = None,
) -> CommandResult:
    """The production `CommandRunner`: hand the command line to the operating system."""
    environment = os.environ.copy()
    if env_overrides is not None:
        environment.update(env_overrides)

    try:
        with subprocess.Popen(  # noqa: S603 - a list of arguments, never a shell string
            args,
            cwd=str(cwd),
            env=environment,
            stderr=subprocess.DEVNULL if stderr_to_devnull else None,
            start_new_session=_OWN_SESSION,
        ) as process:
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _stop(process)
                return CommandResult(
                    returncode=None,
                    warning=f"{args[0]} timed out after {timeout:g} seconds and was stopped.",
                    timed_out=True,
                )
            except BaseException:
                _kill(process)
                raise
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

    return CommandResult(returncode=returncode)


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


def _tidy_report(
    path: Path, *, path_key: str | None = None, exclude_dirs: Sequence[str] = ()
) -> LoadedJson:
    """Pretty-print the report a scanner left, without the findings under `exclude_dirs`.

    What comes back is what the report now holds. One that is absent or not JSON is left alone.
    """
    if not path.exists():
        return LoadedJson()
    loaded = load_json(path)
    if loaded.error is not None:
        return loaded
    raw_data = loaded.data
    if path_key is not None:
        raw_data = _without_excluded(raw_data, path_key, exclude_dirs)
    path.write_text(json.dumps(raw_data, indent=2, ensure_ascii=False), encoding="utf-8")
    return LoadedJson(data=raw_data)


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


def run_scanner(
    scanner: Scanner,
    request: ScanRequest,
    runner: CommandRunner,
    *,
    timeout: float | None = None,
) -> ToolRunResult:
    """Build this scanner's command line, run it, and read what it left, once."""
    command = scanner.build_command(request)
    result = runner(
        command.args,
        cwd=command.cwd,
        stderr_to_devnull=command.stderr_to_devnull,
        env_overrides=command.env_overrides,
        timeout=timeout,
    )
    if result.timed_out:
        # Whatever a stopped scanner left behind is not a finished report.
        request.report_path.unlink(missing_ok=True)
        if command.on_timeout is not None:
            # Best effort: the container may be gone already, and only the attempt matters.
            runner(command.on_timeout, cwd=command.cwd, stderr_to_devnull=True, timeout=30)
    report = _tidy_report(
        request.report_path, path_key=scanner.path_key, exclude_dirs=request.exclude_dirs
    )
    return ToolRunResult(
        scanner=scanner,
        returncode=result.returncode,
        report_path=request.report_path,
        report_written=request.report_path.exists(),
        report_usable=scanner.reads_report(report.data),
        warning=result.warning,
    )
