from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from warden._models import CommandResult


@dataclass(slots=True, frozen=True)
class RecordedCommand:
    """One command line a `CommandRunner` was asked to run."""

    args: list[str]
    cwd: Path
    stderr_to_devnull: bool
    env_overrides: dict[str, str] | None


@dataclass(slots=True)
class RecordingRunner:
    """A `CommandRunner` that records what it was asked for and returns a scripted result."""

    returncode: int | None = 0
    warning: str | None = None
    report_text: str | None = None
    commands: list[RecordedCommand] = field(default_factory=list[RecordedCommand])

    def __call__(
        self,
        args: list[str],
        *,
        cwd: Path,
        stderr_to_devnull: bool = False,
        env_overrides: dict[str, str] | None = None,
    ) -> CommandResult:
        command = RecordedCommand(
            args=list(args),
            cwd=cwd,
            stderr_to_devnull=stderr_to_devnull,
            env_overrides=env_overrides,
        )
        self.commands.append(command)
        if self.report_text is not None:
            self._write_report(command, self.report_text)
        return CommandResult(returncode=self.returncode, warning=self.warning)

    @staticmethod
    def _write_report(command: RecordedCommand, text: str) -> None:
        """Write where the real scanner would: its first `.json` argument, resolved against cwd."""
        for arg in command.args:
            if arg.endswith(".json"):
                (command.cwd / arg).write_text(text, encoding="utf-8")
                return


def symlink_or_skip(link: Path, target: Path) -> None:
    """Symlinks need a privilege on some Windows setups, and the behavior under test needs one."""
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("this platform cannot create symlinks")
