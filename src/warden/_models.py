from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, TypedDict, cast, get_args

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

# Derived from the Literal rather than repeated, so the two cannot drift apart.
SEVERITIES: Final[tuple[Severity, ...]] = cast("tuple[Severity, ...]", get_args(Severity))
DEFAULT_FAIL_ON_SEVERITIES: Final[tuple[Severity, ...]] = ("CRITICAL", "HIGH")


class BaseFindingDict(TypedDict):
    tool: str
    severity: Severity
    file: str
    description: str


class FindingDict(BaseFindingDict, total=False):
    line: int
    fix: str
    rule_id: str
    snippet: str
    solution: str


class ReportSummaryDict(TypedDict):
    total_issues: int
    tools_run: list[str]


class AggregateReportDict(TypedDict):
    summary: ReportSummaryDict
    findings: list[FindingDict]


SummaryCounts = dict[Severity, int]
SummaryBreakdown = dict[Severity, dict[str, int]]


@dataclass(slots=True, frozen=True)
class Finding:
    tool: str
    severity: Severity
    file: str
    description: str
    line: int | None = None
    fix: str | None = None
    rule_id: str | None = None
    snippet: str | None = None
    solution: str | None = None


@dataclass(slots=True, frozen=True)
class ResolvedConfig:
    url: str
    exclude_dirs: list[str]
    enabled_tools: frozenset[str]
    """The scanner keys left enabled after `.warden.yaml` has been applied."""
    warnings: tuple[str, ...] = ()
    """Things worth telling the user about how the configuration was resolved."""


@dataclass(slots=True, frozen=True)
class CliOptions:
    project_root: Path
    cli_url: str
    config_path: Path | None = None


@dataclass(slots=True, frozen=True)
class AggregateCliOptions:
    report_dir: Path
    output_file: Path


@dataclass(slots=True, frozen=True)
class ToolRunResult:
    name: str
    returncode: int | None
    report_path: Path
    accepted_returncodes: frozenset[int]
    warning: str | None = None


@dataclass(slots=True, frozen=True)
class CommandResult:
    returncode: int | None
    warning: str | None = None
