from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ._models import (
    DEFAULT_FAIL_ON_SEVERITIES,
    SEVERITIES,
    Finding,
    Severity,
    SummaryBreakdown,
    SummaryCounts,
)
from ._parsers import normalize_severity
from ._scanners import CATEGORY_ORDER, SCANNERS

TOOL_CATEGORIES: Final[dict[str, str]] = {scanner.label: scanner.category for scanner in SCANNERS}
SUMMARY_ROWS: Final[tuple[tuple[str, Severity, str, bool], ...]] = (
    ("Critical", "CRITICAL", "red", True),
    ("High", "HIGH", "bright_red", True),
    ("Medium", "MEDIUM", "yellow", False),
)


@dataclass(slots=True, frozen=True)
class Verdict:
    """The build's pass/fail decision, and the tallies it was reached from."""

    triggered_by: tuple[Severity, ...]
    counts: SummaryCounts
    breakdown: SummaryBreakdown

    @property
    def failed(self) -> bool:
        return bool(self.triggered_by)


def _category_for_tool(tool: str) -> str:
    return TOOL_CATEGORIES.get(tool, tool)


def judge(findings: Sequence[Finding]) -> Verdict:
    """Tally the findings and decide whether they fail the build."""
    counts: SummaryCounts = dict.fromkeys(SEVERITIES, 0)
    breakdown: SummaryBreakdown = {severity: {} for severity in SEVERITIES}
    for finding in findings:
        severity = normalize_severity(finding.severity)
        counts[severity] += 1
        category = _category_for_tool(finding.tool)
        severity_breakdown = breakdown[severity]
        severity_breakdown[category] = severity_breakdown.get(category, 0) + 1
    return Verdict(
        triggered_by=tuple(
            severity for severity in DEFAULT_FAIL_ON_SEVERITIES if counts[severity] > 0
        ),
        counts=counts,
        breakdown=breakdown,
    )


def _format_breakdown(items: Mapping[str, int], order: Sequence[str]) -> str:
    if not items:
        return ""
    return ", ".join(f"{key}: {items[key]}" for key in order if items.get(key))


def _status_summary(failed: bool) -> tuple[str, str, str]:
    if failed:
        return "red", "FAIL", "High/Critical issues found."
    return "green", "PASS", "No High/Critical issues found."


def print_summary(
    *,
    verdict: Verdict,
    output_file: str | Path,
) -> None:
    counts = verdict.counts
    breakdown = verdict.breakdown
    output_path = str(output_file)

    console = Console()
    console.print("-" * 50)
    console.print(Text("SCAN COMPLETE", style="bold cyan"))
    console.print("-" * 50)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", justify="left")
    table.add_column("Count", justify="right")
    table.add_column("Breakdown", justify="left")

    for label, severity, color, show_breakdown in SUMMARY_ROWS:
        breakdown_text = ""
        if show_breakdown:
            breakdown_text = _format_breakdown(breakdown[severity], order=CATEGORY_ORDER)
        table.add_row(
            f"[{color}]{label}[/{color}]",
            str(counts[severity]),
            breakdown_text,
        )

    console.print(table)
    console.print("-" * 50)
    status_style, status_label, summary_line = _status_summary(verdict.failed)
    # The path is appended as plain text, not parsed as markup or emoji codes: a project directory
    # named like markup (`[/red]`), like an emoji code (`:warning:`) or ending in a backslash must
    # print as written, not raise or change. A Text skips rich's repr highlighter, which colours a
    # path on a terminal, so it is applied explicitly to keep ordinary output the same.
    status_line = Text.from_markup(
        f"[{status_style}]{status_label}:[/{status_style}] {summary_line} See "
    )
    status_line.append(output_path)
    console.print(console.highlighter(status_line))
