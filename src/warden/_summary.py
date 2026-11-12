from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import _out as out
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
    return ", ".join(f"{key}: {items[key]}" for key in order if items.get(key, 0) != 0)


def _status_summary(failed: bool) -> tuple[str, str, str]:
    if failed:
        return "red", "FAIL", "High/Critical issues found."
    return "green", "PASS", "No High/Critical issues found."


def print_summary(
    *,
    verdict: Verdict,
    output_file: str | Path,
) -> None:
    out.say_styled("-" * 50)
    out.say_styled(out.Span("SCAN COMPLETE", "bold cyan"))
    out.say_styled("-" * 50)
    out.table(
        [("Severity", "left"), ("Count", "right"), ("Breakdown", "left")],
        [
            (
                out.Span(label, color),
                str(verdict.counts[severity]),
                _format_breakdown(verdict.breakdown[severity], order=CATEGORY_ORDER)
                if show_breakdown
                else "",
            )
            for label, severity, color, show_breakdown in SUMMARY_ROWS
        ],
    )
    out.say_styled("-" * 50)
    status_style, status_label, summary_line = _status_summary(verdict.failed)
    out.say_styled(out.Span(f"{status_label}:", status_style), f" {summary_line} See {output_file}")
