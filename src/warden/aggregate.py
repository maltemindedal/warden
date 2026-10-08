from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import cast

from ._json import load_json
from ._models import (
    AggregateCliOptions,
    AggregateReportDict,
    Finding,
    FindingDict,
)
from ._parsers import severity_rank
from ._scanners import SCANNERS, Scanner
from ._summary import Verdict, judge, print_summary


def finding_to_dict(finding: Finding) -> FindingDict:
    entry: FindingDict = {
        "tool": finding.tool,
        "severity": finding.severity,
        "file": finding.file,
        "description": finding.description,
    }
    if finding.line is not None:
        entry["line"] = finding.line
    if finding.fix is not None:
        entry["fix"] = finding.fix
    if finding.rule_id is not None:
        entry["rule_id"] = finding.rule_id
    if finding.snippet is not None:
        entry["snippet"] = finding.snippet
    if finding.solution is not None:
        entry["solution"] = finding.solution
    return entry


def _load_reports(report_dir: Path) -> list[tuple[Scanner, object | None]]:
    """Read every scanner's report, warning about any that is present but unusable."""
    reports: list[tuple[Scanner, object | None]] = []
    for scanner in SCANNERS:
        path = report_dir / scanner.report_file
        loaded = load_json(path)
        if loaded.error is not None:
            print(f"Warning: Could not parse {scanner.report_file}: {loaded.error}")
        elif not scanner.reads_report(loaded.data) and path.exists():
            shape = "array" if scanner.report_is_array else "object"
            print(
                f"Warning: {scanner.report_file} is not the JSON {shape} {scanner.label} writes, "
                f"so {scanner.label} is left out of tools_run."
            )
        reports.append((scanner, loaded.data))
    return reports


def detect_tools_run(reports: Sequence[tuple[Scanner, object | None]]) -> list[str]:
    """The scanners whose report has the shape their parser reads, as `--strict` counts them."""
    return [scanner.label for scanner, raw_report in reports if scanner.reads_report(raw_report)]


def build_report(report_dir: str | Path) -> tuple[list[Finding], AggregateReportDict]:
    reports = _load_reports(Path(report_dir))
    findings = [
        finding for scanner, raw_report in reports for finding in scanner.parser(raw_report)
    ]
    findings.sort(key=lambda finding: severity_rank(finding.severity))
    report: AggregateReportDict = {
        "summary": {
            "total_issues": len(findings),
            "tools_run": detect_tools_run(reports),
        },
        "findings": [finding_to_dict(finding) for finding in findings],
    }
    return findings, report


def write_report(output_file: str | Path, report: AggregateReportDict) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def generate_report(
    *,
    report_dir: str | Path,
    output_file: str | Path,
) -> Verdict:
    findings, report = build_report(report_dir)
    write_report(output_file, report)
    print(f"Generated {output_file} with {len(findings)} issues.")
    verdict = judge(findings)
    print_summary(verdict=verdict, output_file=output_file)
    return verdict


def _parse_args(argv: list[str] | None = None) -> AggregateCliOptions:
    parser = argparse.ArgumentParser(
        prog="warden-aggregate",
        description=(
            "Aggregate security scanner reports (Trivy, Semgrep, Gitleaks, ZAP) "
            "into a single JSON file."
        ),
    )
    parser.add_argument(
        "report_dir",
        help="Directory containing tool JSON outputs (for example: trivy.json, semgrep.json)",
    )
    parser.add_argument("output_file", help="Path to write the aggregated JSON report")
    namespace = parser.parse_args(argv)
    report_dir = Path(cast(str, namespace.report_dir)).resolve()
    if not report_dir.is_dir():
        # A missing directory is not "no reports": a typo would otherwise print PASS.
        parser.error(f"report_dir {report_dir} is not an existing directory")
    return AggregateCliOptions(
        report_dir=report_dir,
        output_file=Path(cast(str, namespace.output_file)).resolve(),
    )


def main(argv: list[str] | None = None) -> int:
    options = _parse_args(argv)
    print(f"--- Aggregating Reports from {options.report_dir} ---")
    verdict = generate_report(report_dir=options.report_dir, output_file=options.output_file)
    return 1 if verdict.failed else 0
