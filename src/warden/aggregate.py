from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import cast

from . import _fs as fs
from . import _out as out
from ._json import JsonLimitError, load_json, write_json
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


FAILS_CLOSED = "so the audit fails rather than pass without the findings it may hold."


def _load_reports(report_dir: Path) -> list[tuple[Scanner, object | None]]:
    """Read every scanner's report, warning about any that is present but unusable.

    One that is more JSON than Python can parse raises `JsonLimitError`: it may hold findings,
    so the audit fails rather than pass without them.
    """
    reports: list[tuple[Scanner, object | None]] = []
    for scanner in SCANNERS:
        loaded = load_json(report_dir / scanner.report_file)
        if loaded.error is not None:
            out.say(f"Warning: Could not parse {scanner.report_file}: {loaded.error}")
        elif loaded.found and not scanner.reads_report(loaded.data):
            shape = "array" if scanner.report_is_array else "object"
            out.say(
                f"Warning: {scanner.report_file} is not the JSON {shape} {scanner.label} writes, "
                f"so {scanner.label} is left out of tools_run."
            )
        reports.append((scanner, loaded.data))
    return reports


def detect_tools_run(reports: Sequence[tuple[Scanner, object | None]]) -> list[str]:
    """The scanners whose report has the shape their parser reads: those that count as run.

    The exit status is not consulted: ZAP exits non-zero when it has alerts, and a clean Trivy
    report is an object with no `Results` in it, so only the shape of the file says it ran.
    `warden --strict` reads its answer from here, so the gate and the report cannot disagree.
    """
    return [scanner.label for scanner, raw_report in reports if scanner.reads_report(raw_report)]


def build_report(report_dir: str | Path) -> tuple[list[Finding], AggregateReportDict]:
    reports = _load_reports(Path(report_dir))
    findings = [finding for scanner, raw_report in reports for finding in scanner.parse(raw_report)]
    findings.sort(key=lambda finding: severity_rank(finding.severity))
    report: AggregateReportDict = {
        "summary": {
            "total_issues": len(findings),
            "tools_run": detect_tools_run(reports),
        },
        "findings": [finding_to_dict(finding) for finding in findings],
    }
    return findings, report


def generate_report(
    *,
    report_dir: str | Path,
    output_file: fs.WritableFile,
) -> tuple[Verdict, list[str]]:
    """Write the report; return the verdict and the report's `tools_run`.

    The caller prints the summary, because only `warden` knows whether strict holds the run to
    be incomplete, and it reads that from the `tools_run` returned here.
    """
    findings, report = build_report(report_dir)
    write_json(output_file, report)
    out.say(f"Generated {output_file.path} with {len(findings)} issues.")
    return judge(findings), report["summary"]["tools_run"]


def _parse_args(argv: list[str] | None = None) -> AggregateCliOptions:
    parser = out.ArgumentParser(
        prog="warden-aggregate",
        description=(
            "Aggregate security scanner reports (Trivy, Semgrep, Gitleaks, ZAP) "
            "into a single JSON file."
        ),
    )
    parser.add_argument(
        "report_dir",
        type=out.path_argument,
        help="Directory containing tool JSON outputs (for example: trivy.json, semgrep.json)",
    )
    parser.add_argument(
        "output_file", type=out.path_argument, help="Path to write the aggregated JSON report"
    )
    namespace = parser.parse_args(argv)
    report_dir = cast(Path, namespace.report_dir)
    try:
        if not fs.is_dir(report_dir):
            # A missing directory is not "no reports": a typo would otherwise print PASS.
            parser.error(f"report_dir {report_dir} is not an existing directory")
    except fs.ProjectIOError as error:
        parser.error(f"report_dir {report_dir} cannot be looked up: {error.reason}")
    return AggregateCliOptions(
        report_dir=report_dir,
        output_file=cast(Path, namespace.output_file),
    )


@out.entry_point("warden-aggregate")
def main(argv: list[str] | None = None) -> int:
    options = _parse_args(argv)
    out.say(f"--- Aggregating Reports from {options.report_dir} ---")
    try:
        verdict, _ = generate_report(
            report_dir=options.report_dir, output_file=fs.as_given(options.output_file)
        )
    except JsonLimitError as error:
        return out.error("warden-aggregate", f"{error}, {FAILS_CLOSED}")
    print_summary(verdict=verdict, output_file=options.output_file)
    return 1 if verdict.failed else 0
