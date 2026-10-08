from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from pytest import CaptureFixture

from warden._json import get_int, load_json
from warden._models import Finding, Severity
from warden._parsers import normalize_severity, parse_zap
from warden._scanners import SCANNERS
from warden._summary import judge, print_summary
from warden.aggregate import build_report, main

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _plain_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """rich reads these when a Console is created, so without this the output depends on them."""
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("TTY_COMPATIBLE", raising=False)
    monkeypatch.setenv("COLUMNS", "200")


def _copy_fixture(name: str, destination: Path) -> None:
    shutil.copyfile(FIXTURE_DIR / name, destination / name)


def _findings(*severities: Severity) -> list[Finding]:
    return [
        Finding(tool="Trivy", severity=severity, file="app.py", description="issue")
        for severity in severities
    ]


def test_normalize_severity_maps_tool_specific_values() -> None:
    assert normalize_severity("crit") == "CRITICAL"
    assert normalize_severity("warning") == "MEDIUM"
    assert normalize_severity(None) == "UNKNOWN"


def test_get_int_accepts_a_numeric_string_and_rejects_anything_else() -> None:
    assert get_int({"riskcode": "3"}, "riskcode") == 3
    assert get_int({"riskcode": "high"}, "riskcode") is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (5, 5),
        ("  42 ", 42),
        ("\u0663", 3),  # Arabic-Indic digit three: int() has always accepted it
        ("\u00b2", None),  # superscript two: isdigit() is true but int() raises
        ("\u2460", None),  # circled one, likewise
        pytest.param("9" * 5000, None, id="over-4300-digits"),  # int() refuses that many
        (True, None),  # JSON `true` is not a line number
        (False, None),
        (None, None),
        ("-3", None),
    ],
)
def test_get_int_takes_only_what_int_can_read_and_never_raises(
    value: object, expected: int | None
) -> None:
    assert get_int({"line": value}, "line") == expected


def test_load_json_returns_the_parsed_document_when_the_file_is_valid(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    report.write_text('{"Results": []}', encoding="utf-8")

    loaded = load_json(report)

    assert loaded.data == {"Results": []}
    assert loaded.error is None


def test_load_json_reports_a_parse_failure_as_a_value(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    report.write_text('{"Results": [', encoding="utf-8")

    loaded = load_json(report)

    assert loaded.data is None
    assert loaded.error


def test_load_json_treats_a_missing_file_as_neither_data_nor_error(tmp_path: Path) -> None:
    loaded = load_json(tmp_path / "trivy.json")

    assert loaded.data is None
    assert loaded.error is None


def test_build_report_reads_all_supported_tools(tmp_path: Path) -> None:
    for scanner in SCANNERS:
        _copy_fixture(scanner.report_file, tmp_path)

    findings, report = build_report(tmp_path)

    assert len(findings) == 4
    assert report["summary"]["tools_run"] == [scanner.label for scanner in SCANNERS]
    assert findings[0].severity == "CRITICAL"
    assert report["findings"][0]["tool"] == "Gitleaks"


def test_build_report_keeps_going_when_one_report_cannot_be_parsed(tmp_path: Path) -> None:
    _copy_fixture("gitleaks.json", tmp_path)
    (tmp_path / "trivy.json").write_text('{"Results": [', encoding="utf-8")

    findings, report = build_report(tmp_path)

    assert report["summary"]["tools_run"] == ["Gitleaks"]
    assert [finding.tool for finding in findings] == ["Gitleaks"]


def test_build_report_warns_about_a_report_it_could_not_parse(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    (tmp_path / "trivy.json").write_text('{"Results": [', encoding="utf-8")

    build_report(tmp_path)

    assert "Warning: Could not parse trivy.json:" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("report_file", "text", "shape", "label"),
    [
        ("trivy.json", "[]", "object", "Trivy"),
        ("semgrep.json", '"results"', "object", "Semgrep"),
        ("gitleaks.json", "{}", "array", "Gitleaks"),
        ("zap.json", "null", "object", "ZAP"),
    ],
)
def test_a_report_that_is_not_the_shape_its_scanner_writes_is_left_out_of_tools_run(
    tmp_path: Path,
    capsys: CaptureFixture[str],
    report_file: str,
    text: str,
    shape: str,
    label: str,
) -> None:
    """`tools_run` once listed any report that parsed as JSON, so a Trivy `[]` read as Trivy
    having run while `--strict` held it against the run and no finding could come from it."""
    (tmp_path / report_file).write_text(text, encoding="utf-8")

    findings, report = build_report(tmp_path)

    assert report["summary"]["tools_run"] == []
    assert findings == []
    assert (
        f"Warning: {report_file} is not the JSON {shape} {label} writes, "
        f"so {label} is left out of tools_run."
    ) in capsys.readouterr().out


def test_a_report_that_is_absent_is_not_warned_about(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A disabled scanner writes no report, and that is not worth a warning."""
    _, report = build_report(tmp_path)

    assert report["summary"]["tools_run"] == []
    assert "Warning" not in capsys.readouterr().out


def test_a_finding_whose_file_holds_a_lone_surrogate_is_written_to_the_report(
    tmp_path: Path,
) -> None:
    """`warden-aggregate` raised writing such a finding and left `security_audit.json` empty."""
    (tmp_path / "semgrep.json").write_text(
        r'{"results": [{"check_id": "r", "path": "bad\udcff.py", "start": {"line": 1}, '
        r'"extra": {"severity": "ERROR", "message": "m"}}]}',
        encoding="utf-8",
    )
    output = tmp_path / "security_audit.json"

    exit_code = main([str(tmp_path), str(output)])

    report = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 1
    assert [finding["file"] for finding in report["findings"]] == ["bad\udcff.py"]


def test_parse_zap_reports_unknown_file_without_an_instance_uri() -> None:
    findings = parse_zap(
        {"site": [{"alerts": [{"riskcode": "3", "alert": "No instances"}]}]}, "ZAP"
    )

    assert len(findings) == 1
    assert findings[0].file == "Unknown"


def test_judge_groups_breakdown_by_category(tmp_path: Path) -> None:
    _copy_fixture("trivy.json", tmp_path)
    _copy_fixture("gitleaks.json", tmp_path)

    findings, _ = build_report(tmp_path)
    verdict = judge(findings)

    assert verdict.counts["CRITICAL"] == 1
    assert verdict.counts["HIGH"] == 1
    assert verdict.breakdown["CRITICAL"] == {"Secrets": 1}
    assert verdict.breakdown["HIGH"] == {"Deps": 1}


def test_judge_fails_on_a_critical_finding() -> None:
    verdict = judge(_findings("CRITICAL"))

    assert verdict.failed
    assert verdict.triggered_by == ("CRITICAL",)


def test_judge_fails_on_a_high_finding() -> None:
    verdict = judge(_findings("HIGH"))

    assert verdict.failed
    assert verdict.triggered_by == ("HIGH",)


def test_judge_passes_when_nothing_reaches_the_threshold() -> None:
    verdict = judge(_findings("MEDIUM", "LOW", "INFO", "UNKNOWN"))

    assert not verdict.failed
    assert verdict.triggered_by == ()
    assert verdict.counts["MEDIUM"] == 1


def test_judge_passes_when_there_are_no_findings() -> None:
    verdict = judge([])

    assert not verdict.failed
    assert verdict.triggered_by == ()
    assert verdict.counts["CRITICAL"] == 0


def test_judge_reports_every_severity_that_triggered_the_failure() -> None:
    verdict = judge(_findings("CRITICAL", "HIGH", "MEDIUM"))

    assert verdict.triggered_by == ("CRITICAL", "HIGH")


def test_print_summary_renders_a_table_for_a_failing_verdict(
    capsys: CaptureFixture[str],
) -> None:
    print_summary(verdict=judge(_findings("CRITICAL")), output_file="security_audit.json")

    output = capsys.readouterr().out
    assert "SCAN COMPLETE" in output
    assert "Critical" in output
    assert "FAIL: High/Critical issues found. See security_audit.json" in output


@pytest.mark.parametrize(
    "output_file",
    [
        "proj[/red]x/a.json",
        "proj[bold]x/a.json",
        "x:warning:y/a.json",
        "C:\\Users\\me\\[2024] Proj\\a.json",
        "C:\\proj\\",
    ],
)
def test_print_summary_shows_a_path_literally_even_if_it_looks_like_rich_markup(
    capsys: CaptureFixture[str], output_file: str
) -> None:
    """A project directory name must not be able to crash or rewrite the status line."""
    print_summary(verdict=judge(_findings("CRITICAL")), output_file=output_file)

    assert capsys.readouterr().out.splitlines()[-1].endswith(f"See {output_file}")


def test_aggregate_main_exits_non_zero_when_a_critical_finding_is_present(tmp_path: Path) -> None:
    _copy_fixture("gitleaks.json", tmp_path)
    output_file = tmp_path / "security_audit.json"

    exit_code = main([str(tmp_path), str(output_file)])

    assert exit_code == 1
    report = json.loads(output_file.read_text(encoding="utf-8"))
    assert report["summary"]["total_issues"] == 1


def test_aggregate_main_exits_zero_when_no_reports_are_present(tmp_path: Path) -> None:
    exit_code = main([str(tmp_path), str(tmp_path / "security_audit.json")])

    assert exit_code == 0


def test_a_report_dir_that_does_not_exist_is_a_usage_error_not_a_pass(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A mistyped path used to print `PASS`, exit 0, and write an empty report."""
    output_file = tmp_path / "security_audit.json"

    with pytest.raises(SystemExit) as exit_info:
        main([str(tmp_path / "typo"), str(output_file)])

    assert exit_info.value.code == 2
    assert not output_file.exists()
    assert "is not an existing directory" in capsys.readouterr().err
