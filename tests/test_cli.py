from __future__ import annotations

import io
import json
import shutil
import sys
from pathlib import Path

import pytest
from pytest import CaptureFixture

from fakes import RecordingRunner, symlink_or_skip
from warden import cli
from warden._scanners import SCANNERS

FIXTURE_DIR = Path(__file__).parent / "fixtures"

DISABLE_EVERY_TOOL = """
tools:
  trivy: false
  semgrep: false
  gitleaks: false
  zap: false
"""


def _zap_target(runner: RecordingRunner) -> str:
    """The URL ZAP was pointed at, read back out of the docker command line."""
    args = runner.commands[-1].args
    return args[args.index("-t", args.index("zap-full-scan.py")) + 1]


def test_cli_uses_cli_url_for_zap(tmp_path: Path) -> None:
    (tmp_path / ".warden.yaml").write_text(
        'target_url: "http://from-config"\n',
        encoding="utf-8",
    )
    runner = RecordingRunner(report_text="{}")

    exit_code = cli.main(
        ["--project-root", str(tmp_path), "--url", "http://from-cli"],
        runner=runner,
    )

    assert exit_code == 0
    assert _zap_target(runner) == "http://from-cli"
    report = json.loads((tmp_path / "security_audit.json").read_text(encoding="utf-8"))
    assert report["summary"]["tools_run"] == [scanner.label for scanner in SCANNERS]


def test_cli_rewrites_localhost_target_for_zap(tmp_path: Path) -> None:
    runner = RecordingRunner(report_text="{}")

    exit_code = cli.main(
        ["--project-root", str(tmp_path), "--url", "http://localhost:3000"],
        runner=runner,
    )

    assert exit_code == 0
    assert _zap_target(runner) == "http://host.docker.internal:3000"


def test_cli_exits_non_zero_when_a_critical_finding_is_present(tmp_path: Path) -> None:
    gitleaks_report = (FIXTURE_DIR / "gitleaks.json").read_text(encoding="utf-8")
    runner = RecordingRunner(report_text=gitleaks_report)

    exit_code = cli.main(["--project-root", str(tmp_path)], runner=runner)

    assert exit_code == 1
    report = json.loads((tmp_path / "security_audit.json").read_text(encoding="utf-8"))
    assert [finding["severity"] for finding in report["findings"]] == ["CRITICAL"]


def test_cli_skips_disabled_tools(tmp_path: Path) -> None:
    (tmp_path / ".warden.yaml").write_text(DISABLE_EVERY_TOOL, encoding="utf-8")
    runner = RecordingRunner()

    exit_code = cli.main(["--project-root", str(tmp_path)], runner=runner)

    assert exit_code == 0
    assert runner.commands == []
    report = json.loads((tmp_path / "security_audit.json").read_text(encoding="utf-8"))
    assert report["summary"]["total_issues"] == 0
    assert report["findings"] == []


def test_cli_discards_reports_from_a_previous_run(tmp_path: Path) -> None:
    (tmp_path / ".warden.yaml").write_text(DISABLE_EVERY_TOOL, encoding="utf-8")
    report_dir = tmp_path / ".security_reports"
    report_dir.mkdir()
    shutil.copyfile(FIXTURE_DIR / "gitleaks.json", report_dir / "gitleaks.json")
    (report_dir / "zap.html").write_text("stale", encoding="utf-8")
    runner = RecordingRunner()

    exit_code = cli.main(["--project-root", str(tmp_path)], runner=runner)

    assert exit_code == 0
    assert runner.commands == []
    assert not (report_dir / "zap.html").exists()
    report = json.loads((tmp_path / "security_audit.json").read_text(encoding="utf-8"))
    assert report["summary"]["tools_run"] == []
    assert report["findings"] == []


def test_cli_warns_and_continues_when_a_scanner_is_missing(
    capsys: CaptureFixture[str], tmp_path: Path
) -> None:
    runner = RecordingRunner(returncode=None, warning="trivy was not found on PATH.")

    exit_code = cli.main(["--project-root", str(tmp_path)], runner=runner)

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "[1/4] Running Trivy..." in output
    assert "   -> Warning: trivy was not found on PATH." in output
    assert "[4/4] Skipping ZAP (no URL provided or disabled)." in output


def test_cli_warns_and_continues_when_a_scanner_fails(
    capsys: CaptureFixture[str], tmp_path: Path
) -> None:
    runner = RecordingRunner(returncode=2)

    exit_code = cli.main(["--project-root", str(tmp_path)], runner=runner)

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "   -> Warning: Trivy exited with status 2." in output


def test_a_symlink_where_the_report_goes_is_replaced_not_followed(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / ".warden.yaml").write_text(DISABLE_EVERY_TOOL, encoding="utf-8")
    symlink_or_skip(project / "security_audit.json", victim)

    exit_code = cli.main(["--project-root", str(project)], runner=RecordingRunner())

    report = project / "security_audit.json"
    assert exit_code == 0
    assert victim.read_text(encoding="utf-8") == "keep me"
    assert not report.is_symlink()
    assert json.loads(report.read_text(encoding="utf-8"))["summary"]["total_issues"] == 0


def test_a_project_root_that_does_not_exist_is_a_usage_error_and_nothing_is_created(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A typo in a path used to be created on demand and scanned as an empty tree: PASS, exit 0."""
    missing = tmp_path / "typo" / "does-not-exist"
    runner = RecordingRunner()

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--project-root", str(missing)], runner=runner)

    assert exit_info.value.code == 2
    assert not (tmp_path / "typo").exists()
    assert runner.commands == []
    assert "is not an existing directory" in capsys.readouterr().err


def test_a_project_root_that_is_a_file_is_a_usage_error(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    a_file = tmp_path / "a-file"
    a_file.write_text("", encoding="utf-8")

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--project-root", str(a_file)], runner=RecordingRunner())

    assert exit_info.value.code == 2
    assert "is not an existing directory" in capsys.readouterr().err


def test_a_regular_file_where_the_report_directory_goes_is_a_clear_error_not_a_traceback(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    (tmp_path / ".security_reports").write_text("in the way", encoding="utf-8")
    runner = RecordingRunner()

    exit_code = cli.main(["--project-root", str(tmp_path)], runner=runner)

    assert exit_code == 1
    assert runner.commands == []
    assert "warden: error: cannot prepare the report paths" in capsys.readouterr().err


def test_a_directory_where_a_stale_report_goes_is_a_clear_error_not_a_traceback(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    (tmp_path / ".security_reports" / "trivy.json").mkdir(parents=True)

    exit_code = cli.main(["--project-root", str(tmp_path)], runner=RecordingRunner())

    assert exit_code == 1
    assert "warden: error: cannot prepare the report paths" in capsys.readouterr().err


def test_a_directory_where_the_report_goes_is_a_clear_error_after_the_scans_ran(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    (tmp_path / ".warden.yaml").write_text(DISABLE_EVERY_TOOL, encoding="utf-8")
    (tmp_path / "security_audit.json").mkdir()

    exit_code = cli.main(["--project-root", str(tmp_path)], runner=RecordingRunner())

    assert exit_code == 1
    assert "warden: error: cannot read the reports or write security_audit.json" in (
        capsys.readouterr().err
    )


@pytest.mark.parametrize(
    "url",
    [
        "localhost:3000",
        "ftp://example.com",
        "http://",
        "HTTP://example.com",
        "http://example.com/\x1b[31mred",
        "http://example.com/\u202egpj.exe",
    ],
)
def test_an_unusable_dast_url_is_a_warning_and_zap_is_skipped(
    tmp_path: Path, capsys: CaptureFixture[str], url: str
) -> None:
    runner = RecordingRunner(report_text="{}")

    exit_code = cli.main(["--project-root", str(tmp_path), "--url", url], runner=runner)

    output = capsys.readouterr().out
    assert exit_code == 0
    assert not [command for command in runner.commands if "zap-full-scan.py" in command.args]
    assert "Warning: the DAST URL" in output
    assert "skipping ZAP" in output
    assert "DAST URL:" not in output
    assert "[4/4] Skipping ZAP" in output
    assert "\x1b" not in output
    assert "\u202e" not in output


def test_a_usable_dast_url_is_announced_and_scanned(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    runner = RecordingRunner(report_text="{}")

    cli.main(["--project-root", str(tmp_path), "--url", "https://example.com"], runner=runner)

    assert "   DAST URL: https://example.com" in capsys.readouterr().out
    assert _zap_target(runner) == "https://example.com"


def test_the_cli_prints_what_the_config_warned_about(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    (tmp_path / ".warden.yaml").write_text('target_url: "http://app.example"\n', encoding="utf-8")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    runner = RecordingRunner(report_text="{}")

    exit_code = cli.main(["--project-root", str(tmp_path)], runner=runner)

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Warning: target_url in .warden.yaml is ignored" in output
    assert not [command for command in runner.commands if "zap-full-scan.py" in command.args]


def test_the_timeout_reaches_every_scanner_and_defaults_to_none(tmp_path: Path) -> None:
    limited = RecordingRunner(report_text="{}")
    unlimited = RecordingRunner(report_text="{}")
    url = ["--url", "http://example.com"]

    cli.main(["--project-root", str(tmp_path), *url, "--timeout", "90"], runner=limited)
    cli.main(["--project-root", str(tmp_path), *url], runner=unlimited)

    assert [command.timeout for command in limited.commands] == [90.0] * len(SCANNERS)
    assert [command.timeout for command in unlimited.commands] == [None] * len(SCANNERS)


@pytest.mark.parametrize("value", ["0", "-5", "nan", "soon", "inf", "-inf", "1e999", "4294968"])
def test_a_timeout_that_is_not_a_positive_number_is_a_usage_error(
    tmp_path: Path, capsys: CaptureFixture[str], value: str
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--project-root", str(tmp_path), "--timeout", value], runner=RecordingRunner())

    assert exit_info.value.code == 2
    assert "--timeout" in capsys.readouterr().err


def test_a_scanner_that_timed_out_is_reported_as_a_warning_not_as_done(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    runner = RecordingRunner(
        returncode=None, timed_out=True, warning="trivy timed out after 5 seconds and was stopped."
    )

    exit_code = cli.main(["--project-root", str(tmp_path), "--timeout", "5"], runner=runner)

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "   -> Warning: trivy timed out after 5 seconds and was stopped." in output
    assert "Done." not in output


USABLE_REPORTS = {"trivy.json": "{}", "semgrep.json": '{"results": []}', "gitleaks.json": "[]"}


def _strict(tmp_path: Path, runner: RecordingRunner, *extra: str) -> int:
    return cli.main(["--project-root", str(tmp_path), "--strict", *extra], runner=runner)


def test_strict_passes_when_every_scanner_that_ran_left_a_usable_report(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A clean Trivy report is an object with no `Results`, and a clean Gitleaks one is `[]`."""
    exit_code = _strict(tmp_path, RecordingRunner(report_texts=USABLE_REPORTS))

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "STRICT" not in output
    assert "AUDIT COMPLETE!" in output


def test_strict_is_exit_3_when_a_scanner_is_missing_where_the_default_passes(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    runner = RecordingRunner(returncode=None, warning="trivy was not found on PATH.")

    default_exit = cli.main(["--project-root", str(tmp_path)], runner=runner)
    strict_exit = _strict(tmp_path, runner)

    output = capsys.readouterr().out
    assert (default_exit, strict_exit) == (0, cli.EXIT_INCOMPLETE)
    assert "STRICT: Trivy, Semgrep, Gitleaks did not produce a usable report" in output
    assert "AUDIT INCOMPLETE!" in output


def test_strict_is_exit_3_when_scanners_exited_without_writing_a_report(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    exit_code = _strict(tmp_path, RecordingRunner(returncode=2))

    assert exit_code == cli.EXIT_INCOMPLETE
    assert "STRICT: Trivy, Semgrep, Gitleaks did not produce a usable report" in (
        capsys.readouterr().out
    )


def test_strict_is_exit_3_when_a_report_is_there_but_is_not_json(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    runner = RecordingRunner(report_texts={**USABLE_REPORTS, "semgrep.json": ""})

    exit_code = _strict(tmp_path, runner)

    assert exit_code == cli.EXIT_INCOMPLETE
    assert "STRICT: Semgrep did not produce a usable report" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("report", "wrong"),
    [("{}", "Gitleaks"), ("null", "Gitleaks"), ("not json", "Gitleaks")],
)
def test_strict_needs_the_shape_each_scanner_writes(
    tmp_path: Path, capsys: CaptureFixture[str], report: str, wrong: str
) -> None:
    runner = RecordingRunner(report_texts={**USABLE_REPORTS, "gitleaks.json": report})

    exit_code = _strict(tmp_path, runner)

    assert exit_code == cli.EXIT_INCOMPLETE
    assert f"STRICT: {wrong} did not produce a usable report" in capsys.readouterr().out


def test_strict_counts_a_report_whose_scanner_exited_non_zero_because_it_had_alerts(
    tmp_path: Path,
) -> None:
    """ZAP exits 1 or 2 when it has alerts, and still writes its report."""
    runner = RecordingRunner(returncode=2, report_texts={**USABLE_REPORTS, "zap.json": "{}"})

    assert _strict(tmp_path, runner, "--url", "http://example.com") == 0


def test_strict_is_exit_3_when_no_scanner_ran_at_all(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    (tmp_path / ".warden.yaml").write_text(DISABLE_EVERY_TOOL, encoding="utf-8")

    exit_code = _strict(tmp_path, RecordingRunner())

    assert exit_code == cli.EXIT_INCOMPLETE
    assert "STRICT: no scanner ran" in capsys.readouterr().out


def test_strict_leaves_a_failing_finding_as_exit_1_but_still_says_what_is_incomplete(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    gitleaks_report = (FIXTURE_DIR / "gitleaks.json").read_text(encoding="utf-8")
    runner = RecordingRunner(report_texts={"gitleaks.json": gitleaks_report})

    exit_code = _strict(tmp_path, runner)

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "STRICT: Trivy, Semgrep did not produce a usable report" in output
    assert "AUDIT FAILED!" in output


def test_strict_holds_an_unusable_dast_url_against_the_run(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    runner = RecordingRunner(report_texts=USABLE_REPORTS)

    exit_code = _strict(tmp_path, runner, "--url", "localhost:3000")

    assert exit_code == cli.EXIT_INCOMPLETE
    assert "STRICT: ZAP did not produce a usable report" in capsys.readouterr().out


def test_strict_holds_a_scanner_that_timed_out_against_the_run(tmp_path: Path) -> None:
    runner = RecordingRunner(
        returncode=None,
        timed_out=True,
        warning="trivy timed out after 5 seconds and was stopped.",
        report_text="{}",
    )

    assert _strict(tmp_path, runner, "--timeout", "5") == cli.EXIT_INCOMPLETE


@pytest.mark.parametrize("encoding", ["cp1252", "ascii"])
def test_text_the_console_cannot_encode_is_printed_escaped_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, encoding: str
) -> None:
    """A stray line in `.warden.yaml` is echoed in a warning; on a redirected Windows stdout
    a character outside the code page used to raise UnicodeEncodeError after the setup."""
    (tmp_path / ".warden.yaml").write_text(
        DISABLE_EVERY_TOOL + "\u65e5\u672c\u8a9e\n", encoding="utf-8"
    )
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding=encoding, write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)

    exit_code = cli.main(["--project-root", str(tmp_path)], runner=RecordingRunner())

    output = raw.getvalue().decode(encoding)
    assert exit_code == 0
    assert "Warning: .warden.yaml: line" in output
    assert "\\u65e5\\u672c\\u8a9e" in output
    assert "AUDIT COMPLETE!" in output
