from __future__ import annotations

import json
import shutil
from pathlib import Path

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
