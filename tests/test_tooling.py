from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from fakes import RecordingRunner, symlink_or_skip
from warden import tooling
from warden._models import ToolRunResult
from warden._scanners import (
    GITLEAKS,
    SCANNERS,
    SEMGREP,
    TRIVY,
    ZAP,
    ZAP_HTML_REPORT,
    ZAP_IMAGE,
    Scanner,
    resolve_host_report_dir,
)

HOST_PATH_VARIABLES = ("WARDEN_HOST_REPORT_DIR", "WARDEN_HOST_WORKSPACE", "GITHUB_WORKSPACE")


def _forget_host_path_variables(monkeypatch: MonkeyPatch) -> None:
    for name in HOST_PATH_VARIABLES:
        monkeypatch.delenv(name, raising=False)


def _run(
    scanner: Scanner,
    tmp_path: Path,
    runner: RecordingRunner,
    *,
    exclude_dirs: Sequence[str] = (),
    url: str = "",
    timeout: float | None = None,
) -> ToolRunResult:
    request = tooling.scan_request(
        scanner,
        project_root=tmp_path,
        report_dir=tmp_path,
        exclude_dirs=exclude_dirs,
        url=url,
    )
    return tooling.run_scanner(scanner, request, runner, timeout=timeout)


def test_trivy_builds_its_command_line(tmp_path: Path) -> None:
    runner = RecordingRunner()

    _run(TRIVY, tmp_path, runner)

    command = runner.commands[0]
    assert command.args == [
        "trivy",
        "fs",
        ".",
        "--format",
        "json",
        "--output",
        str(tmp_path.resolve() / "trivy.json"),
        "--quiet",
        "--scanners",
        "vuln",
    ]
    assert command.cwd == tmp_path.resolve()
    assert not command.stderr_to_devnull
    assert command.env_overrides is None


def test_trivy_joins_its_exclude_dirs_with_commas(tmp_path: Path) -> None:
    runner = RecordingRunner()

    _run(TRIVY, tmp_path, runner, exclude_dirs=["build", "node_modules"])

    assert runner.commands[0].args[-2:] == ["--skip-dirs", "build,node_modules"]


def test_semgrep_builds_its_command_line(tmp_path: Path) -> None:
    runner = RecordingRunner()

    _run(SEMGREP, tmp_path, runner)

    command = runner.commands[0]
    assert command.args == [
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        "--output",
        str(tmp_path.resolve() / "semgrep.json"),
        "--quiet",
        ".",
    ]
    assert command.cwd == tmp_path.resolve()
    assert command.stderr_to_devnull
    assert command.env_overrides == {"PYTHONUTF8": "1"}


def test_semgrep_repeats_its_exclude_flag_per_directory(tmp_path: Path) -> None:
    runner = RecordingRunner()

    _run(SEMGREP, tmp_path, runner, exclude_dirs=["build", "", "node_modules"])

    assert runner.commands[0].args[-4:] == [
        "--exclude",
        "build",
        "--exclude",
        "node_modules",
    ]


def test_gitleaks_builds_its_command_line(tmp_path: Path) -> None:
    runner = RecordingRunner()

    _run(GITLEAKS, tmp_path, runner)

    command = runner.commands[0]
    assert command.args == [
        "gitleaks",
        "detect",
        "--source",
        ".",
        "--no-git",
        "--report-path",
        str(tmp_path.resolve() / "gitleaks.json"),
        "--exit-code",
        "0",
        "--redact",
    ]
    assert command.cwd == tmp_path.resolve()
    assert command.stderr_to_devnull
    assert command.env_overrides is None


def test_gitleaks_is_never_given_a_path_flag_because_it_has_none(tmp_path: Path) -> None:
    """`gitleaks detect` rejects `--exclude-path` ("unknown flag", exit 126), which used to switch
    secret scanning off for any project with `exclude_dirs` while the audit still passed."""
    runner = RecordingRunner()

    _run(GITLEAKS, tmp_path, runner, exclude_dirs=["build", "", "node_modules"])

    args = runner.commands[0].args
    assert "--exclude-path" not in args
    assert not {"build", "node_modules"} & set(args)


def _gitleaks_files_reported(tmp_path: Path, *, exclude_dirs: Sequence[str]) -> list[str]:
    report = [
        {"RuleID": "github-pat", "File": "src/app.env"},
        {"RuleID": "github-pat", "File": "vendor/lib.env"},
        {"RuleID": "github-pat", "File": "vendor/deep/lib.env"},
        {"RuleID": "github-pat", "File": "vendor-old/x.env"},
        {"RuleID": "github-pat", "File": "sub/vendor/x.env"},
        {"RuleID": "github-pat", "File": "vendor"},
        {"RuleID": "github-pat", "File": "/abs/app.env"},
        {"RuleID": "github-pat", "File": ""},
        {"RuleID": "github-pat"},
    ]
    runner = RecordingRunner(report_text=json.dumps(report))

    _run(GITLEAKS, tmp_path, runner, exclude_dirs=exclude_dirs)

    kept = json.loads((tmp_path / "gitleaks.json").read_text(encoding="utf-8"))
    return [entry.get("File", "<none>") for entry in kept]


def test_gitleaks_findings_under_an_excluded_directory_are_dropped(tmp_path: Path) -> None:
    assert _gitleaks_files_reported(tmp_path, exclude_dirs=["vendor/"]) == [
        "src/app.env",
        "vendor-old/x.env",
        "sub/vendor/x.env",
        "/abs/app.env",
        "",
        "<none>",
    ]


def test_a_finding_matching_any_one_of_several_entries_is_dropped(tmp_path: Path) -> None:
    assert _gitleaks_files_reported(tmp_path, exclude_dirs=["build/", "vendor/", "sub"]) == [
        "src/app.env",
        "vendor-old/x.env",
        "/abs/app.env",
        "",
        "<none>",
    ]


@pytest.mark.parametrize(
    "entry",
    [
        "vendor",
        "vendor/",
        "./vendor",
        " vendor ",
        pytest.param(
            "vendor\\",
            marks=pytest.mark.skipif(
                os.sep != "\\", reason="a backslash separates only on Windows"
            ),
        ),
    ],
)
def test_an_excluded_directory_may_be_written_in_any_of_the_usual_forms(
    tmp_path: Path, entry: str
) -> None:
    files = _gitleaks_files_reported(tmp_path, exclude_dirs=[entry])

    assert "vendor/lib.env" not in files
    assert "vendor/deep/lib.env" not in files
    assert "vendor-old/x.env" in files


@pytest.mark.parametrize("entry", ["", "/", ".", "./", "*", "**/vendor", "vend"])
def test_an_entry_that_is_not_a_directory_below_the_root_excludes_nothing(
    tmp_path: Path, entry: str
) -> None:
    """Dropping a finding is never the safe way to be wrong, so anything unclear keeps it."""
    assert len(_gitleaks_files_reported(tmp_path, exclude_dirs=[entry])) == 9


def test_a_backslash_separates_path_parts_only_where_the_platform_uses_it(tmp_path: Path) -> None:
    """On POSIX `vendor\\lib.env` is one file name in the root, not a file under `vendor/`."""
    runner = RecordingRunner(report_text=json.dumps([{"File": "vendor\\lib.env"}]))

    _run(GITLEAKS, tmp_path, runner, exclude_dirs=["vendor"])

    kept = json.loads((tmp_path / "gitleaks.json").read_text(encoding="utf-8"))
    assert (kept == []) is (os.sep == "\\")


def test_a_finding_that_is_not_an_object_with_a_path_is_kept(tmp_path: Path) -> None:
    report = [1, None, "vendor/x", ["vendor/x"], {"File": 3}, {"File": None}]
    runner = RecordingRunner(report_text=json.dumps(report))

    _run(GITLEAKS, tmp_path, runner, exclude_dirs=["vendor"])

    assert json.loads((tmp_path / "gitleaks.json").read_text(encoding="utf-8")) == report


def test_filtering_does_not_slow_down_with_many_entries_and_findings(tmp_path: Path) -> None:
    """A hostile `.warden.yaml` controls the entries and a hostile tree the findings."""
    entries = [f"dir{index}/" for index in range(20_000)]
    report = [{"File": f"other{index}/x.env"} for index in range(20_000)]
    runner = RecordingRunner(report_text=json.dumps(report))

    started = time.perf_counter()
    _run(GITLEAKS, tmp_path, runner, exclude_dirs=entries)

    assert time.perf_counter() - started < 5
    kept = json.loads((tmp_path / "gitleaks.json").read_text(encoding="utf-8"))
    assert len(kept) == 20_000


def test_filtering_does_not_slow_down_with_deep_paths(tmp_path: Path) -> None:
    """Only as many leading parts as the deepest entry has can match, however deep a path goes."""
    report = [{"File": "a/" * 3_000 + "x.env"} for _ in range(2_000)]
    runner = RecordingRunner(report_text=json.dumps(report))

    started = time.perf_counter()
    _run(GITLEAKS, tmp_path, runner, exclude_dirs=["vendor"])

    assert time.perf_counter() - started < 4
    kept = json.loads((tmp_path / "gitleaks.json").read_text(encoding="utf-8"))
    assert len(kept) == 2_000


def test_a_relative_entry_never_matches_an_absolute_path_and_an_absolute_one_no_relative_path(
    tmp_path: Path,
) -> None:
    report = [{"File": "/vendor/x.env"}, {"File": "vendor/x.env"}]
    runner = RecordingRunner(report_text=json.dumps(report))

    _run(GITLEAKS, tmp_path, runner, exclude_dirs=["vendor"])
    kept_by_relative_entry = json.loads((tmp_path / "gitleaks.json").read_text(encoding="utf-8"))
    _run(GITLEAKS, tmp_path, runner, exclude_dirs=["/vendor"])
    kept_by_absolute_entry = json.loads((tmp_path / "gitleaks.json").read_text(encoding="utf-8"))

    assert kept_by_relative_entry == [{"File": "/vendor/x.env"}]
    assert {"File": "vendor/x.env"} in kept_by_absolute_entry


@pytest.mark.skipif(os.sep == "\\", reason="a backslash separates parts on Windows")
def test_a_backslash_in_an_entry_is_part_of_its_name_on_posix(tmp_path: Path) -> None:
    runner = RecordingRunner(report_text=json.dumps([{"File": "vendor/x.env"}]))

    _run(GITLEAKS, tmp_path, runner, exclude_dirs=["vendor\\"])

    kept = json.loads((tmp_path / "gitleaks.json").read_text(encoding="utf-8"))
    assert kept == [{"File": "vendor/x.env"}]


def test_only_a_scanner_that_cannot_skip_paths_has_its_report_filtered(tmp_path: Path) -> None:
    runner = RecordingRunner(report_text='[{"File": "vendor/x"}]')

    _run(TRIVY, tmp_path, runner, exclude_dirs=["vendor/"])

    assert json.loads((tmp_path / "trivy.json").read_text(encoding="utf-8")) == [
        {"File": "vendor/x"}
    ]


def test_a_gitleaks_report_that_is_not_a_list_is_left_as_it_is(tmp_path: Path) -> None:
    runner = RecordingRunner(report_text='{"File": "vendor/x"}')

    _run(GITLEAKS, tmp_path, runner, exclude_dirs=["vendor/"])

    assert json.loads((tmp_path / "gitleaks.json").read_text(encoding="utf-8")) == {
        "File": "vendor/x"
    }


def test_an_empty_exclude_list_omits_the_exclude_flag(tmp_path: Path) -> None:
    runner = RecordingRunner()

    for scanner in (TRIVY, SEMGREP, GITLEAKS):
        _run(scanner, tmp_path, runner)

    arguments = {argument for command in runner.commands for argument in command.args}
    assert not arguments & {"--skip-dirs", "--exclude", "--exclude-path"}


def test_zap_builds_its_docker_command_line(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    _forget_host_path_variables(monkeypatch)
    runner = RecordingRunner()

    _run(ZAP, tmp_path, runner, url="http://localhost:3000")

    command = runner.commands[0]
    name = command.args[command.args.index("--name") + 1]
    assert re.fullmatch(r"warden-zap-[0-9a-f]{32}", name)
    assert command.args == [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "-v",
        f"{tmp_path.resolve()}:/zap/wrk/:rw",
        "-t",
        ZAP_IMAGE,
        "zap-full-scan.py",
        "-t",
        "http://host.docker.internal:3000",
        "-J",
        "zap.json",
        "-r",
        ZAP_HTML_REPORT,
        "-I",
    ]
    assert command.cwd == tmp_path.resolve()


def test_zap_mounts_the_host_report_dir_when_one_is_supplied(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _forget_host_path_variables(monkeypatch)
    monkeypatch.setenv("WARDEN_HOST_WORKSPACE", "/host/workspace")
    runner = RecordingRunner()

    _run(ZAP, tmp_path, runner, url="http://example.test")

    mount = Path("/host/workspace") / ".security_reports"
    args = runner.commands[0].args
    assert args[args.index("-v") + 1] == f"{mount}:/zap/wrk/:rw"


def test_resolve_host_report_dir_prefers_the_explicit_report_dir(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("WARDEN_HOST_REPORT_DIR", "/host/reports")
    monkeypatch.setenv("WARDEN_HOST_WORKSPACE", "/host/workspace")
    monkeypatch.setenv("GITHUB_WORKSPACE", "/github/workspace")

    assert resolve_host_report_dir(tmp_path) == Path("/host/reports")


def test_resolve_host_report_dir_falls_back_to_the_host_workspace(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _forget_host_path_variables(monkeypatch)
    monkeypatch.setenv("WARDEN_HOST_WORKSPACE", "/host/workspace")
    monkeypatch.setenv("GITHUB_WORKSPACE", "/github/workspace")

    expected = Path("/host/workspace") / ".security_reports"
    assert resolve_host_report_dir(tmp_path) == expected


def test_resolve_host_report_dir_falls_back_to_the_github_workspace(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _forget_host_path_variables(monkeypatch)
    monkeypatch.setenv("GITHUB_WORKSPACE", "/github/workspace")

    expected = Path("/github/workspace") / ".security_reports"
    assert resolve_host_report_dir(tmp_path) == expected


def test_resolve_host_report_dir_falls_back_to_the_local_path(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _forget_host_path_variables(monkeypatch)

    assert resolve_host_report_dir(tmp_path) == tmp_path.resolve()


def test_run_subprocess_reports_the_exit_code_and_applies_env_overrides(tmp_path: Path) -> None:
    result = tooling.run_subprocess(
        [sys.executable, "-c", "import os, sys; sys.exit(int(os.environ['WARDEN_TEST_EXIT']))"],
        cwd=tmp_path,
        stderr_to_devnull=True,
        env_overrides={"WARDEN_TEST_EXIT": "3"},
    )

    assert result.returncode == 3
    assert result.warning is None


def test_run_subprocess_warns_when_the_executable_is_missing(tmp_path: Path) -> None:
    result = tooling.run_subprocess(["warden-no-such-scanner"], cwd=tmp_path)

    assert result.returncode is None
    assert result.warning == "warden-no-such-scanner was not found on PATH."


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits and exec formats")
@pytest.mark.parametrize(
    ("mode", "content", "reasons"),
    [
        (0o644, "#!/bin/sh\nexit 0\n", ("Permission denied",)),
        # A temporary directory mounted noexec answers EACCES before the kernel looks at the format.
        (0o755, "not an executable format\n", ("Exec format error", "Permission denied")),
    ],
)
def test_a_tool_that_cannot_be_started_warns_instead_of_aborting_the_audit(
    tmp_path: Path, mode: int, content: str, reasons: tuple[str, ...]
) -> None:
    """These raised out of `subprocess.run`, so the remaining scanners never ran."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    tool = bin_dir / "warden-broken-scanner"
    tool.write_text(content, encoding="utf-8")
    tool.chmod(mode)

    result = tooling.run_subprocess(
        ["warden-broken-scanner"], cwd=tmp_path, env_overrides={"PATH": str(bin_dir)}
    )

    assert result.returncode is None
    assert result.warning in {f"warden-broken-scanner could not be started: {r}" for r in reasons}


def test_a_working_directory_that_is_a_file_warns_instead_of_aborting_the_audit(
    tmp_path: Path,
) -> None:
    a_file = tmp_path / "a-file"
    a_file.write_text("", encoding="utf-8")

    result = tooling.run_subprocess([sys.executable, "-c", "pass"], cwd=a_file)

    assert result.returncode is None
    assert result.warning is not None
    assert result.warning.startswith(f"{sys.executable} could not be started")


def test_an_argument_the_system_cannot_take_warns_instead_of_aborting_the_audit(
    tmp_path: Path,
) -> None:
    """`.warden.yaml` values reach a scanner's command line, and a NUL byte cannot be passed."""
    result = tooling.run_subprocess([sys.executable, "-c", "pass", "a\x00b"], cwd=tmp_path)

    assert result.returncode is None
    assert result.warning is not None
    assert result.warning.startswith(f"{sys.executable} could not be started")


SLEEP_FOR_A_MINUTE = [sys.executable, "-c", "import time; time.sleep(60)"]


def test_a_scanner_that_outlives_its_timeout_is_stopped_with_a_warning(tmp_path: Path) -> None:
    started = time.perf_counter()

    result = tooling.run_subprocess(SLEEP_FOR_A_MINUTE, cwd=tmp_path, timeout=0.5)

    assert time.perf_counter() - started < 30
    assert result.returncode is None
    assert result.timed_out
    assert result.warning == f"{sys.executable} timed out after 0.5 seconds and was stopped."


def test_a_scanner_that_finishes_inside_its_timeout_is_untouched(tmp_path: Path) -> None:
    result = tooling.run_subprocess(
        [sys.executable, "-c", "raise SystemExit(3)"], cwd=tmp_path, timeout=60
    )

    assert (result.returncode, result.warning, result.timed_out) == (3, None, False)


def test_a_scanner_that_ignores_the_request_to_stop_is_killed(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    """`docker run` passes SIGTERM on, but a scanner that traps it must not hold the build."""
    monkeypatch.setattr(tooling, "_STOP_GRACE_SECONDS", 0.5)
    stubborn = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
    started = time.perf_counter()

    result = tooling.run_subprocess([sys.executable, "-c", stubborn], cwd=tmp_path, timeout=0.5)

    assert result.timed_out
    assert time.perf_counter() - started < 30


def test_what_a_timed_out_scanner_left_behind_is_not_kept_as_its_report(tmp_path: Path) -> None:
    runner = RecordingRunner(returncode=None, timed_out=True, report_text='{"Results": []}')

    result = _run(TRIVY, tmp_path, runner, timeout=5)

    assert runner.commands[0].timeout == 5
    assert not result.report_path.exists()


def test_a_scanner_that_is_missing_warns_instead_of_raising(tmp_path: Path) -> None:
    runner = RecordingRunner(returncode=None, warning="trivy was not found on PATH.")

    result = _run(TRIVY, tmp_path, runner)

    assert not tooling.tool_succeeded(result)
    assert not tooling.report_written(result)
    assert result.warning == "trivy was not found on PATH."


def test_semgrep_accepts_a_run_that_found_something(tmp_path: Path) -> None:
    runner = RecordingRunner(returncode=1)

    assert tooling.tool_succeeded(_run(SEMGREP, tmp_path, runner))


def test_the_other_scanners_accept_only_a_clean_exit(tmp_path: Path) -> None:
    runner = RecordingRunner(returncode=1)

    assert not tooling.tool_succeeded(_run(TRIVY, tmp_path, runner))
    assert not tooling.tool_succeeded(_run(GITLEAKS, tmp_path, runner))
    assert not tooling.tool_succeeded(_run(ZAP, tmp_path, runner, url="http://example.test"))


def test_a_report_is_pretty_printed_after_the_scanner_writes_it(tmp_path: Path) -> None:
    runner = RecordingRunner(report_text='{"Results":[]}')

    result = _run(TRIVY, tmp_path, runner)

    assert tooling.tool_succeeded(result)
    assert (tmp_path / "trivy.json").read_text(encoding="utf-8") == '{\n  "Results": []\n}'


def test_a_report_that_is_not_json_is_left_alone(tmp_path: Path) -> None:
    runner = RecordingRunner(report_text="not json")

    _run(TRIVY, tmp_path, runner)

    assert (tmp_path / "trivy.json").read_text(encoding="utf-8") == "not json"


def test_every_scanner_can_build_a_command_line(tmp_path: Path) -> None:
    """The registry is the only place a scanner is declared, so every record must be runnable."""
    runner = RecordingRunner()

    for scanner in SCANNERS:
        _run(scanner, tmp_path, runner, url="http://example.test")

    assert len(runner.commands) == len(SCANNERS)
    assert all(command.args for command in runner.commands)


def test_prepare_report_dir_removes_previous_reports(tmp_path: Path) -> None:
    report_dir = tmp_path / ".security_reports"
    report_dir.mkdir()
    (report_dir / "trivy.json").write_text("{}", encoding="utf-8")
    (report_dir / "zap.html").write_text("stale", encoding="utf-8")
    (report_dir / "notes.txt").write_text("keep me", encoding="utf-8")

    prepared = tooling.prepare_report_dir(tmp_path)

    assert prepared == report_dir
    assert not (report_dir / "trivy.json").exists()
    assert not (report_dir / "zap.html").exists()
    assert (report_dir / "notes.txt").exists()


def test_prepare_report_dir_appends_to_an_existing_gitignore(tmp_path: Path) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.log\n", encoding="utf-8")

    tooling.prepare_report_dir(tmp_path)

    assert ".security_reports/" in gitignore.read_text(encoding="utf-8").splitlines()


def test_prepare_report_dir_does_not_list_the_report_dir_twice(tmp_path: Path) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.log\n.security_reports/\n", encoding="utf-8")

    tooling.prepare_report_dir(tmp_path)

    assert gitignore.read_text(encoding="utf-8") == "*.log\n.security_reports/\n"


def test_a_gitignore_in_a_legacy_encoding_is_appended_to_not_fatal(tmp_path: Path) -> None:
    """A cp1252 `.gitignore` (an accented comment) used to abort the run with UnicodeDecodeError."""
    gitignore = tmp_path / ".gitignore"
    original = b"# caf\xe9\n*.log\n"
    gitignore.write_bytes(original)

    tooling.prepare_report_dir(tmp_path)

    written = gitignore.read_bytes()
    assert written.startswith(original)
    assert written[len(original) :].split() == [b".security_reports/"]


def test_a_gitignore_that_is_not_text_is_left_alone_with_a_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A UTF-16 file cannot be read by git, and appending ASCII to it would only corrupt it."""
    gitignore = tmp_path / ".gitignore"
    original = "*.log\n".encode("utf-16")
    gitignore.write_bytes(original)

    tooling.prepare_report_dir(tmp_path)

    assert gitignore.read_bytes() == original
    assert "could not add .security_reports/ to .gitignore: not a text file" in (
        capsys.readouterr().out
    )


def test_a_gitignore_that_cannot_be_written_warns_instead_of_aborting_the_run(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / ".gitignore").write_text("*.log\n", encoding="utf-8")
    real_open = Path.open

    def refuse_to_append(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if self.name == ".gitignore" and "a" in mode:
            raise PermissionError(13, "Permission denied")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", refuse_to_append)

    report_dir = tooling.prepare_report_dir(tmp_path)

    assert report_dir.is_dir()
    assert "could not add .security_reports/ to .gitignore: Permission denied" in (
        capsys.readouterr().out
    )


def test_prepare_report_dir_replaces_a_symlinked_report_dir_instead_of_following_it(
    tmp_path: Path,
) -> None:
    """A project can ship `.security_reports -> <elsewhere>`; nothing there may be deleted."""
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "trivy.json").write_text("{}", encoding="utf-8")
    (victim / "notes.txt").write_text("keep me", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    symlink_or_skip(project / ".security_reports", victim)

    report_dir = tooling.prepare_report_dir(project)

    assert report_dir.is_dir()
    assert not report_dir.is_symlink()
    assert (victim / "trivy.json").read_text(encoding="utf-8") == "{}"
    assert (victim / "notes.txt").read_text(encoding="utf-8") == "keep me"


def test_a_symlinked_gitignore_is_not_appended_to(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    symlink_or_skip(project / ".gitignore", victim)

    tooling.prepare_report_dir(project)

    assert victim.read_text(encoding="utf-8") == "keep me\n"


def test_clear_output_file_removes_a_symlink_without_touching_its_target(tmp_path: Path) -> None:
    """A project can ship `security_audit.json -> ~/.bashrc`; the report must not land there."""
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    output_file = tmp_path / "security_audit.json"
    symlink_or_skip(output_file, victim)

    tooling.clear_output_file(output_file)

    assert not output_file.exists() and not output_file.is_symlink()
    assert victim.read_text(encoding="utf-8") == "keep me"


def test_clear_output_file_removes_a_dangling_symlink_without_creating_its_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "does-not-exist.txt"
    output_file = tmp_path / "security_audit.json"
    symlink_or_skip(output_file, target)

    tooling.clear_output_file(output_file)

    assert not output_file.is_symlink()
    assert not target.exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_clear_output_file_removes_a_named_pipe(tmp_path: Path) -> None:
    """Opening a pipe for writing blocks forever, so the report could never be written."""
    output_file = tmp_path / "security_audit.json"
    os.mkfifo(output_file)

    tooling.clear_output_file(output_file)

    assert not output_file.exists()


def test_clear_output_file_leaves_a_regular_file_and_a_missing_path_alone(tmp_path: Path) -> None:
    existing = tmp_path / "security_audit.json"
    existing.write_text("old report", encoding="utf-8")

    tooling.clear_output_file(existing)
    tooling.clear_output_file(tmp_path / "missing.json")

    assert existing.read_text(encoding="utf-8") == "old report"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_gitignore_that_is_a_named_pipe_is_left_alone_without_being_read(
    tmp_path: Path,
) -> None:
    """Reading a pipe blocks forever. Run in a subprocess so a regression fails on the timeout."""
    os.mkfifo(tmp_path / ".gitignore")

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from warden import tooling; tooling.prepare_report_dir(sys.argv[1])",
            str(tmp_path),
        ],
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
        timeout=30,
    )

    assert completed.returncode == 0
    assert (tmp_path / ".security_reports").is_dir()


def test_a_timed_out_zap_container_is_killed_by_name(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """Stopping the `docker run` client leaves the container running: its PID 1 is the ZAP script,
    which handles no signal. So the container is named, and killed by name after a timeout."""
    _forget_host_path_variables(monkeypatch)
    runner = RecordingRunner(returncode=None, timed_out=True)

    _run(ZAP, tmp_path, runner, url="http://localhost:3000", timeout=5)

    started, cleanup = runner.commands
    name = started.args[started.args.index("--name") + 1]
    assert cleanup.args == ["docker", "kill", name]
    assert cleanup.stderr_to_devnull


def test_no_container_is_killed_when_zap_finishes_or_a_static_scanner_times_out(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _forget_host_path_variables(monkeypatch)
    finished = RecordingRunner()
    timed_out = RecordingRunner(returncode=None, timed_out=True)

    _run(ZAP, tmp_path, finished, url="http://localhost:3000")
    _run(TRIVY, tmp_path, timed_out, timeout=5)

    assert len(finished.commands) == 1
    assert len(timed_out.commands) == 1


def test_a_stopped_scanner_is_sent_a_stop_request_before_it_is_killed(tmp_path: Path) -> None:
    """SIGTERM first: a scanner that can clean up (or pass the signal on) gets to."""
    marker = tmp_path / "got-sigterm"
    child = (
        "import signal, sys, time\n"
        f"def stop(*_): open({str(marker)!r}, 'w').close(); sys.exit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "time.sleep(60)\n"
    )

    result = tooling.run_subprocess([sys.executable, "-c", child], cwd=tmp_path, timeout=1.5)

    assert result.timed_out
    assert marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="a process group is a POSIX notion")
def test_a_worker_the_scanner_started_is_stopped_with_it(tmp_path: Path) -> None:
    """Semgrep runs `semgrep-core` as its own process: stopping only the wrapper left it running."""
    heartbeat = tmp_path / "worker.heartbeat"
    worker = (
        "import os, time\n"
        f"path = {str(heartbeat)!r}\n"
        "while True:\n"
        "    open(path, 'w').write(f'{os.getpid()} {time.perf_counter()}')\n"
        "    time.sleep(0.05)\n"
    )
    wrapper = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {worker!r}])\n"
        "time.sleep(60)\n"
    )

    result = tooling.run_subprocess([sys.executable, "-c", wrapper], cwd=tmp_path, timeout=1.5)

    assert result.timed_out
    time.sleep(0.3)  # a zombie still exists to `kill(pid, 0)`, so watch for writes instead
    before = heartbeat.read_text(encoding="utf-8")
    time.sleep(0.5)
    after = heartbeat.read_text(encoding="utf-8")
    if before != after:
        os.kill(int(after.split()[0]), signal.SIGKILL)
    assert before == after, "the worker was still running after the scanner was stopped"


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX signals")
def test_an_interrupt_while_waiting_for_a_scanner_to_stop_still_kills_it(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr(tooling, "_STOP_GRACE_SECONDS", 30)
    stubborn = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", stubborn], cwd=tmp_path, start_new_session=True
    )
    time.sleep(0.5)  # let it install its handler
    real_wait: Any = process.wait
    calls = 0

    def interrupted_once(timeout: float | None = None) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise KeyboardInterrupt
        returncode = real_wait(timeout=timeout)
        assert isinstance(returncode, int)
        return returncode

    monkeypatch.setattr(process, "wait", interrupted_once)

    with pytest.raises(KeyboardInterrupt):
        tooling._stop(process)  # pyright: ignore[reportPrivateUsage]

    assert process.poll() is not None
