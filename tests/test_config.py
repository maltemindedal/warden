from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from pytest import CaptureFixture

from fakes import symlink_or_skip
from warden._scanners import SCANNERS, ZAP
from warden.config import main, parse_minimal_yaml, resolve_config


def test_parse_minimal_yaml_handles_lists_and_tools() -> None:
    raw_config = parse_minimal_yaml(
        """
        target_url: "http://localhost:3000"
        exclude_dirs:
          - "tests/"
          - "legacy/"
        tools:
          zap: false
          semgrep: true
        """
    )

    assert raw_config["target_url"] == "http://localhost:3000"
    assert raw_config["exclude_dirs"] == ["tests/", "legacy/"]
    assert raw_config["tools"] == {"zap": False, "semgrep": True}


def test_parse_minimal_yaml_strips_comments_but_keeps_an_escaped_hash() -> None:
    raw_config = parse_minimal_yaml(
        """
        target_url: "http://localhost:3000"  # the app under test
        url: "http://localhost:3000/\\#/login"
        """
    )

    assert raw_config["target_url"] == "http://localhost:3000"
    assert raw_config["url"] == "http://localhost:3000/\\#/login"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('target_url: "http://app/path#frag"', "http://app/path#frag"),
        ("target_url: 'http://app/#/login'  # the app", "http://app/#/login"),
        ("target_url: 'it''s # not a comment'", "it''s # not a comment"),
        # Unquoted, a `#` still starts a comment, as it always did.
        ("target_url: http://localhost:4200/#/login", "http://localhost:4200/"),
        # A quote only opens a value where a value starts, and only if it is closed.
        ('target_url: "http://app#unterminated', '"http://app'),
        ('target_url: it"s # comment"', 'it"s'),
    ],
)
def test_a_hash_inside_a_quoted_value_is_part_of_the_value(line: str, expected: str) -> None:
    assert parse_minimal_yaml(line)["target_url"] == expected


def test_a_hash_inside_a_quoted_list_item_is_part_of_the_item() -> None:
    raw_config = parse_minimal_yaml('exclude_dirs:\n  - "vendor#1/"  # third party\n  - build/\n')

    assert raw_config["exclude_dirs"] == ["vendor#1/", "build/"]


def test_a_long_line_of_quotes_is_parsed_in_linear_time() -> None:
    """A project controls `.warden.yaml`, and rescanning for a closing quote was quadratic."""
    hostile = "target_url: " + 'x:"' * 200_000

    started = time.perf_counter()
    parse_minimal_yaml(hostile)

    assert time.perf_counter() - started < 5


def test_parse_minimal_yaml_reads_the_scalar_forms_it_supports() -> None:
    raw_config = parse_minimal_yaml(
        """
        target_url: http://unquoted
        exclude_dirs:
          -
          - 'quoted/'
        tools:
          trivy: 0
          semgrep: yes
          zap:
        """
    )

    assert raw_config["target_url"] == "http://unquoted"
    assert raw_config["exclude_dirs"] == ["quoted/"]
    assert raw_config["tools"] == {"trivy": 0, "semgrep": True, "zap": ""}


def test_parse_minimal_yaml_ignores_lines_it_cannot_make_sense_of() -> None:
    raw_config = parse_minimal_yaml(
        """
        nonsense
        exclude_dirs:
          tests/
        tools:
          zap
        """
    )

    assert raw_config == {"exclude_dirs": [], "tools": {}}


def test_resolve_config_prefers_cli_url(tmp_path: Path) -> None:
    config_path = tmp_path / ".warden.yaml"
    config_path.write_text('target_url: "http://from-config"\n', encoding="utf-8")

    resolved = resolve_config(project_root=tmp_path, cli_url="http://from-cli")

    assert resolved.url == "http://from-cli"


def test_resolve_config_falls_back_to_url_alias(tmp_path: Path) -> None:
    config_path = tmp_path / ".warden.yaml"
    config_path.write_text('url: "http://from-alias"\n', encoding="utf-8")

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.url == "http://from-alias"


def test_resolve_config_prefers_target_url_even_when_empty(tmp_path: Path) -> None:
    config_path = tmp_path / ".warden.yaml"
    config_path.write_text(
        """
        target_url: ""
        url: "http://from-alias"
        """,
        encoding="utf-8",
    )

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.url == ""


def test_resolve_config_clears_url_when_zap_is_disabled(tmp_path: Path) -> None:
    config_path = tmp_path / ".warden.yaml"
    config_path.write_text(
        """
        target_url: "http://localhost:3000"
        tools:
          zap: false
        """,
        encoding="utf-8",
    )

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.url == ""
    assert ZAP.key not in resolved.enabled_tools


def test_resolve_config_drops_blank_exclude_dirs(tmp_path: Path) -> None:
    config_path = tmp_path / ".warden.yaml"
    config_path.write_text(
        """
        exclude_dirs:
          - "tests/"
          - "   "
          - "legacy/"
        """,
        encoding="utf-8",
    )

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.exclude_dirs == ["tests/", "legacy/"]


def test_resolve_config_reads_the_off_switches_a_user_might_write(tmp_path: Path) -> None:
    config_path = tmp_path / ".warden.yaml"
    config_path.write_text(
        """
        tools:
          trivy: 0
          semgrep: "off"
          gitleaks: "on"
        """,
        encoding="utf-8",
    )

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert "trivy" not in resolved.enabled_tools
    assert "semgrep" not in resolved.enabled_tools
    assert "gitleaks" in resolved.enabled_tools
    assert ZAP.key in resolved.enabled_tools


def test_resolve_config_falls_back_to_defaults_when_the_file_cannot_be_read(
    tmp_path: Path,
) -> None:
    (tmp_path / ".warden.yaml").write_bytes(b'target_url: "http://\xff\xfe"\n')

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.url == ""
    assert all(scanner.key in resolved.enabled_tools for scanner in SCANNERS)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_config_passed_explicitly_may_be_a_pipe(tmp_path: Path) -> None:
    """Only the project's own `.warden.yaml` must be a regular file; a named pipe passed with
    `--config` is still read. (A pipe on `/dev/stdin` never was: it resolves to a path that does
    not exist.)"""
    fifo = tmp_path / "config.fifo"
    os.mkfifo(fifo)
    writer = threading.Thread(
        target=lambda: fifo.write_text("tools:\n  trivy: false\n", encoding="utf-8"), daemon=True
    )
    writer.start()

    resolved = resolve_config(project_root=tmp_path, cli_url="", config_path=fifo)

    writer.join(timeout=10)
    assert "trivy" not in resolved.enabled_tools


@pytest.mark.parametrize(
    ("text", "url", "gitleaks_enabled"),
    [
        ('target_url: "http://localhost:3000"\n', "http://localhost:3000", True),
        ("tools:\n  gitleaks: false\n", "", False),
    ],
)
def test_a_utf8_byte_order_mark_does_not_swallow_the_first_key(
    tmp_path: Path, text: str, url: str, gitleaks_enabled: bool
) -> None:
    """Windows editors write a BOM; it used to become part of the first key, which was ignored."""
    (tmp_path / ".warden.yaml").write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.url == url
    assert ("gitleaks" in resolved.enabled_tools) is gitleaks_enabled


@pytest.mark.parametrize(
    ("scalar", "expected"),
    [
        ("12", 12),
        ("-5", -5),
        ("\u0663", 3),
        ("\u00b2", "\u00b2"),
        ("\u2460", "\u2460"),
        pytest.param("9" * 5000, "9" * 5000, id="over-4300-digits"),
    ],
)
def test_a_numeric_looking_config_value_never_raises(scalar: str, expected: object) -> None:
    """`\u00b2` and over-long digit strings used to raise, discarding the whole config file."""
    assert parse_minimal_yaml(f"retries: {scalar}\n")["retries"] == expected


def test_a_value_that_int_cannot_read_does_not_cost_the_rest_of_the_config(
    tmp_path: Path,
) -> None:
    (tmp_path / ".warden.yaml").write_text(
        "retries: \u00b2\ntools:\n  gitleaks: false\n", encoding="utf-8"
    )

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert "gitleaks" not in resolved.enabled_tools


def test_a_config_path_the_system_refuses_to_look_up_is_treated_as_absent(tmp_path: Path) -> None:
    """A component longer than NAME_MAX made `Path.exists()` raise ENAMETOOLONG (before 3.14)."""
    too_long = tmp_path / ("a" * 300)

    resolved = resolve_config(project_root=tmp_path, cli_url="", config_path=too_long)

    assert resolved.url == ""
    assert all(scanner.key in resolved.enabled_tools for scanner in SCANNERS)


def test_a_project_config_the_system_refuses_to_look_up_is_treated_as_absent(
    tmp_path: Path,
) -> None:
    """The project controls its own `.warden.yaml`: a link to an over-long name must not crash."""
    symlink_or_skip(tmp_path / ".warden.yaml", tmp_path / ("a" * 300))

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert all(scanner.key in resolved.enabled_tools for scanner in SCANNERS)


def test_config_main_reports_every_scanner_as_enabled_by_default(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    exit_code = main([str(tmp_path)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert list(payload) == ["url", "exclude_dirs", "tools"]
    assert payload["url"] == ""
    assert payload["exclude_dirs"] == []
    assert list(payload["tools"]) == [scanner.key for scanner in SCANNERS]
    assert payload["tools"] == {scanner.key: True for scanner in SCANNERS}


def test_config_main_reports_the_resolved_config_file(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    (tmp_path / ".warden.yaml").write_text(
        """
        target_url: "http://from-config"
        exclude_dirs:
          - "tests/"
        tools:
          zap: false
        """,
        encoding="utf-8",
    )

    exit_code = main([str(tmp_path)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["url"] == ""
    assert payload["exclude_dirs"] == ["tests/"]
    assert payload["tools"] == {scanner.key: scanner is not ZAP for scanner in SCANNERS}


def test_config_main_prefers_the_cli_url_over_the_config_file(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    (tmp_path / ".warden.yaml").write_text('target_url: "http://from-config"\n', encoding="utf-8")

    exit_code = main([str(tmp_path), "--cli-url", "http://from-cli"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["url"] == "http://from-cli"


def test_config_main_reads_a_config_file_outside_the_project_root(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    config_path = tmp_path / "elsewhere" / "warden.yaml"
    config_path.parent.mkdir()
    config_path.write_text('target_url: "http://from-elsewhere"\n', encoding="utf-8")

    exit_code = main([str(tmp_path), "--config", str(config_path)])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["url"] == "http://from-elsewhere"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_config_that_is_not_a_regular_file_is_treated_as_absent_without_being_read(
    tmp_path: Path,
) -> None:
    """A project can ship `.warden.yaml` as a named pipe, and reading one blocks forever.

    Run in a subprocess so that a regression fails on the timeout instead of hanging the suite.
    """
    os.mkfifo(tmp_path / ".warden.yaml")

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from warden.config import main; raise SystemExit(main())",
            str(tmp_path),
        ],
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout)["exclude_dirs"] == []


def _project_with_target_url(tmp_path: Path) -> None:
    (tmp_path / ".warden.yaml").write_text('target_url: "http://app.example"\n', encoding="utf-8")


def test_target_url_from_the_projects_own_config_is_ignored_on_a_ci_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a runner the file can come from a pull request, and the URL starts an active scan."""
    _project_with_target_url(tmp_path)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.url == ""
    assert len(resolved.warnings) == 1
    assert "target_url" in resolved.warnings[0]
    assert "--url" in resolved.warnings[0]


def test_an_explicit_url_or_config_still_sets_the_target_on_a_ci_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _project_with_target_url(tmp_path)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    outside = tmp_path / "outside.yaml"
    outside.write_text('target_url: "http://trusted.example"\n', encoding="utf-8")

    from_flag = resolve_config(project_root=tmp_path, cli_url="http://flag.example")
    from_explicit_config = resolve_config(project_root=tmp_path, cli_url="", config_path=outside)

    assert (from_flag.url, from_flag.warnings) == ("http://flag.example", ())
    assert (from_explicit_config.url, from_explicit_config.warnings) == (
        "http://trusted.example",
        (),
    )


def test_target_url_is_read_from_the_projects_config_off_a_ci_runner(tmp_path: Path) -> None:
    _project_with_target_url(tmp_path)

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert (resolved.url, resolved.warnings) == ("http://app.example", ())


def test_warden_config_prints_its_warnings_to_stderr_and_keeps_stdout_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    _project_with_target_url(tmp_path)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    assert main([str(tmp_path)]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["url"] == ""
    assert "Warning: target_url" in captured.err


def _warnings_for(tmp_path: Path, text: str) -> tuple[str, ...]:
    (tmp_path / ".warden.yaml").write_text(text, encoding="utf-8")
    return resolve_config(project_root=tmp_path, cli_url="").warnings


def test_a_correct_config_produces_no_warnings(tmp_path: Path) -> None:
    text = (
        "# scan settings\n"
        'target_url: "http://localhost:3000"  # the app\n'
        "exclude_dirs:\n  - tests/\n  - 'legacy/'\n"
        "tools:\n  zap: true\n  gitleaks: false\n  semgrep: 0\n  trivy: yes\n"
    )

    assert _warnings_for(tmp_path, text) == ()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # PyYAML's default list style: same indent as its key, so it is not under `exclude_dirs`.
        ("exclude_dirs:\n- vendor/\n", "line 2 ('- vendor/') is not `key: value`"),
        ("exclude_dir:\n  - vendor/\n", "unknown key 'exclude_dir' is ignored"),
        ("target_url: 3000\n", "target_url is not a string"),
        ("exclude_dirs: vendor/\n", "exclude_dirs is not a list"),
        ("tools: false\n", "tools is not a mapping"),
        ("tools: {zap: false}\n", "tools is not a mapping"),
        ("tools:\n  gitleaks2: false\n", "unknown tool 'gitleaks2' under tools is ignored"),
        ("tools:\n  trivy: ture\n", "tools.trivy is 'ture', which counts as false"),
        ("tools:\n  zap:\n", "tools.zap is '', which counts as false"),
        ("tools:\n  zap\n", "line 2 ('zap') is not `tool: value`"),
        ("exclude_dirs:\n  vendor/\n", "line 2 ('vendor/') is not a `- entry`"),
        ("target_url: x\n  stray: y\n", "line 2 ('stray: y') is indented but not under"),
        ("---\ntarget_url: x\n", "line 1 ('---') is not `key: value`"),
    ],
)
def test_a_config_mistake_warden_can_see_is_warned_about(
    tmp_path: Path, text: str, expected: str
) -> None:
    warnings = _warnings_for(tmp_path, text)

    assert any(f".warden.yaml: {expected}" in warning for warning in warnings), warnings


def test_a_warned_about_config_resolves_exactly_as_it_did_without_the_warning(
    tmp_path: Path,
) -> None:
    (tmp_path / ".warden.yaml").write_text(
        "exclude_dirs:\n- vendor/\ntools:\n  trivy: ture\n  zap: false\n", encoding="utf-8"
    )

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.exclude_dirs == []
    assert resolved.enabled_tools == frozenset({"semgrep", "gitleaks"})
    assert resolved.warnings


def test_an_explicit_config_that_does_not_exist_is_warned_about(tmp_path: Path) -> None:
    resolved = resolve_config(project_root=tmp_path, cli_url="", config_path=tmp_path / "nope.yaml")

    assert len(resolved.warnings) == 1
    assert "--config" in resolved.warnings[0]
    assert "does not exist" in resolved.warnings[0]


def test_a_config_that_cannot_be_read_is_warned_about(tmp_path: Path) -> None:
    (tmp_path / ".warden.yaml").write_bytes(b"\xff\xfet\x00a\x00")

    warnings = resolve_config(project_root=tmp_path, cli_url="").warnings

    assert len(warnings) == 1
    assert warnings[0].startswith(".warden.yaml could not be read (")
    assert warnings[0].endswith("): using the defaults.")


def test_an_absent_project_config_is_not_worth_a_warning(tmp_path: Path) -> None:
    assert resolve_config(project_root=tmp_path, cli_url="").warnings == ()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_project_config_that_is_not_a_regular_file_is_warned_about(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / ".warden.yaml")

    warnings = resolve_config(project_root=tmp_path, cli_url="").warnings

    assert warnings == (".warden.yaml is not a regular file: using the defaults.",)


def test_a_hostile_config_produces_a_capped_number_of_warnings(tmp_path: Path) -> None:
    warnings = _warnings_for(tmp_path, "x\n" * 500)

    assert len(warnings) == 11
    assert warnings[-1] == "... and 490 more."


def test_a_warning_shows_project_text_escaped_and_cut(tmp_path: Path) -> None:
    warnings = _warnings_for(tmp_path, 'tools:\n  trivy: "\x1b[2J' + "x" * 200 + '"\n')

    assert len(warnings) == 1
    assert "\x1b" not in warnings[0]
    assert "\\x1b[2J" in warnings[0]
    assert len(warnings[0]) < 200


def test_warden_config_prints_config_warnings_to_stderr(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    (tmp_path / ".warden.yaml").write_text("exclude_dir:\n", encoding="utf-8")

    assert main([str(tmp_path)]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["exclude_dirs"] == []
    assert "Warning: .warden.yaml: unknown key 'exclude_dir' is ignored" in captured.err
