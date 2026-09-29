from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from pytest import CaptureFixture

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
