"""The outcome the output sink protects, asserted through the three real entry points, each in
its own process: whatever the project names its root or writes in `.warden.yaml`, and whatever
the stdout encoding, Warden exits with its documented status, prints no traceback, and writes no
character that can drive the terminal.

`tests/test_boundaries.py` and the lint keep code on the sink. This is what still fails if the
sink itself is wrong, or an entry point finds a way around it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HOSTILE_NAMES = {
    "esc": "esc\x1b[31mx",
    "bidi-override": "rlo‮abc",
    "non-latin": "日本",
    "zero-width": "zw​j",
}
ENCODINGS = ("utf-8", "cp1252", "ascii")
MODULES = {"warden": "cli", "warden-config": "config", "warden-aggregate": "aggregate"}

DISABLE_EVERY_TOOL = "tools:\n  trivy: false\n  semgrep: false\n  gitleaks: false\n  zap: false\n"


def _run(entry: str, encoding: str, *argv: str) -> tuple[int, str, str]:
    """Run a console script's `main` in a child Python whose streams use `encoding`."""
    env = {
        name: value
        for name, value in os.environ.items()
        if name not in {"GITHUB_WORKSPACE", "PYTHONUTF8", "FORCE_COLOR", "TTY_COMPATIBLE"}
    }
    env |= {"PYTHONIOENCODING": encoding, "COLUMNS": "200"}
    code = f"import sys; from warden.{MODULES[entry]} import main; sys.exit(main())"
    done = subprocess.run(
        [sys.executable, "-c", code, *argv], env=env, capture_output=True, check=False, timeout=60
    )
    return done.returncode, done.stdout.decode(encoding), done.stderr.decode(encoding)


def _project(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    try:
        root.mkdir()
    except OSError as error:
        pytest.skip(f"this file system cannot hold the directory name: {error}")
    return root


def _assert_harmless(*streams: str) -> None:
    for text in streams:
        assert "Traceback" not in text
        assert [char for char in text if not char.isprintable() and char not in "\r\n"] == []


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("name", sorted(HOSTILE_NAMES))
def test_warden_never_lets_a_hostile_project_drive_the_terminal_or_crash_it(
    tmp_path: Path, name: str, encoding: str
) -> None:
    """`   Target:`, `Generated`, the summary and `Report saved to:` printed the root path raw
    (ESC and U+202E reached the terminal), on every stdout encoding."""
    root = _project(tmp_path, HOSTILE_NAMES[name])
    stray_line = f"{HOSTILE_NAMES[name]}\n"
    (root / ".warden.yaml").write_text(DISABLE_EVERY_TOOL + stray_line, encoding="utf-8")

    status, stdout, stderr = _run("warden", encoding, "--strict", "--project-root", str(root))

    _assert_harmless(stdout, stderr)
    assert status == 3
    assert "   Target: " in stdout
    assert "Warning: .warden.yaml: line 6 (" in stdout
    assert "STRICT: no scanner ran" in stdout
    assert "AUDIT INCOMPLETE!" in stdout


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("name", sorted(HOSTILE_NAMES))
def test_warden_config_prints_one_json_document_that_round_trips_a_hostile_config(
    tmp_path: Path, name: str, encoding: str
) -> None:
    """`warden-config` raised `UnicodeEncodeError` on a cp1252 stdout for a `target_url` holding
    U+202E, and printed that character raw on a UTF-8 one."""
    hostile = HOSTILE_NAMES[name]
    root = _project(tmp_path, hostile)
    (root / ".warden.yaml").write_text(
        f"target_url: http://{hostile}/\nexclude_dirs:\n  - {hostile}\nstray {hostile}\n",
        encoding="utf-8",
    )

    status, stdout, stderr = _run("warden-config", encoding, str(root))

    _assert_harmless(stdout, stderr)
    assert status == 0
    assert "Warning: .warden.yaml: line 4 (" in stderr
    document = json.loads(stdout)
    assert document["url"] == f"http://{hostile}/"
    assert document["exclude_dirs"] == [hostile]


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("name", sorted(HOSTILE_NAMES))
def test_warden_aggregate_never_lets_a_hostile_report_path_drive_the_terminal_or_crash_it(
    tmp_path: Path, name: str, encoding: str
) -> None:
    """`--- Aggregating Reports from <dir> ---` raised `UnicodeEncodeError` on a cp1252 stdout
    for a directory named in Japanese, and `Generated <path>` printed the path raw."""
    report_dir = _project(tmp_path, HOSTILE_NAMES[name])
    (report_dir / "trivy.json").write_text('{"Results": [', encoding="utf-8")

    status, stdout, stderr = _run(
        "warden-aggregate", encoding, str(report_dir), str(report_dir / "out.json")
    )

    _assert_harmless(stdout, stderr)
    assert status == 0
    assert "--- Aggregating Reports from " in stdout
    assert "Warning: Could not parse trivy.json: " in stdout
    assert "PASS: No High/Critical issues found. See " in stdout


@pytest.mark.parametrize("entry", sorted(MODULES))
def test_a_usage_error_that_echoes_argv_does_not_print_it_raw(entry: str) -> None:
    """argparse echoes an argument it does not recognise, and Warden echoes a path that is not a
    directory, both straight to stderr."""
    status, stdout, stderr = _run(entry, "utf-8", "--no-such\x1b[31m-flag", "/no/such‮/dir")

    _assert_harmless(stdout, stderr)
    assert status == 2
    assert f"{entry}: error: " in stderr
