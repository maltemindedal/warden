from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from fakes import skip_unless_executable

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(sys.platform == "win32", reason="runs the bash wrapper")
def test_the_shell_wrapper_runs_warden_in_the_callers_directory(tmp_path: Path) -> None:
    """`uv run --directory` moves into Warden's checkout, so the caller's project is never scanned.

    `--project` finds Warden's project but leaves the working directory alone. A stub `uv` records
    its arguments and the directory it was started in. The stub does not emulate `--directory`, so
    the flag is pinned by its argument and the directory by where the wrapper starts `uv`.
    """
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir()
    caller = tmp_path / "caller"
    caller.mkdir()
    recorded = tmp_path / "uv-args.txt"
    stub = stub_dir / "uv"
    stub.write_text(
        f'#!/bin/sh\n{{ pwd -P; printf \'%s\\n\' "$@"; }} > "{recorded}"\n', encoding="utf-8"
    )
    stub.chmod(0o755)
    skip_unless_executable(stub)
    recorded.unlink()
    env = {"PATH": f"{stub_dir}:/usr/bin:/bin"}

    subprocess.run(
        ["bash", str(REPO_ROOT / "bin" / "warden.sh"), "--url", "http://x"],
        check=True,
        cwd=caller,
        env=env,
        timeout=30,
    )

    assert recorded.read_text(encoding="utf-8").splitlines() == [
        str(caller.resolve()),
        "run",
        "--project",
        str(REPO_ROOT),
        "warden",
        "--url",
        "http://x",
    ]
