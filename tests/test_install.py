from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from fakes import skip_unless_executable

INSTALL_SH = Path(__file__).resolve().parents[1] / "install.sh"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="runs the bash installer")


@pytest.fixture
def stubs(tmp_path: Path) -> Path:
    """Stand-ins for every tool install.sh looks for, so it installs and downloads nothing."""
    stub_dir = tmp_path / "stubs"
    stub_dir.mkdir()
    for name in ("docker", "uv", "trivy", "gitleaks"):
        stub = stub_dir / name
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)
    skip_unless_executable(stub_dir / "uv")
    return stub_dir


def _install(
    home: Path, stubs: Path, *, login_shell: str = "/bin/bash", path_prefix: str = ""
) -> str:
    completed = subprocess.run(
        ["bash", str(INSTALL_SH)],
        capture_output=True,
        check=True,
        cwd=home,
        env={
            "HOME": str(home),
            "SHELL": login_shell,
            "PATH": f"{path_prefix}{stubs}:/usr/bin:/bin",
        },
        text=True,
        timeout=60,
    )
    return completed.stdout


def test_the_uv_bin_dir_is_added_to_the_profile_once_when_it_is_not_on_path(
    tmp_path: Path, stubs: Path
) -> None:
    """The check used to look at a PATH the script had already extended, so it never wrote."""
    home = tmp_path / "home"
    home.mkdir()

    first = _install(home, stubs)
    second = _install(home, stubs)

    profile = (home / ".bashrc").read_text(encoding="utf-8")
    assert "Adding" in first
    assert profile.count("export PATH=") == 1
    assert f'export PATH="{home}/.local/bin:$PATH"' in profile
    assert "Adding" not in second
    assert "Restart your terminal" in second


def test_nothing_is_written_when_the_uv_bin_dir_is_already_on_the_callers_path(
    tmp_path: Path, stubs: Path
) -> None:
    home = tmp_path / "home"
    home.mkdir()

    output = _install(home, stubs, path_prefix=f"{home}/.local/bin:")

    profiles = (".bashrc", ".zshrc", ".profile")
    assert not any((home / name).exists() for name in profiles)
    assert "already on PATH" in output


def test_the_line_uvs_own_installer_writes_is_not_duplicated(tmp_path: Path, stubs: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    uv_line = '. "$HOME/.local/bin/env"\n'
    (home / ".bashrc").write_text(uv_line, encoding="utf-8")

    output = _install(home, stubs)

    assert (home / ".bashrc").read_text(encoding="utf-8") == uv_line
    assert "already on PATH" not in output
    assert "Restart your terminal" in output


@pytest.mark.parametrize(
    "unrelated",
    [
        '# export PATH="$HOME/.local/bin:$PATH"  (removed)\n',
        'eval "$(~/.local/bin/mise activate bash)"\n',
        "alias u=~/.local/bin/uv\n",
    ],
)
def test_a_profile_line_that_only_mentions_the_directory_does_not_stop_it_being_added(
    tmp_path: Path, stubs: Path, unrelated: str
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".bashrc").write_text(unrelated, encoding="utf-8")

    _install(home, stubs)

    profile = (home / ".bashrc").read_text(encoding="utf-8")
    assert profile.startswith(unrelated)
    assert f'\nexport PATH="{home}/.local/bin:$PATH"\n' in profile


def test_a_profile_that_cannot_be_written_does_not_fail_the_install(
    tmp_path: Path, stubs: Path
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".bashrc").mkdir()

    output = _install(home, stubs)

    assert "Could not write to" in output
    assert "Installation complete!" in output


def test_a_zsh_login_shell_gets_zshrc_wherever_zsh_is_installed(
    tmp_path: Path, stubs: Path
) -> None:
    home = tmp_path / "home"
    home.mkdir()

    _install(home, stubs, login_shell="/usr/bin/zsh")

    assert (home / ".zshrc").is_file()
    assert not (home / ".bashrc").exists()
