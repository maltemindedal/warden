from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fakes import skip_unless_executable

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO_ROOT / "install.sh"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="runs the bash installer")


@pytest.fixture
def stubs(tmp_path: Path) -> Path:
    """Stand-ins for every tool install.sh looks for, so it installs and downloads nothing."""
    stub_dir = tmp_path / "stubs"
    stub_dir.mkdir()
    for name in ("docker", "trivy", "gitleaks"):
        stub = stub_dir / name
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)
    # uv reports the version in STUB_UV_VERSION and records every other call in STUB_UV_LOG.
    uv = stub_dir / "uv"
    uv.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "uv ${STUB_UV_VERSION:-0.12.18} (stub)"; exit 0; fi\n'
        '[ -n "${STUB_UV_LOG:-}" ] && echo "$@" >> "$STUB_UV_LOG"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    uv.chmod(0o755)
    skip_unless_executable(uv)
    return stub_dir


def _run_install(
    home: Path,
    stubs: Path,
    *,
    login_shell: str = "/bin/bash",
    path_prefix: str = "",
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(INSTALL_SH)],
        capture_output=True,
        check=False,
        cwd=home,
        env={
            "HOME": str(home),
            "SHELL": login_shell,
            "PATH": f"{path_prefix}{stubs}:/usr/bin:/bin",
            **(extra_env or {}),
        },
        text=True,
        timeout=60,
    )


def _install(
    home: Path, stubs: Path, *, login_shell: str = "/bin/bash", path_prefix: str = ""
) -> str:
    completed = _run_install(home, stubs, login_shell=login_shell, path_prefix=path_prefix)
    completed.check_returncode()
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


def test_the_cooldown_is_passed_to_uv_tool_install(tmp_path: Path, stubs: Path) -> None:
    """`uv tool install` ignores [tool.uv], so it did not get the seven-day cooldown."""
    home = tmp_path / "home"
    home.mkdir()
    log = tmp_path / "uv.log"

    completed = _run_install(home, stubs, extra_env={"STUB_UV_LOG": str(log)})

    assert completed.returncode == 0, completed.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert any(
        call.startswith("tool install --force --python 3.11 --exclude-newer 7 days -e ")
        for call in calls
    ), calls


@pytest.mark.parametrize("version", ["0.9.17", "0.10.0", "0.12.18", "1.0.0"])
def test_a_uv_that_can_read_the_cooldown_is_accepted(
    tmp_path: Path, stubs: Path, version: str
) -> None:
    home = tmp_path / "home"
    home.mkdir()

    completed = _run_install(home, stubs, extra_env={"STUB_UV_VERSION": version})

    assert completed.returncode == 0, completed.stdout


@pytest.mark.parametrize("version", ["0.9.16", "0.8.17", "0.9", "0.0.1"])
def test_a_uv_too_old_to_read_the_cooldown_stops_the_install_before_it_installs_anything(
    tmp_path: Path, stubs: Path, version: str
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    log = tmp_path / "uv.log"

    completed = _run_install(
        home, stubs, extra_env={"STUB_UV_VERSION": version, "STUB_UV_LOG": str(log)}
    )

    assert completed.returncode == 1
    assert f"uv {version} is too old" in completed.stdout
    assert "0.9.17 or newer" in completed.stdout
    assert not log.exists()


def _fetch_verified(
    tmp_path: Path, *, served: bytes | None, expected: str
) -> tuple[int, str, Path]:
    """Run install.sh's own `fetch_verified` with a `curl` that serves `served` (or fails)."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("fetch_verified() {")
    function = text[start : text.index("\n}\n", start) + 3]
    stub_dir = tmp_path / "curl-stub"
    stub_dir.mkdir()
    source = tmp_path / "served.bin"
    if served is not None:
        source.write_bytes(served)
    curl = stub_dir / "curl"
    curl.write_text(
        f'#!/bin/sh\n[ -f "{source}" ] || exit 22\ncp "{source}" "$4"\n', encoding="utf-8"
    )
    curl.chmod(0o755)
    dest = tmp_path / "downloaded.tgz"
    completed = subprocess.run(
        [
            "bash",
            "-c",
            f'RED=""; NC=""; {function}\nfetch_verified https://example.invalid/x "$1" "$2"',
            "bash",
            expected,
            str(dest),
        ],
        capture_output=True,
        check=False,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin"},
        text=True,
        timeout=60,
    )
    return completed.returncode, completed.stdout, dest


needs_sha256sum = pytest.mark.skipif(
    shutil.which("sha256sum") is None, reason="the Linux download path uses sha256sum"
)


@needs_sha256sum
def test_a_download_whose_checksum_matches_is_kept(tmp_path: Path) -> None:
    payload = b"a release archive"
    digest = (
        subprocess.run(["sha256sum"], input=payload, capture_output=True, check=True)
        .stdout.split()[0]
        .decode()
    )

    returncode, _, dest = _fetch_verified(tmp_path, served=payload, expected=digest)

    assert returncode == 0
    assert dest.read_bytes() == payload


@needs_sha256sum
def test_a_download_whose_checksum_does_not_match_is_removed_and_refused(tmp_path: Path) -> None:
    returncode, output, dest = _fetch_verified(tmp_path, served=b"tampered", expected="0" * 64)

    assert returncode == 1
    assert "does not match its expected checksum" in output
    assert not dest.exists()


@needs_sha256sum
def test_a_download_that_fails_is_refused(tmp_path: Path) -> None:
    returncode, _, dest = _fetch_verified(tmp_path, served=None, expected="0" * 64)

    assert returncode != 0
    assert not dest.exists()


def _pins(text: str, pattern: str) -> list[str]:
    return [str(pin) for pin in re.findall(pattern, text)]


def test_the_installer_and_the_dockerfile_pin_the_same_versions_and_digests() -> None:
    """They are edited by hand, so nothing else keeps two copies of a digest in step."""
    docker = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    install = INSTALL_SH.read_text(encoding="utf-8")

    for name in ("TRIVY", "GITLEAKS"):
        assert _pins(docker, rf"ARG {name}_VERSION=(\S+)") == _pins(
            install, rf'^{name}_VERSION="(\S+)"'.replace("^", "(?m)^")
        )
        assert _pins(docker, rf"ARG {name}_SHA256_(?:AMD64|ARM64)=([0-9a-f]{{64}})") == _pins(
            install, rf'{name}_SHA256="([0-9a-f]{{64}})"'
        )
    assert _pins(docker, r"ghcr\.io/astral-sh/uv:(\d+\.\d+\.\d+)@") == _pins(
        install, r'(?m)^UV_VERSION="(\S+)"'
    )
    assert len(_pins(install, r'TRIVY_SHA256="([0-9a-f]{64})"')) == 2
