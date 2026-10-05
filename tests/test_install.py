from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
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
        '[ -n "${STUB_UV_LOG:-}" ] && { printf "%s\\n" "$@"; echo ---; } >> "$STUB_UV_LOG"\n'
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


def _uv_calls(log: Path) -> list[list[str]]:
    """Each call the uv stub recorded, as its list of arguments."""
    calls: list[list[str]] = []
    current: list[str] = []
    for line in log.read_text(encoding="utf-8").splitlines():
        if line == "---":
            calls.append(current)
            current = []
        else:
            current.append(line)
    return calls


def test_the_cooldown_is_passed_to_uv_tool_install_as_one_quoted_argument(
    tmp_path: Path, stubs: Path
) -> None:
    """`uv tool install` ignores [tool.uv], so it did not get the 24-hour cooldown, and an
    unquoted `--exclude-newer 24 hours` is two arguments that real uv rejects."""
    home = tmp_path / "home"
    home.mkdir()
    log = tmp_path / "uv.log"

    completed = _run_install(home, stubs, extra_env={"STUB_UV_LOG": str(log)})

    assert completed.returncode == 0, completed.stderr
    install = next(call for call in _uv_calls(log) if call[:2] == ["tool", "install"])
    assert install[:7] == [
        "tool",
        "install",
        "--force",
        "--python",
        "3.11",
        "--exclude-newer",
        "24 hours",
    ]
    assert install[7] == "-e"


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
    shutil.which("sha256sum", path="/usr/bin:/bin") is None,
    reason="the Linux download path uses sha256sum, and the script under test gets /usr/bin:/bin",
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


def test_install_ps1_pins_the_same_uv_as_install_sh_and_the_dockerfile() -> None:
    """Dependabot bumps the Dockerfile's uv stage alone; nothing else would notice the copies."""
    docker = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    install = INSTALL_SH.read_text(encoding="utf-8")
    powershell = (REPO_ROOT / "install.ps1").read_text(encoding="utf-8")

    version = _pins(powershell, r'(?m)^\$UvVersion = "(\S+)"')
    assert version == _pins(install, r'(?m)^UV_VERSION="(\S+)"')
    assert version == _pins(docker, r"ghcr\.io/astral-sh/uv:(\d+\.\d+\.\d+)@")
    assert _pins(powershell, r'(?m)^\$UvMinVersion = \[version\]"(\S+)"') == _pins(
        install, r'(?m)^UV_MIN_VERSION="(\S+)"'
    )


def _function_text(name: str) -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index(f"{name}() {{")
    return text[start : text.index("\n}\n", start) + 3]


def _run_installer_function(
    tmp_path: Path, tool: str, *, archive: bytes, tar_fails: bool = False
) -> tuple[subprocess.CompletedProcess[str], Path, list[str]]:
    """Run install.sh's own `install_<tool>` with a `curl` that serves `archive`, and a `tar`
    that writes down its arguments and then runs the real one (or fails)."""
    stub_dir = tmp_path / "function-stubs"
    stub_dir.mkdir()
    served = tmp_path / "served.tgz"
    served.write_bytes(archive)
    curl = stub_dir / "curl"
    curl.write_text(f'#!/bin/sh\ncp "{served}" "$4"\n', encoding="utf-8")
    curl.chmod(0o755)
    tar_log = tmp_path / "tar-args.txt"
    tar = stub_dir / "tar"
    body = "exit 2" if tar_fails else 'exec "$REAL_TAR" "$@"'
    tar.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{tar_log}"\n{body}\n', encoding="utf-8")
    tar.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    digest = (
        subprocess.run(["sha256sum"], input=archive, capture_output=True, check=True)
        .stdout.split()[0]
        .decode()
    )
    upper = tool.upper()
    script = (
        f'RED=""; YELLOW=""; NC=""; OS_TYPE=Linux; SUDO=""; BIN_DIR="{bin_dir}"\n'
        f'{upper}_ARCH=x; {upper}_VERSION=1.2.3; {upper}_SHA256="{digest}"\n'
        f"{_function_text('fetch_verified')}\n{_function_text(f'install_{tool}')}\n"
        f"install_{tool}"
    )
    completed = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        check=False,
        env={
            "PATH": f"{stub_dir}:/usr/bin:/bin",
            "REAL_TAR": shutil.which("tar", path="/usr/bin:/bin") or "tar",
        },
        text=True,
        timeout=60,
    )
    args = tar_log.read_text(encoding="utf-8").splitlines() if tar_log.exists() else []
    return completed, bin_dir, args


def _tool_archive(tool: str) -> bytes:
    """A gzip tarball holding `tool`, recorded as owned by an unrelated user id."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        payload = b"#!/bin/sh\nexit 0\n"
        member = tarfile.TarInfo(name=tool)
        member.size = len(payload)
        member.mode = 0o755
        member.uid = member.gid = 1001
        archive.addfile(member, io.BytesIO(payload))
    return buffer.getvalue()


@needs_sha256sum
@pytest.mark.parametrize("tool", ["trivy", "gitleaks"])
def test_a_scanner_is_extracted_without_the_owner_recorded_in_the_archive(
    tmp_path: Path, tool: str
) -> None:
    """As root, tar keeps the archive's uid: a system binary owned by user id 1001 or 501."""
    completed, bin_dir, tar_args = _run_installer_function(
        tmp_path, tool, archive=_tool_archive(tool)
    )

    assert completed.returncode == 0, completed.stdout
    assert "--no-same-owner" in tar_args
    installed = bin_dir / tool
    assert installed.is_file()
    if os.geteuid() == 0:
        assert installed.stat().st_uid == 0


@needs_sha256sum
@pytest.mark.parametrize("tool", ["trivy", "gitleaks"])
def test_a_failed_extraction_is_a_failed_install_so_the_warning_is_printed(
    tmp_path: Path, tool: str
) -> None:
    completed, bin_dir, tar_args = _run_installer_function(
        tmp_path, tool, archive=_tool_archive(tool), tar_fails=True
    )

    assert completed.returncode != 0
    assert not (bin_dir / tool).exists()
    assert not Path(tar_args[tar_args.index("-f") + 1]).exists()
