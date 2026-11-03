from __future__ import annotations

import io
import json
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
    for name in ("docker", "uv", "trivy", "gitleaks"):
        stub = stub_dir / name
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)
    skip_unless_executable(stub_dir / "uv")
    return stub_dir


def _run_install(
    home: Path,
    stubs: Path,
    *,
    login_shell: str = "/bin/bash",
    path_prefix: str = "",
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


_INTEL_MAC = "Intel Macs are not supported. Apple Silicon (arm64) is supported."
_NATIVE_ARM = "Rerun this command from a native arm64 terminal."


def _write_executable(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _stub_host(stubs: Path, *, kernel: str, machine: str, translated: str | None) -> None:
    _write_executable(
        stubs,
        "uname",
        "#!/bin/sh\n"
        'case "$1" in\n'
        f'\t-s) echo "{kernel}" ;;\n'
        f'\t-m) echo "{machine}" ;;\n'
        "\t*) exit 1 ;;\n"
        "esac\n",
    )
    if translated is None:
        body = "#!/bin/sh\nexit 1\n"
    else:
        body = (
            "#!/bin/sh\n"
            '[ "$1" = "-n" ] && [ "$2" = "sysctl.proc_translated" ] || exit 1\n'
            f'echo "{translated}"\n'
        )
    _write_executable(stubs, "sysctl", body)


def _log_stub(stubs: Path, name: str, log: Path) -> None:
    _write_executable(
        stubs,
        name,
        f'#!/bin/sh\nprintf "%s\\n" "{name}" "$@" >> "{log}"\n',
    )


def _run_warden(stubs: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(REPO_ROOT / "bin" / "warden.sh"), *args],
        capture_output=True,
        check=False,
        cwd=stubs.parent,
        env={"PATH": f"{stubs}:/usr/bin:/bin"},
        text=True,
        timeout=30,
    )


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


def test_install_sh_on_darwin_x86_64_exits_before_any_check_download_or_install(
    tmp_path: Path, stubs: Path
) -> None:
    """An Intel Mac used to reach uv and could then print PASS with a broken Semgrep."""
    home = tmp_path / "home"
    home.mkdir()
    log = tmp_path / "calls.log"
    _stub_host(stubs, kernel="Darwin", machine="x86_64", translated=None)
    _log_stub(stubs, "docker", log)
    _log_stub(stubs, "uv", log)

    refused = _run_install(home, stubs)

    assert refused.returncode == 1
    assert _INTEL_MAC in refused.stdout
    assert _NATIVE_ARM not in refused.stdout
    assert "Detected:" not in refused.stdout
    assert "Missing requirement: Docker" not in refused.stdout
    assert "Installation complete!" not in refused.stdout
    assert not log.exists()

    (stubs / "docker").unlink()
    refused_without_docker = _run_install(home, stubs)

    assert refused_without_docker.returncode == 1
    assert _INTEL_MAC in refused_without_docker.stdout
    assert "Missing requirement: Docker" not in refused_without_docker.stdout
    assert not log.exists()


def test_install_sh_on_darwin_x86_64_under_rosetta_names_a_native_terminal(
    tmp_path: Path, stubs: Path
) -> None:
    """A Rosetta shell reports x86_64 and would install the same broken Semgrep sdist."""
    home = tmp_path / "home"
    home.mkdir()
    log = tmp_path / "calls.log"
    _stub_host(stubs, kernel="Darwin", machine="x86_64", translated="1")
    _log_stub(stubs, "docker", log)
    _log_stub(stubs, "uv", log)

    refused = _run_install(home, stubs)

    assert refused.returncode == 1
    assert refused.stdout.index(_INTEL_MAC) < refused.stdout.index(_NATIVE_ARM)
    assert "Detected:" not in refused.stdout
    assert not log.exists()


def test_install_sh_on_darwin_arm64_gets_past_the_os_check(tmp_path: Path, stubs: Path) -> None:
    """Apple Silicon still installs. A failing sysctl on PATH must not abort that path."""
    home = tmp_path / "home"
    home.mkdir()
    _stub_host(stubs, kernel="Darwin", machine="arm64", translated=None)

    output = _install(home, stubs)

    assert "Detected: Mac" in output
    assert _INTEL_MAC not in output
    assert "Installation complete!" in output


def test_install_sh_on_linux_x86_64_still_installs(tmp_path: Path, stubs: Path) -> None:
    """The Linux x86_64 archive map is a tarball name, not a support refusal."""
    home = tmp_path / "home"
    home.mkdir()
    _stub_host(stubs, kernel="Linux", machine="x86_64", translated=None)

    output = _install(home, stubs)

    assert "Detected: Linux" in output
    assert _INTEL_MAC not in output
    assert "Installation complete!" in output


def test_warden_sh_on_darwin_x86_64_exits_without_calling_uv(tmp_path: Path, stubs: Path) -> None:
    """The launcher installs Semgrep through `uv run`, so it stops on the same hosts."""
    log = tmp_path / "calls.log"
    _stub_host(stubs, kernel="Darwin", machine="x86_64", translated=None)
    for name in ("uv", "python3", "python"):
        _log_stub(stubs, name, log)

    refused = _run_warden(stubs, "--url", "http://x")

    assert refused.returncode == 1
    assert _INTEL_MAC in refused.stdout
    assert _NATIVE_ARM not in refused.stdout
    assert not log.exists()


def test_warden_sh_on_darwin_x86_64_under_rosetta_uses_the_same_message(
    tmp_path: Path, stubs: Path
) -> None:
    """The launcher tells a translated shell to rerun from a native arm64 terminal."""
    log = tmp_path / "calls.log"
    _stub_host(stubs, kernel="Darwin", machine="x86_64", translated="1")
    for name in ("uv", "python3", "python"):
        _log_stub(stubs, name, log)

    refused = _run_warden(stubs, "--url", "http://x")

    assert refused.returncode == 1
    assert refused.stdout.index(_INTEL_MAC) < refused.stdout.index(_NATIVE_ARM)
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


def _cloud_install_text() -> str:
    payload: object = json.loads(
        (REPO_ROOT / ".cursor/environment.json").read_text(encoding="utf-8")
    )
    if not isinstance(payload, dict):
        raise AssertionError("environment.json is not an object")
    command = payload["install"]
    if not isinstance(command, str):
        raise AssertionError("environment.json install is not a string")
    if command.startswith("bash .cursor/"):
        script = (REPO_ROOT / command.removeprefix("bash ").strip()).read_text(encoding="utf-8")
        if not isinstance(script, str):
            raise AssertionError("the cloud install script is not text")
        return script
    return command


def test_the_cloud_install_takes_the_uv_version_from_install_sh(tmp_path: Path) -> None:
    """A hardcoded UV_VERSION keeps installing 0.13.5 when install.sh says 9.9.9."""
    (tmp_path / "install.sh").write_text('UV_VERSION="9.9.9"\n', encoding="utf-8")
    lines: list[str] = []
    for line in _cloud_install_text().splitlines():
        lines.append(line)
        if line.startswith("UV_VERSION="):
            break
    else:
        raise AssertionError("the cloud install never assigns UV_VERSION")
    completed = subprocess.run(
        ["bash", "-c", "\n".join(lines) + '\nprintf %s "$UV_VERSION"'],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "9.9.9"


def test_install_ps1_pins_the_same_uv_as_install_sh_and_the_dockerfile() -> None:
    """Dependabot bumps the Dockerfile's uv stage alone; nothing else would notice the copies."""
    docker = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    install = INSTALL_SH.read_text(encoding="utf-8")
    powershell = (REPO_ROOT / "install.ps1").read_text(encoding="utf-8")

    version = _pins(powershell, r'(?m)^\$UvVersion = "(\S+)"')
    assert version == _pins(install, r'(?m)^UV_VERSION="(\S+)"')
    assert version == _pins(docker, r"ghcr\.io/astral-sh/uv:(\d+\.\d+\.\d+)@")


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
