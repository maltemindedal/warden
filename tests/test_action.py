from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from fakes import skip_unless_executable, symlink_or_skip

ACTION_YML = Path(__file__).resolve().parents[1] / "action.yml"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="the action runs its shell step on a Linux runner"
)


def _run_step_script() -> str:
    """The `Run Warden` step's shell script, exactly as action.yml has it."""
    text = ACTION_YML.read_text(encoding="utf-8")
    start = text.index("- name: Run Warden")
    script_at = text.index("run: |\n", start) + len("run: |\n")
    return textwrap.dedent(text[script_at : text.index("\n    - name:", script_at)])


class Step:
    """`action.yml`'s script run against a `docker` that only writes down what it was given."""

    def __init__(self, tmp_path: Path) -> None:
        self.workspace = tmp_path / "workspace"
        self.workspace.mkdir()
        self.github_workspace = self.workspace  # what the runner calls the workspace
        self.outside = tmp_path / "runner-temp"
        self.outside.mkdir()
        self._stubs = tmp_path / "stubs"
        self._stubs.mkdir()
        self.docker_log = tmp_path / "docker-args.txt"
        docker = self._stubs / "docker"
        docker.write_text(
            f'#!/bin/sh\nprintf "%s\\n" "$@" > "{self.docker_log}"\n', encoding="utf-8"
        )
        docker.chmod(0o755)
        skip_unless_executable(docker)
        self.docker_log.unlink()  # the probe ran it once
        self._script = tmp_path / "step.sh"
        self._script.write_text(_run_step_script(), encoding="utf-8")

    def run(
        self, *, url: str = "", strict: str = "false", config: str = ""
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(self._script)],
            capture_output=True,
            check=False,
            env={
                "PATH": f"{self._stubs}:/usr/bin:/bin",
                "GITHUB_WORKSPACE": str(self.github_workspace),
                "INPUT_URL": url,
                "INPUT_STRICT": strict,
                "INPUT_CONFIG": config,
            },
            text=True,
            timeout=60,
        )

    def docker_args(self) -> list[str]:
        return self.docker_log.read_text(encoding="utf-8").splitlines()

    def warden_args(self) -> list[str]:
        """What follows the image name: the arguments Warden itself gets."""
        args = self.docker_args()
        return args[args.index("warden:action") + 1 :]


@pytest.fixture
def step(tmp_path: Path) -> Step:
    return Step(tmp_path)


def test_by_default_warden_gets_no_arguments_and_the_workspace_is_mounted(step: Step) -> None:
    completed = step.run()

    assert completed.returncode == 0, completed.stderr
    assert step.warden_args() == []
    assert f"{step.workspace}:/src" in step.docker_args()


def test_the_url_and_strict_inputs_become_flags(step: Step) -> None:
    step.run(url="https://example.com", strict="true")

    assert step.warden_args() == ["--url", "https://example.com", "--strict"]


@pytest.mark.parametrize("value", ["true", "True", "TRUE"])
def test_strict_is_on_for_the_spellings_of_true(step: Step, value: str) -> None:
    step.run(strict=value)

    assert step.warden_args() == ["--strict"]


@pytest.mark.parametrize("value", ["false", "False", "FALSE", ""])
def test_strict_is_off_for_the_spellings_of_false(step: Step, value: str) -> None:
    step.run(strict=value)

    assert step.warden_args() == []


@pytest.mark.parametrize("value", ["yes", "1", "on", " true", "truee"])
def test_a_strict_value_that_is_neither_true_nor_false_is_an_error_not_a_silent_off(
    step: Step, value: str
) -> None:
    """A gate that quietly runs without `--strict` because of a spelling would fail open."""
    completed = step.run(strict=value)

    assert completed.returncode == 1
    assert "The strict input must be true or false" in completed.stdout
    assert not step.docker_log.exists()


def test_a_config_from_outside_the_checkout_is_mounted_read_only_and_used(step: Step) -> None:
    config = step.outside / "warden.yaml"
    config.write_text("tools:\n  zap: false\n", encoding="utf-8")

    completed = step.run(config=str(config))

    assert completed.returncode == 0, completed.stderr
    assert f"{config.resolve()}:/warden-config.yaml:ro" in step.docker_args()
    assert step.warden_args() == ["--config", "/warden-config.yaml"]


def test_a_config_inside_the_checkout_is_refused_before_anything_runs(step: Step) -> None:
    config = step.workspace / ".warden.yaml"
    config.write_text("tools:\n  trivy: false\n", encoding="utf-8")

    completed = step.run(config=str(config))

    assert completed.returncode == 1
    assert "must point outside the checked-out workspace" in completed.stdout
    assert not step.docker_log.exists()


def test_a_symlink_that_leads_into_the_checkout_is_refused_too(step: Step) -> None:
    real = step.workspace / "policy.yaml"
    real.write_text("tools:\n  trivy: false\n", encoding="utf-8")
    link = step.outside / "looks-outside.yaml"
    symlink_or_skip(link, real)

    completed = step.run(config=str(link))

    assert completed.returncode == 1
    assert not step.docker_log.exists()


def test_a_config_that_is_not_a_file_is_refused(step: Step) -> None:
    completed = step.run(config=str(step.outside / "missing.yaml"))

    assert completed.returncode == 1
    assert "does not name a file" in completed.stdout
    assert not step.docker_log.exists()


def test_a_config_in_a_directory_that_does_not_exist_gets_the_annotation_too(step: Step) -> None:
    completed = step.run(config=str(step.outside / "no" / "such" / "warden.yaml"))

    assert completed.returncode == 1
    assert "does not name a file" in completed.stdout
    assert not step.docker_log.exists()


def test_a_workspace_that_is_itself_a_symlink_does_not_hide_a_config_inside_it(
    step: Step, tmp_path: Path
) -> None:
    config = step.workspace / "policy.yaml"
    config.write_text("tools:\n  trivy: false\n", encoding="utf-8")
    link = tmp_path / "workspace-link"
    symlink_or_skip(link, step.workspace)
    step.github_workspace = link

    completed = step.run(config=str(config))

    assert completed.returncode == 1
    assert "must point outside the checked-out workspace" in completed.stdout
    assert not step.docker_log.exists()


def test_a_directory_whose_name_only_starts_like_the_workspace_is_outside_it(
    step: Step, tmp_path: Path
) -> None:
    """`/work` is not `/workspace`: the prefix test must stop at a path separator."""
    short = tmp_path / "work"
    short.mkdir()
    step.github_workspace = short  # `workspace` (the fixture's directory) starts with `work`
    config = step.workspace / "warden.yaml"
    config.write_text("tools:\n  zap: false\n", encoding="utf-8")

    completed = step.run(config=str(config))

    assert completed.returncode == 0, completed.stdout
    assert step.warden_args() == ["--config", "/warden-config.yaml"]
