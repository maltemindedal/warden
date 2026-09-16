from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ._models import Finding
from ._parsers import parse_gitleaks, parse_semgrep, parse_trivy, parse_zap

ZAP_IMAGE: Final[str] = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_HTML_REPORT: Final[str] = "zap.html"

ReportParser = Callable[[object | None], list[Finding]]


@dataclass(slots=True, frozen=True)
class ScanRequest:
    """Everything any scanner's command line can be built from."""

    project_root: Path
    report_dir: Path
    report_path: Path
    exclude_dirs: tuple[str, ...] = ()
    url: str = ""


@dataclass(slots=True, frozen=True)
class Command:
    """A built command line, and how the operating system should be asked to run it."""

    args: list[str]
    cwd: Path
    stderr_to_devnull: bool = False
    env_overrides: dict[str, str] | None = None


CommandBuilder = Callable[[ScanRequest], Command]


def rewrite_zap_target(url: str) -> str:
    """ZAP runs in its own container, where the host's loopback is not the host."""
    if "localhost" in url or "127.0.0.1" in url:
        return url.replace("localhost", "host.docker.internal").replace(
            "127.0.0.1", "host.docker.internal"
        )
    return url


def resolve_host_report_dir(report_dir: str | Path) -> Path:
    """The bind-mount source ZAP needs, which is a host path even when Warden is containerised."""
    report_path = Path(report_dir).resolve()
    if host_report_dir := os.environ.get("WARDEN_HOST_REPORT_DIR"):
        return Path(host_report_dir)
    if host_workspace := os.environ.get("WARDEN_HOST_WORKSPACE"):
        return Path(host_workspace) / ".security_reports"
    if github_workspace := os.environ.get("GITHUB_WORKSPACE"):
        return Path(github_workspace) / ".security_reports"
    return report_path


def _build_trivy_command(request: ScanRequest) -> Command:
    args = ["trivy", "fs", ".", "--format", "json", "--output", str(request.report_path), "--quiet"]
    if request.exclude_dirs:
        args.extend(["--skip-dirs", ",".join(request.exclude_dirs)])
    return Command(args=args, cwd=request.project_root)


def _build_semgrep_command(request: ScanRequest) -> Command:
    args = [
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        "--output",
        str(request.report_path),
        "--quiet",
        ".",
    ]
    for exclude_dir in request.exclude_dirs:
        if exclude_dir:
            args.extend(["--exclude", exclude_dir])
    return Command(
        args=args,
        cwd=request.project_root,
        stderr_to_devnull=True,
        env_overrides={"PYTHONUTF8": "1"},
    )


def _build_gitleaks_command(request: ScanRequest) -> Command:
    args = [
        "gitleaks",
        "detect",
        "--source",
        ".",
        "--no-git",
        "--report-path",
        str(request.report_path),
        "--exit-code",
        "0",
    ]
    for exclude_dir in request.exclude_dirs:
        if exclude_dir:
            args.extend(["--exclude-path", exclude_dir])
    return Command(args=args, cwd=request.project_root, stderr_to_devnull=True)


def _build_zap_command(request: ScanRequest) -> Command:
    args = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{resolve_host_report_dir(request.report_dir)}:/zap/wrk/:rw",
        "-t",
        ZAP_IMAGE,
        "zap-full-scan.py",
        "-t",
        rewrite_zap_target(request.url),
        "-J",
        request.report_path.name,
        "-r",
        ZAP_HTML_REPORT,
        "-I",
    ]
    return Command(args=args, cwd=request.report_dir)


@dataclass(slots=True, frozen=True)
class Scanner:
    """One scanner Warden knows about: what it is called, how to run it, how to read it."""

    label: str
    report_file: str
    category: str
    summary_order: int
    parser: ReportParser
    build_command: CommandBuilder
    accepted_returncodes: frozenset[int]
    requires_url: bool = False
    extra_artifacts: tuple[str, ...] = ()
    """Anything else this scanner drops in the report directory, cleared between runs."""

    def __post_init__(self) -> None:
        # `key` is derived rather than stored so the two cannot drift apart, which only
        # holds while the label is a single word that survives lowercasing.
        if not self.label.isalnum():
            raise ValueError(f"Scanner label must be a single alphanumeric word: {self.label!r}")

    @property
    def key(self) -> str:
        """The `.warden.yaml` key, derived from the label so the two cannot drift apart."""
        return self.label.lower()


TRIVY: Final[Scanner] = Scanner(
    label="Trivy",
    report_file="trivy.json",
    category="Deps",
    summary_order=2,
    parser=parse_trivy,
    build_command=_build_trivy_command,
    accepted_returncodes=frozenset({0}),
)
SEMGREP: Final[Scanner] = Scanner(
    label="Semgrep",
    report_file="semgrep.json",
    category="Code",
    summary_order=1,
    parser=parse_semgrep,
    build_command=_build_semgrep_command,
    accepted_returncodes=frozenset({0, 1}),
)
GITLEAKS: Final[Scanner] = Scanner(
    label="Gitleaks",
    report_file="gitleaks.json",
    category="Secrets",
    summary_order=0,
    parser=parse_gitleaks,
    build_command=_build_gitleaks_command,
    accepted_returncodes=frozenset({0}),
)
ZAP: Final[Scanner] = Scanner(
    label="ZAP",
    report_file="zap.json",
    category="ZAP",
    summary_order=3,
    parser=parse_zap,
    build_command=_build_zap_command,
    accepted_returncodes=frozenset({0}),
    requires_url=True,
    extra_artifacts=(ZAP_HTML_REPORT,),
)

# Order matters: it is the stage order, the order findings are collected in, and the
# order `tools_run` is reported in.
SCANNERS: Final[tuple[Scanner, ...]] = (TRIVY, SEMGREP, GITLEAKS, ZAP)

# The summary breakdown reads categories in their own order, which is deliberately not
# the stage order. Each record therefore has `summary_order` instead of relying on a
# second hand-written list.
CATEGORY_ORDER: Final[tuple[str, ...]] = tuple(
    dict.fromkeys(scanner.category for scanner in sorted(SCANNERS, key=lambda s: s.summary_order))
)
