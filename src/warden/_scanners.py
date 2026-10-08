from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ._models import Finding
from ._parsers import parse_gitleaks, parse_semgrep, parse_trivy, parse_zap

ZAP_IMAGE: Final[str] = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_HTML_REPORT: Final[str] = "zap.html"

ReportParser = Callable[[object | None, str], list[Finding]]
"""Reads a report into findings, each tagged with the label it is given: see `Scanner.parse`."""


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
    on_timeout: list[str] | None = None
    """A command to run, best effort, after this one was stopped for running too long."""


CommandBuilder = Callable[[ScanRequest], Command]


# The pieces of a URL, found without backtracking: an optional scheme and `//`, then the
# authority up to the first `/`, `?` or `#`, whose host follows its last `@`.
_URL_LEAD: Final = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*:)?//")
_AUTHORITY_END: Final = re.compile(r"[/?#]")
_HTTP_LEAD: Final = re.compile(r"https?://")
_LOOPBACK_HOST: Final = re.compile(r"(?:localhost|127\.0\.0\.1)(?P<dot>\.?)(?=:|\Z)")


def rewrite_zap_target(url: str) -> str:
    """ZAP runs in its own container, where the host's loopback is not the host.

    Only the URL's host is rewritten, and only when it is exactly `localhost` or `127.0.0.1`: the
    same text in the user name, path, query or fragment is left alone, and so is everything
    else in the URL. It is linear in the length of the URL, because a project controls it.
    """
    lead = _URL_LEAD.match(url)
    start = lead.end() if lead else 0
    boundary = _AUTHORITY_END.search(url, start)
    end = boundary.start() if boundary else len(url)
    last_at = url.rfind("@", start, end)
    host_start = last_at + 1 if last_at != -1 else start
    host = _LOOPBACK_HOST.match(url, host_start, end)
    if host is None:
        return url
    return f"{url[:host_start]}host.docker.internal{host['dot']}{url[host.end() :]}"


def url_problem(url: str) -> str | None:
    """Why `url` cannot be a DAST target, or `None` if it looks like one.

    ZAP only takes an `http://` or `https://` target with a host, and its check is a literal
    lowercase prefix test. A project supplies the URL, so an escape sequence, a bidirectional
    override or any other character that is not plainly printable must never reach the terminal.
    """
    if not url.isprintable():
        return "it contains control or non-printable characters"
    lead = _HTTP_LEAD.match(url)
    if lead is None:
        return "it does not start with http:// or https:// (lowercase, as ZAP requires)"
    boundary = _AUTHORITY_END.search(url, lead.end())
    authority = url[lead.end() : boundary.start() if boundary else len(url)]
    host_and_port = authority.rpartition("@")[2]
    host = (
        host_and_port[: host_and_port.find("]") + 1]
        if host_and_port.startswith("[")
        else (host_and_port.partition(":")[0])
    )
    if not host:
        return "it has no host"
    return None


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
    # Only vulnerabilities are read (`parse_trivy`). Trivy's default also runs its secret scanner
    # over the whole tree, whose result is discarded and which Gitleaks already covers.
    args = [
        "trivy",
        "fs",
        ".",
        "--format",
        "json",
        "--output",
        str(request.report_path),
        "--quiet",
        "--scanners",
        "vuln",
    ]
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
    # `gitleaks detect` has no flag for skipping paths (it rejects `--exclude-path` as an unknown
    # flag), so `exclude_dirs` is applied to its report afterwards. See `Scanner.path_key`.
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
        # The raw report otherwise holds every matched secret in clear text. Only the rule, the
        # file and the line are read from it.
        "--redact",
    ]
    return Command(args=args, cwd=request.project_root, stderr_to_devnull=True)


def _build_zap_command(request: ScanRequest) -> Command:
    # Stopping the `docker run` client does not stop the container: the ZAP script is the
    # container's PID 1 and handles no signal. A name lets a timeout `docker kill` it.
    container = f"warden-zap-{uuid.uuid4().hex}"
    args = [
        "docker",
        "run",
        "--rm",
        "--name",
        container,
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
    return Command(args=args, cwd=request.report_dir, on_timeout=["docker", "kill", container])


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
    path_key: str | None = None
    """For a scanner with no flag to skip paths: the key holding each finding's file path.

    Its report is filtered against `exclude_dirs` after the scan."""
    report_is_array: bool = False
    """Whether the report is a JSON array (Gitleaks) rather than a JSON object."""

    def __post_init__(self) -> None:
        # `key` is derived rather than stored so the two cannot drift apart, which only
        # holds while the label is a single word that survives lowercasing.
        if not self.label.isalnum():
            raise ValueError(f"Scanner label must be a single alphanumeric word: {self.label!r}")

    @property
    def key(self) -> str:
        """The `.warden.yaml` key, derived from the label so the two cannot drift apart."""
        return self.label.lower()

    def parse(self, report: object | None) -> list[Finding]:
        """The findings in `report`, each tagged with this scanner's label.

        The parser is handed the label rather than naming its own tool, so the label a finding
        carries and the one the summary looks its category up by cannot drift apart.
        """
        return self.parser(report, self.label)

    def reads_report(self, report: object | None) -> bool:
        """Whether `report` has the shape this scanner's parser reads, so its run counts."""
        return isinstance(report, list if self.report_is_array else dict)


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
    path_key="File",
    report_is_array=True,
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
