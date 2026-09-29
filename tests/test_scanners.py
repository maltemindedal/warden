from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from fakes import RecordingRunner
from warden import tooling
from warden._models import Finding
from warden._parsers import parse_zap
from warden._scanners import CATEGORY_ORDER, SCANNERS, ZAP, Scanner, rewrite_zap_target, url_problem
from warden._summary import judge
from warden.config import resolve_config

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_registry_holds_the_documented_scanners_in_report_order() -> None:
    assert [scanner.label for scanner in SCANNERS] == ["Trivy", "Semgrep", "Gitleaks", "ZAP"]
    assert [scanner.key for scanner in SCANNERS] == ["trivy", "semgrep", "gitleaks", "zap"]


def test_a_label_that_would_not_survive_lowercasing_is_rejected() -> None:
    """`key` is derived from `label`, which only holds for a single lowercase-able word."""
    with pytest.raises(ValueError, match="single alphanumeric word"):
        Scanner(
            label="OWASP ZAP",
            report_file="owasp.json",
            category="ZAP",
            summary_order=9,
            parser=parse_zap,
            build_command=ZAP.build_command,
            accepted_returncodes=frozenset({0}),
        )


def test_the_summary_category_order_is_derived_from_the_registry() -> None:
    """Display order is deliberately not stage order, so it is carried by `summary_order`."""
    assert CATEGORY_ORDER == ("Secrets", "Code", "Deps", "ZAP")
    assert set(CATEGORY_ORDER) == {scanner.category for scanner in SCANNERS}


def test_summary_categories_are_read_from_the_registry() -> None:
    findings = [
        Finding(tool=scanner.label, severity="HIGH", file="f", description="d")
        for scanner in SCANNERS
    ]

    verdict = judge(findings)

    assert verdict.breakdown["HIGH"] == {scanner.category: 1 for scanner in SCANNERS}


def test_each_parser_tags_its_findings_with_its_scanner_label() -> None:
    for scanner in SCANNERS:
        raw_report: object = json.loads(
            (FIXTURE_DIR / scanner.report_file).read_text(encoding="utf-8")
        )

        findings = scanner.parser(raw_report)

        assert {finding.tool for finding in findings} == {scanner.label}


def test_every_scanner_runs_through_the_same_interface(tmp_path: Path) -> None:
    """No scanner is special-cased at dispatch: ZAP included, each record carries its own argv."""
    runner = RecordingRunner()

    for scanner in SCANNERS:
        request = tooling.scan_request(
            scanner, project_root=tmp_path, report_dir=tmp_path, url="http://example.test"
        )
        result = tooling.run_scanner(scanner, request, runner)
        assert result.name == scanner.label
        assert result.report_path == tmp_path.resolve() / scanner.report_file
        assert result.accepted_returncodes == scanner.accepted_returncodes


def test_prepare_report_dir_clears_every_registered_report(tmp_path: Path) -> None:
    report_dir = tmp_path / ".security_reports"
    report_dir.mkdir()
    for scanner in SCANNERS:
        (report_dir / scanner.report_file).write_text("{}", encoding="utf-8")

    tooling.prepare_report_dir(tmp_path)

    assert not [scanner for scanner in SCANNERS if (report_dir / scanner.report_file).exists()]


def test_every_scanner_is_enabled_by_default(tmp_path: Path) -> None:
    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert all(scanner.key in resolved.enabled_tools for scanner in SCANNERS)


def test_every_scanner_can_be_disabled_by_its_key(tmp_path: Path) -> None:
    overrides = "\n".join(f"  {scanner.key}: false" for scanner in SCANNERS)
    (tmp_path / ".warden.yaml").write_text(f"tools:\n{overrides}\n", encoding="utf-8")

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert not [scanner for scanner in SCANNERS if scanner.key in resolved.enabled_tools]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://localhost:3000", "http://host.docker.internal:3000"),
        ("https://127.0.0.1:8443/app?x=1#top", "https://host.docker.internal:8443/app?x=1#top"),
        ("http://localhost", "http://host.docker.internal"),
        ("http://localhost/", "http://host.docker.internal/"),
        ("http://user:pw@localhost:3000/", "http://user:pw@host.docker.internal:3000/"),
        ("//localhost:3000", "//host.docker.internal:3000"),
        ("HTTP://localhost:3000", "HTTP://host.docker.internal:3000"),
        # The host is what follows the last `@` of the authority and ends at `/`, `?` or `#`.
        ("http://localhost:3000/@me", "http://host.docker.internal:3000/@me"),
        ("localhost:3000/a//b", "host.docker.internal:3000/a//b"),
        ("http://localhost/?e=a@b", "http://host.docker.internal/?e=a@b"),
        ("http://127.0.0.1#f@g", "http://host.docker.internal#f@g"),
        ("http://localhost?x=1", "http://host.docker.internal?x=1"),
        ("http://localhost#f", "http://host.docker.internal#f"),
        # A trailing dot makes a fully qualified name; it is still the loopback host.
        ("http://localhost.:3000/", "http://host.docker.internal.:3000/"),
        ("http://127.0.0.1./x", "http://host.docker.internal./x"),
        # ZAP rejects a target without http(s)://, but the rewrite has always applied to it.
        ("localhost:3000", "host.docker.internal:3000"),
        ("http://example.com", "http://example.com"),
        ("http://[::1]:3000", "http://[::1]:3000"),
        # Matching is case-sensitive, as it has always been.
        ("http://LOCALHOST:3000", "http://LOCALHOST:3000"),
    ],
)
def test_the_loopback_hosts_are_rewritten_for_the_zap_container(url: str, expected: str) -> None:
    assert rewrite_zap_target(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost.example.com/",
        "http://mylocalhost.example/",
        "http://127.0.0.10/",
        "http://127.0.0.1.nip.io/",
        "http://127x0y0z1/",
        "http://127-0-0-1:8080/",
        "example.com/?next=http://localhost/",
        "http://example.com/localhost/127.0.0.1",
        "http://example.com/?next=http://localhost:3000/",
        "http://user:localhost@example.com/",
        "http://localhost:pw@example.com/",
        "http://localhost:3000@example.com/",
        "http://127.0.0.1:pw@example.com/",
        "http://[::1",
        "http://[localhost]/",
        # Not a `scheme://`, so not rewritten (ZAP rejects both anyway); the old code did.
        "http:/localhost:3000",
        "http:localhost:3000",
    ],
)
def test_only_the_host_is_rewritten_never_a_lookalike_or_other_part_of_the_url(url: str) -> None:
    """A substring replace sent the active scan to hosts the user never named."""
    assert rewrite_zap_target(url) == url


def test_the_same_text_in_userinfo_path_and_query_is_left_alone_beside_a_loopback_host() -> None:
    assert (
        rewrite_zap_target("http://a@b@localhost:3000/localhost?q=127.0.0.1#localhost")
        == "http://a@b@host.docker.internal:3000/localhost?q=127.0.0.1#localhost"
    )


def test_a_hostile_url_is_rewritten_in_linear_time() -> None:
    """A project controls the URL (`target_url`); a backtracking pattern took minutes on this."""
    hostile = "http://" + "localhost:@" * 100_000

    started = time.perf_counter()
    result = rewrite_zap_target(hostile)

    assert result == hostile
    assert time.perf_counter() - started < 5


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:3000",
        "https://example.com",
        "http://user:pw@host:8080/path?q=1#frag",
        "http://[::1]:3000/",
        "http://127.0.0.1",
    ],
)
def test_an_http_url_with_a_host_is_a_usable_dast_target(url: str) -> None:
    assert url_problem(url) is None


@pytest.mark.parametrize(
    ("url", "problem"),
    [
        ("localhost:3000", "does not start with http:// or https://"),
        ("ftp://example.com", "does not start with http:// or https://"),
        ("file:///etc/passwd", "does not start with http:// or https://"),
        ("//example.com", "does not start with http:// or https://"),
        # zap-full-scan.py tests the prefix literally, in lowercase.
        ("HTTP://example.com", "does not start with http:// or https://"),
        ("Https://example.com", "does not start with http:// or https://"),
        ("http://", "has no host"),
        ("http:///path", "has no host"),
        ("http://:3000/", "has no host"),
        ("http://user:pw@/", "has no host"),
        ("http://[", "has no host"),
        ("http://example.com/\x1b[2J", "contains control or non-printable characters"),
        ("http://example.com\x00", "contains control or non-printable characters"),
        ("http://example.com/\n", "contains control or non-printable characters"),
        ("http://example.com/\u202egpj.exe", "contains control or non-printable characters"),
        ("http://example.com/\u2028", "contains control or non-printable characters"),
        ("http://example.com/\u200b", "contains control or non-printable characters"),
        ("http://example.com/\u009b", "contains control or non-printable characters"),
        ("http://example.com/\ud800", "contains control or non-printable characters"),
        ("http://exa\u00a0mple.com", "contains control or non-printable characters"),
    ],
)
def test_a_url_that_is_not_http_with_a_host_or_holds_control_characters_is_refused(
    url: str, problem: str
) -> None:
    assert url_problem(url) is not None
    assert problem in (url_problem(url) or "")


def test_a_hostile_url_is_checked_in_linear_time() -> None:
    hostile = "http://" + "@" * 1_000_000

    started = time.perf_counter()
    result = url_problem(hostile)

    assert result == "it has no host"
    assert time.perf_counter() - started < 5
