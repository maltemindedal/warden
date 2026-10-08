from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from ._json import as_mapping, get_int, get_string, iter_mappings
from ._models import Finding, Severity

SEVERITY_ALIASES: Final[dict[str, Severity]] = {
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "HIGH": "HIGH",
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATION": "INFO",
    "INFORMATIONAL": "INFO",
    "UNKNOWN": "UNKNOWN",
}
SEVERITY_RANK: Final[dict[Severity, int]] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}
ZAP_RISK_MAP: Final[dict[str, Severity]] = {
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "INFO",
}


def normalize_severity(value: object) -> Severity:
    normalized = str(value).strip().upper()
    if not normalized:
        return "UNKNOWN"
    return SEVERITY_ALIASES.get(normalized, "UNKNOWN")


def severity_rank(severity: Severity) -> int:
    return SEVERITY_RANK[normalize_severity(severity)]


def _trivy_title(vulnerability: Mapping[str, object]) -> str:
    return (
        get_string(vulnerability, "Title")
        or get_string(vulnerability, "VulnerabilityID")
        or "Vulnerability"
    )


def _build_trivy_finding(vulnerability: Mapping[str, object], target: str, tool: str) -> Finding:
    package_name = get_string(vulnerability, "PkgName") or "Unknown package"
    installed_version = get_string(vulnerability, "InstalledVersion") or "Unknown version"
    return Finding(
        tool=tool,
        severity=normalize_severity(vulnerability.get("Severity")),
        file=target,
        description=f"{package_name} {installed_version}: {_trivy_title(vulnerability)}",
        fix=get_string(vulnerability, "FixedVersion") or "No fix available",
    )


def parse_trivy(raw_data: object | None, tool: str) -> list[Finding]:
    root = as_mapping(raw_data)
    if root is None:
        return []

    findings: list[Finding] = []
    for result in iter_mappings(root.get("Results")):
        target = get_string(result, "Target") or "Unknown"
        for vulnerability in iter_mappings(result.get("Vulnerabilities")):
            findings.append(_build_trivy_finding(vulnerability, target, tool))
    return findings


def parse_semgrep(raw_data: object | None, tool: str) -> list[Finding]:
    root = as_mapping(raw_data)
    if root is None:
        return []

    findings: list[Finding] = []
    for result in iter_mappings(root.get("results")):
        extra = as_mapping(result.get("extra")) or {}
        start = as_mapping(result.get("start")) or {}
        findings.append(
            Finding(
                tool=tool,
                severity=normalize_severity(extra.get("severity")),
                file=get_string(result, "path") or "Unknown",
                line=get_int(start, "line"),
                description=get_string(extra, "message") or "Semgrep finding",
                rule_id=get_string(result, "check_id") or "Unknown",
            )
        )
    return findings


def parse_gitleaks(raw_data: object | None, tool: str) -> list[Finding]:
    findings: list[Finding] = []
    for leak in iter_mappings(raw_data):
        rule_id = get_string(leak, "RuleID") or "Unknown"
        findings.append(
            Finding(
                tool=tool,
                severity="CRITICAL",
                file=get_string(leak, "File") or "Unknown",
                line=get_int(leak, "StartLine"),
                description=f"Secret detected: {rule_id}",
                snippet="REDACTED",
            )
        )
    return findings


def _zap_target_url(alert: Mapping[str, object]) -> str:
    for instance in iter_mappings(alert.get("instances")):
        uri = get_string(instance, "uri")
        if uri is not None:
            return uri
    return "Unknown"


def _build_zap_finding(alert: Mapping[str, object], tool: str) -> Finding:
    return Finding(
        tool=tool,
        severity=ZAP_RISK_MAP.get(str(alert.get("riskcode")), "UNKNOWN"),
        file=_zap_target_url(alert),
        description=get_string(alert, "alert") or "ZAP alert",
        solution=get_string(alert, "solution"),
    )


def parse_zap(raw_data: object | None, tool: str) -> list[Finding]:
    root = as_mapping(raw_data)
    if root is None:
        return []

    findings: list[Finding] = []
    for site in iter_mappings(root.get("site")):
        for alert in iter_mappings(site.get("alerts")):
            findings.append(_build_zap_finding(alert, tool))
    return findings
