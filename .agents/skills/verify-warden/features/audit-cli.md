# Security gate CLI

## Sub-features

- `warden --project-root <dir>` runs the scanners, writes `<dir>/security_audit.json` and `<dir>/.security_reports/`, exits 1 on any Critical/High finding.
- `--help`. Not driven yet: `--strict` (exit 3), `--url` (ZAP), `--config`, `warden-config`, `warden-aggregate`.

## How to get to it (user POV)

`uv run warden --project-root path/to/project`, or the `bin/warden` wrappers.

## Driving it with verify.sh

`verify.sh cli` builds a vulnerable and a clean fixture under the artifacts
dir. End state: vulnerable exits 1 with a High finding in its report; clean
exits 0 and has a report.

## Gotchas

- Needs network: Semgrep downloads its rules.
- With Trivy and Gitleaks absent, Warden warns and passes; only Semgrep findings are exercised here.
