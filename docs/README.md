# Warden documentation

This index groups the documentation by purpose. Start with
[Getting started](getting-started.md) if you have never run Warden.

## Tutorial

For newcomers working through a first success end to end.

| Document | Covers |
| --- | --- |
| [Getting started](getting-started.md) | Install Warden and scan your first project. Assumes no prior knowledge. |

## How-to guides

Goal-oriented recipes. Each assumes you already have Warden working.

| Document | Covers |
| --- | --- |
| [Configuring scans](guides/configuring-scans.md) | Write a `.warden.yaml`: exclude directories, disable tools, set a DAST target. |
| [Running with Docker](guides/running-with-docker.md) | Run the containerised scanner without installing the tools locally, including the DAST setup. |
| [Using Warden in CI](guides/ci-github-actions.md) | Wire the scan into GitHub Actions, in this repo or another one. |
| [Troubleshooting](guides/troubleshooting.md) | Diagnose skipped tools, permission errors, and unexpected exit codes. |

## Reference

Exhaustive and factual. For readers who already know what they want.

| Document | Covers |
| --- | --- |
| [CLI](reference/cli.md) | Every command, flag, and exit code across `warden`, `warden-config`, and `warden-aggregate`. |
| [Configuration](reference/configuration.md) | Every `.warden.yaml` key and environment variable, with types, defaults, and precedence. |
| [Report format](reference/report-format.md) | The `security_audit.json` schema and how each tool's severities are normalised. |

## Explanation

Background and rationale.

| Document | Covers |
| --- | --- |
| [Architecture overview](architecture/overview.md) | How the pieces fit together, the data flow through a scan, and the trade-offs behind non-obvious choices. |

## Contributing

| Document | Covers |
| --- | --- |
| [Contributing](../CONTRIBUTING.md) | Development environment, the quality gate, and what CI enforces. |
| [Code of conduct](../CODE_OF_CONDUCT.md) | How to behave in this community, and how to report a violation. |
| [Security policy](../SECURITY.md) | How to report a vulnerability privately, and what is in scope. |
| [AGENTS.md](../AGENTS.md) | Behavioural guidelines for AI coding agents working in this repository. |
