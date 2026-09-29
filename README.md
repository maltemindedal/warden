# Warden

Warden orchestrates Trivy, Semgrep, Gitleaks, and OWASP ZAP, merges their
output into a single report, and exits non-zero when it finds anything Critical
or High. Each of those tools has its own flags, output format, and severity
vocabulary; Warden reconciles them so you can gate a build on one exit code
instead of four. It runs the same way on Windows, macOS, and Linux, locally or
in CI.

| Tool | Finds |
| --- | --- |
| [Trivy](https://trivy.dev) | Vulnerable dependencies |
| [Semgrep](https://semgrep.dev) | Insecure code patterns (SAST) |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Committed secrets |
| [OWASP ZAP](https://www.zaproxy.org) | Vulnerabilities in a running web app (DAST, optional) |

## Quick start

Requires **Python 3.11+**, **Docker**, and **Git**. The installer fetches uv,
Trivy, and Gitleaks if you don't already have them.

```bash
git clone https://github.com/maltemindedal/warden.git
cd warden
./install.sh          # Windows: .\install.ps1
```

Then scan any project:

```bash
cd /path/to/your/project
warden
```

```
[1/4] Running Trivy...
   -> Done.
[2/4] Running Semgrep...
   -> Done.
[3/4] Running Gitleaks...
   -> Done.
[4/4] Skipping ZAP (no URL provided or disabled).

[*] Generating Final Report...
Generated security_audit.json with 4 issues.
--------------------------------------------------
┏━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━┓
┃ Severity ┃ Count ┃ Breakdown  ┃
┡━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━┩
│ Critical │     1 │ Secrets: 1 │
│ High     │     1 │ Deps: 1    │
│ Medium   │     2 │            │
└──────────┴───────┴────────────┘
--------------------------------------------------
FAIL: High/Critical issues found. See security_audit.json
```

Full findings land in `security_audit.json`; raw scanner output in
`.security_reports/`.

## Usage

Scan the current directory:

```bash
warden
```

Add a DAST scan against a running application:

```bash
warden --url "http://localhost:3000"
```

Or without installing anything, using the bundled container:

```bash
docker build -t warden:local .
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd):/src" warden:local
```

Configure per-project with a `.warden.yaml`:

```yaml
target_url: "http://localhost:3000"
exclude_dirs:
  - "node_modules/"
tools:
  gitleaks: false
```

## Documentation

| Guide | For |
| --- | --- |
| [Getting started](docs/getting-started.md) | First install and first scan, start to finish |
| [Configuring scans](docs/guides/configuring-scans.md) | Excluding directories, disabling tools, setting a DAST target |
| [Running with Docker](docs/guides/running-with-docker.md) | Containerised scans, including the DAST setup |
| [Using Warden in CI](docs/guides/ci-github-actions.md) | GitHub Actions, and other CI systems |
| [Troubleshooting](docs/guides/troubleshooting.md) | Skipped tools, permission errors, config that won't take |
| [CLI reference](docs/reference/cli.md) | Every command, flag, and exit code |
| [Configuration reference](docs/reference/configuration.md) | Every config key and environment variable |
| [Report format](docs/reference/report-format.md) | The `security_audit.json` schema and severity mapping |
| [Architecture](docs/architecture/overview.md) | How it fits together and why |

Full index: [docs/README.md](docs/README.md).

## Project structure

```
src/warden/    Typed Python package and CLI implementation
bin/          Shell and PowerShell wrappers for running from a checkout
tests/        Pytest suite, with scanner output fixtures
docs/         Documentation
action.yml    Composite GitHub Action
Dockerfile    Container bundling Warden with the scanners
```

## Contributing

See [docs/contributing.md](docs/contributing.md) for the development setup and
the quality gate (`ruff`, `ty`, `pytest`).

## License

MIT. See [LICENSE](LICENSE).
