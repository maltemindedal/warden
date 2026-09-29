# Getting started

By the end of this tutorial you will have Warden installed and a
`security_audit.json` report for a project of your choice. It takes about ten
minutes, most of which is downloading scanner binaries.

## What Warden does

Warden runs four security scanners over a project and merges their output into
one report with one exit code:

| Tool | Finds |
| --- | --- |
| Trivy | Vulnerable dependencies and misconfigured infrastructure files |
| Semgrep | Insecure code patterns (SAST) |
| Gitleaks | Committed secrets |
| OWASP ZAP | Optional DAST for vulnerabilities in a *running* web app |

The first three read your files. ZAP needs the URL of a running application, so
it only runs when you give it one.

## Prerequisites

- **Python 3.11 or newer.** The installers download 3.11 for you.
- **Docker.** Required by both installers, which exit if it is missing. Only the
  optional ZAP scan uses Docker. The other three tools run natively.
- **Git**, to clone the repository.

You do not need to install Trivy, Semgrep, or Gitleaks yourself. The installer
handles Trivy and Gitleaks; Semgrep arrives as a Python dependency.

## Step 1: Install

Clone the repository and run the installer for your platform.

On macOS or Linux:

```bash
git clone https://github.com/maltemindedal/warden.git
cd warden
./install.sh
```

On Windows, in PowerShell:

```powershell
git clone https://github.com/maltemindedal/warden.git
cd warden
.\install.ps1
```

The installer checks for Docker, installs [uv](https://docs.astral.sh/uv/) if
you don't have it, installs Trivy and Gitleaks if they are missing, then
installs Warden itself as a uv tool. It also adds `~/.local/bin` to your `PATH`
if it isn't already there.

If the installer says it added a directory to your `PATH`, or that your shell
profile already does, restart your terminal before continuing.

## Step 2: Confirm the install

```bash
warden --help
```

You should see:

```
usage: warden [-h] [-u URL] [--project-root PROJECT_ROOT] [--config CONFIG]

Run the Warden security audit.
```

If the command is not found, see
[Troubleshooting](guides/troubleshooting.md#the-warden-command-is-not-found).

## Step 3: Run your first scan

Change into any project directory and run:

```bash
cd /path/to/your/project
warden
```

Warden prints its progress as it works through the tools:

```
STARTING SECURITY AUDIT
   Target: /path/to/your/project

[1/4] Running Trivy...
   -> Done.
[2/4] Running Semgrep...
   -> Done.
[3/4] Running Gitleaks...
   -> Done.
[4/4] Skipping ZAP (no URL provided or disabled).

[*] Generating Final Report...
Generated /path/to/your/project/security_audit.json with 4 issues.
```

The first Semgrep run downloads its rule set, so it is slower than later runs.

`[4/4] Skipping ZAP` is expected because you have not given it a URL yet.

## Step 4: Read the result

Warden finishes with a summary table and a verdict:

```
--------------------------------------------------
SCAN COMPLETE
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

Two things to understand about this output:

- **Only Critical and High cause a failure.** Medium, Low, and Info findings are
  counted and reported, but they do not change the verdict.
- **The verdict sets the exit code.** `FAIL` exits `1`, `PASS` exits `0`. That is
  what makes Warden usable as a CI gate.

Full details are in `security_audit.json` next to your project, and each tool's
raw output is in `.security_reports/`. If your project has a `.gitignore`, Warden adds
`.security_reports/` to it automatically so those files are not committed. If it
cannot (an unwritable or non-text `.gitignore`) it warns and carries on; add the line
yourself. Without a `.gitignore` it creates none.

## Step 5: Add a DAST scan (optional)

To also scan a *running* application, start it, then pass its URL:

```bash
warden --url "http://localhost:3000"
```

This launches OWASP ZAP in a container, which is why Docker is a prerequisite.
Warden rewrites a URL host of `localhost` or `127.0.0.1` to
`host.docker.internal` so the container can reach an app running on your machine.

A full ZAP scan takes minutes rather than seconds.

## Where to go next

- Exclude directories or turn tools off: [Configuring scans](guides/configuring-scans.md)
- Run it in CI: [Using Warden in CI](guides/ci-github-actions.md)
- Every flag and exit code: [CLI reference](reference/cli.md)
- Understand the report structure: [Report format](reference/report-format.md)
