# CLI reference

Warden installs three console scripts. `warden` is the one you normally run;
the other two expose internal stages for scripting and debugging.

| Command | Purpose |
| --- | --- |
| [`warden`](#warden) | Run the full audit: scanners, then aggregation. |
| [`warden-config`](#warden-config) | Resolve `.warden.yaml` and print the effective configuration. |
| [`warden-aggregate`](#warden-aggregate) | Merge existing tool reports into `security_audit.json`. |

---

## `warden`

Runs the enabled scanners over a project, writes `security_audit.json`, and
exits non-zero if any Critical or High finding is present.

```
usage: warden [-h] [-u URL] [--project-root PROJECT_ROOT] [--config CONFIG]
```

### Options

| Flag | Default | Effect |
| --- | --- | --- |
| `-u`, `--url`, `-Url`, `--Url` | `""` | DAST target URL. Enables the ZAP stage. Overrides `target_url` from the config file. |
| `--project-root` | `.` | Directory to scan. Resolved to an absolute path; the report is written here. |
| `--config` | `<project-root>/.warden.yaml` | Path to an alternate config file. |
| `-h`, `--help` | Not applicable | Print usage and exit. |

The `-Url` and `--Url` spellings exist so the same invocation works in
PowerShell habits and POSIX shells. All four spellings set the same value.

### Behaviour

- **A URL alone is not enough to run ZAP.** If `tools.zap` is `false` in the
  config, the resolved URL is discarded and ZAP is skipped, even when `--url` is
  passed explicitly. See [Configuration](configuration.md#interaction-between-target_url-and-toolszap).
- A URL host of `localhost` or `127.0.0.1` is rewritten to
  `host.docker.internal` before ZAP runs, so the ZAP container can reach an app
  on the host. Only the host is rewritten, not the same text in the path or query.
- The report directory `.security_reports/` is created inside the project root
  if absent, and `.security_reports/` is appended to the project's `.gitignore`
  if that file exists and does not already list it.
- Reports from a previous run are deleted before the scanners start. Only the
  files listed in [Report format](report-format.md#input-files) and `zap.html`
  are removed; anything else in the directory is left alone.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No Critical or High findings. Printed as `PASS`. |
| `1` | At least one Critical or High finding. Printed as `FAIL`. |

Medium, Low, Info, and Unknown findings never affect the exit code. The
threshold is fixed at Critical and High and is not currently configurable from
the CLI or the config file.

A scanner that fails to run does **not** by itself cause a non-zero exit. The
failure is printed as a warning and the run continues with whatever reports were
produced. A scan can therefore report `PASS` while a tool was unavailable.
See [Troubleshooting](../guides/troubleshooting.md#a-tool-was-skipped-or-warned-but-the-scan-still-passed).

### Per-tool exit-code handling

Each scanner has its own notion of a clean run. Warden treats these codes as
success and anything else as a warning:

| Tool | Accepted exit codes | Notes |
| --- | --- | --- |
| Trivy | `0` | |
| Semgrep | `0`, `1` | Semgrep exits `1` when it has findings, which is not an error. |
| Gitleaks | `0` | Invoked with `--exit-code 0` so leaks do not fail the process. |
| ZAP | `0` | Invoked with `-I` so informational alerts do not fail the process. |

A tool whose report file exists is also treated as having succeeded, regardless
of exit code.

---

## `warden-config`

Resolves the configuration for a project and prints it. Useful for confirming
what Warden will actually do before running a scan.

```
usage: warden-config [-h] [--cli-url CLI_URL] [--config CONFIG]
                      project_root
```

| Argument | Default | Effect |
| --- | --- | --- |
| `project_root` | required | Directory whose config to resolve. |
| `--cli-url` | `""` | Simulate a `--url` flag, to check precedence. |
| `--config` | `<project_root>/.warden.yaml` | Alternate config path. |

Exits `0`.

### Examples

```console
$ warden-config .
{"url": "", "exclude_dirs": [], "tools": {"trivy": true, "semgrep": true, "gitleaks": true, "zap": true}}
```

---

## `warden-aggregate`

Merges existing scanner JSON reports into a single report without running any
scanners.

```
usage: warden-aggregate [-h] report_dir output_file
```

| Argument | Effect |
| --- | --- |
| `report_dir` | Directory holding `trivy.json`, `semgrep.json`, `gitleaks.json`, and/or `zap.json`. Missing files are skipped. |
| `output_file` | Path to write the aggregated report. Parent directories are created. |

Exit codes match `warden`: `1` if any Critical or High finding is present,
otherwise `0`.

### Example

```console
$ warden-aggregate .security_reports security_audit.json
--- Aggregating Reports from /path/to/.security_reports ---
Generated security_audit.json with 4 issues.
```

The filenames it looks for are fixed. See
[Report format](report-format.md#input-files) for the exact list.
