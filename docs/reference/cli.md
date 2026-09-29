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
              [--strict] [--timeout SECONDS]
```

### Options

| Flag | Default | Effect |
| --- | --- | --- |
| `-u`, `--url`, `-Url`, `--Url` | `""` | DAST target URL. Enables the ZAP stage. Overrides `target_url` from the config file. A `target_url` in the project's own `.warden.yaml` is not used at all when `GITHUB_WORKSPACE` is set; one in a file given with `--config` still is. |
| `--project-root` | `.` | Directory to scan. Must be an existing directory. Resolved to an absolute path; the report is written here. |
| `--config` | `<project-root>/.warden.yaml` | Path to an alternate config file. |
| `--strict` | off | Fail the run (exit `3`) when a scanner that ran left no usable report, or when no scanner ran. See [Behaviour](#behaviour). |
| `--timeout` | none | Stop any single scanner that runs longer than this many seconds (a number greater than 0 and at most 4294967). See [Behaviour](#behaviour). |
| `-h`, `--help` | Not applicable | Print usage and exit. |

The `-Url` and `--Url` spellings exist so the same invocation works in
PowerShell habits and POSIX shells. All four spellings set the same value.

### Behaviour

- **A URL alone is not enough to run ZAP.** If `tools.zap` is `false` in the
  config, the resolved URL is discarded and ZAP is skipped, even when `--url` is
  passed explicitly. See [Configuration](configuration.md#interaction-between-target_url-and-toolszap).
- **The URL must start with lowercase `http://` or `https://`, have a host, and hold
  only printable characters** (ZAP tests the prefix literally). Anything else
  (`localhost:3000` without a scheme, `HTTP://...`, `ftp://...`, an escape sequence in
  the value) prints `Warning: the DAST URL ... is not usable` and skips
  ZAP; the other scanners still run and the exit code is unaffected, unless you pass
  `--strict`, which counts a refused URL as ZAP failing to run (exit `3`). ZAP itself
  rejects such a target, so nothing that worked is lost.
- A URL host of `localhost` or `127.0.0.1` is rewritten to
  `host.docker.internal` before ZAP runs, so the ZAP container can reach an app
  on the host. Only the host is rewritten, not the same text in the path or query.
- The report directory `.security_reports/` is created inside the project root
  if absent, and `.security_reports/` is appended to the project's `.gitignore`
  if that file exists and does not already list it. A `.gitignore` that cannot be
  read or written, or that is not text, is skipped with a warning and the audit
  carries on; add the entry yourself, since the raw reports can hold sensitive data.
- Warden never writes through a symlink at a path it owns, because the project
  it scans is not trusted. A symlink named `.security_reports` is replaced by a
  real directory, a symlink or named pipe named `security_audit.json` is replaced
  by the report, and a `.gitignore` that is a symlink or not a regular file is left
  untouched.
- **`--strict` makes a broken scan fail instead of pass.** By default a missing,
  crashed or unparsable scanner is only a warning and the run can print `PASS`.
  With `--strict`, a scanner that was started (or a DAST URL that was refused) and
  did not leave a report of the right shape (a JSON object for Trivy, Semgrep and
  ZAP, an array for Gitleaks) is named after the summary as
  `STRICT: <tools> did not produce a usable report, so the scan is incomplete.`, and
  the run exits `3`. The exit status of the scanner is not what counts, because ZAP
  exits non-zero when it has alerts and still writes its report; a clean scan is
  still a report. A run in which every scanner is disabled or skipped fails the same
  way (`STRICT: no scanner ran`). Findings win: a Critical or High finding is still
  exit `1`, and the `STRICT:` line is printed as well. Scanners you turned off in
  `.warden.yaml` are not held against the run. It is a flag and not a config key on
  purpose: an older Warden rejects an unknown flag, where it would ignore an unknown
  key and quietly run without the check.
- **`--timeout` limits each scanner, not the run.** A scanner still going after that
  many seconds is sent a stop request (SIGTERM), and whatever is left ten seconds
  later is killed. On Linux and macOS the scanner is started as the leader of its own
  process group and the whole group is signalled, so the workers it started (Semgrep
  runs a separate `semgrep-core`) stop with it; on Windows only the scanner process
  itself is stopped. Stopping the `docker run` client does not stop the ZAP container
  (its script is the container's first process and handles no signal), so ZAP's
  container is named and `docker kill` is run on it. Warden then prints
  `<tool> timed out after N seconds and was stopped.`, deletes whatever partial report
  the scanner left, and goes on to the next scanner. Like any scanner that fails to run,
  that is a warning and not a failure (`--strict` makes it one); without the flag nothing
  is limited, and a DAST scan can run for as long as ZAP takes.
- Reports from a previous run are deleted before the scanners start. Only the
  files listed in [Report format](report-format.md#input-files) and `zap.html`
  are removed; anything else in the directory is left alone.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No Critical or High findings. Printed as `PASS`. |
| `1` | At least one Critical or High finding, printed as `FAIL`; or a path Warden owns cannot be used (`.security_reports` is a regular file, a report in it is a directory, `security_audit.json` is a directory), printed as `warden: error: ...` on stderr. |
| `2` | Invalid arguments, including a `--project-root` that is not an existing directory. Nothing is scanned or written. |
| `3` | Only with `--strict`: no finding failed the build, but a scanner that ran left no usable report, or no scanner ran. The report is still written. |

Medium, Low, Info, and Unknown findings never affect the exit code. The
threshold is fixed at Critical and High and is not currently configurable from
the CLI or the config file.

Unless you pass `--strict`, a scanner that fails to run does **not** by itself
cause a non-zero exit. The failure is printed as a warning and the run continues
with whatever reports were produced. A scan can therefore report `PASS` while a
tool was unavailable.
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
| `report_dir` | Directory holding `trivy.json`, `semgrep.json`, `gitleaks.json`, and/or `zap.json`. It must exist; missing files in it are skipped. |
| `output_file` | Path to write the aggregated report. Parent directories are created. |

Exit codes match `warden`: `1` if any Critical or High finding is present,
otherwise `0`, and `2` for invalid arguments, including a `report_dir` that is not
an existing directory (nothing is written).

### Example

```console
$ warden-aggregate .security_reports security_audit.json
--- Aggregating Reports from /path/to/.security_reports ---
Generated security_audit.json with 4 issues.
```

The filenames it looks for are fixed. See
[Report format](report-format.md#input-files) for the exact list.
