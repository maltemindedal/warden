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
              [--strict] [--no-strict] [--timeout SECONDS]
```

### Options

| Flag | Default | Effect |
| --- | --- | --- |
| `-u`, `--url`, `-Url`, `--Url` | `""` | DAST target URL. Enables the ZAP stage. Overrides `target_url` from the config file. A `target_url` in the project's own `.warden.yaml` is not used at all when `GITHUB_WORKSPACE` is set; one in a file given with `--config` still is. |
| `--project-root` | `.` | Directory to scan. Must be an existing directory. Resolved to an absolute path; the report is written here. |
| `--config` | `<project-root>/.warden.yaml` | Path to an alternate config file. Read through a symbolic link, which the default path is not, and like it at most 64 KiB: see [Configuration](configuration.md#the-config-file-format-is-a-yaml-subset). |
| `--strict` | on | Accepted so that older invocations keep working. Strict is the default: the run fails (exit `3`) when a scanner that ran left no usable report, when no scanner ran, or when a config file was there and was not read. See [Behaviour](#behaviour). |
| `--no-strict` | off | Turn strict off: a scanner that left no usable report is only a warning, and the run can print `PASS`. When both flags are given, the last one wins. |
| `--timeout` | none | Stop any single scanner that runs longer than this many seconds (a number greater than 0 and at most 4294967). See [Behaviour](#behaviour). |
| `-h`, `--help` | Not applicable | Print usage and exit. |

The `-Url` and `--Url` spellings exist so the same invocation works in
PowerShell habits and POSIX shells. All four spellings set the same value.

### Behaviour

- **A URL alone is not enough to run ZAP.** If `tools.zap` is `false` in the
  config, the resolved URL is discarded and ZAP is skipped, even when `--url` is
  passed explicitly. See [Configuration](configuration.md#interaction-between-target_url-and-toolszap).
- **The URL must start with lowercase `http://` or `https://`, have a host, hold
  only printable characters, and be at most 2048 characters long** (ZAP tests the
  prefix literally). Anything else (`localhost:3000` without a scheme, `HTTP://...`,
  `ftp://...`, an escape sequence in the value, a longer URL) prints `Warning: the DAST URL ... is not usable` and skips
  ZAP; the other scanners still run. Strict mode, the default, counts a refused URL
  as ZAP failing to run (exit `3`); with `--no-strict` the exit code is unaffected. ZAP itself
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
  untouched. It does not read the project's own `.warden.yaml` through a symlink
  either: the defaults are used, with a warning, and strict mode, the default,
  fails the run (next item).
- **A broken scan fails instead of passing, unless you pass `--no-strict`.** By
  default a scanner that was started (or a DAST URL that was refused) and did not
  leave a report of the right shape (a JSON object for Trivy, Semgrep and ZAP, an
  array for Gitleaks) is named after the summary as
  `STRICT: <tools> did not produce a usable report, so the scan is incomplete; to accept an incomplete scan, pass --no-strict.`,
  and the run exits `3`. The summary's last line then reads
  `INCOMPLETE: No High/Critical issues found in the reports that were read. See <report>`
  in place of `PASS: ...`: a run that exits `3` never prints `PASS`. A missing scanner counts: on a machine without Trivy or
  Gitleaks on `PATH`, `warden` exits `3` until you install them, run the Docker image,
  or pass `--no-strict`. The exit status of the scanner is not what counts, because ZAP
  exits non-zero when it has alerts and still writes its report; a clean scan is
  still a report. A run in which every scanner is disabled or skipped fails the same
  way (`STRICT: no scanner ran, ...`). So does a run whose config file was there and
  was not read: a project `.warden.yaml` that is a symbolic link or not a regular
  file, a config over 64 KiB or that cannot be read, or a `--config` path that does
  not exist. The defaults are used, so a `target_url` in that file starts no ZAP
  scan, and the run would otherwise pass without the scan the file asks for:
  `STRICT: .warden.yaml was not read, so what it asks for (a DAST target_url, say) was not scanned and the scan is incomplete; to accept an incomplete scan, pass --no-strict.`
  A project with no `.warden.yaml` is not affected. Findings win: a Critical or High finding is still
  exit `1`, and the `STRICT:` line is printed as well. The check reads its answer
  from `tools_run` in the report (see [Report format](report-format.md#summary)): it
  names each scanner that was started and is missing from it. Scanners you turned
  off in `.warden.yaml` are not held against the run. With `--no-strict`, a missing,
  crashed or unparsable scanner is only a warning and the run can print `PASS`. The
  opt-out is a flag and not a config key on purpose: an older Warden, where strict
  was opt-in, rejects `--no-strict` with exit `2`, where it would ignore an unknown
  key.
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
  that fails the run with exit `3` (only a warning under `--no-strict`); without
  `--timeout` nothing is limited, and a DAST scan can run for as long as ZAP takes.
- **Text from the project is printed escaped.** A project path, a line quoted from
  `.warden.yaml` or a URL can hold characters that drive a terminal. In everything
  Warden prints, on stdout and stderr, a character that is not printable is written
  as its backslash escape: a control character or ESC (`\x1b`), a line break (`\n`),
  a tab (`\t`), a bidirectional override or zero-width character (`\u202e`), and
  every space except the plain one, such as a no-break space (`\xa0`) or an
  ideographic space (`\u3000`). A character the output encoding cannot hold (a
  redirected stdout on a Windows code page) is written as `\uXXXX` as well. Other
  text is printed as it is. `security_audit.json` holds the exact values. The same
  holds for `warden-config` and `warden-aggregate`. What the scanners print
  themselves is not changed.
- A report Warden cannot read or parse is named by its file name:
  `Warning: Could not parse trivy.json: <reason>`. The reason is the JSON error or
  the operating system's message (`Is a directory`), without the report's path.
- Reports from a previous run are deleted before the scanners start. Only the
  files listed in [Report format](report-format.md#input-files) and `zap.html`
  are removed; anything else in the directory is left alone.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No Critical or High findings. Printed as `PASS`. |
| `1` | At least one Critical or High finding, printed as `FAIL`; or a path Warden owns cannot be used (`.security_reports` is a regular file, a report in it is a directory, `security_audit.json` is a directory); or a report is more JSON than Python can parse (nested past about 1,000 levels on Python 3.11 or 10,000 from 3.12, or holding an integer of more than 4,300 digits), which may hold findings, reported once every scanner has run. Both of the last two are printed as `warden: error: ...` on stderr, and neither writes `security_audit.json`. Any other path Warden cannot look up, write or delete ends the run the same way, as `warden: error: <path>: <reason>`. |
| `2` | Invalid arguments, including a `--project-root` that is not an existing directory or that cannot be looked up (`warden: error: --project-root <path> cannot be looked up: <reason>`), and a `--project-root` or `--config` that cannot be resolved because it is a symbolic link loop (`warden: error: argument --config: cannot resolve <path>: symbolic link loop`). Nothing is scanned or written. |
| `3` | No finding failed the build, but a scanner that ran left no usable report, no scanner ran, or a config file was there and was not read. Printed as `INCOMPLETE` in the summary, then a `STRICT:` line and `AUDIT INCOMPLETE!`. Never with `--no-strict`. The report is still written. |

Medium, Low, Info, and Unknown findings never affect the exit code. The
threshold is fixed at Critical and High and is not currently configurable from
the CLI or the config file.

With `--no-strict`, a scanner that fails to run does **not** by itself cause a
non-zero exit. The failure is printed as a warning and the run continues with
whatever reports were produced, so a scan can report `PASS` while a tool was
unavailable.
See [Troubleshooting](../guides/troubleshooting.md#a-tool-was-skipped-or-warned-and-the-scan-exits-3).

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
| `--config` | `<project_root>/.warden.yaml` | Alternate config path. Read through a symbolic link, which the default path is not. |

Exits `0`, or `2` for invalid arguments, including a `project_root` or `--config`
that is a symbolic link loop.

stdout is one line holding one JSON document. A character in a value that is not
printable (a control character, a bidirectional override, a no-break space), or
that the output encoding cannot hold, is written as a JSON `\uXXXX` escape, so
the document parses to the configured values on any terminal and code page.
Other non-ASCII text is left readable. Warnings go to stderr.

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

Exit codes match `warden`: `1` if any Critical or High finding is present, or
if a report is more JSON than Python can parse, or a report cannot be looked up,
or `output_file` cannot be written (it is a directory, say), each printed as
`warden-aggregate: error: ...` on stderr with nothing written, otherwise `0`,
and `2` for invalid arguments, including a `report_dir` that is not an existing
directory or cannot be looked up, and either path being a symbolic link loop
(nothing is written).

### Example

```console
$ warden-aggregate .security_reports security_audit.json
--- Aggregating Reports from /path/to/.security_reports ---
Generated security_audit.json with 4 issues.
```

The filenames it looks for are fixed. See
[Report format](report-format.md#input-files) for the exact list.
