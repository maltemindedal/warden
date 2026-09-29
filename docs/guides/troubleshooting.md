# Troubleshooting

Symptoms and their causes, in rough order of how often they come up.

## The `warden` command is not found

The installer puts the executable in `~/.local/bin` and appends that directory
to your shell profile. A shell started before the install will not have it. If
the installer could not write the profile it says so; add `~/.local/bin` to your
`PATH` yourself.

Restart your terminal, or source the profile the installer edited:

```bash
source ~/.bashrc   # or ~/.zshrc, or ~/.profile
```

Confirm the directory is on your path:

```bash
echo "$PATH" | tr ':' '\n' | grep '.local/bin'
```

On Windows the installer sets the user `PATH` environment variable, which
existing terminals do not pick up. Open a new PowerShell window.

Without installing, you can always run from a checkout:

```bash
uv run warden --help
```

## A tool was skipped or warned, but the scan still passed

Output like this means a scanner did not run cleanly:

```
[1/4] Running Trivy...
   -> Warning: trivy was not found on PATH.
```

**This does not fail the build.** Warden reports the warning and continues,
then bases its verdict on whatever reports exist. A scan can print `PASS` while a
scanner never ran.

Four causes:

- **`... was not found on PATH.`** The binary is missing. Re-run the installer,
  or use the [Docker image](running-with-docker.md), which bundles all three
  static scanners.
- **`... timed out after N seconds and was stopped.`** You passed `--timeout` and
  that scanner was still running when it expired. Raise the limit, or exclude the
  directories that make it slow (see below).
- **`... could not be started: <reason>`** The binary is there but the
  operating system would not run it, for example `Permission denied` on a file
  that is not executable. The other scanners still run.
- **`... exited with status N.`** The tool ran and failed. Its stderr is
  suppressed for Semgrep and Gitleaks, so run the tool directly to see why.

To make this a failure instead of a warning, run `warden --strict`: it exits `3`
when a scanner that ran left no usable report (see the
[CLI reference](../reference/cli.md#behaviour)). To confirm which tools actually
contributed, check `tools_run`:

```bash
python -c "import json;print(json.load(open('security_audit.json'))['summary']['tools_run'])"
```

## ZAP is skipped even though I passed `--url`

The message is always the same regardless of cause:

```
[4/4] Skipping ZAP (no URL provided or disabled).
```

Check the resolved configuration:

```bash
warden-config . --cli-url "http://localhost:3000"
```

If `"url"` is empty while `"zap"` is `false`, that is the cause: **`tools.zap:
false` blanks the URL after the CLI flag is applied**, so an explicit `--url`
cannot override it. Remove `zap: false` from `.warden.yaml`.

## `PermissionError` when running the Docker image

```
PermissionError: [Errno 13] Permission denied: '/src/.security_reports/semgrep.json'
```

The image runs as an unprivileged user that cannot write to your bind mount. Add
the `--user` flag:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd):/src" warden:local
```

See [Why the `--user` flag is required](running-with-docker.md#why-the---user-flag-is-required).

## `permission denied` connecting to the Docker socket

```
permission denied while trying to connect to the Docker daemon socket
```

The unprivileged container user is not in the socket's group. Add it:

```bash
--group-add "$(stat -c '%g' /var/run/docker.sock)"
```

## `Warning: could not add .security_reports/ to .gitignore`

Warden keeps the raw reports out of version control by appending
`.security_reports/` to the project's `.gitignore`. When it cannot (the file is
read-only, or not text, such as a UTF-16 file) it prints this warning, gives the
reason, and carries on with the scan. Nothing is ignored in that case, so add
`.security_reports/` to your ignore rules yourself: Gitleaks redacts the secrets
it finds, but the reports still name every finding and where it is.

## Changes to `.warden.yaml` have no effect

A config file that cannot be read is discarded and defaults are used, and Warden
warns about what it did not understand in the file it did read (see
[the format notes](../reference/configuration.md#the-config-file-format-is-a-yaml-subset)).
Read the `Warning:` lines after `Target:`, then check what it resolved:

```bash
warden-config .
```

If the output shows defaults, the file was not read or not understood. Common
causes:

- The file is not at `<project-root>/.warden.yaml`. Pass `--config` to point
  elsewhere.
- The YAML uses features the parser does not support. It handles top-level
  scalars, a `-` list under `exclude_dirs`, and a one-level mapping under
  `tools`. Inline collections (`tools: {zap: false}`), anchors, and deeper
  nesting are ignored. See
  [the format notes](../reference/configuration.md#the-config-file-format-is-a-yaml-subset).
- Indentation is inconsistent. Any indentation marks a nested line, but it must
  follow the `exclude_dirs:` or `tools:` key it belongs to. A list written at the
  *same* indent as `exclude_dirs:` (the default style of many YAML tools) is not
  under it: indent the `- entry` lines.

## Findings from `node_modules`, `.venv`, or `vendor`

Warden scans everything under the project root by default, including installed
dependencies. A checkout with dependencies installed can produce many findings
that are not about your code. Gitleaks, for example, flags test fixtures and
sample keys inside third-party packages.

Exclude those directories:

```yaml
exclude_dirs:
  - "node_modules/"
  - ".venv/"
```

See [Configuring scans](configuring-scans.md#exclude-directories-from-scanning).

## Trivy fails on a large or unusual tree

Trivy can time out walking very large directories:

```
FATAL Fatal error run error: fs scan error: ... context deadline exceeded
```

Exclude the directory it is struggling with. Dependency and build output
directories are the usual causes.

## The first Semgrep run is slow

Semgrep uses `--config=auto`, which downloads a rule set on first use. Later
runs are faster. In CI, a fresh container downloads rules every time.

## Gitleaks misses a secret that was committed and removed

Gitleaks runs with `--no-git`, so it scans files as they exist on disk rather
than walking history. A secret removed in a later commit is still in your git
history but will not be reported. Scan history separately with Gitleaks
directly if that matters to you.
