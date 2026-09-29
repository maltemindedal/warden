# Configuring scans

How to adjust what Warden scans using a `.warden.yaml` file in your project
root. For the exhaustive key list, see
[Configuration reference](../reference/configuration.md).

## Check what is in effect

Before and after any change, confirm what Warden resolved:

```bash
warden-config .
```

```json
{"url": "", "exclude_dirs": [], "tools": {"trivy": true, "semgrep": true, "gitleaks": true, "zap": true}}
```

This is worth doing because a config file that fails to parse is silently
ignored rather than reported as an error.

## Exclude directories from scanning

Vendored dependencies and build output produce noise and slow scans down. Add
them to `exclude_dirs`:

```yaml
exclude_dirs:
  - "node_modules/"
  - "vendor/"
  - ".venv/"
```

Verify:

```bash
warden-config .
```

```json
{"url": "", "exclude_dirs": ["node_modules/", "vendor/", ".venv/"], ...}
```

Each entry is applied to all three static scanners, but they interpret
exclusions differently. Trivy takes directory paths and Semgrep takes patterns.
Gitleaks scans everything and Warden drops its findings under each listed
directory, counted from the project root, so give it a plain directory such as
`vendor/` rather than a glob. If something is still being scanned after you
excluded it, try both a bare name (`node_modules`) and a trailing-slash form
(`node_modules/`).

Installed dependency directories often produce false positives. A `.venv/` or
`node_modules/` full of third-party code will generate findings that are not
about your project. Exclude these directories unless you intend to scan their
contents.

## Turn a tool off

Disable any scanner you don't want:

```yaml
tools:
  gitleaks: false
```

Unlisted tools stay enabled. `false`, `no`, `off`, and `0` all work.

Disabling a tool means its report file is never written, so it will not appear
in `tools_run` in the report.

## Set a default DAST target

Rather than passing `--url` every time, record it:

```yaml
target_url: "http://localhost:3000"
```

`warden` now runs ZAP whenever that app is up. A `--url` flag on the command
line takes precedence.

> Setting `tools.zap: false` clears the target URL after the CLI flag is applied.
> With `zap: false` in your config, even
> `warden --url http://localhost:3000` will skip ZAP. Check this setting if
> Warden skips a DAST scan unexpectedly.

## A worked example

A Python web service with a virtualenv, a test suite you don't want scanned, and
a local dev server:

```yaml
target_url: "http://localhost:8000"
exclude_dirs:
  - ".venv/"
  - "tests/"
tools:
  trivy: true
  semgrep: true
  gitleaks: true
  zap: true
```

Confirm it parsed as intended:

```bash
warden-config .
```

Then run the scan with the dev server up:

```bash
warden
```

## Use a config file from elsewhere

To share one config across repositories, point at it directly:

```bash
warden --config /path/to/shared.warden.yaml
```

The file is read from that path instead of `<project-root>/.warden.yaml`. The
project root itself is unchanged. Use `--project-root` to scan somewhere else:

```bash
warden --project-root /path/to/project --config /path/to/shared.warden.yaml
```

## Parser limitations

`.warden.yaml` is read by a small hand-written parser, not a YAML library. It
handles top-level scalars, a `-` list under `exclude_dirs`, a one-level mapping
under `tools`, and `#` comments. It ignores unsupported YAML syntax, including
anchors, nested mappings, and inline `[a, b]` collections.

This is why `warden-config .` is the reliable way to check your work. See the
[format notes](../reference/configuration.md#the-config-file-format-is-a-yaml-subset)
for the full list of what is and isn't supported.
