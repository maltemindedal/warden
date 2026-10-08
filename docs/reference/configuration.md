# Configuration reference

Warden is configured from three places, in increasing order of precedence:

1. Built-in defaults
2. `.warden.yaml` in the project root
3. Command-line flags

For task-oriented examples, see [Configuring scans](../guides/configuring-scans.md).

> **The project's own `.warden.yaml` is trusted input.** It, and the scanners' own
> files in the tree (`.trivyignore`, `.gitleaks.toml`, `.semgrepignore` and the
> like), decide what is scanned. For a pull request gate, keep the settings outside
> the change: see [Gating pull requests](../guides/ci-github-actions.md#gating-pull-requests).

## The config file format is a YAML subset

`.warden.yaml` is **not** parsed by a YAML library. Warden uses a small
hand-written parser that understands only the shapes documented here. This keeps
the tool dependency-free at the config layer, at the cost of rejecting most of
YAML.

What the parser supports:

- Top-level `key: value` scalars
- Exactly one level of nesting, under `exclude_dirs` (a `-` list) and `tools` (a
  mapping)
- `#` comments, including trailing comments. A `#` inside a quoted value is part of
  the value; outside quotes it starts a comment unless it is escaped with `\`
- Single or double quoted strings, which are the way to write a URL that contains
  a `#` (`target_url: "http://localhost:4200/#/login"`)

What it does **not** support: anchors, multi-line strings, nested mappings
deeper than one level, inline `[a, b]` or `{a: b}` collections, or documents
with `---` separators. Unrecognised top-level keys are parsed and then ignored.

A file that cannot be read or parsed is treated as empty, and so is the
project's own `.warden.yaml` when it is not a regular file (a named pipe, say).
A path given with `--config` is read as given. Warden falls back to defaults rather
than stopping, so a mistake never turns into an error, but it does turn into a
**warning** for what it can see: a file that cannot be read or does not exist
(`--config`), a line it does not understand (a list at the same indent as its key,
`---`, an indented line under nothing), an unknown top-level key or tool name, a
`tools:` value that is not true or false (`ture` counts as false, so the scanner is
disabled), and a `target_url`, `exclude_dirs` or `tools` of the wrong shape. Every
warning says the value is ignored or read as false; none changes what is resolved.
`warden` prints them after the `Target:` line, `warden-config` prints them to
stderr (its stdout stays JSON), and at most ten are shown, followed by a count of
the rest. The one notice that is never cut is the one about an ignored `target_url`
(below), and it is not shown when `tools.zap` is `false`, since no scan could follow.
An `exclude_dirs` entry that holds a NUL byte, which no command line can carry, is
dropped with a warning; the other entries and every scanner are unaffected. Verify with
`warden-config .` when in doubt.

## Keys

### `target_url`

| | |
| --- | --- |
| Type | string |
| Default | `""` |
| Alias | `url` |

DAST target for OWASP ZAP. When empty, ZAP is skipped. It must start with
lowercase `http://` or `https://`, have a host and hold only printable characters;
anything else is reported with a warning and ZAP is skipped.

`url` is accepted as an alias. If both are present, `target_url` wins.

```yaml
target_url: "http://localhost:3000"
```

Overridden by the `--url` flag.

**It is ignored when `GITHUB_WORKSPACE` is set.** GitHub Actions sets it on every
step and the bundled action passes it into the image, so under the action a
`target_url` in the project's own `.warden.yaml` is not used: that file can be
changed by whoever opens a pull request, and the URL starts an *active* scan.
Warden prints a warning (unless `tools.zap` is `false`); pass `--url` (or the
action's `url` input) to scan. A file given with `--config` is not affected. Where
`GITHUB_WORKSPACE` is not passed through, which includes any other CI system, the
project's `target_url` is used: see
[Other CI systems](../guides/ci-github-actions.md#other-ci-systems).

### `exclude_dirs`

| | |
| --- | --- |
| Type | list of strings |
| Default | `[]` |

Paths excluded from the three static scanners. Empty and whitespace-only entries
are dropped.

```yaml
exclude_dirs:
  - "tests/"
  - "vendor/"
```

Each value is applied to every static tool, but the tools interpret exclusions
differently:

| Tool | Applied as | Form |
| --- | --- | --- |
| Trivy | `--skip-dirs` | All values joined with commas into one flag |
| Semgrep | `--exclude` | One flag per value |
| Gitleaks | Findings dropped after the scan | One directory per value, relative to the project root |

Gitleaks has no flag for skipping paths, so it scans everything and Warden then
drops the findings under each listed directory from `gitleaks.json`. A value
matches that directory and everything below it, from the project root only:
`vendor` and `vendor/` exclude `vendor/lib.env` but not `sub/vendor/lib.env`, and
a glob such as `**/vendor` matches nothing. A `gitleaks.json` nested more than 100
levels deep is left as Gitleaks wrote it, with a warning, so nothing is dropped
from it.

Because the semantics differ per tool, a pattern that excludes cleanly in one
scanner may not in another. ZAP scans a URL rather than the filesystem, so
`exclude_dirs` does not affect it.

### `tools`

| | |
| --- | --- |
| Type | mapping of string to boolean |
| Default | all `true` |

Enables or disables individual scanners. Recognised keys are `trivy`,
`semgrep`, `gitleaks`, and `zap`. Any other key is ignored.

```yaml
tools:
  zap: true
  semgrep: true
  gitleaks: false
  trivy: true
```

Booleans are accepted in several forms:

| Value | Parsed as |
| --- | --- |
| `true`, `yes`, `on`, `1` | `true` |
| `false`, `no`, `off`, `0` | `false` |
| any other string | `false` |

Comparison is case-insensitive. Quoted values such as `"true"` are also
accepted.

## Interaction between `target_url` and `tools.zap`

`tools.zap: false` clears the resolved URL entirely. This happens **after** the
CLI flag is applied, so it overrides an explicit `--url`:

```console
$ warden-config . --cli-url "http://example.com"
{"url": "", "exclude_dirs": [...], "tools": {..., "zap": false}}
```

If you pass `--url` and ZAP is skipped anyway, check `tools.zap`.

## Full example

```yaml
target_url: "http://localhost:3000"
exclude_dirs:
  - "tests/"
  - "legacy/"
tools:
  zap: true
  semgrep: true
  gitleaks: false
  trivy: true
```

## Environment variables

Warden reads scanner selection and exclusions only from the config file and
flags. The environment variables below control where the ZAP container mounts
its output, and `GITHUB_WORKSPACE` also decides whether the project's own
`target_url` is used.

| Variable | Read by | Effect |
| --- | --- | --- |
| `WARDEN_HOST_REPORT_DIR` | ZAP stage | Absolute host path to mount as ZAP's working directory. Highest precedence. |
| `WARDEN_HOST_WORKSPACE` | ZAP stage | Host path to the project; `.security_reports` under it is mounted. |
| `GITHUB_WORKSPACE` | ZAP stage, config resolution | Same as above. Set automatically by GitHub Actions. Its presence also stops `target_url` in the project's `.warden.yaml` from being used. |

These exist because ZAP runs in a sibling container. When Warden is itself
running inside a container, the report path it sees is a container path, which
the Docker daemon cannot mount. These variables supply the *host* path instead.
They are consulted in the order listed; if none is set, the in-process report
directory path is used.

When running Warden directly on your machine, leave all three unset.

The Docker image also sets `HOME`, the `XDG_*` directories, `TRIVY_CACHE_DIR`,
and `SEMGREP_SETTINGS_FILE` to writable paths so the scanners work under an
arbitrary user ID. Those are internal to the image; see
[Running with Docker](../guides/running-with-docker.md#why-the---user-flag-is-required).

## Fixed values

Not configurable, but useful to know:

| Value | Setting |
| --- | --- |
| Failing severities | Critical and High |
| Report directory | `.security_reports/` in the project root |
| Aggregated report | `security_audit.json` in the project root |
| ZAP image | `ghcr.io/zaproxy/zaproxy:stable` |
| Semgrep rules | `--config=auto` (Semgrep's registry-selected rule set) |
| Gitleaks mode | `--no-git` (scans the working tree, not history) |

Note that Gitleaks runs with `--no-git`, so it inspects files as they are on
disk. **Secrets that were committed and later removed are not detected.**
