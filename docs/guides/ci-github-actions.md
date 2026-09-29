# Using Warden in CI

Warden exits non-zero when it finds Critical or High issues, which is all most
CI systems need to turn a build red. This guide covers the bundled GitHub
Actions workflow and the reusable action.

## How the gate works

GitHub Actions decides pass or fail from the process exit code:

| Exit code | Result |
| --- | --- |
| `0` | Job passes |
| non-zero | Job fails |

Warden exits `1` when any Critical or High finding is present. Medium and below
are reported but do not fail the job. See
[Exit codes](../reference/cli.md#exit-codes).

**By default a scanner that fails to run does not fail the build.** Warden prints
a warning and continues. Treat a green build as "no High or Critical findings *in
the reports that were produced*", and check the log or `tools_run` in the report
if you need certainty that every scanner ran. To get that certainty from the gate
itself, pass `--strict` (the action's `strict` input): the run then exits `3` when
a scanner that ran left no usable report, or nothing ran.

## The workflow in this repository

`.github/workflows/ci.yml` runs on pushes to `main`, on pull requests, and on
manual dispatch. It has two jobs:

- `quality` runs formatting, linting, type checking, and tests. See
  [Contributing](../contributing.md).
- `scan` runs Warden on this repository via the local action after `quality`
  passes.

To run a DAST scan, trigger the workflow manually from the Actions tab and
supply the `url` input. On pushes and pull requests that input is empty, so ZAP
is skipped.

Both jobs declare `permissions: contents: read`, restricting the `GITHUB_TOKEN`
to the minimum the scan needs.

## Using Warden from another repository

This repository ships a composite action at `action.yml`. Add a step:

```yaml
- name: Warden scan
  uses: maltemindedal/warden@main
  with:
    upload-artifact: true
    artifact-name: warden-report
```

> **This repository has no tags or releases.** Pinning to `@v1` will fail
> because that ref does not exist. Until a release is published, reference
> `@main` or a specific commit SHA. A SHA is safer because a branch ref can
> change, and this action executes a Docker build.

To enable DAST, add a `url`:

```yaml
- name: Warden scan
  uses: maltemindedal/warden@main
  with:
    url: http://host.docker.internal:3000
    upload-artifact: true
```

Start the target application in an earlier step; the action does not start it
for you. A `target_url` in the repository's own `.warden.yaml` is **not** used by the
action (it could come from a pull request, and it starts an active scan): DAST is
turned on by the `url` input, or by a `target_url` in a file given through the
[`config` input](#gating-pull-requests), which the workflow's author chooses.

### Action inputs

| Input | Default | Effect |
| --- | --- | --- |
| `url` | none | DAST target. Omit to skip ZAP. |
| `config` | none | Path to a `.warden.yaml` **outside the checkout**, used instead of the repository's own. See [Gating pull requests](#gating-pull-requests). |
| `strict` | `"false"` | Pass `--strict`: exit `3` when a scanner that ran left no usable report. Must be `true` or `false` (any case); anything else fails the step, so a misspelling cannot switch the check off. |
| `upload-artifact` | `"true"` | Whether to upload the reports as a build artifact. |
| `artifact-name` | `"warden-report"` | Name of the uploaded artifact. |

The action has no outputs. Consume the result via the step's exit status, or by
downloading the artifact.

### Gating pull requests

**Warden trusts the files in the tree it scans to say what to scan.** That is right
for a developer scanning their own project, and wrong for a gate on someone else's
pull request: the change under review can switch the gate off. Any of these, added or
edited in the pull request, can turn a failing scan green:

- `.warden.yaml`: `tools: <name>: false`, and `exclude_dirs`;
- the scanners' own files: `trivy.yaml`, `.trivyignore`, `.gitleaks.toml`,
  `.gitleaksignore`, `.semgrepignore`;
- inline suppressions (`gitleaks:allow`, `# nosemgrep`), and Semgrep's silent skip of
  files over 1 MB.

The `config` input covers the first. Point it at a file that does not come from the
change, and the workspace's own `.warden.yaml` is not read at all (the action refuses a
path inside the checkout, symlinks resolved, and one that is not a file):

```yaml
- name: Trusted Warden settings
  run: |
    cat > "$RUNNER_TEMP/warden.yaml" <<'EOF'
    exclude_dirs:
      - node_modules/
    EOF
- uses: maltemindedal/warden@<commit sha>
  with:
    config: ${{ runner.temp }}/warden.yaml
    strict: true
```

It only helps if the workflow that names it is not itself taken from the change: a
pull request can edit a `pull_request` workflow, including the step that writes the
trusted file or the `config:` line that uses it, so run the gate from a workflow the
change cannot alter (a `pull_request_target` or base-branch workflow, a required
workflow or ruleset) or require review of changes under `.github/`. A `target_url` in a
trusted file is honored, so it can also start a DAST scan.

It does not cover the scanners' own files or inline suppressions: Warden runs Trivy,
Semgrep and Gitleaks over the checkout as they find it, so a reviewer of a pull request
has to read changes to those files as changes to the gate. Pair it with `strict`, so a
scanner that the change broke fails the run instead of passing it.

### What the action does

1. Builds the bundled `Dockerfile` as `warden:action`.
2. Runs it against `GITHUB_WORKSPACE`, mounted at `/src`, as the runner's own
   user ID, with the Docker socket mounted for the optional ZAP scan.
3. Uploads `security_audit.json` as an artifact (`.security_reports/**` is listed
   too, but see below). The `if: always()` condition preserves the report from a
   failing scan.

Because step 1 builds the image on every run, expect roughly a minute of build
time before scanning starts.

The artifact contains `security_audit.json`, in which Gitleaks findings are
redacted. The action also lists `.security_reports/**`, but that directory starts
with a dot and `actions/upload-artifact` skips hidden files unless it is given
`include-hidden-files: true`, so the raw scanner reports are not uploaded. The action
deliberately does not set that input: it would publish every raw report on every
consumer's next run. They
stay on the runner in `.security_reports/`, where `gitleaks.json` shows where each
secret is but not the secret itself (Gitleaks runs with `--redact`). Keep the
artifact private anyway: it names every finding.

## Other CI systems

Nothing in Warden is GitHub-specific. Any runner that can build a container and
read an exit code will work:

```bash
docker build -t warden:ci .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" warden:ci
```

The non-zero exit fails the job. For DAST, add the socket mount and
`WARDEN_HOST_WORKSPACE` as described in
[Running with Docker](running-with-docker.md#report-paths-across-containers).

The protection the action gives a `target_url` does not travel with this recipe. It
keys on `GITHUB_WORKSPACE`, which the action passes into the container and a plain
`docker run` does not, so here a `target_url` in the repository's own `.warden.yaml`
is honored, and on a pull request it can start an active ZAP scan of an address the
change chose. Mount a `.warden.yaml` from outside the change and pass it with
`--config` (or set `tools: zap: false` in it), so the repository's own file is not
read.
