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

**A scanner that fails to run does not fail the build.** Warden prints a warning
and continues. Treat a
green build as "no High or Critical findings *in the reports that were
produced*", and check the log or `tools_run` in the report if you need
certainty that every scanner ran.

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
for you. A `target_url` in the repository's own `.warden.yaml` is **not** used on a
runner (it could come from a pull request, and it starts an active scan): the
`url` input is the only way to turn DAST on.

### Action inputs

| Input | Default | Effect |
| --- | --- | --- |
| `url` | none | DAST target. Omit to skip ZAP. |
| `upload-artifact` | `"true"` | Whether to upload the reports as a build artifact. |
| `artifact-name` | `"warden-report"` | Name of the uploaded artifact. |

The action has no outputs. Consume the result via the step's exit status, or by
downloading the artifact.

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
`include-hidden-files: true`, so the raw scanner reports are not uploaded. They
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
