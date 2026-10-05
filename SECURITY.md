# Security policy

## Supported versions

Warden has no releases yet. Fixes land on `main`, and only the latest commit on
`main` is supported. If you pin the action to a commit SHA, move the pin forward
to pick up a fix.

## Reporting a vulnerability

Do not open a public issue, pull request, or discussion for a vulnerability.
Report it privately through GitHub instead:
[report a vulnerability](https://github.com/maltemindedal/warden/security/advisories/new).

Include:

- the affected part: the CLI, the GitHub Action, the Docker image, or an installer;
- the commit you tested;
- steps to reproduce, ideally a minimal project that triggers it;
- what an attacker gains.

## Scope

In scope is Warden's own code and packaging: the `warden`, `warden-config`, and
`warden-aggregate` commands, `action.yml`, the `Dockerfile`, `install.sh`,
`install.ps1`, and the wrappers in `bin/`. For example:

- a scanned project that makes Warden write, delete, or follow a symlink outside
  the paths it owns (the scanned project is not trusted; see the
  [CLI reference](docs/reference/cli.md#behaviour));
- a finding that Warden drops, or rates below the
  [severity mapping](docs/reference/report-format.md#severity-normalisation), so
  the run passes when it should fail;
- a secret from the scanned tree reaching the action's uploaded artifact;
- an installer or the image accepting a scanner binary that does not match its
  pinned checksum or digest.

Out of scope:

- Vulnerabilities in Trivy, Semgrep, Gitleaks, or OWASP ZAP themselves. Report
  those to the project concerned.
- A project's `.warden.yaml`, the scanners' own config files, and inline
  suppressions deciding what is scanned. These are trusted by design; see
  [Gating pull requests](docs/guides/ci-github-actions.md#gating-pull-requests)
  for how to keep them out of a pull request's reach.
- The access a container gets when you mount the Docker socket into it, which is
  documented in
  [Running with Docker](docs/guides/running-with-docker.md#security-note-on-the-socket-mount).
