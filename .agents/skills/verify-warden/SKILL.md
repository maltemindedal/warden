---
name: verify-warden
description: Verify Warden, the Trivy/Semgrep/Gitleaks/ZAP security gate CLI, by running its pre-PR gate and driving `warden --project-root` on throwaway vulnerable and clean projects. Use after changing src/, tests, the lockfile or packaging, or when you need evidence that the gate still fails and passes when it should.
---

# verify-warden

Warden's surface is a short-lived CLI (`warden`, plus `warden-config` and
`warden-aggregate`) and the composite `action.yml`/Docker image that wrap it.
There is no server to keep alive: launch means `uv sync --locked`, and each
drive is one `warden` process on a fixture directory this skill creates.

## Launch

```bash
.agents/skills/verify-warden/scripts/verify.sh doctor
```

`doctor` runs `uv sync --locked` and checks Python >= 3.11. Ready means the
sync exited 0. It also reports which of semgrep, trivy, gitleaks and docker are
present: `uv sync` installs Semgrep; Trivy, Gitleaks and Docker usually are not.

## Doctor

`verify.sh doctor` is read-only apart from syncing `.venv`. Run it first
whenever a result looks odd. `all` stops if doctor fails.

## Drive

```bash
.agents/skills/verify-warden/scripts/verify.sh test     # CI quality job: lock, format, lint, ty, pytest
.agents/skills/verify-warden/scripts/verify.sh cli      # warden on a vulnerable and a clean project
.agents/skills/verify-warden/scripts/verify.sh image    # CI scan job (Docker); SKIP without Docker
.agents/skills/verify-warden/scripts/verify.sh all      # doctor, test, cli, image, cleanup
```

`cli` writes `fixtures/vulnerable/app.py` (`subprocess.call(input(), shell=True)`)
and `fixtures/clean/app.py` under the artifacts dir, then asserts the vulnerable
one exits 1, prints `AUDIT FAILED` and writes a `security_audit.json` with a High
or Critical finding, and the clean one exits 0. Semgrep fetches its rules over
the network, so `cli` needs network.

`RESULT: PASS` means every check passed. `RESULT: PASS with SKIP` means
something (today: the Docker image) was not exercised; say so in the PR.

## Evidence

Every step leaves `<name>.cmd`, `.stdout`, `.stderr` and `.exit` under
`/tmp/warden-verify/<run-id>/` (override with `VERIFY_RUN` or
`VERIFY_ARTIFACTS`). Fixture projects and their `security_audit.json` and
`.security_reports/` stay there too. Quote the `RESULT:` line, the pytest
summary and the finding counts, not a paraphrase.

Proof standard: drive the real `warden` entry point on real files. Without
Trivy and Gitleaks Warden prints warnings and still passes, so the vulnerable
fixture relies on Semgrep; a Trivy or Gitleaks change needs `image` (or those
tools on PATH) to be verified.

## Cleanup

`verify.sh cleanup` starts nothing long-lived and deletes nothing: evidence
stays in the artifacts dir. Remove old runs by hand with
`rm -rf /tmp/warden-verify/<run-id>`.

## Feature map

See [features/README.md](features/README.md).
