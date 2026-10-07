# AGENTS.md

Warden runs Trivy, Semgrep, Gitleaks and optional OWASP ZAP over a project, merges their JSON into `security_audit.json`, and exits 1 on any Critical or High finding. A change usually protects two invariants: the gate never passes when it should fail, and the scanned project is hostile input.

## Commands

- Install as CI does: `uv sync --locked`
- Pre-PR gate, CI's `quality` job in order. `uv lock --check` stands in for CI's `UV_LOCKED=1`, which fails on a `uv.lock` that drifted from `pyproject.toml` where a local `uv run` relocks silently:

  ```bash
  uv lock --check && uv run ruff format --check . && uv run ruff check . && uv run ty check && uv run pytest
  ```

- One test: `uv run pytest tests/test_scanners.py::test_registry_holds_the_documented_scanners_in_report_order`, or by keyword: `uv run pytest -k gitleaks`
- Linux replay of the gate (Docker, about 25 s, expect exactly 1 skip). Off Linux, `tests/test_action.py` and the `sha256sum` tests in `tests/test_install.py` skip while CI runs them, so run this after touching `action.yml` or `install.sh`:

  ```bash
  docker run --rm -v "$PWD:/src:ro" -e UV_LOCKED=1 ghcr.io/astral-sh/uv:python3.11-trixie-slim bash -c 'mkdir /w && tar -C /src --exclude=./.venv -cf - . | tar -C /w -xf - && cd /w && uv sync --locked -q && uv run ruff format --check . && uv run ruff check . && uv run ty check && uv run pytest -q'
  ```

- CI's `scan` job, the self-scan (Docker and network: the build downloads Trivy and Gitleaks, Semgrep fetches its rules). It must exit 0; its reports land in the git-ignored `security_audit.json` and `.security_reports/`:

  ```bash
  docker build -t warden:local . && docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" warden:local
  ```

## Conventions

Commits and PRs:

- Subjects follow Conventional Commits, `type(scope): lower-case imperative summary` (`fix`, `feat`, `docs`, `refactor`, `perf`, `build`, `ci`, `chore(deps)`). PRs are squash-merged, so the PR title becomes the subject on `main`.
- The body, wrapped near 72 columns, says why, which upstream behaviour the change relies on, and which alternatives were rejected. The repo has no changelog, so spell out every behaviour change there. A fix's body opens with `BUG FIX.` or `SECURITY FIX (<severity>).` and shows the broken behaviour; `git show f5388bc` is the model, with a before/after run of the real tool.
- State only what you ran or read, with numbers (test counts, findings before and after). PR #9 rewrote 13 commit messages that overstated something.
- PR bodies follow `.github/pull_request_template.md`. When a check fails for reasons outside the change (the "Code scanning AI findings" check fails on account quota), explain it in a PR comment with the job-log evidence and leave the code as it is.

Code:

- Hostile input includes what looks impossible: symlinks, FIFOs, NUL bytes, huge values. At a path Warden owns, replace or skip a symlink or FIFO rather than following it. Escape project text with `_text.shown` before printing it, keep parsing linear-time, turn a scanner problem into a warning rather than a traceback, and when in doubt keep the finding: dropping one is never the safe way to be wrong.
- Every scanner fact lives in its `Scanner` record in the single `SCANNERS` registry in `_scanners.py`; grow a field rather than writing a second list of tools. A new scanner also needs its parser, command builder, a fixture in `tests/fixtures/`, the hard-coded order in `tests/test_scanners.py`, the `Dockerfile`, both installers, the table in `README.md` and the reference docs.
- New behaviour goes behind a CLI flag, not a `.warden.yaml` key: an older Warden rejects an unknown flag but silently ignores an unknown key. The Critical/High threshold stays fixed, and runtime dependencies stay `rich` and `semgrep` (which is why `config.py` parses a YAML subset by hand).

Tests:

- Inject command execution through `cli.main(argv, runner=RecordingRunner(...))` from `tests/fakes.py` instead of patching `subprocess` or module internals; the suite has no `unittest.mock`. Use `symlink_or_skip` and `skip_unless_executable` from the same file for platform gaps.
- Name each test as a full sentence, give it a docstring saying which regression it guards or why, and work in `tmp_path`.
- Mutation-check a regression test: revert the fix, confirm the test fails, and say so in the PR.

Docs mirror the code exactly; change them in the same commit:

- `cli.py` usage, flags and exit codes: `docs/reference/cli.md`
- `_parsers.py` severity maps: `docs/reference/report-format.md`
- `config.py`: `docs/reference/configuration.md`
- `tests/fixtures/`: the sample output in `README.md`
- A new doc gets a row in `docs/README.md`. Run every command you document.

## Gotchas

- Never pass `--url` to `warden`, or the workflow's `url` input: ZAP runs an active attack scan against that host. Exercise DAST code through `RecordingRunner` tests instead.
- Green unit tests do not prove a scanner flag exists, because `RecordingRunner` only records the argv Warden built. A nonexistent Gitleaks `--exclude-path` passed the tests while silently disabling secret scanning (`f5388bc`). After changing a command builder, check each flag against the pinned tool in the image, for example `docker run --rm --entrypoint gitleaks warden:local detect --help` (likewise `trivy fs --help`, `semgrep scan --help`).
- `uv sync` installs the real Semgrep, but Trivy and Gitleaks are usually absent on the host, so `uv run warden <dir>` prints PASS and exits 0 with only warnings. Add `--strict` (exit 3) or run the image to see a real result.
- Some tests read files as text, so their shape is load-bearing: `test_action.py` slices the `Run Warden` step of `action.yml` from `run: |` to the next `    - name:`, and `test_install.py` extracts `install.sh` functions up to a closing `}` line and regex-matches the version and SHA-256 lines.
- Pins move together, and tests enforce it. uv: the `Dockerfile` `FROM` line, `UV_VERSION` in `install.sh`, `$UvVersion` in `install.ps1`. Trivy and Gitleaks: version plus amd64 and arm64 SHA-256 in the `Dockerfile` and `install.sh`, with digests from each release's checksums file. Dependabot's uv PR changes only the `Dockerfile`, so bump both installers in that same PR.
- Relock one package at a time: `uv lock --upgrade-package <pkg>`. A blanket `uv lock --upgrade` moves `mcp` past Semgrep's own `mcp==` pin (the `override-dependencies` entry allows it), and mcp 2.x breaks Semgrep at import; `uv lock --upgrade-package mcp==<semgrep's pin>` restores it.
- The self-scan goes red with no code change when new advisories match `uv.lock`. Fix it with a targeted relock of the affected package rather than a suppression, and turn down a Dependabot PR that downgrades Semgrep to reach a fix.
- Release-age cooldowns were added in #9, cut in #18 because they blocked a security fix, and removed in #22: keep them out of `pyproject.toml`, the installers and `dependabot.yml`, and take a blocked-fix trade-off to the owner. The self-scan's Medium "missing dependency cooldown" findings follow from that decision and do not fail the gate.
- The Trivy download in `docker build` can time out (curl exit 28): rerun the build. BuildKit's `SecretsUsedInArgOrEnv` warning on `GIT_CONFIG_KEY_0` is a false positive; that variable turns off the scanned repo's `core.fsmonitor`.
- `install.sh`, `bin/warden` and `bin/warden.sh` stay mode `100755` (lost once, restored in `853f891`).
- No CI runs Windows: `install.ps1`, `bin/warden.ps1`, `bin/warden.cmd` and the non-POSIX branches in `tooling.py` are unverified, so say so in the PR when you change them.
- Semgrep 1.179 emits `MEDIUM`-style severities while `report-format.md` and `tests/fixtures/semgrep.json` still show `ERROR` and `WARNING`; `SEVERITY_ALIASES` maps both vocabularies, so keep both.
- `ruff format` skips `*.md` on purpose: ruff 0.16 formats Markdown, and `.agents/skills/**` is vendored and hash-locked in `skills-lock.json`. Edit Markdown by hand. The vendored `dataverse-python-production-code` skill targets an unrelated SDK and does not apply here.
- No check is required on `main`, so `gh pr merge` succeeds with red checks: confirm `quality` and `scan` are green first.

## Docs

- Before a structural change or a new module: `docs/architecture/overview.md` (module roles, one-way dependencies, why ZAP runs as a sibling container).
- Before changing what the action scans in a pull request: `docs/guides/ci-github-actions.md#gating-pull-requests`.
- Before touching the `Dockerfile`, `--user` or the Docker socket mount: `docs/guides/running-with-docker.md`.
- To judge whether a change touches the threat model: the "Scope" list in `SECURITY.md`.
- Before a dependency or pin bump: "Dependencies" in `CONTRIBUTING.md` and the header comment of `.github/dependabot.yml`.
