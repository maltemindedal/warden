# Contributing

Everyone taking part in this project is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Development environment

Warden uses [uv](https://docs.astral.sh/uv/) for dependency and environment
management. From a clone:

```bash
uv sync --python 3.11
```

This creates a virtual environment with the runtime and development
dependencies. To reproduce CI exactly, install from the lockfile without
updating it; this fails if `uv.lock` has drifted from `pyproject.toml`:

```bash
uv sync --locked
```

Run the CLI from the checkout without installing it:

```bash
uv run warden --help
```

## The quality gate

Four checks, each run by CI in this order. Run them locally before pushing:

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest
```

To apply formatting rather than only check it:

```bash
uv run ruff format .
```

### What each check enforces

| Check | Configured in | Notes |
| --- | --- | --- |
| `ruff format` | `[tool.ruff.format]` | 100-character lines, double quotes, spaces. |
| `ruff check` | `[tool.ruff.lint]` | Rule sets `B`, `BLE`, `E`, `F`, `I`, `PGH`, `S`, `UP`, `W`. Import sorting is included via `I`; `S` is the bandit security rules (asserts and list-form `subprocess` calls are allowed in tests). |
| `ty check` | `[tool.ty.*]` | **All rules as errors.** Targets Python 3.11 across `src` and `tests`. |
| `pytest` | `[tool.pytest.ini_options]` | Tests live in `tests/`, with `src` on the path. Unknown markers and config keys, any warning, and an `xfail` that passes are all errors. |

ty runs with every rule promoted to an error (`[tool.ty.rules] all = "error"`),
so new code needs complete type annotations, and an ignore comment that is no
longer needed is itself an error.

## Tests

```bash
uv run pytest
```

Tests live in `tests/`, with static tool output in `tests/fixtures/`. The
fixtures are small hand-written samples of each scanner's JSON, used to exercise
parsing and severity normalisation without running the real scanners. Command
execution is injected rather than patched: tests pass the recording
`CommandRunner` in `tests/fakes.py` and assert on the command line that was
built, so the suite runs without Trivy, Semgrep, Gitleaks, or Docker installed.

Warnings are errors here. If a dependency warning you cannot fix fails the run,
silence just that warning with a narrow `filterwarnings` ignore entry in
`pyproject.toml` and a comment saying why.

When adding support for a new field or tool, add a fixture. Using fixtures keeps
the suite fast and deterministic.

`pytest-cov` is available for coverage runs:

```bash
uv run pytest --cov=warden
```

## Dependencies

Runtime dependencies are declared in `[project.dependencies]`; development tools
in `[dependency-groups]`. Add one with:

```bash
uv add <package>
uv add --dev <package>
```

One constraint in `[tool.uv]` is deliberate and will affect you:

- **`override-dependencies = ["mcp>=1.28.1,<2"]`** overrides the
  `mcp==1.23.3` pin of Semgrep 1.146 to 1.172 (older releases pin older mcp
  releases or none), which carries known advisories. Warden uses Semgrep's CLI scanner and never its MCP server, so the
  pin is overridden to a patched release. The cap at 2 is needed because mcp 2.x
  renamed the modules Semgrep imports, which makes `semgrep` fail at startup.
  From Semgrep 1.173 the pin is `mcp==1.29.0` (patched), so with such a Semgrep
  locked the override only serves as the cap, and a relock can move mcp past that
  pin: use `uv lock --upgrade-package mcp==<the pin>` to keep them in step.

Commit `uv.lock` alongside any change to `pyproject.toml` that affects resolution:
dependency bounds, `requires-python`, the project version or `[tool.uv]`
settings. Run `uv lock` after editing it; CI and the image build install with
`--locked`, so a stale lock fails them.

`.github/dependabot.yml` opens pull requests for the `uv` lock, the pinned GitHub
Actions and the Dockerfile's `FROM` lines (the uv stage and the Python base, held
to 3.11). No cooldown is configured, so Dependabot's own default delay for version
updates applies; security updates are never delayed. There is one exception: for
the Dockerfile Dependabot applies that delay only to Docker Hub images, so a pull
request for the uv stage (`ghcr.io/astral-sh/uv`) appears as soon as the release
does. Check the release's age before merging it, and change `UV_VERSION` in
`install.sh` and `$UvVersion` in `install.ps1` to the same version in that pull
request (a test fails until all three agree).

The Trivy and Gitleaks versions and digests are Dockerfile build args that
Dependabot cannot read: change them by hand, in the `Dockerfile` and in `install.sh`
together (a test fails if the two disagree).

## CI

`.github/workflows/ci.yml` runs on pushes to `main`, on pull requests, and on
manual dispatch:

- `quality` runs the four checks above on Ubuntu with Python 3.11, installing
  with `uv sync --locked` and `UV_LOCKED=1`, so it fails on a stale `uv.lock`.
- `scan` runs Warden against this repository after `quality` passes.

The `scan` job means the project scans itself: a change that introduces a High
or Critical finding will fail CI, including findings in workflow files or the
`Dockerfile`. See [Using Warden in CI](docs/guides/ci-github-actions.md).

Actions are pinned to commit SHAs with the version in a trailing comment. When
updating one, update both.

## Project conventions

- Public functions are typed; internal helpers are prefixed with `_`.
- Data structures are frozen dataclasses or `TypedDict`s in `_models.py`, kept
  free of logic. A record that needs a derived accessor lives beside the code
  that uses it instead. `Scanner` lives in `_scanners.py`, `Verdict` in
  `_summary.py`, and `ToolRunResult` in `tooling.py`.
- `tooling.py` is the only module that runs subprocesses. A scanner's command
  line is built by its `Scanner` record; `tooling.run_scanner` is what runs it.
- Adding a scanner means adding a `Scanner` record, its parser, and its command
  builder. If you find yourself editing a second list of tools, the registry
  should have grown a field instead.
- `from __future__ import annotations` at the top of every module.

## Documentation

Documentation lives in `docs/`, organised by purpose: tutorial, how-to guides,
reference, explanation. When adding a document, add it to the table in
[`docs/README.md`](docs/README.md). Readers will not find an unlisted document from
the documentation index.

Verify any command you document by running it.
