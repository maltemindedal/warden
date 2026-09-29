# Contributing

## Development environment

Warden uses [uv](https://docs.astral.sh/uv/) for dependency and environment
management. You need uv 0.9.17 or newer, because the dependency cooldown below
is a relative duration that older releases cannot parse. From a clone:

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
| `pytest` | `[tool.pytest.ini_options]` | Tests live in `tests/`, with `src` on the path. |

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

Two constraints in `[tool.uv]` are deliberate and will affect you:

- **`exclude-newer = "7 days"`** sets a dependency cooldown. Distributions
  published in the last seven days are not resolvable, so a new release
  cannot be pulled in silently. If a lock fails on a very recent version, this is
  why; wait for it to age out rather than removing the setting. A relative
  duration needs uv 0.9.17 or newer; older releases cannot parse it, skip the
  cooldown, re-resolve, and `uv sync --locked` fails.
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

## CI

`.github/workflows/ci.yml` runs on pushes to `main`, on pull requests, and on
manual dispatch:

- `quality` runs the four checks above on Ubuntu with Python 3.11, installing
  with `uv sync --locked` and `UV_LOCKED=1`, so it fails on a stale `uv.lock`.
- `scan` runs Warden against this repository after `quality` passes.

The `scan` job means the project scans itself: a change that introduces a High
or Critical finding will fail CI, including findings in workflow files or the
`Dockerfile`. See [Using Warden in CI](guides/ci-github-actions.md).

Actions are pinned to commit SHAs with the version in a trailing comment. When
updating one, update both.

## Project conventions

- Public functions are typed; internal helpers are prefixed with `_`.
- Data structures are frozen dataclasses or `TypedDict`s in `_models.py`, kept
  free of logic. A record that needs a derived accessor lives beside the code
  that uses it instead. `Scanner` lives in `_scanners.py`, and `Verdict` lives
  in `_summary.py`.
- `tooling.py` is the only module that runs subprocesses. A scanner's command
  line is built by its `Scanner` record; `tooling.run_scanner` is what runs it.
- Adding a scanner means adding a `Scanner` record, its parser, and its command
  builder. If you find yourself editing a second list of tools, the registry
  should have grown a field instead.
- `from __future__ import annotations` at the top of every module.

## Documentation

Documentation lives in `docs/`, organised by purpose: tutorial, how-to guides,
reference, explanation. When adding a document, add it to the table in
[`docs/README.md`](README.md). Readers will not find an unlisted document from
the documentation index.

Verify any command you document by running it.
