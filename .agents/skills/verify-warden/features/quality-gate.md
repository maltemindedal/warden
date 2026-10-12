# Pre-PR quality gate

## Sub-features

- `uv lock --check`, `ruff format --check`, `ruff check`, `ty check`, `pytest`, the order CI's `quality` job uses.

## How to get to it (user POV)

A contributor runs the gate in `AGENTS.md` before opening a PR.

## Driving it with verify.sh

`verify.sh test`. Each step must exit 0; the pytest summary line is printed
(on Linux expect exactly 1 skip, as `AGENTS.md` says).

## Gotchas

- A plain `uv run` relocks silently; the script uses `--no-sync` after `doctor` and checks the lock with `uv lock --check`.
