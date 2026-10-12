#!/usr/bin/env bash
# Drive Warden the way a contributor and a CI user do, and keep the evidence.
# Usage: verify.sh <doctor|test|cli|image|cleanup|all>
set -uo pipefail

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
RUN_ID="${VERIFY_RUN:-$(date +%Y%m%d-%H%M%S)}"
ART="${VERIFY_ARTIFACTS:-/tmp/warden-verify/$RUN_ID}"
mkdir -p "$ART"
cd "$ROOT" || exit 1

# run <name> <cmd...>: records command, stdout, stderr and exit code under $ART/<name>.*
run() {
  local name="$1"; shift
  printf '%q ' "$@" > "$ART/$name.cmd"; echo >> "$ART/$name.cmd"
  "$@" > "$ART/$name.stdout" 2> "$ART/$name.stderr"
  local rc=$?
  echo "$rc" > "$ART/$name.exit"
  echo "[$name] exit=$rc  ($ART/$name.*)"
  return "$rc"
}

expect() {
  local desc="$1" file="$2" pattern="$3"
  if grep -E -- "$pattern" "$file" >/dev/null; then echo "  PASS $desc"; else echo "  FAIL $desc (no /$pattern/ in $file)"; FAILED=1; fi
}

# gate <name> <cmd...>: one pre-PR gate step that must exit 0
gate() {
  local name="$1"; shift
  if run "$name" "$@"; then echo "  PASS $name"; else echo "  FAIL $name (see $ART/$name.stdout/.stderr)"; FAILED=1; fi
}

FAILED=0
SKIPPED=0

doctor_common() {
  echo "artifacts: $ART"
  echo "repo: $ROOT @ $(git rev-parse --short HEAD) ($(git rev-parse --abbrev-ref HEAD))"
  command -v uv >/dev/null || { echo "  FAIL uv not on PATH (https://docs.astral.sh/uv/)"; return 1; }
  echo "  PASS uv $(uv --version | cut -d' ' -f2)"
}

result() {
  if [ "$FAILED" != 0 ]; then echo "RESULT: FAIL ($1)"; elif [ "$SKIPPED" != 0 ]; then echo "RESULT: PASS with SKIP ($1): skipped features are unverified"; else echo "RESULT: PASS ($1)"; fi
  exit "$FAILED"
}

doctor() {
  doctor_common || return 1
  run sync uv sync --locked || { echo "  FAIL uv sync --locked (stale uv.lock?)"; return 1; }
  local pv; pv="$(uv run --no-sync python -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  python3 - "$pv" <<'PY' && echo "  PASS python $pv >= 3.11" || { echo "  FAIL python $pv < 3.11"; return 1; }
import sys
sys.exit(0 if tuple(map(int, sys.argv[1].split("."))) >= (3, 11) else 1)
PY
  for t in semgrep trivy gitleaks docker; do
    if command -v "$t" >/dev/null || { [ "$t" = semgrep ] && [ -x .venv/bin/semgrep ]; }; then echo "  info $t present"; else echo "  info $t absent"; fi
  done
}

# CI's quality job in order, with `uv lock --check` standing in for UV_LOCKED=1.
test_gate() {
  gate lock uv lock --check
  gate format uv run --no-sync ruff format --check .
  gate lint uv run --no-sync ruff check .
  gate ty uv run --no-sync ty check
  gate pytest uv run --no-sync pytest -q
  local line; line="$(grep -E '[0-9]+ passed' "$ART/pytest.stdout" | tail -1)"
  echo "  pytest: ${line:-no summary line}"
  if grep -E '[0-9]+ (failed|error)' "$ART/pytest.stdout" >/dev/null; then echo "  FAIL pytest summary reports failures"; FAILED=1; fi
}

# The real user path: `warden --project-root <dir>` on a throwaway project.
# Semgrep must be installed (uv sync does) and fetches its rules over the network.
cli() {
  run cli-help uv run --no-sync warden --help
  expect "--help exits 0" "$ART/cli-help.exit" '^0$'
  expect "--help prints usage" "$ART/cli-help.stdout" '^usage: warden '

  local bad="$ART/fixtures/vulnerable" ok="$ART/fixtures/clean"
  rm -rf "$bad" "$ok"; mkdir -p "$bad" "$ok"
  printf 'import subprocess\n\nsubprocess.call(input(), shell=True)\n' > "$bad/app.py"
  printf 'def add(a, b):\n    return a + b\n' > "$ok/app.py"

  run cli-vulnerable uv run --no-sync warden --project-root "$bad"
  expect "vulnerable project fails the gate (exit 1)" "$ART/cli-vulnerable.exit" '^1$'
  expect "vulnerable project prints AUDIT FAILED" "$ART/cli-vulnerable.stdout" 'AUDIT FAILED'
  if python3 - "$bad/security_audit.json" > "$ART/cli-vulnerable.report" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
high = [f for f in d["findings"] if str(f.get("severity", "")).lower() in ("high", "critical")]
print(len(d["findings"]), "findings,", len(high), "high/critical")
sys.exit(0 if high else 1)
PY
  then echo "  PASS security_audit.json written with a High finding ($(cat "$ART/cli-vulnerable.report"))"
  else echo "  FAIL security_audit.json missing or has no High/Critical finding"; FAILED=1; fi

  run cli-clean uv run --no-sync warden --project-root "$ok"
  expect "clean project passes the gate (exit 0)" "$ART/cli-clean.exit" '^0$'
  expect "clean project wrote its report" "$ok/security_audit.json" '"findings"'
}

# CI's scan job: build the image and self-scan. Needs Docker and network.
image() {
  if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
    echo "  SKIP image: no usable Docker here, so the Dockerfile build and CI's self-scan are unverified"
    echo "skipped: no docker" > "$ART/image.skip"; SKIPPED=1; return
  fi
  gate image-build docker build -t warden:verify .
  gate image-selfscan docker run --rm --user "$(id -u):$(id -g)" -v "$ROOT:/src" warden:verify
}

cleanup() {
  # Nothing long-lived is started. The fixtures stay as evidence; only scratch goes.
  echo "cleanup done; evidence kept in $ART"
}

case "${1:-}" in
  doctor) doctor || FAILED=1 ;;
  test) test_gate ;;
  cli) cli ;;
  image) image ;;
  cleanup) cleanup ;;
  all) if doctor; then test_gate; cli; image; else FAILED=1; echo "  doctor failed: not driving this checkout"; fi; cleanup ;;
  *) sed -n '2,3p' "$0"; exit 2 ;;
esac
result "$1"
