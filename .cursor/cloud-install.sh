#!/usr/bin/env bash
set -euo pipefail

pin() {
  local name="$1"
  sed -n "s/^[[:space:]]*${name}=\"\\([^\"]*\\)\"/\\1/p" install.sh | head -n 1
}

UV_VERSION="$(pin UV_VERSION)"
if [ -z "$UV_VERSION" ]; then
  echo "cloud-install: install.sh has no UV_VERSION" >&2
  exit 1
fi

current=""
if command -v uv >/dev/null 2>&1; then
  current="$(uv --version | awk '{print $2}')"
fi
if [ "$current" != "$UV_VERSION" ]; then
  curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" | UV_NO_MODIFY_PATH=1 sh
  sudo ln -sfn "${HOME}/.local/bin/uv" /usr/local/bin/uv
  if [ -x "${HOME}/.local/bin/uvx" ]; then
    sudo ln -sfn "${HOME}/.local/bin/uvx" /usr/local/bin/uvx
  fi
  hash -r
fi

uv python install 3.11
uv sync --locked

arch_arm="$(
  awk -v arch="$(uname -m)" '
    function names_arch(line, want, pat, n, i, parts) {
      if (line !~ /^[[:space:]]*[A-Za-z0-9_|]+\)[[:space:]]*$/) return 0
      pat = line
      gsub(/[[:space:]]/, "", pat)
      sub(/\)/, "", pat)
      n = split(pat, parts, "|")
      for (i = 1; i <= n; i++) if (parts[i] == want) return 1
      return 0
    }
    names_arch($0, arch) { emit = 1; next }
    emit && /^[[:space:]]*;;/ { exit }
    emit { print }
  ' install.sh
)"
if [ -z "$arch_arm" ]; then
  echo "cloud-install: install.sh has no scanner archive for $(uname -m)" >&2
  exit 1
fi

arm_pin() {
  local name="$1"
  printf '%s\n' "$arch_arm" | sed -n "s/^[[:space:]]*${name}=\"\\([^\"]*\\)\"/\\1/p" | head -n 1
}

require_pin() {
  local label="$1"
  local value="$2"
  if [ -z "$value" ]; then
    echo "cloud-install: install.sh has no ${label}" >&2
    exit 1
  fi
}

TRIVY_VERSION="$(pin TRIVY_VERSION)"
GITLEAKS_VERSION="$(pin GITLEAKS_VERSION)"
TRIVY_SHA256="$(arm_pin TRIVY_SHA256)"
GITLEAKS_SHA256="$(arm_pin GITLEAKS_SHA256)"
TRIVY_ARCH="$(arm_pin TRIVY_ARCH)"
GITLEAKS_ARCH="$(arm_pin GITLEAKS_ARCH)"
require_pin TRIVY_VERSION "$TRIVY_VERSION"
require_pin GITLEAKS_VERSION "$GITLEAKS_VERSION"
require_pin TRIVY_SHA256 "$TRIVY_SHA256"
require_pin GITLEAKS_SHA256 "$GITLEAKS_SHA256"
require_pin TRIVY_ARCH "$TRIVY_ARCH"
require_pin GITLEAKS_ARCH "$GITLEAKS_ARCH"

tool_version() {
  case "$1" in
    trivy) trivy --version | awk '/^Version:/{print $2; exit}' ;;
    gitleaks) gitleaks version | awk '{print $1; exit}' ;;
    *) return 1 ;;
  esac
}

install_released_bin() {
  local bin="$1"
  local version="$2"
  local url="$3"
  local sha="$4"
  if command -v "$bin" >/dev/null 2>&1 && [ "$(tool_version "$bin")" = "$version" ]; then
    return 0
  fi
  local archive
  archive="$(mktemp)"
  curl -fsSL "$url" -o "$archive"
  if ! echo "${sha}  ${archive}" | sha256sum -c -; then
    rm -f "$archive"
    exit 1
  fi
  sudo tar -xz --no-same-owner -C /usr/local/bin -f "$archive" "$bin"
  rm -f "$archive"
}

install_released_bin trivy "$TRIVY_VERSION" \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" \
  "$TRIVY_SHA256"
install_released_bin gitleaks "$GITLEAKS_VERSION" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz" \
  "$GITLEAKS_SHA256"
