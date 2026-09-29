#!/usr/bin/env bash
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UV_BIN_DIR="$HOME/.local/bin"

# What gets downloaded is pinned, and the scanner archives are checked against the SHA-256 of the
# release. Keep these in step with the Dockerfile, which pins the same versions.
UV_VERSION="0.12.18"
UV_MIN_VERSION="0.9.17" # the first uv that reads a duration such as "7 days" for --exclude-newer
TRIVY_VERSION="0.74.0"
GITLEAKS_VERSION="8.30.1"

echo -e "${CYAN}Installing Warden...${NC}"

OS="$(uname -s)"
case "$OS" in
	Linux*)  OS_TYPE="Linux" ;;
	Darwin*) OS_TYPE="Mac" ;;
	*)       echo -e "${RED}Unsupported OS: $OS${NC}"; exit 1 ;;
esac
echo "   Detected: $OS_TYPE"

if ! command -v docker >/dev/null 2>&1; then
	echo -e "${RED}Missing requirement: Docker. Please install it first.${NC}"
	exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
	echo -e "${YELLOW}   -> Installing uv...${NC}"
	curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" | sh
fi

# The user's PATH as it stood, before uv's directory is added for this script's own use below.
# The check at the end has to look at this one, or it can never find the directory missing.
CALLER_PATH="$PATH"
export PATH="$UV_BIN_DIR:$PATH"

# Where the Linux scanner binaries go. Prefer the system directory, escalate if
# we cannot write it, and fall back to the user's own bin directory when there
# is no sudo either. This keeps an unprivileged install working.
BIN_DIR="/usr/local/bin"
SUDO=""
if [ "$OS_TYPE" = "Linux" ] && [ ! -w "$BIN_DIR" ]; then
	if command -v sudo >/dev/null 2>&1; then
		SUDO="sudo"
	else
		BIN_DIR="$UV_BIN_DIR"
		mkdir -p "$BIN_DIR"
		echo -e "${YELLOW}   -> No write access to /usr/local/bin and no sudo; using $BIN_DIR.${NC}"
	fi
fi

# Trivy and Gitleaks publish per-architecture archives; match the Dockerfile's mapping.
case "$(uname -m)" in
	x86_64|amd64)
		TRIVY_ARCH="Linux-64bit"
		TRIVY_SHA256="2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
		GITLEAKS_ARCH="linux_x64"
		GITLEAKS_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
		;;
	aarch64|arm64)
		TRIVY_ARCH="Linux-ARM64"
		TRIVY_SHA256="b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5"
		GITLEAKS_ARCH="linux_arm64"
		GITLEAKS_SHA256="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
		;;
	*)
		TRIVY_ARCH=""
		GITLEAKS_ARCH=""
		;;
esac

# Download to a file, and keep it only if its SHA-256 is the expected one.
fetch_verified() {
	local url="$1" expected="$2" dest="$3"
	curl -fsSL "$url" -o "$dest" || return 1
	if ! echo "$expected  $dest" | sha256sum -c - >/dev/null 2>&1; then
		echo -e "${RED}   $url does not match its expected checksum; not installing it.${NC}"
		rm -f "$dest"
		return 1
	fi
}

install_trivy() {
	if [ "$OS_TYPE" = "Mac" ]; then
		if ! command -v brew >/dev/null 2>&1; then
			echo -e "${RED}   Homebrew not found. Please install Trivy manually: https://trivy.dev${NC}"
			return 0
		fi
		brew install trivy
		return 0
	fi

	if [ -z "$TRIVY_ARCH" ]; then
		echo -e "${RED}   No Trivy build for $(uname -m). Install it manually: https://trivy.dev${NC}"
		return 0
	fi

	local archive
	archive="$(mktemp)"
	fetch_verified \
		"https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" \
		"$TRIVY_SHA256" "$archive" || {
		rm -f "$archive"
		return 1
	}
	# --no-same-owner: as root, tar would otherwise keep the owner recorded in the archive, and a
	# scanner binary in a system directory would belong to an unrelated user id.
	$SUDO tar -xz --no-same-owner -C "$BIN_DIR" -f "$archive" trivy || {
		rm -f "$archive"
		return 1
	}
	rm -f "$archive"
}

install_gitleaks() {
	if [ "$OS_TYPE" = "Mac" ]; then
		if ! command -v brew >/dev/null 2>&1; then
			echo -e "${RED}   Homebrew not found. Please install Gitleaks manually: https://github.com/gitleaks/gitleaks${NC}"
			return 0
		fi
		brew install gitleaks
		return 0
	fi

	if [ -z "$GITLEAKS_ARCH" ]; then
		echo -e "${RED}   No Gitleaks build for $(uname -m). Install it manually: https://github.com/gitleaks/gitleaks${NC}"
		return 0
	fi

	local archive
	archive="$(mktemp)"
	fetch_verified \
		"https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz" \
		"$GITLEAKS_SHA256" "$archive" || {
		rm -f "$archive"
		return 1
	}
	# --no-same-owner: as root, tar would otherwise keep the owner recorded in the archive, and a
	# scanner binary in a system directory would belong to an unrelated user id.
	$SUDO tar -xz --no-same-owner -C "$BIN_DIR" -f "$archive" gitleaks || {
		rm -f "$archive"
		return 1
	}
	rm -f "$archive"
}

# A scanner that fails to install is a warning, not a fatal error: Warden runs
# without it and reports the tool as skipped.
echo -e "${CYAN}[*] Checking dependency tools...${NC}"
if ! command -v trivy >/dev/null 2>&1; then
	echo -e "${YELLOW}   -> Installing Trivy...${NC}"
	install_trivy || echo -e "${RED}   Trivy install failed. Warden will report it as unavailable.${NC}"
else
	echo -e "${GREEN}   -> Trivy already installed.${NC}"
fi

if ! command -v gitleaks >/dev/null 2>&1; then
	echo -e "${YELLOW}   -> Installing Gitleaks...${NC}"
	install_gitleaks || echo -e "${RED}   Gitleaks install failed. Warden will report it as unavailable.${NC}"
else
	echo -e "${GREEN}   -> Gitleaks already installed.${NC}"
fi

# Is dotted version $1 at least $2? Numeric parts only, so it also works on bash 3.2 and macOS.
version_at_least() {
	local IFS=. index have need
	read -ra have <<<"$1"
	read -ra need <<<"$2"
	for index in 0 1 2; do
		local h="${have[index]:-0}" n="${need[index]:-0}"
		h="${h%%[!0-9]*}"
		n="${n%%[!0-9]*}"
		if ((10#${h:-0} > 10#${n:-0})); then return 0; fi
		if ((10#${h:-0} < 10#${n:-0})); then return 1; fi
	done
	return 0
}

# `uv tool install` ignores this repository's uv.lock and its [tool.uv] settings, including the
# seven-day cooldown on new releases, so the cooldown is passed explicitly. A uv older than
# UV_MIN_VERSION rejects `--exclude-newer "7 days"` with a bare parse error, so say what is
# wrong and what to do before it gets that far.
uv_version="$(uv --version | awk '{print $2}')"
if ! version_at_least "$uv_version" "$UV_MIN_VERSION"; then
	echo -e "${RED}uv $uv_version is too old: this install needs uv $UV_MIN_VERSION or newer.${NC}"
	echo -e "${RED}Update it (https://docs.astral.sh/uv/getting-started/installation/) and run this script again.${NC}"
	exit 1
fi

echo -e "${CYAN}[*] Installing Warden with uv...${NC}"
uv python install 3.11
uv tool install --force --python 3.11 --exclude-newer "7 days" -e "$SCRIPT_DIR"

# These are unset in a non-interactive shell, so every read needs a default.
# Without one, `set -u` would abort the script before it finishes.
LOGIN_SHELL="${SHELL:-}"
if [ -n "${ZSH_VERSION:-}" ] || [ "${LOGIN_SHELL##*/}" = "zsh" ]; then
	SHELL_RC="$HOME/.zshrc"
elif [ -n "${BASH_VERSION:-}" ] || [ "${SHELL:-}" = "/bin/bash" ]; then
	SHELL_RC="$HOME/.bashrc"
else
	SHELL_RC="$HOME/.profile"
fi

# What counts as the profile already putting the directory on PATH: the line uv's own installer
# writes (`. "$HOME/.local/bin/env"`, late-bound) or an `export PATH=` line, like the one below.
# A comment or an unrelated command that merely mentions the directory does not.
PROFILE_PATH_LINE='^[[:space:]]*((\.|source)[[:space:]].*\.local/bin/env|export[[:space:]]+PATH=.*\.local/bin)'

if [[ ":$CALLER_PATH:" == *":$UV_BIN_DIR:"* ]]; then
	echo -e "${GREEN}uv tool bin directory is already on PATH.${NC}"
elif grep -qsE "$PROFILE_PATH_LINE" "$SHELL_RC"; then
	echo -e "${YELLOW}$SHELL_RC already adds '$UV_BIN_DIR' to your PATH.${NC}"
	echo -e "${YELLOW}Restart your terminal or run: source $SHELL_RC${NC}"
else
	echo -e "${CYAN}[*] Adding '$UV_BIN_DIR' to your PATH...${NC}"
	if {
		echo ""
		echo "# Warden and uv tools"
		echo "export PATH=\"$UV_BIN_DIR:\$PATH\""
	} >> "$SHELL_RC"; then
		echo -e "${GREEN}Added to $SHELL_RC${NC}"
		echo -e "${YELLOW}Restart your terminal or run: source $SHELL_RC${NC}"
	else
		echo -e "${YELLOW}Could not write to $SHELL_RC. Add '$UV_BIN_DIR' to your PATH yourself.${NC}"
	fi
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo -e "Run ${CYAN}warden${NC} from any project directory to start a security audit."
