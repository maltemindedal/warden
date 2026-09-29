#!/usr/bin/env bash
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UV_BIN_DIR="$HOME/.local/bin"

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
	curl -LsSf https://astral.sh/uv/install.sh | sh
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

# Gitleaks publishes per-architecture archives; match the Dockerfile's mapping.
case "$(uname -m)" in
	x86_64|amd64)  GITLEAKS_ARCH="linux_x64" ;;
	aarch64|arm64) GITLEAKS_ARCH="linux_arm64" ;;
	*)             GITLEAKS_ARCH="" ;;
esac

install_trivy() {
	if [ "$OS_TYPE" = "Mac" ]; then
		if ! command -v brew >/dev/null 2>&1; then
			echo -e "${RED}   Homebrew not found. Please install Trivy manually: https://trivy.dev${NC}"
			return 0
		fi
		brew install trivy
		return 0
	fi

	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
		| $SUDO sh -s -- -b "$BIN_DIR"
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

	local version
	version="$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
		| grep '"tag_name"' | head -n 1 | sed -E 's/.*"v?([^"]+)".*/\1/')"
	if [ -z "$version" ]; then
		echo -e "${RED}   Could not determine the latest Gitleaks release. Install it manually: https://github.com/gitleaks/gitleaks${NC}"
		return 0
	fi

	curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_${GITLEAKS_ARCH}.tar.gz" \
		| $SUDO tar -xz -C "$BIN_DIR" gitleaks
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

echo -e "${CYAN}[*] Installing Warden with uv...${NC}"
uv python install 3.11
uv tool install --force --python 3.11 -e "$SCRIPT_DIR"

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
