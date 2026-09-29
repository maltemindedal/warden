# Warden Docker image
# Build:
#   docker build -t warden:local .
# Run (the image is unprivileged, so --user is required on Linux for the report
# to be writable back into the bind-mounted project):
#   docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd):/src" warden:local
# DAST also needs the Docker socket and its group:
#   docker run --rm --user "$(id -u):$(id -g)" \
#     --group-add "$(getent group docker | cut -d: -f3)" \
#     -v "$(pwd):/src" -v /var/run/docker.sock:/var/run/docker.sock \
#     warden:local -u "http://host.docker.internal:3000"

# uv, pinned by version and digest and copied in as a binary: nothing is piped into a shell.
FROM ghcr.io/astral-sh/uv:0.12.18@sha256:3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc AS uv

FROM python:3.11-slim-trixie

# The scanner versions and the SHA-256 of the release archive for each architecture. Every
# download is checked against these, so changing a version means changing its digests too
# (they are in the release's checksums file).
ARG TRIVY_VERSION=0.74.0
ARG TRIVY_SHA256_AMD64=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
ARG TRIVY_SHA256_ARM64=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080

ENV PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
  UV_LINK_MODE=copy \
  UV_COMPILE_BYTECODE=1 \
  UV_PYTHON_DOWNLOADS=never

# Base utilities and the Docker CLI (client only) for optional ZAP scans
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      docker-cli \
      git \
      gzip \
      tar \
 && rm -rf /var/lib/apt/lists/*

# From here on a failure anywhere in a pipeline fails the step, so a download or a
# checksum that fails can never build an image without a tool (every scan would then warn
# that the tool is missing, and pass).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Trivy
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) archive="Linux-64bit"; sha256="${TRIVY_SHA256_AMD64}" ;; \
      arm64) archive="Linux-ARM64"; sha256="${TRIVY_SHA256_ARM64}" ;; \
      *) echo "Unsupported architecture for trivy: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${archive}.tar.gz" -o /tmp/trivy.tgz; \
    echo "${sha256}  /tmp/trivy.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    rm -f /tmp/trivy.tgz

# Gitleaks
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) archive="linux_x64"; sha256="${GITLEAKS_SHA256_AMD64}" ;; \
      arm64) archive="linux_arm64"; sha256="${GITLEAKS_SHA256_ARM64}" ;; \
      *) echo "Unsupported architecture for gitleaks: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${archive}.tar.gz" -o /tmp/gitleaks.tgz; \
    echo "${sha256}  /tmp/gitleaks.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    rm -f /tmp/gitleaks.tgz

# uv, for the Warden runtime dependencies below
COPY --from=uv /uv /usr/local/bin/uv

# Fail the build here, not on the first scan, if a tool does not run on this architecture.
RUN trivy --version && gitleaks version && uv --version

# Copy Warden scripts into the image
WORKDIR /opt/warden
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ ./src/

RUN uv sync --locked --no-dev --no-cache \
 && ln -sf /opt/warden/.venv/bin/warden /usr/local/bin/warden

ENV PATH="/opt/warden/.venv/bin:${PATH}"

# Run as a non-root user. Callers are also expected to override the uid to match
# the owner of the bind-mounted project (see action.yml), so every path the tools
# write to at runtime must be usable by an arbitrary UID. The image therefore
# uses a sticky, world-writable state directory instead of a home under /home.
RUN useradd --no-create-home --uid 10001 --shell /usr/sbin/nologin warden \
 && mkdir -p /var/tmp/warden \
 && chmod 1777 /var/tmp/warden

ENV HOME=/var/tmp/warden \
    XDG_CACHE_HOME=/var/tmp/warden/cache \
    XDG_CONFIG_HOME=/var/tmp/warden/config \
    XDG_DATA_HOME=/var/tmp/warden/data \
    TRIVY_CACHE_DIR=/var/tmp/warden/cache/trivy \
    SEMGREP_SETTINGS_FILE=/var/tmp/warden/config/semgrep/settings.yml

# /src is owned by the host user, so git (and therefore gitleaks) would otherwise
# refuse to operate on it under a different uid. Set system-wide rather than via
# GIT_CONFIG_* env vars so it survives any HOME the caller supplies.
RUN git config --system --add safe.directory '*'

# The scanned tree is not trusted, and neither is a `.git/config` it carries: its
# `core.fsmonitor` would run a command of the project's choosing whenever git looks at
# the tree (Semgrep runs `git ls-files`). Config from the environment outranks every
# config file, the repository's own included.
ENV GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=core.fsmonitor \
    GIT_CONFIG_VALUE_0=false

USER warden

# The scanned project is expected to be bind-mounted at /src
WORKDIR /src

ENTRYPOINT ["warden"]
