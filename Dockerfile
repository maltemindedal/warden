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

FROM python:3.11-slim-trixie

# Optional build args for reproducible builds
ARG TRIVY_VERSION=
ARG GITLEAKS_VERSION=

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

# From here on a failure anywhere in a pipeline fails the step: without it a failed
# `curl ... | sh` builds an image without the tool and every scan then warns and passes.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin ${TRIVY_VERSION}

# uv and Warden runtime dependencies
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
 && ln -sf /root/.local/bin/uv /usr/local/bin/uv

# Gitleaks
RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) gl_arch="linux_x64" ;; \
      arm64) gl_arch="linux_arm64" ;; \
      *) echo "Unsupported architecture for gitleaks: $arch" >&2; exit 1 ;; \
    esac; \
    if [ -z "${GITLEAKS_VERSION}" ]; then \
      GITLEAKS_VERSION="$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | head -n 1 | sed -E 's/.*"v?([^\"]+)\".*/\1/')"; \
    fi; \
    url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${gl_arch}.tar.gz"; \
    curl -sSL "$url" -o /tmp/gitleaks.tgz; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    rm -f /tmp/gitleaks.tgz; \
    chmod +x /usr/local/bin/gitleaks

# Copy Warden scripts into the image
WORKDIR /opt/warden
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ ./src/

RUN uv sync --locked --no-dev \
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
