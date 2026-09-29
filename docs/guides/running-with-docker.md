# Running with Docker

The included `Dockerfile` bundles Warden with Trivy, Semgrep, and Gitleaks, so
you can scan a project without installing any of them.

No image is published to a registry. Build it locally.

## Build the image

From a clone of this repository:

```bash
docker build -t warden:local .
```

The image pins what it downloads. uv comes from a build stage pinned by version and
digest (`ghcr.io/astral-sh/uv`), and Trivy and Gitleaks are fetched at a fixed
version whose release archive must match a SHA-256 recorded in the `Dockerfile`, one
per architecture (amd64 and arm64). A download that does not match fails the build.
Nothing is piped into a shell, and updating means editing the `Dockerfile`. The `uv`
stage is also tracked by Dependabot (see `.github/dependabot.yml`), and the same uv
version is pinned in `install.sh` and `install.ps1`.

To build with other scanner versions, pass the version **and** its digests. Both
versions are given without a leading `v`, and the digests are the archive's line in
the release's checksums file (`trivy_<version>_Linux-64bit.tar.gz`,
`trivy_<version>_Linux-ARM64.tar.gz`, `gitleaks_<version>_linux_x64.tar.gz`,
`gitleaks_<version>_linux_arm64.tar.gz`):

```bash
docker build -t warden:local \
  --build-arg TRIVY_VERSION=<version> \
  --build-arg TRIVY_SHA256_AMD64=<digest> --build-arg TRIVY_SHA256_ARM64=<digest> \
  --build-arg GITLEAKS_VERSION=<version> \
  --build-arg GITLEAKS_SHA256_AMD64=<digest> --build-arg GITLEAKS_SHA256_ARM64=<digest> .
```

Take them from the release pages for
[Trivy](https://github.com/aquasecurity/trivy/releases) and
[Gitleaks](https://github.com/gitleaks/gitleaks/releases). A checksum fetched from
the release it belongs to proves the download is intact, not that the release is
trustworthy, which is why the digests are committed rather than fetched.

## Scan a project

Mount the project at `/src`:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd):/src" warden:local
```

The report is written to `security_audit.json` in the mounted directory, owned
by your user.

Everything after the image name is passed to Warden, so the usual flags work:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd):/src" warden:local --help
```

## Why the `--user` flag is required

The image runs as an unprivileged user (`warden`, UID 10001). Without
`--user`, the container writes as UID 10001, which will not have permission to
create files in a bind-mounted directory owned by you. The run normally stops
before any scanner starts, with:

```
warden: error: cannot prepare the report paths: /src/.security_reports: Permission denied
```

Passing `--user "$(id -u):$(id -g)"` runs the container as you, so the report
lands with the right ownership.

On Docker Desktop for macOS and Windows, the bind mount ignores UNIX ownership.
The flag is unnecessary there but harmless, so the commands above always use it.

Because the container may run as any UID, the image keeps its scanner caches and
settings under `/var/tmp/warden` rather than a fixed home directory, and sets
`safe.directory` system-wide so git, which Semgrep runs (`git ls-files`), accepts a
repository owned by a different user. Because the scanned tree is not trusted, it also
switches `core.fsmonitor` off through the environment, so a `.git/config` shipped inside
the project cannot run a command when a scanner calls `git`.

## Add a DAST scan

ZAP runs in its own container, so the Warden container needs to talk to the
Docker daemon. Mount the socket and grant the unprivileged container access to
the socket's group:

```bash
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --group-add "$(getent group docker | cut -d: -f3)" \
    -v "$(pwd):/src" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    warden:local --url "http://host.docker.internal:3000"
```

Without `--group-add`, the socket is unreadable and ZAP fails with
`permission denied while trying to connect to the Docker daemon socket`.

If your host's docker group is not named `docker`, read the group ID off the
socket instead:

```bash
--group-add "$(stat -c '%g' /var/run/docker.sock)"
```

### Reaching the target application

Warden rewrites a URL host of `localhost` or `127.0.0.1` to
`host.docker.internal` automatically, so `--url http://localhost:3000` usually
works from inside a container.

On Linux, `host.docker.internal` is not resolvable by default. Either target a
service running in Docker by its container or network address, or add:

```bash
--add-host=host.docker.internal:host-gateway
```

### Report paths across containers

ZAP is started by the Warden container but runs as a *sibling* under the host's
Docker daemon, so the path Warden passes as a volume must be a **host** path,
not a container path. Set one of `WARDEN_HOST_REPORT_DIR`,
`WARDEN_HOST_WORKSPACE`, or `GITHUB_WORKSPACE` to supply it:

```bash
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --group-add "$(stat -c '%g' /var/run/docker.sock)" \
    -e WARDEN_HOST_WORKSPACE="$(pwd)" \
    -v "$(pwd):/src" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    warden:local --url "http://host.docker.internal:3000"
```

The GitHub Action sets `GITHUB_WORKSPACE` for you. Passing it also stops the project's
own `.warden.yaml` from supplying the `target_url` (`--url` still works), so prefer
`WARDEN_HOST_WORKSPACE` if you want that file's target used. See
[Configuration](../reference/configuration.md#environment-variables) for
precedence.

## Security note on the socket mount

Mounting `/var/run/docker.sock` grants the container effective root on the host,
because anything that can talk to the daemon can start a privileged container.
Only mount it when you need the DAST scan, and only for images you trust. The
static scanners need no socket. Use the first command in this guide unless you
need ZAP.
