# Running with Docker

The included `Dockerfile` bundles Warden with Trivy, Semgrep, and Gitleaks, so
you can scan a project without installing any of them.

No image is published to a registry. Build it locally.

## Build the image

From a clone of this repository:

```bash
docker build -t warden:local .
```

The build pulls Trivy and Gitleaks from their upstream release channels. Both
default to the latest release. To pin them instead, pass the version you want:

```bash
docker build -t warden:local \
  --build-arg TRIVY_VERSION=<version> \
  --build-arg GITLEAKS_VERSION=<version> .
```

Take the values from the release pages for
[Trivy](https://github.com/aquasecurity/trivy/releases) and
[Gitleaks](https://github.com/gitleaks/gitleaks/releases), without the leading
`v`. This repository pins neither tool, so there is no tested version pair to
copy. Choose the releases, build the image, and record the versions you used.

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
create files in a bind-mounted directory owned by you. The scan fails partway
through with:

```
PermissionError: [Errno 13] Permission denied: '/src/.security_reports/semgrep.json'
```

Passing `--user "$(id -u):$(id -g)"` runs the container as you, so the report
lands with the right ownership.

On Docker Desktop for macOS and Windows, the bind mount ignores UNIX ownership.
The flag is unnecessary there but harmless, so the commands above always use it.

Because the container may run as any UID, the image keeps its scanner caches and
settings under `/var/tmp/warden` rather than a fixed home directory, and sets
`safe.directory` system-wide so Gitleaks can read a repository owned by a
different user. Because the scanned tree is not trusted, it also switches
`core.fsmonitor` off through the environment, so a `.git/config` shipped inside the
project cannot run a command when a scanner calls `git`.

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

The GitHub Action sets `GITHUB_WORKSPACE` for you. See
[Configuration](../reference/configuration.md#environment-variables) for
precedence.

## Security note on the socket mount

Mounting `/var/run/docker.sock` grants the container effective root on the host,
because anything that can talk to the daemon can start a privileged container.
Only mount it when you need the DAST scan, and only for images you trust. The
static scanners need no socket. Use the first command in this guide unless you
need ZAP.
