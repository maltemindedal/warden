# Docker image and self-scan

## Sub-features

- `docker build` (downloads pinned Trivy and Gitleaks), then the image scans this repo, as CI's `scan` job does.

## How to get to it (user POV)

`docker build -t warden:local . && docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" warden:local`

## Driving it with verify.sh

`verify.sh image`. Without a usable Docker daemon it prints SKIP and the run
ends `PASS with SKIP`; with Docker both commands must exit 0.

## Gotchas

- The Trivy download can time out (curl exit 28); rerun.
- New advisories against `uv.lock` turn the self-scan red with no code change.
