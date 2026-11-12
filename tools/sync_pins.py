#!/usr/bin/env python3
"""Copy the Dockerfile's uv version into install.sh and install.ps1.

Dependabot bumps the `FROM ghcr.io/astral-sh/uv:<version>@sha256:...` line
and cannot edit the installers. Run this after such a bump:

    python3 tools/sync_pins.py          rewrite the installers (idempotent)
    python3 tools/sync_pins.py --check  report drift, exit 1, change nothing

Trivy and Gitleaks pins are not synced: their SHA-256 digests come from each
release's checksums file, so a version alone cannot be copied across.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMAND = "python3 tools/sync_pins.py"

DOCKERFILE_UV = re.compile(
    r"^FROM ghcr\.io/astral-sh/uv:(\d+\.\d+\.\d+)@sha256:[0-9a-f]{64}\b", re.MULTILINE
)
INSTALLER_PINS = {
    "install.sh": re.compile(r'^(UV_VERSION=")([^"\s]+)(")', re.MULTILINE),
    "install.ps1": re.compile(r'^(\$UvVersion = ")([^"\s]+)(")', re.MULTILINE),
}
CLOUD_INSTALL = ".cursor/cloud-install.sh"


def dockerfile_uv_version(root: Path) -> str:
    matches = DOCKERFILE_UV.findall((root / "Dockerfile").read_text(encoding="utf-8"))
    if len(matches) != 1:
        raise SystemExit(f"Dockerfile has {len(matches)} pinned uv FROM lines, expected 1")
    return str(matches[0])


def sync(root: Path, *, write: bool) -> list[str]:
    """Return one line per pin that disagrees with the Dockerfile; fix them when `write`."""
    version = dockerfile_uv_version(root)
    problems: list[str] = []
    for name, pattern in INSTALLER_PINS.items():
        path = root / name
        with path.open(encoding="utf-8", newline="") as handle:
            text = handle.read()
        found = pattern.findall(text)
        if len(found) != 1:
            raise SystemExit(f"{name} has {len(found)} uv pin lines, expected 1")
        if found[0][1] == version:
            continue
        problems.append(f"{name} pins uv {found[0][1]}, the Dockerfile pins {version}")
        if write:
            fixed = pattern.sub(rf"\g<1>{version}\g<3>", text)
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(fixed)
    cloud = root / CLOUD_INSTALL
    if cloud.exists() and re.search(r'^\s*UV_VERSION="\d', cloud.read_text(encoding="utf-8"), re.M):
        problems.append(f"{CLOUD_INSTALL} hardcodes UV_VERSION; it must read it from install.sh")
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="report drift and exit 1")
    args = parser.parse_args(argv)
    problems = sync(ROOT, write=not args.check)
    for line in problems:
        print(line)
    if args.check:
        return 1 if problems else 0
    return 1 if any(CLOUD_INSTALL in line for line in problems) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
