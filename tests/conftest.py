from __future__ import annotations

import pytest

CI_VARIABLES = ("GITHUB_WORKSPACE", "WARDEN_HOST_WORKSPACE", "WARDEN_HOST_REPORT_DIR")


@pytest.fixture(autouse=True)
def _outside_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    """Warden behaves differently on a CI runner, and the tests run on one: start from a laptop."""
    for name in CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _plain_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """rich reads these when a Console is created, so without this the output depends on them."""
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("TTY_COMPATIBLE", raising=False)
    monkeypatch.setenv("COLUMNS", "200")
