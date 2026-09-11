# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""HOME, USERPROFILE, the key dir and the audit-log root are redirected to a
per-session directory BEFORE the package is first imported (the audit chain
evaluates its defaults at import), so the suite never touches ``~/.workspace``.
The package is deliberately left unimported here."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

#: Value of ``loomground_audit_chain.mutation_log.RVND_LOG_ROOT_ENV`` — a
#: compatibility constant of the audit chain, named here as its value so the
#: redirect lands before that module is imported.
LOG_ROOT_ENV = "RVND_LOG_ROOT"

_HOME: Path | None = None


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    global _HOME
    factory = getattr(config, "_tmp_path_factory", None)
    if factory is not None:
        home = factory.mktemp("home")
    else:  # pragma: no cover
        home = Path(tempfile.mkdtemp(prefix="drift-home-"))
    _HOME = Path(home)
    os.environ["HOME"] = str(_HOME)
    os.environ["USERPROFILE"] = str(_HOME)
    os.environ["WORKSPACE_KEY_DIR"] = str(_HOME / ".workspace" / "keys")
    os.environ[LOG_ROOT_ENV] = str(_HOME / ".workspace" / "log")


@pytest.fixture(autouse=True)
def _isolated_chain_env(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv(LOG_ROOT_ENV, str(tmp_path / "log"))
    monkeypatch.setenv("WORKSPACES_ALLOW_UNREGISTERED", "1")
    for var in ("WORKSPACE_KEY_PINNING", "WORKSPACE_STRICT_KEY_PINNING",
                "WORKSPACE_STRICT_HOST_DIVERGENCE", "WORKSPACE_KEY_PASSPHRASE",
                "WORKSPACE_HOST_ID", "WORKSPACE_KEY_PIN_DIR", "WORKSPACE_L0_LOG_ROOT"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def folder(tmp_path):
    f = tmp_path / "ws"
    f.mkdir()
    return f


@pytest.fixture
def log_root(tmp_path):
    return tmp_path / "logroot"
