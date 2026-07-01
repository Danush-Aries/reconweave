"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from reconweave.engine import Engine


@pytest.fixture()
def engine():
    eng = Engine(use_cache=False)
    yield eng
    eng.close()


@pytest.fixture()
def domain_scan(engine):
    return engine.scan("example.com")


@pytest.fixture()
def email_scan(engine):
    return engine.scan("john.doe@example.com")


@pytest.fixture()
def username_scan(engine):
    return engine.scan("someuser", "username")
