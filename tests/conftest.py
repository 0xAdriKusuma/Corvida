"""
tests/conftest.py — Shared pytest fixtures.
"""

import pytest
from pathlib import Path


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    return Path(__file__).parent / "samples" / "pwn"


@pytest.fixture(scope="session")
def rules_dir() -> Path:
    return Path(__file__).parent.parent / "rules"
