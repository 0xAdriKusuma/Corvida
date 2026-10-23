"""
core/config.py — Runtime configuration passed through the pipeline.

A single Config object is created from CLI flags and threaded through
every stage so that analyzers/reporters don't need global state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """
    Immutable (by convention) configuration for a single Corvida run.

    All fields have sensible defaults so that most code just does
    ``config = Config()`` and overrides what it needs.
    """

    verbose: bool = False
    no_color: bool = False
    output_format: str = "terminal"

    max_strings: int = 20
    """Maximum number of interesting strings to report."""

    min_string_len: int = 6
    """Minimum string length to consider."""

    rules_dir: Path = field(default_factory=lambda: _default_rules_dir())

    rzpipe_timeout: int = 30
    """Seconds to wait for rizin operations."""

    def __post_init__(self) -> None:
        self.rules_dir = Path(self.rules_dir).resolve()


def _default_rules_dir() -> Path:
    """Locate the `rules/` directory relative to the installed package."""
    here = Path(__file__).parent
    pkg  = here.parent
    src  = pkg.parent
    root = src.parent
    return root / "rules"
