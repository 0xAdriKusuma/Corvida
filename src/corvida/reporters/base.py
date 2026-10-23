"""
reporters/base.py — Abstract base class for all reporters.

A reporter takes a completed Report and renders it somewhere
(terminal, JSON file, HTML, …).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from corvida.core.config import Config
from corvida.core.models import Report


class BaseReporter(ABC):
    """
    Abstract reporter.

    Class attributes
    ----------------
    name : str
        Short identifier.  Used as registry key and as ``--format`` value.
    """

    name: str = ""

    @abstractmethod
    def render(self, report: Report, config: Config) -> None:
        """Render *report* to the appropriate output medium."""
