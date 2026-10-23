"""
analyzers/base.py — Abstract base class for all analyzers.

An analyzer:
  * Declares which ``Target.file_type`` values it supports (``supports``).
  * Declares its output category (``category``).
  * Receives a Target + optional backend + Config, returns list[Finding].

Analyzers must NOT crash the pipeline; they should catch internal errors
and return a Finding with category=ERROR instead.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from corvida.backends.base import BaseBackend
from corvida.core.config import Config
from corvida.core.models import Category, Finding, Target


class BaseAnalyzer(ABC):
    """
    Abstract analyzer.

    Class attributes
    ----------------
    name : str
        Unique short identifier.  Used as registry key.
    category : Category
        The type of findings this analyzer produces.
    supports : list[str]
        file_type values this analyzer can handle (e.g. ["ELF"]).
        Empty list means "all types".
    requires_backend : bool
        If True, the pipeline will pass a live backend instance.
        If False, backend may be None.
    """

    name:             str      = ""
    category:         Category = Category.BINARY_INFO   # type: ignore[assignment]
    supports:         list[str] = []
    requires_backend: bool      = False

    @abstractmethod
    def analyze(
        self,
        target:  Target,
        config:  Config,
        backend: BaseBackend | None = None,
    ) -> list[Finding]:
        """
        Perform analysis.

        Must NOT raise (catch internally and return error Finding).
        Must return a list (may be empty).
        """

    def _error_finding(self, title: str, detail: str) -> Finding:
        from corvida.core.models import Confidence, Severity
        return Finding(
            title=title,
            category=Category.ERROR,
            severity=Severity.INFO,
            confidence=Confidence.CERTAIN,
            evidence=[detail],
        )
