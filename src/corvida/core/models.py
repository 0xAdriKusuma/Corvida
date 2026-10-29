"""
core/models.py — Shared data structures for the entire Corvida pipeline.

All analyzers produce Finding objects; all reporters consume Report objects.
Nothing outside this module should define its own output schema.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Risk level of a finding."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class Category(str, Enum):
    """Broad category a finding belongs to."""
    BINARY_INFO    = "binary_info"
    PROTECTIONS    = "protections"
    STRINGS        = "strings"
    DANGEROUS_FUNC = "dangerous_func"
    ADVISORY       = "advisory"
    ERROR          = "error"
    INFO           = "info"


class Confidence(str, Enum):
    """How confident the heuristic is."""
    CERTAIN  = "certain"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


@dataclass
class Target:
    """Represents the binary file under analysis."""

    path: Path
    """Absolute path to the binary."""

    sha256: str = field(init=False)
    """SHA-256 of the file content, computed on construction."""

    size: int = field(init=False)
    """File size in bytes."""

    arch: str | None = None
    bits: int | None = None
    endian: str | None = None
    file_type: str | None = None
    is_stripped: bool | None = None
    is_pie: bool | None = None
    interpreter: str | None = None

    def __post_init__(self) -> None:
        self.path = Path(self.path).resolve()
        stat = self.path.stat()
        self.size = stat.st_size
        self.sha256 = _sha256(self.path)

    @property
    def name(self) -> str:
        return self.path.name


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Finding:
    """
    A single piece of triage information produced by an analyzer.

    Reporters consume lists of Finding objects; advisors may read them too.
    """

    title: str
    """Short human-readable title (one line)."""

    category: Category

    severity: Severity = Severity.INFO

    confidence: Confidence = Confidence.MEDIUM

    id: str | None = None
    """
    Optional stable identifier assigned by the AI context builder.
    Format: F0001, F0002, … — used so AI claims can reference specific findings.
    None until the AI layer assigns one (rule-based path never touches this).
    """

    location: str | None = None
    """
    Where in the binary this was found.
    Free-form: could be an address ("0x401234"), section (".text"),
    import name, or similar.
    """

    evidence: list[str] = field(default_factory=list)
    """
    Raw supporting evidence: disasm snippets, string values, offsets, etc.
    Kept short; reporters may truncate long lists.
    """

    advice: str | None = None
    """One-liner suggestion for the CTF player (optional)."""

    extra: dict[str, Any] = field(default_factory=dict)
    """
    Arbitrary extra data for machine consumers (JSON reporter).
    Do NOT use this field in terminal rendering logic.
    """

    _score: float | None = field(default=None, repr=False)

    @property
    def score(self) -> float:
        """
        Numeric priority (higher = more important).
        Set explicitly by scoring.py; otherwise falls back to a simple formula.
        """
        if self._score is not None:
            return self._score
        return _default_score(self.severity, self.confidence)

    @score.setter
    def score(self, value: float) -> None:
        self._score = value

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (used by JSON reporter)."""
        d: dict[str, Any] = {
            "title":      self.title,
            "category":   self.category.value,
            "severity":   self.severity.value,
            "confidence": self.confidence.value,
            "score":      round(self.score, 3),
            "location":   self.location,
            "evidence":   self.evidence,
            "advice":     self.advice,
            "extra":      self.extra,
        }
        if self.id is not None:
            d["id"] = self.id
        return d


def _default_score(severity: Severity, confidence: Confidence) -> float:
    SEV = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH:     0.75,
        Severity.MEDIUM:   0.5,
        Severity.LOW:      0.25,
        Severity.INFO:     0.0,
    }
    CONF = {
        Confidence.CERTAIN: 1.0,
        Confidence.HIGH:    0.8,
        Confidence.MEDIUM:  0.6,
        Confidence.LOW:     0.4,
    }
    return SEV[severity] * CONF[confidence]


@dataclass
class Report:
    """Aggregated analysis results for one Target."""

    target: Target

    findings: list[Finding] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)
    """
    Tool-level metadata: versions, analysis time, flags used, etc.
    """

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def by_category(self, cat: Category) -> list[Finding]:
        return [f for f in self.findings if f.category == cat]

    def sorted_by_score(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.score, reverse=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "target": {
                "path":      str(self.target.path),
                "name":      self.target.name,
                "sha256":    self.target.sha256,
                "size":      self.target.size,
                "arch":      self.target.arch,
                "bits":      self.target.bits,
                "endian":    self.target.endian,
                "file_type": self.target.file_type,
                "stripped":  self.target.is_stripped,
                "pie":       self.target.is_pie,
                "interpreter": self.target.interpreter,
            },
            "findings": [f.to_dict() for f in self.sorted_by_score()],
            "errors":   self.errors,
            "metadata": self.metadata,
        }
