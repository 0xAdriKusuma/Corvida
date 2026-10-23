"""
analyzers/common/strings.py — Interesting string extractor.

Strategy
--------
1. Use backend.strings() if a backend is available (rizin is more accurate).
2. Fall back to a pure-Python scan of the binary if no backend.
3. Score each string by matching against interest patterns.
4. Return only the top-N strings (config.max_strings).

Interest patterns are defined in this file rather than YAML because they
are general-purpose (not pwn-specific) and rarely change.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from corvida.analyzers.base import BaseAnalyzer
from corvida.backends.base import BaseBackend
from corvida.core.config import Config
from corvida.core.models import (
    Category, Confidence, Finding, Severity, Target,
)
from corvida.core.registry import register_analyzer

_PATTERNS: list[tuple[str, str, Severity, float]] = [
    # Shell
    (r"/bin/sh",              "Shell invocation",        Severity.HIGH,   1.0),
    (r"/bin/bash",            "Shell invocation",        Severity.HIGH,   1.0),
    (r"/bin/dash",            "Shell invocation",        Severity.HIGH,   1.0),
    (r"execve|system\(",      "Exec call in string",     Severity.HIGH,   0.8),
    # Flag patterns
    (r"flag\{",               "Flag placeholder",        Severity.HIGH,   0.9),
    (r"CTF\{",                "CTF flag pattern",        Severity.HIGH,   0.9),
    (r"picoCTF\{",            "picoCTF flag",            Severity.HIGH,   0.9),
    (r"\w{3,8}\{[^}]{5,50}\}","Generic flag pattern",   Severity.MEDIUM, 0.7),
    # Menu/interaction
    (r"[Ee]nter (?:your |a )?(?:choice|option|input|command|password|name)",
                              "User interaction prompt", Severity.MEDIUM, 0.6),
    (r"[Mm]enu|[Oo]ption|[Cc]hoice",
                              "Menu text",               Severity.LOW,    0.5),
    # Passwords/secrets
    (r"[Pp]assword|[Ss]ecret|[Kk]ey|[Tt]oken",
                              "Credential string",       Severity.MEDIUM, 0.6),
    # Format strings
    (r"%\d*\$[a-zA-Z]",       "Format string specifier", Severity.HIGH,  0.8),
    # Paths
    (r"/etc/passwd|/etc/shadow|/proc/",
                              "Sensitive path",          Severity.MEDIUM, 0.7),
    # Debug / dev
    (r"debug|DEBUG|HACK|TODO|FIXME",
                              "Debug/dev artifact",      Severity.LOW,    0.4),
    # Addresses / hex patterns
    (r"0x[0-9a-fA-F]{6,}",   "Hardcoded address",       Severity.LOW,    0.4),
]

_COMPILED = [
    (re.compile(pat), label, sev, boost)
    for pat, label, sev, boost in _PATTERNS
]


_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _scan_binary(path: Path, min_len: int) -> list[dict]:
    """Extract printable strings directly from binary bytes."""
    results = []
    with open(path, "rb") as fh:
        data = fh.read()

    buf: list[int] = []
    offset = 0
    for i, b in enumerate(data):
        if b in _PRINTABLE:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                s = bytes(buf).decode("ascii", errors="replace")
                results.append({
                    "string":  s,
                    "vaddr":   i - len(buf),
                    "section": None,
                    "length":  len(buf),
                })
            buf = []
    return results


def _score_string(s: str) -> tuple[float, str, Severity, Confidence]:
    """Return (score, label, severity, confidence) for a string."""
    best_score = 0.0
    best_label = "Interesting string"
    best_sev   = Severity.LOW
    best_conf  = Confidence.LOW

    for pat, label, sev, boost in _COMPILED:
        if pat.search(s):
            if boost > best_score:
                best_score = boost
                best_label = label
                best_sev   = sev
                best_conf  = Confidence.HIGH if boost >= 0.8 else Confidence.MEDIUM

    return best_score, best_label, best_sev, best_conf


@register_analyzer
class StringsAnalyzer(BaseAnalyzer):
    """Extracts and scores interesting printable strings from a binary."""

    name     = "strings"
    category = Category.STRINGS
    supports = []
    requires_backend = False

    def analyze(
        self, target: Target, config: Config, backend: BaseBackend | None = None
    ) -> list[Finding]:
        if backend is not None:
            try:
                raw = backend.strings(min_len=config.min_string_len)
            except Exception:    # noqa: BLE001
                raw = _scan_binary(target.path, config.min_string_len)
        else:
            raw = _scan_binary(target.path, config.min_string_len)

        scored: list[tuple[float, dict, str, Severity, Confidence]] = []
        for entry in raw:
            s = entry.get("string", "")
            sc, label, sev, conf = _score_string(s)
            if sc > 0:
                scored.append((sc, entry, label, sev, conf))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[: config.max_strings]

        findings: list[Finding] = []
        for sc, entry, label, sev, conf in top:
            s    = entry["string"]
            addr = entry.get("vaddr", 0)
            sec  = entry.get("section") or "?"
            findings.append(Finding(
                title      = f"{label}: {s[:60]!r}",
                category   = Category.STRINGS,
                severity   = sev,
                confidence = conf,
                location   = f"{addr:#010x} ({sec})" if addr else sec,
                evidence   = [s],
                advice     = None,
                extra      = {"string": s, "vaddr": addr, "section": sec},
            ))

        return findings
