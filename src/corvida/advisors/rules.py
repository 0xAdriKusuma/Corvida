"""
advisors/rules.py — Rule-based advisory system.

Reads the current Report (after all analyzers have run) and produces
high-level Finding objects of category=ADVISORY summarising attack paths.

Rules are evaluated in order; each rule can fire at most once.
Rules are simple Python dataclasses here (not YAML) because they express
*relationships between findings*, not properties of specific functions.
Extracting them to YAML would require a mini-language; the dataclass
approach is clearer and easier to test.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from corvida.core.config import Config
from corvida.core.models import (
    Category, Confidence, Finding, Report, Severity,
)


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------

@dataclass
class AdvisoryRule:
    """A single advisory rule."""
    name:       str
    title:      str
    severity:   Severity
    confidence: Confidence
    advice:     str
    condition:  Callable[[Report], bool]
    tags:       list[str]


# ---------------------------------------------------------------------------
# Helpers for rule conditions
# ---------------------------------------------------------------------------

def _prot(report: Report, key: str) -> bool | str | None:
    """Return the 'value' extra field for a protection finding keyed by 'key'."""
    for f in report.by_category(Category.PROTECTIONS):
        if f.extra.get("key") == key:
            return f.extra.get("value")
    return None


def _nx(r: Report) -> bool:
    v = _prot(r, "nx")
    return bool(v) if v is not None else True   # assume on if unknown


def _canary(r: Report) -> bool:
    v = _prot(r, "canary")
    return bool(v) if v is not None else True


def _pie(r: Report) -> bool:
    v = _prot(r, "pie")
    return bool(v) if v is not None else True


def _relro(r: Report) -> str:
    v = _prot(r, "relro")
    return str(v) if v else "full"


def _has_dangerous_tag(report: Report, *tags: str) -> bool:
    for f in report.by_category(Category.DANGEROUS_FUNC):
        for tag in tags:
            if tag in f.extra.get("tags", []):
                return True
    return False


def _has_func(report: Report, name: str) -> bool:
    """Check if a dangerous import with given func_name is in findings."""
    for f in report.by_category(Category.DANGEROUS_FUNC):
        if f.extra.get("func_name", "").lower() == name.lower():
            return True
    return False


def _has_string(report: Report, pattern: str) -> bool:
    import re
    for f in report.by_category(Category.STRINGS):
        s = f.extra.get("string", "")
        if re.search(pattern, s, re.IGNORECASE):
            return True
    return False


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

_RULES: list[AdvisoryRule] = [

    AdvisoryRule(
        name       = "ret2win_candidate",
        title      = "Attack path: ret2win candidate",
        severity   = Severity.HIGH,
        confidence = Confidence.HIGH,
        advice     = (
            "No canary + no PIE = predictable stack & addresses. "
            "Overflow the buffer and overwrite the return address with a win function. "
            "Look for functions like 'win', 'backdoor', 'flag', or 'get_flag'."
        ),
        condition  = lambda r: (
            not _canary(r)
            and not _pie(r)
            and _has_dangerous_tag(r, "stack_overflow")
        ),
        tags = ["ret2win", "stack_overflow"],
    ),

    AdvisoryRule(
        name       = "ret2libc_candidate",
        title      = "Attack path: ret2libc candidate",
        severity   = Severity.HIGH,
        confidence = Confidence.HIGH,
        advice     = (
            "NX is on (no shellcode) but no canary. "
            "Stack overflow is likely; pivot to ret2libc via 'system' or 'execve'. "
            "Leak a libc address first if PIE/ASLR is active."
        ),
        condition  = lambda r: (
            _nx(r)
            and not _canary(r)
            and _has_dangerous_tag(r, "stack_overflow")
            and (_has_func(r, "system") or _has_func(r, "execve"))
        ),
        tags = ["ret2libc", "stack_overflow"],
    ),

    AdvisoryRule(
        name       = "shellcode_candidate",
        title      = "Attack path: shellcode injection candidate",
        severity   = Severity.CRITICAL,
        confidence = Confidence.HIGH,
        advice     = (
            "NX is DISABLED — stack is executable. "
            "Overflow the buffer and inject shellcode directly. "
            "Use pwntools shellcraft or write custom shellcode."
        ),
        condition  = lambda r: (
            not _nx(r)
            and not _canary(r)
            and _has_dangerous_tag(r, "stack_overflow")
        ),
        tags = ["shellcode", "stack_overflow"],
    ),

    AdvisoryRule(
        name       = "format_string_candidate",
        title      = "Attack path: format string vulnerability",
        severity   = Severity.HIGH,
        confidence = Confidence.MEDIUM,
        advice     = (
            "printf/fprintf found — check if format string is user-controlled "
            "(printf(buf) vs printf('%s', buf)). "
            "Use %p/%x to leak stack values, %n to write arbitrary addresses."
        ),
        condition  = lambda r: _has_dangerous_tag(r, "format_string"),
        tags = ["format_string", "info_leak"],
    ),

    AdvisoryRule(
        name       = "got_overwrite_candidate",
        title      = "Attack path: GOT overwrite candidate",
        severity   = Severity.HIGH,
        confidence = Confidence.MEDIUM,
        advice     = (
            "No/partial RELRO: GOT entries are writable. "
            "Combine with a write primitive (format string or heap write) "
            "to overwrite a GOT entry (e.g. free → system)."
        ),
        condition  = lambda r: (
            _relro(r) in ("none", "partial")
            and (
                _has_dangerous_tag(r, "format_string")
                or _has_dangerous_tag(r, "heap")
            )
        ),
        tags = ["got_overwrite"],
    ),

    AdvisoryRule(
        name       = "heap_exploitation_candidate",
        title      = "Attack path: heap exploitation candidate",
        severity   = Severity.MEDIUM,
        confidence = Confidence.MEDIUM,
        advice     = (
            "malloc/free detected — look for use-after-free (UAF), double-free, "
            "or heap overflow bugs. Check glibc version for available techniques "
            "(tcache poisoning, house-of-X, etc.)."
        ),
        condition  = lambda r: (
            _has_func(r, "malloc")
            and _has_func(r, "free")
        ),
        tags = ["heap", "uaf", "double_free"],
    ),

    AdvisoryRule(
        name       = "static_binary_rop",
        title      = "Note: statically linked binary — ROP within binary",
        severity   = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        advice     = (
            "No dynamic linker: ret2libc via PLT is not applicable. "
            "Use ROPgadget or ropper to find gadgets within the binary itself. "
            "Target syscall gadgets for ret2syscall (execve)."
        ),
        condition  = lambda r: r.target.interpreter is None and _has_dangerous_tag(r, "stack_overflow"),
        tags = ["rop", "ret2syscall"],
    ),

    AdvisoryRule(
        name       = "interesting_string_shell",
        title      = "Hint: /bin/sh string found in binary",
        severity   = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        advice     = (
            "/bin/sh is present in the binary. "
            "Its address can be used as argument to system() or execve() "
            "in a ret2libc/ROP chain — no need to inject the string yourself."
        ),
        condition  = lambda r: _has_string(r, r"/bin/sh|/bin/bash"),
        tags = ["ret2libc", "ret2win"],
    ),
]


# ---------------------------------------------------------------------------
# Advisor
# ---------------------------------------------------------------------------

class RulesAdvisor:
    """Evaluates advisory rules against a completed Report."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def advise(self, report: Report) -> list[Finding]:
        findings: list[Finding] = []
        for rule in _RULES:
            try:
                if rule.condition(report):
                    findings.append(Finding(
                        title      = rule.title,
                        category   = Category.ADVISORY,
                        severity   = rule.severity,
                        confidence = rule.confidence,
                        advice     = rule.advice,
                        evidence   = [f"Rule '{rule.name}' matched"],
                        extra      = {"rule": rule.name, "tags": rule.tags},
                    ))
            except Exception:   # noqa: BLE001
                pass   # advisory rules must never crash the pipeline
        return findings
