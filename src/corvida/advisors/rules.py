"""
advisors/rules.py — Rule-based advisory system.

Reads the current Report (after all analyzers have run) and produces
high-level Finding objects of category=ADVISORY summarising attack paths.

Rules are evaluated in order; each rule can fire at most once.
Rules are simple Python dataclasses here (not YAML) because they express
*relationships between findings*, not properties of specific functions.
Extracting them to YAML would require a mini-language; the dataclass
approach is clearer and easier to test.

Confidence semantics
--------------------
In advisory findings we use two separate confidence attributes:
  - confidence (presence_confidence):   How certain are we the vulnerability *exists*?
  - exploitability_confidence:          How easy is it to *exploit* it in practice?

The extra dict carries both so reporters and the AI layer can use them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from corvida.core.config import Config
from corvida.core.models import (
    Category, Confidence, Finding, Report, Severity,
)


@dataclass
class AdvisoryRule:
    """A single advisory rule."""
    name:                       str
    title:                      str
    severity:                   Severity
    confidence:                 Confidence   # presence_confidence
    exploitability_confidence:  Confidence   # how easy is exploitation
    advice:                     str
    condition:                  Callable[[Report], bool]
    tags:                       list[str]
    context_notes:              list[str]    # arch/prot-specific hints (added per match)


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


def _bits(r: Report) -> int | None:
    """Return architecture bitness from binary_info findings."""
    for f in r.by_category(Category.BINARY_INFO):
        if f.extra.get("key") == "bits":
            try:
                return int(f.extra["value"])
            except (KeyError, TypeError, ValueError):
                pass
    # Also check target directly
    bits = r.target.bits
    if bits:
        return int(bits)
    return None


def _is_32bit(r: Report) -> bool:
    return _bits(r) == 32


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


def _has_stack_overflow_func(report: Report) -> bool:
    """
    True if an import-only-dangerous function that can actually overflow the
    stack is present (gets, strcpy, strcat, sprintf, scanf, read without bounds).
    Excludes import-only functions like printf/puts whose exploitability
    depends entirely on usage context.
    """
    HIGH_RISK_OVERFLOW = {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "__isoc99_scanf"}
    for f in report.by_category(Category.DANGEROUS_FUNC):
        fn = f.extra.get("func_name", "").lower()
        if fn in HIGH_RISK_OVERFLOW and "stack_overflow" in f.extra.get("tags", []):
            return True
    return False


def _has_string(report: Report, pattern: str) -> bool:
    import re
    for f in report.by_category(Category.STRINGS):
        s = f.extra.get("string", "")
        if re.search(pattern, s, re.IGNORECASE):
            return True
    return False


def _context_notes_for(r: Report, base_notes: list[str]) -> list[str]:
    """
    Build context notes list, injecting arch/protection-specific hints.
    """
    notes = list(base_notes)
    if _is_32bit(r):
        notes.append("32-bit binary: function arguments passed on stack (not registers); "
                      "adjust ROP/ret2libc payload for cdecl calling convention.")
    if _nx(r) and not _canary(r) and _has_stack_overflow_func(r):
        if _pie(r):
            notes.append("PIE enabled: leak a binary/libc address first before building ROP chain.")
        else:
            notes.append("No PIE: binary base is fixed — gadget addresses are predictable.")
    if _relro(r) == "full":
        notes.append("Full RELRO: GOT is read-only — GOT overwrite is NOT viable; use ROP/ret2libc.")
    elif _relro(r) == "partial":
        notes.append("Partial RELRO: GOT is partially writable — GOT overwrite may work.")
    return notes


_RULES: list[AdvisoryRule] = [

    AdvisoryRule(
        name       = "stack_overflow_rop_32bit",
        title      = "Attack path: stack overflow → ROP (32-bit)",
        severity   = Severity.CRITICAL,
        confidence = Confidence.HIGH,
        exploitability_confidence = Confidence.HIGH,
        advice     = (
            "Classic 32-bit stack overflow: no canary + NX + stack overflow function. "
            "Build a ROP chain: gets/strcpy → overflow return address → ROP gadgets → shell. "
            "For ret2libc: find system() + '/bin/sh' in libc; pass them as stack args (cdecl)."
        ),
        condition  = lambda r: (
            _is_32bit(r)
            and not _canary(r)
            and _nx(r)
            and _has_stack_overflow_func(r)
        ),
        tags = ["ret2libc", "rop", "stack_overflow", "32bit"],
        context_notes = [],
    ),

    AdvisoryRule(
        name       = "ret2win_candidate",
        title      = "Attack path: ret2win candidate",
        severity   = Severity.HIGH,
        confidence = Confidence.HIGH,
        exploitability_confidence = Confidence.HIGH,
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
        context_notes = [],
    ),

    AdvisoryRule(
        name       = "ret2libc_candidate",
        title      = "Attack path: ret2libc candidate",
        severity   = Severity.HIGH,
        confidence = Confidence.HIGH,
        exploitability_confidence = Confidence.HIGH,
        advice     = (
            "NX is on (no shellcode) but no canary. "
            "Stack overflow is likely; pivot to ret2libc via 'system' or 'execve'. "
            "Leak a libc address first if PIE/ASLR is active."
        ),
        condition  = lambda r: (
            _nx(r)
            and not _canary(r)
            and _has_stack_overflow_func(r)
            and (_has_func(r, "system") or _has_func(r, "execve"))
        ),
        tags = ["ret2libc", "stack_overflow"],
        context_notes = [],
    ),

    AdvisoryRule(
        name       = "shellcode_candidate",
        title      = "Attack path: shellcode injection candidate",
        severity   = Severity.CRITICAL,
        confidence = Confidence.HIGH,
        exploitability_confidence = Confidence.HIGH,
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
        context_notes = [],
    ),

    AdvisoryRule(
        name       = "format_string_candidate",
        title      = "Attack path: format string vulnerability",
        severity   = Severity.HIGH,
        confidence = Confidence.MEDIUM,
        # printf/puts imported ≠ definitely exploitable — need to verify call site
        exploitability_confidence = Confidence.LOW,
        advice     = (
            "printf/fprintf found — check if format string is user-controlled "
            "(printf(buf) vs printf('%s', buf)). "
            "Use %p/%x to leak stack values, %n to write arbitrary addresses. "
            "NOTE: low exploitability confidence — import only; verify call site."
        ),
        condition  = lambda r: _has_dangerous_tag(r, "format_string"),
        tags = ["format_string", "info_leak"],
        context_notes = [],
    ),

    AdvisoryRule(
        name       = "got_overwrite_candidate",
        title      = "Attack path: GOT overwrite candidate",
        severity   = Severity.HIGH,
        confidence = Confidence.MEDIUM,
        exploitability_confidence = Confidence.MEDIUM,
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
        context_notes = [],
    ),

    AdvisoryRule(
        name       = "heap_exploitation_candidate",
        title      = "Attack path: heap exploitation candidate",
        severity   = Severity.MEDIUM,
        confidence = Confidence.MEDIUM,
        exploitability_confidence = Confidence.MEDIUM,
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
        context_notes = [],
    ),

    AdvisoryRule(
        name       = "static_binary_rop",
        title      = "Note: statically linked binary — ROP within binary",
        severity   = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        exploitability_confidence = Confidence.MEDIUM,
        advice     = (
            "No dynamic linker: ret2libc via PLT is not applicable. "
            "Use ROPgadget or ropper to find gadgets within the binary itself. "
            "Target syscall gadgets for ret2syscall (execve)."
        ),
        condition  = lambda r: r.target.interpreter is None and _has_dangerous_tag(r, "stack_overflow"),
        tags = ["rop", "ret2syscall"],
        context_notes = [],
    ),

    AdvisoryRule(
        name       = "interesting_string_shell",
        title      = "Hint: /bin/sh string found in binary",
        severity   = Severity.MEDIUM,
        confidence = Confidence.HIGH,
        exploitability_confidence = Confidence.HIGH,
        advice     = (
            "/bin/sh is present in the binary. "
            "Its address can be used as argument to system() or execve() "
            "in a ret2libc/ROP chain — no need to inject the string yourself."
        ),
        condition  = lambda r: _has_string(r, r"/bin/sh|/bin/bash"),
        tags = ["ret2libc", "ret2win"],
        context_notes = [],
    ),
]


class RulesAdvisor:
    """Evaluates advisory rules against a completed Report."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def advise(self, report: Report) -> list[Finding]:
        findings: list[Finding] = []
        for rule in _RULES:
            try:
                if rule.condition(report):
                    # Build context-aware notes
                    notes = _context_notes_for(report, rule.context_notes)
                    advice = rule.advice
                    if notes:
                        advice = advice + "\n\nContext: " + " | ".join(notes)

                    findings.append(Finding(
                        title      = rule.title,
                        category   = Category.ADVISORY,
                        severity   = rule.severity,
                        confidence = rule.confidence,
                        advice     = advice,
                        evidence   = [f"Rule '{rule.name}' matched"],
                        extra      = {
                            "rule":                      rule.name,
                            "tags":                      rule.tags,
                            "presence_confidence":       rule.confidence.value,
                            "exploitability_confidence": rule.exploitability_confidence.value,
                            "context_notes":             notes,
                        },
                    ))
            except Exception:   # noqa: BLE001
                pass   # advisory rules must never crash the pipeline
        return findings
