"""
analyzers/pwn/binary_info.py — Basic ELF metadata analyzer.

Emits Finding objects for: arch, bits, stripped status, PIE, interpreter.
These findings have category=BINARY_INFO and severity=INFO.
They are the first things printed in the terminal reporter.
"""

from __future__ import annotations

from corvida.analyzers.base import BaseAnalyzer
from corvida.core.config import Config
from corvida.core.models import (
    Category, Confidence, Finding, Severity, Target,
)
from corvida.core.registry import register_analyzer


@register_analyzer
class BinaryInfoAnalyzer(BaseAnalyzer):
    """Emits basic ELF metadata as INFO findings."""

    name     = "binary_info"
    category = Category.BINARY_INFO
    supports = ["ELF"]
    requires_backend = False

    def analyze(
        self, target: Target, config: Config, backend=None
    ) -> list[Finding]:
        findings: list[Finding] = []

        arch_str = target.arch or "unknown"
        bits_str = str(target.bits) + "-bit" if target.bits else "unknown bits"
        endian   = target.endian or "unknown endian"

        findings.append(Finding(
            title      = f"Architecture: {arch_str} {bits_str} {endian}-endian",
            category   = Category.BINARY_INFO,
            severity   = Severity.INFO,
            confidence = Confidence.CERTAIN,
            evidence   = [f"ELF e_machine: {arch_str}, class: {bits_str}"],
            extra      = {"arch": target.arch, "bits": target.bits, "endian": endian},
        ))

        stripped = target.is_stripped
        findings.append(Finding(
            title      = f"Symbols: {'STRIPPED' if stripped else 'not stripped (has .symtab)'}",
            category   = Category.BINARY_INFO,
            severity   = Severity.INFO,
            confidence = Confidence.CERTAIN,
            evidence   = [
                "No .symtab section found — symbol names unavailable."
                if stripped else
                ".symtab section present — function names available."
            ],
            advice     = (
                "Binary is stripped: function names from analysis may be generic (fcn.xxxxx). "
                "Confidence of heuristics is reduced."
                if stripped else None
            ),
            extra      = {"stripped": stripped},
        ))

        pie = target.is_pie
        findings.append(Finding(
            title      = f"Type: {'PIE (ET_DYN)' if pie else 'executable (ET_EXEC)'}",
            category   = Category.BINARY_INFO,
            severity   = Severity.INFO,
            confidence = Confidence.CERTAIN,
            evidence   = ["ET_DYN" if pie else "ET_EXEC"],
            extra      = {"is_pie": pie},
        ))

        interp = target.interpreter
        findings.append(Finding(
            title      = f"Linker: {interp or 'statically linked'}",
            category   = Category.BINARY_INFO,
            severity   = Severity.INFO,
            confidence = Confidence.CERTAIN,
            evidence   = [f"PT_INTERP: {interp}" if interp else "No PT_INTERP — static binary"],
            advice     = (
                "Statically linked: ret2libc via GOT/PLT not directly applicable; "
                "look for gadgets within the binary itself."
                if not interp else None
            ),
            extra      = {"interpreter": interp, "static": interp is None},
        ))

        return findings
