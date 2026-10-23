"""
analyzers/pwn/checksec.py — Security mitigations analyzer for ELF binaries.

Uses pyelftools directly (no backend needed) to check:
  NX, PIE, Stack Canary, RELRO (none/partial/full), FORTIFY.

Each mitigation becomes a separate Finding so reporters can display
them in a structured table.

References
----------
* checksec.sh by Tobias Klein / Brian Davis
* https://github.com/slimm609/checksec.sh
"""

from __future__ import annotations

import traceback
from pathlib import Path

from corvida.analyzers.base import BaseAnalyzer
from corvida.core.config import Config
from corvida.core.models import (
    Category, Confidence, Finding, Severity, Target,
)
from corvida.core.registry import register_analyzer


def _get_elftools():
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSection
        return ELFFile, DynamicSection
    except ImportError:
        return None, None


def _has_symbol(elf, name: str) -> bool:
    """Check if a symbol exists in .dynsym or .symtab."""
    for sec_name in (".dynsym", ".symtab"):
        sec = elf.get_section_by_name(sec_name)
        if sec is None:
            continue
        try:
            if sec.get_symbol_by_name(name):
                return True
        except Exception:  # noqa: BLE001
            pass
    return False


def _check_nx(elf) -> bool:
    """NX: GNU_STACK segment must be non-executable (flags & PF_X == 0)."""
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_GNU_STACK":
            return (seg.header.p_flags & 0x1) == 0   # PF_X bit
    return False   # No GNU_STACK → assume NX off (conservative)


def _check_canary(elf) -> bool:
    """Stack canary: binary references __stack_chk_fail."""
    return _has_symbol(elf, "__stack_chk_fail")


def _check_relro(elf) -> str:
    """
    RELRO level.

    Returns "full", "partial", or "none".
    """
    has_relro_seg = False
    has_bind_now = False

    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_GNU_RELRO":
            has_relro_seg = True
            break

    # Check BIND_NOW or FLAGS_1=DF_1_NOW in dynamic section
    for sec in elf.iter_sections():
        try:
            from elftools.elf.dynamic import DynamicSection
            if not isinstance(sec, DynamicSection):
                continue
            for tag in sec.iter_tags():
                if tag.entry.d_tag == "DT_BIND_NOW":
                    has_bind_now = True
                elif tag.entry.d_tag == "DT_FLAGS":
                    if tag.entry.d_val & 0x8:   # DF_BIND_NOW
                        has_bind_now = True
                elif tag.entry.d_tag == "DT_FLAGS_1":
                    if tag.entry.d_val & 0x1:   # DF_1_NOW
                        has_bind_now = True
        except Exception:  # noqa: BLE001
            continue

    if has_relro_seg and has_bind_now:
        return "full"
    if has_relro_seg:
        return "partial"
    return "none"


def _check_fortify(elf) -> bool:
    """
    FORTIFY_SOURCE: look for __*_chk symbols in .dynsym.

    This is a heuristic — compile-time fortification affects symbol names.
    """
    chk_syms = ["__printf_chk", "__sprintf_chk", "__strcpy_chk",
                 "__memcpy_chk", "__gets_chk"]
    for sym in chk_syms:
        if _has_symbol(elf, sym):
            return True
    return False


@register_analyzer
class ChecksecAnalyzer(BaseAnalyzer):
    """Checks ELF security mitigations (NX, PIE, Canary, RELRO, FORTIFY)."""

    name     = "checksec"
    category = Category.PROTECTIONS
    supports = ["ELF"]
    requires_backend = False

    def analyze(
        self, target: Target, config: Config, backend=None
    ) -> list[Finding]:
        ELFFile, _ = _get_elftools()
        if ELFFile is None:
            return [self._error_finding(
                "checksec skipped",
                "pyelftools not installed. Run: pip install pyelftools",
            )]

        try:
            with open(target.path, "rb") as fh:
                elf = ELFFile(fh)
                return self._run(target, elf)
        except Exception as exc:   # noqa: BLE001
            return [self._error_finding(
                "checksec error",
                f"{exc}\n{traceback.format_exc()}" if config.verbose else str(exc),
            )]

    def _run(self, target: Target, elf) -> list[Finding]:
        findings: list[Finding] = []

        nx = _check_nx(elf)
        findings.append(Finding(
            title    = f"NX: {'enabled' if nx else 'DISABLED'}",
            category = Category.PROTECTIONS,
            severity = Severity.INFO if nx else Severity.HIGH,
            confidence = Confidence.CERTAIN,
            location = "PT_GNU_STACK",
            evidence = ["Stack is non-executable" if nx else "Stack is EXECUTABLE — shellcode possible"],
            advice   = None if nx else "Stack is executable; shellcode injection may be viable.",
            extra    = {"key": "nx", "value": nx},
        ))

        pie = target.is_pie
        findings.append(Finding(
            title    = f"PIE: {'enabled' if pie else 'DISABLED'}",
            category = Category.PROTECTIONS,
            severity = Severity.INFO if pie else Severity.MEDIUM,
            confidence = Confidence.CERTAIN,
            location = "ELF header e_type",
            evidence = ["ET_DYN → PIE" if pie else "ET_EXEC → no ASLR on binary itself"],
            advice   = None if pie else "No PIE: binary base address is fixed; simplifies ROP.",
            extra    = {"key": "pie", "value": pie},
        ))

        canary = _check_canary(elf)
        findings.append(Finding(
            title    = f"Stack Canary: {'present' if canary else 'ABSENT'}",
            category = Category.PROTECTIONS,
            severity = Severity.INFO if canary else Severity.HIGH,
            confidence = Confidence.HIGH,
            location = "__stack_chk_fail symbol",
            evidence = ["__stack_chk_fail found in dynamic symbols" if canary
                        else "__stack_chk_fail NOT found"],
            advice   = None if canary else "No stack canary: stack overflow may overwrite return address directly.",
            extra    = {"key": "canary", "value": canary},
        ))

        relro = _check_relro(elf)
        relro_sev = {
            "full":    Severity.INFO,
            "partial": Severity.LOW,
            "none":    Severity.MEDIUM,
        }[relro]
        findings.append(Finding(
            title    = f"RELRO: {relro.upper()}",
            category = Category.PROTECTIONS,
            severity = relro_sev,
            confidence = Confidence.HIGH,
            location = "PT_GNU_RELRO / DT_BIND_NOW",
            evidence = [f"RELRO level detected: {relro}"],
            advice   = (
                "No RELRO: GOT is writable — GOT overwrite attacks viable." if relro == "none"
                else "Partial RELRO: GOT partially writable (PLT section still attackable)." if relro == "partial"
                else None
            ),
            extra    = {"key": "relro", "value": relro},
        ))

        fortify = _check_fortify(elf)
        findings.append(Finding(
            title    = f"FORTIFY: {'enabled' if fortify else 'not detected'}",
            category = Category.PROTECTIONS,
            severity = Severity.INFO,
            confidence = Confidence.MEDIUM,
            location = "__*_chk symbols",
            evidence = ["__*_chk symbols found" if fortify else "No __*_chk symbols detected"],
            advice   = None,
            extra    = {"key": "fortify", "value": fortify},
        ))

        return findings
