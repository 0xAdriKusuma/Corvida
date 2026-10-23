"""
analyzers/pwn/dangerous_funcs.py — Dangerous function import analyzer.

For each import found by the backend, checks against rules/dangerous_functions.yaml.
If the function is dangerous:
  1. Creates a Finding with severity/confidence from the rules file.
  2. Queries the backend for cross-references (callers) and attaches them.

Requires a backend (rizin) for xref data.
Without a backend, falls back to pyelftools for import list only
(no caller information).
"""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Any

import yaml

from corvida.analyzers.base import BaseAnalyzer
from corvida.backends.base import BaseBackend
from corvida.core.config import Config
from corvida.core.errors import RuleError
from corvida.core.models import (
    Category, Confidence, Finding, Severity, Target,
)
from corvida.core.registry import register_analyzer


# ---------------------------------------------------------------------------
# Rules loader
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
}

_CONFIDENCE_MAP = {
    "certain": Confidence.CERTAIN,
    "high":    Confidence.HIGH,
    "medium":  Confidence.MEDIUM,
    "low":     Confidence.LOW,
}


def load_rules(rules_dir: Path) -> dict[str, dict]:
    """
    Load dangerous_functions.yaml and return a dict keyed by function name.

    All aliases are expanded into separate keys pointing to the same entry.
    """
    rules_file = rules_dir / "dangerous_functions.yaml"
    if not rules_file.exists():
        raise RuleError(
            f"Rules file not found: {rules_file}\n"
            "Make sure the 'rules/' directory is present in the project root."
        )

    with open(rules_file, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict) or "functions" not in data:
        raise RuleError(f"Invalid rules file schema: {rules_file}")

    result: dict[str, dict] = {}
    for entry in data["functions"]:
        name = entry.get("name", "")
        if not name:
            continue
        result[name] = entry
        for alias in entry.get("aliases", []):
            result[alias] = entry

    return result


# ---------------------------------------------------------------------------
# ELF import fallback (no backend)
# ---------------------------------------------------------------------------

def _get_imports_via_pyelftools(path: Path) -> list[dict[str, Any]]:
    """Parse ELF imports using pyelftools when backend is unavailable."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return []

    imports = []
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            for sec_name in (".dynsym",):
                sec = elf.get_section_by_name(sec_name)
                if sec is None:
                    continue
                for sym in sec.iter_symbols():
                    if sym.entry.st_shndx == "SHN_UNDEF" and sym.name:
                        imports.append({
                            "name": sym.name,
                            "plt":  None,
                            "type": sym.entry.st_info.type,
                            "bind": sym.entry.st_info.bind,
                        })
    except Exception:  # noqa: BLE001
        pass
    return imports


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@register_analyzer
class DangerousFuncsAnalyzer(BaseAnalyzer):
    """Identifies dangerous imported functions and their call sites."""

    name     = "dangerous_funcs"
    category = Category.DANGEROUS_FUNC
    supports = ["ELF"]
    requires_backend = False   # backend improves xref info but not required

    def analyze(
        self, target: Target, config: Config, backend: BaseBackend | None = None
    ) -> list[Finding]:
        # Load rules
        try:
            rules = load_rules(config.rules_dir)
        except RuleError as exc:
            return [self._error_finding("dangerous_funcs: rules error", str(exc))]

        # Get imports
        if backend is not None:
            try:
                imports = backend.imports()
            except Exception:   # noqa: BLE001
                imports = _get_imports_via_pyelftools(target.path)
        else:
            imports = _get_imports_via_pyelftools(target.path)

        findings: list[Finding] = []

        for imp in imports:
            func_name = imp.get("name", "").lstrip("_")   # strip leading _
            # Try exact match, then strip @GLIBC suffix
            rule = rules.get(func_name) or rules.get(func_name.split("@")[0])
            # Also try original name with leading underscores stripped
            if rule is None:
                orig = imp.get("name", "")
                rule = rules.get(orig) or rules.get(orig.split("@")[0])

            if rule is None:
                continue

            severity   = _SEVERITY_MAP.get(rule.get("severity", "low"),   Severity.LOW)
            confidence = _CONFIDENCE_MAP.get(rule.get("confidence", "medium"), Confidence.MEDIUM)
            description = rule.get("description", "").strip()
            advice      = rule.get("advice", "")
            tags        = rule.get("tags", [])

            # Cross-references (callers) — best-effort
            callers: list[str] = []
            plt_addr = imp.get("plt")
            if backend is not None and plt_addr:
                try:
                    xrefs = backend.xrefs_to(plt_addr)
                    for xr in xrefs[:5]:   # limit evidence lines
                        caller_addr = xr.get("from", 0)
                        fcn = xr.get("fcn_name", "")
                        callers.append(
                            f"called from {fcn} @ {caller_addr:#010x}"
                            if fcn else f"called from {caller_addr:#010x}"
                        )
                except Exception:  # noqa: BLE001
                    pass

            # If stripped and no xrefs, lower confidence
            if target.is_stripped and not callers:
                if confidence == Confidence.CERTAIN:
                    confidence = Confidence.HIGH
                elif confidence == Confidence.HIGH:
                    confidence = Confidence.MEDIUM

            evidence = [description] + callers
            location = (
                f"PLT @ {plt_addr:#010x}" if plt_addr
                else f"import: {imp.get('name', func_name)}"
            )

            findings.append(Finding(
                title      = f"Dangerous import: {imp.get('name', func_name)}()",
                category   = Category.DANGEROUS_FUNC,
                severity   = severity,
                confidence = confidence,
                location   = location,
                evidence   = evidence,
                advice     = advice,
                extra      = {
                    "func_name": func_name,
                    "plt":       plt_addr,
                    "callers":   callers,
                    "tags":      tags,
                    "category":  rule.get("category", ""),
                },
            ))

        return findings
