"""
model/context_builder.py — Convert a Report into a compact, token-bounded
JSON context suitable for sending to an LLM.

Design principles
-----------------
* Only TEXT is sent — never the raw binary.
* Finding IDs (F0001…) are assigned here, stable within one run.
* Token budget is enforced by character ÷ 4 estimation (no heavy tokeniser).
* Truncation is deterministic and logged in context["truncation_notes"].
* Strings can be excluded entirely via config.ai_exclude_strings.

Output shape (JSON-serialisable dict)
--------------------------------------
{
  "target":   {sha256, name, arch, bits, stripped, pie, file_type, size},
  "protections": {nx, canary, relro, pie, fortify, ...},
  "findings": [
    {
      "id":         "F0001",
      "title":      "...",
      "severity":   "high",
      "confidence": "medium",
      "location":   "0x401234",
      "evidence":   ["..."],   # truncated to 2 items
      "advice":     "..."
    }, ...
  ],
  "strings_sample": ["...", ...],   # omitted if ai_exclude_strings
  "truncation_notes": ["3 findings omitted (token budget)"],
  "total_findings": 42
}
"""

from __future__ import annotations

import json
import logging
from typing import Any

from corvida.core.models import Category, Report

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token estimation
# ---------------------------------------------------------------------------

def _estimate_tokens(text: str) -> int:
    """Rough token estimate: characters ÷ 4."""
    return max(1, len(text) // 4)


def _budget_remaining(used_chars: int, max_tokens: int) -> int:
    """Remaining character budget."""
    return max(0, max_tokens * 4 - used_chars)


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

_MAX_EVIDENCE_PER_FINDING = 2
_MAX_STRINGS              = 10


def build_context(
    report:             Report,
    max_tokens:         int  = 6000,
    exclude_strings:    bool = False,
) -> dict[str, Any]:
    """
    Convert *report* into a compact context dict.

    Assigns Finding.id in-place (F0001, F0002, …) for all findings.
    Returns the dict and sets any truncation notes inside it.
    """
    truncation_notes: list[str] = []

    # Assign stable IDs to all findings (in score order for consistency)
    sorted_findings = report.sorted_by_score()
    for i, f in enumerate(sorted_findings, start=1):
        f.id = f"F{i:04d}"

    ctx: dict[str, Any] = {
        "target":           _build_target(report),
        "protections":      _build_protections(report),
        "findings":         [],
        "strings_sample":   [],
        "truncation_notes": truncation_notes,
        "total_findings":   len(report.findings),
    }

    # Reserve space for target + protections
    header_json  = json.dumps({"target": ctx["target"], "protections": ctx["protections"]})
    used_chars   = len(header_json) + 200  # overhead buffer

    # Add findings (sorted by score, already ID-assigned)
    findings_added   = 0
    findings_skipped = 0
    analysis_findings = [
        f for f in sorted_findings
        if f.category not in (Category.STRINGS,)
    ]

    for f in analysis_findings:
        entry = {
            "id":         f.id,
            "title":      f.title,
            "severity":   f.severity.value,
            "confidence": f.confidence.value,
            "location":   f.location,
            "evidence":   (f.evidence or [])[:_MAX_EVIDENCE_PER_FINDING],
            "advice":     f.advice,
        }
        entry_json = json.dumps(entry)
        if _budget_remaining(used_chars + len(entry_json), max_tokens) <= 0:
            findings_skipped += 1
            continue
        ctx["findings"].append(entry)
        used_chars += len(entry_json)
        findings_added += 1

    if findings_skipped > 0:
        note = f"{findings_skipped} finding(s) omitted to stay within token budget"
        truncation_notes.append(note)
        logger.debug("context_builder: %s", note)

    # Add strings sample (optional)
    if not exclude_strings:
        string_findings = [
            f for f in sorted_findings
            if f.category == Category.STRINGS
        ]
        strings_added = 0
        for f in string_findings[:_MAX_STRINGS]:
            s = f.extra.get("string", f.title)
            s_repr = repr(s[:80])
            if _budget_remaining(used_chars + len(s_repr), max_tokens) <= 0:
                break
            ctx["strings_sample"].append(s[:80])
            used_chars += len(s_repr)
            strings_added += 1

        omitted_strings = len(string_findings) - strings_added
        if omitted_strings > 0:
            note = f"{omitted_strings} interesting string(s) omitted (budget/limit)"
            truncation_notes.append(note)
            logger.debug("context_builder: %s", note)

    return ctx


# ---------------------------------------------------------------------------
# Sub-builders
# ---------------------------------------------------------------------------

def _build_target(report: Report) -> dict[str, Any]:
    t = report.target
    return {
        "name":      t.name,
        "sha256":    t.sha256,
        "size":      t.size,
        "arch":      t.arch,
        "bits":      t.bits,
        "file_type": t.file_type,
        "stripped":  t.is_stripped,
        "pie":       t.is_pie,
        "interpreter": t.interpreter,
    }


def _build_protections(report: Report) -> dict[str, Any]:
    prots: dict[str, Any] = {}
    for f in report.by_category(Category.PROTECTIONS):
        key = f.extra.get("key")
        val = f.extra.get("value")
        if key is not None:
            prots[key] = val
    return prots
