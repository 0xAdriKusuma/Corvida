"""
model/validators.py — Deterministic (non-LLM) claim validation.

Checks AI claims against the actual facts in the report:
  * finding_id references must exist
  * address strings in claim descriptions must appear in findings
  * function names in claims must appear in findings

This runs WITHOUT calling any model — it's pure Python logic.
The output marks each claim as valid or flagged with a reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from corvida.core.models import Report

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ClaimValidation:
    """Result of validating a single AI claim against report facts."""
    finding_id:   str
    description:  str
    valid:        bool
    flags:        list[str] = field(default_factory=list)
    """Human-readable reasons why the claim was flagged (empty = clean)."""


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

_HEX_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{4,}")


def validate_claims(
    claims: list[dict[str, Any]],
    report: Report,
) -> list[ClaimValidation]:
    """
    Validate each claim against the facts in *report*.

    Parameters
    ----------
    claims:
        List of dicts with keys: finding_id, description, (optionally) status.
    report:
        The completed Report (findings must have .id assigned).

    Returns
    -------
    List of ClaimValidation, one per input claim.
    """
    known_ids = {f.id for f in report.findings if f.id}
    known_addresses: set[str] = set()
    for f in report.findings:
        if f.location:
            known_addresses.update(re.findall(r"0x[0-9a-fA-F]+", f.location))
        for ev in (f.evidence or []):
            known_addresses.update(re.findall(r"0x[0-9a-fA-F]+", str(ev)))

    known_func_names: set[str] = set()
    for f in report.findings:
        fn = f.extra.get("func_name")
        if fn:
            known_func_names.add(fn.lower())
        callers = f.extra.get("callers", [])
        for c in callers:
            known_func_names.add(str(c).lower())

    results: list[ClaimValidation] = []
    for claim in claims:
        fid   = str(claim.get("finding_id", ""))
        desc  = str(claim.get("description", ""))
        flags: list[str] = []

        # Check 1: finding_id must exist
        if fid and fid not in known_ids:
            flags.append(
                f"finding_id '{fid}' not found in report "
                f"(known: {sorted(known_ids)[:5]}…)"
            )

        # Check 2: addresses mentioned in description must appear in findings
        mentioned_addrs = set(re.findall(r"0x[0-9a-fA-F]{4,}", desc))
        bad_addrs = mentioned_addrs - known_addresses
        if bad_addrs:
            flags.append(
                f"address(es) {bad_addrs} mentioned in claim not found in any finding"
            )

        # Check 3: function names (common dangerous ones) must appear in findings
        # We look for words that appear in known_func_names
        desc_lower  = desc.lower()
        desc_words  = set(re.findall(r"\b[a-z_][a-z0-9_]{2,}\b", desc_lower))
        bad_funcs = desc_words & _COMMON_DANGEROUS_FUNCS - known_func_names
        if bad_funcs and known_func_names:  # only check if we have func data
            flags.append(
                f"function(s) {bad_funcs} mentioned in claim not found in dangerous-func findings"
            )

        results.append(ClaimValidation(
            finding_id=fid,
            description=desc,
            valid=len(flags) == 0,
            flags=flags,
        ))

    return results


# ---------------------------------------------------------------------------
# Common dangerous function names to check against
# ---------------------------------------------------------------------------

_COMMON_DANGEROUS_FUNCS: frozenset[str] = frozenset({
    "gets", "strcpy", "strcat", "sprintf", "vsprintf",
    "scanf", "fscanf", "sscanf", "printf", "fprintf",
    "system", "execve", "execl", "execvp", "popen",
    "malloc", "free", "realloc", "calloc",
    "read", "write", "fread", "fwrite",
    "memcpy", "memmove", "memset",
    "strlen", "strncpy", "strncat",
})
