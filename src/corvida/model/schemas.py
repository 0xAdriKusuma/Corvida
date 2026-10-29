"""
model/schemas.py — Pydantic schemas for AI output validation.

All AI responses are JSON that must validate against these schemas before
being used.  Unknown extra fields are allowed (ignored) for forward compat.

If pydantic is not installed, a lightweight fallback validator is used that
checks only required top-level keys.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Try to import pydantic; fall back gracefully
# ---------------------------------------------------------------------------

try:
    from pydantic import BaseModel, Field, field_validator

    class _LikelyVuln(BaseModel):
        """A vulnerability claim from the summariser."""
        model_config = {"extra": "ignore"}

        finding_id:   str
        description:  str
        how_to_verify: str = ""

    class SummaryOutput(BaseModel):
        """Expected JSON output from the summariser role."""
        model_config = {"extra": "ignore"}

        summary:       str
        likely_vulns:  list[_LikelyVuln] = Field(default_factory=list)
        next_steps:    list[str]         = Field(default_factory=list)
        confidence:    str               = "low"   # high / medium / low

        @field_validator("confidence")
        @classmethod
        def _check_conf(cls, v: str) -> str:
            allowed = {"high", "medium", "low"}
            if v.lower() not in allowed:
                return "low"
            return v.lower()

    class _Claim(BaseModel):
        """A single claim from the summariser to be verified."""
        model_config = {"extra": "ignore"}

        finding_id:  str
        description: str
        status:      str = "unclear"   # supported / unsupported / unclear

        @field_validator("status")
        @classmethod
        def _check_status(cls, v: str) -> str:
            allowed = {"supported", "unsupported", "unclear"}
            return v.lower() if v.lower() in allowed else "unclear"

    class VerifierOutput(BaseModel):
        """Expected JSON output from the verifier role."""
        model_config = {"extra": "ignore"}

        claims: list[_Claim] = Field(default_factory=list)

    _PYDANTIC_AVAILABLE = True

except ImportError:
    _PYDANTIC_AVAILABLE = False

    # Minimal fallback dicts — no pydantic required for basic operation
    SummaryOutput  = None  # type: ignore[assignment, misc]
    VerifierOutput = None  # type: ignore[assignment, misc]


# ---------------------------------------------------------------------------
# Public validation helpers (work regardless of pydantic availability)
# ---------------------------------------------------------------------------

def validate_summary(data: dict[str, Any]) -> dict[str, Any]:
    """
    Validate and normalise a summary dict.

    Returns a plain dict (not a pydantic model) for easy JSON serialisation.
    Raises ValueError on missing required keys.
    """
    if _PYDANTIC_AVAILABLE:
        m = SummaryOutput.model_validate(data)
        return m.model_dump()
    return _fallback_validate_summary(data)


def validate_verifier(data: dict[str, Any]) -> dict[str, Any]:
    """
    Validate and normalise a verifier output dict.

    Returns a plain dict.
    """
    if _PYDANTIC_AVAILABLE:
        m = VerifierOutput.model_validate(data)
        return m.model_dump()
    return _fallback_validate_verifier(data)


# ---------------------------------------------------------------------------
# Fallback validators (no pydantic)
# ---------------------------------------------------------------------------

def _fallback_validate_summary(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise TypeError("Summary output must be a JSON object")
    if "summary" not in data:
        raise ValueError("Summary output missing required key: 'summary'")
    return {
        "summary":      str(data.get("summary", "")),
        "likely_vulns": [
            {
                "finding_id":    str(v.get("finding_id", "")),
                "description":   str(v.get("description", "")),
                "how_to_verify": str(v.get("how_to_verify", "")),
            }
            for v in (data.get("likely_vulns") or [])
            if isinstance(v, dict)
        ],
        "next_steps": [str(s) for s in (data.get("next_steps") or []) if s],
        "confidence": str(data.get("confidence", "low")).lower(),
    }


def _fallback_validate_verifier(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise TypeError("Verifier output must be a JSON object")
    return {
        "claims": [
            {
                "finding_id":  str(c.get("finding_id", "")),
                "description": str(c.get("description", "")),
                "status":      str(c.get("status", "unclear")).lower(),
            }
            for c in (data.get("claims") or [])
            if isinstance(c, dict)
        ]
    }
