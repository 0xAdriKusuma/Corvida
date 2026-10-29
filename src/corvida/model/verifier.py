"""
model/verifier.py — Verifier role: second LLM cross-checks summariser claims.

Design
------
* Uses a DIFFERENT model from the summariser where possible.
* Receives the context + list of claims (from summariser output).
* Returns per-claim status: supported / unsupported / unclear.
* Also applies deterministic pre-check (validators.py) before calling LLM.
* Claims that fail deterministic check are marked "unsupported" immediately.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from corvida.core.models import Report
from corvida.model import schemas
from corvida.model.prompts import load_prompt
from corvida.model.router import Router, RouterResult
from corvida.model.validators import ClaimValidation, validate_claims

logger = logging.getLogger(__name__)


def run_verifier(
    context:       dict[str, Any],
    summary:       dict[str, Any],
    report:        Report,
    router:        Router,
    summary_provider: str,
) -> tuple[list[dict[str, Any]], RouterResult | None]:
    """
    Verify each claim in *summary* against *context* and *report*.

    Parameters
    ----------
    context:
        The same context dict passed to the summariser.
    summary:
        Validated summariser output dict.
    report:
        The original Report (for deterministic validation).
    router:
        Router instance (will prefer a different provider from summariser).
    summary_provider:
        Provider name that generated the summary — verifier will avoid it.

    Returns
    -------
    (enriched_claims, router_result)
        enriched_claims: list of dicts with keys:
            finding_id, description, det_valid, det_flags,
            llm_status, verified
        router_result: RouterResult or None if LLM skipped/failed.
    """
    raw_claims = summary.get("likely_vulns", [])
    if not raw_claims:
        return [], None

    # Step 1: deterministic pre-check
    det_results: list[ClaimValidation] = validate_claims(raw_claims, report)

    # Step 2: prepare claims for LLM verification
    system_prompt, _version = load_prompt("verifier")
    user_content = json.dumps({
        "context": {
            "target":    context.get("target", {}),
            "findings":  context.get("findings", []),
        },
        "claims": [
            {"finding_id": c.finding_id, "description": c.description}
            for c in det_results
        ],
    }, indent=2, ensure_ascii=False)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_content},
    ]

    llm_statuses: dict[str, str] = {}
    router_result: RouterResult | None = None

    try:
        # Prefer a different provider from the summariser
        router_result = router.call("verifier", messages)
        parsed        = _parse_verifier_output(router_result.content)
        validated     = schemas.validate_verifier(parsed)
        for claim in validated.get("claims", []):
            fid = claim.get("finding_id", "")
            if fid:
                llm_statuses[fid] = claim.get("status", "unclear")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Verifier LLM call failed: %s — using deterministic results only", exc)

    # Step 3: merge deterministic + LLM results
    enriched: list[dict[str, Any]] = []
    for det in det_results:
        llm_status = llm_statuses.get(det.finding_id, "unclear")

        # Final verdict: if deterministic says invalid, mark unsupported
        if not det.valid:
            final_verified = "unsupported"
        elif llm_status == "supported":
            final_verified = "supported"
        elif llm_status == "unsupported":
            final_verified = "unsupported"
        else:
            final_verified = "unclear"

        enriched.append({
            "finding_id":  det.finding_id,
            "description": det.description,
            "det_valid":   det.valid,
            "det_flags":   det.flags,
            "llm_status":  llm_status,
            "verified":    final_verified,
        })

    return enriched, router_result


def _parse_verifier_output(raw: str) -> dict[str, Any]:
    """Extract JSON from verifier response."""
    for text in [raw, _extract_json(raw)]:
        if text is None:
            continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            continue
    raise ValueError("Verifier: could not parse JSON from model response")


def _extract_json(text: str) -> str | None:
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        return m.group(1)
    m = re.search(r"(\{.*\})", text, re.DOTALL)
    if m:
        return m.group(1)
    return None
