"""
model/summarizer.py — Summariser role: call LLM, parse and validate output.

Flow
----
1. Load the summarizer prompt (versioned .md file).
2. Build the user message from the context dict.
3. Call router.call("summarizer", messages).
4. Parse JSON from response (try once, then attempt a repair pass).
5. Validate schema with schemas.py.
6. If parse/validate fails, fall back to next model via router retry.
7. Return a validated dict or raise ProviderError if all models exhausted.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from corvida.model import schemas
from corvida.model.prompts import load_prompt
from corvida.model.router import Router, RouterResult

logger = logging.getLogger(__name__)


def run_summarizer(
    context: dict[str, Any],
    router:  Router,
) -> tuple[dict[str, Any], RouterResult]:
    """
    Call the summarizer role and return (validated_summary_dict, router_result).

    Raises
    ------
    ProviderError
        If every model in the chain fails or returns invalid output.
    """
    system_prompt, _version = load_prompt("summarizer")
    user_content = _build_user_message(context)

    messages = [
        {"role": "system",  "content": system_prompt},
        {"role": "user",    "content": user_content},
    ]

    # Try router — it handles fallback internally
    result = router.call("summarizer", messages)

    # Parse and validate output
    validated = _parse_and_validate(result.content, "summarizer")
    return validated, result


def _build_user_message(context: dict[str, Any]) -> str:
    return (
        "CONTEXT:\n"
        + json.dumps(context, indent=2, ensure_ascii=False)
    )


def _parse_and_validate(raw: str, role: str) -> dict[str, Any]:
    """
    Extract JSON from *raw*, validate schema, return clean dict.

    Attempt 1: parse the whole string as JSON.
    Attempt 2: extract the first JSON block (model may add prose).
    Raises ValueError on failure.
    """
    for attempt, text in enumerate([raw, _extract_json_block(raw)], start=1):
        if text is None:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.debug("%s: JSON parse failed on attempt %d", role, attempt)
            continue

        try:
            validated = schemas.validate_summary(data)
            return validated
        except (ValueError, Exception) as exc:  # noqa: BLE001
            logger.debug("%s: schema validation failed on attempt %d: %s", role, attempt, exc)
            continue

    raise ValueError(f"{role}: could not parse valid JSON from model response")


def _extract_json_block(text: str) -> str | None:
    """Try to extract the first ```json ... ``` block or bare {...} block."""
    # Try markdown code block first
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        return m.group(1)

    # Try bare JSON object
    m = re.search(r"(\{.*\})", text, re.DOTALL)
    if m:
        return m.group(1)

    return None
