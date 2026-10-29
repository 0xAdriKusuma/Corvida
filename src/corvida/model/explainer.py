"""
model/explainer.py — Code explainer role (optional).

Explains pseudo-C decompilation of key functions.
Only called when the backend provides function pseudo-code.
Currently a stub — wired to the prompt but not called by the main pipeline
unless a backend provides pseudo-C snippets.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from corvida.model.prompts import load_prompt
from corvida.model.router import Router, RouterResult

logger = logging.getLogger(__name__)


def run_explainer(
    function_snippet: str,
    function_name:    str,
    context:          dict[str, Any],
    router:           Router,
) -> tuple[dict[str, Any] | None, RouterResult | None]:
    """
    Explain a decompiled function snippet.

    Returns (explanation_dict, router_result) or (None, None) on failure.
    This is opportunistic — failure here never blocks the main pipeline.
    """
    system_prompt, _version = load_prompt("explainer")

    user_content = json.dumps({
        "target":    context.get("target", {}),
        "function":  {"name": function_name, "code": function_snippet},
    }, indent=2, ensure_ascii=False)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_content},
    ]

    try:
        result = router.call("code_explainer", messages)
        data   = _parse_explainer(result.content)
        return data, result
    except Exception as exc:  # noqa: BLE001
        logger.debug("Explainer failed (non-fatal): %s", exc)
        return None, None


def _parse_explainer(raw: str) -> dict[str, Any]:
    for text in [raw, _extract_json(raw)]:
        if text is None:
            continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            continue
    return {"summary": raw[:500], "dangerous_operations": [], "exploit_hint": "parse error"}


def _extract_json(text: str) -> str | None:
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        return m.group(1)
    m = re.search(r"(\{.*\})", text, re.DOTALL)
    if m:
        return m.group(1)
    return None
