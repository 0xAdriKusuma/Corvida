"""
model/_runner.py — Main AI layer orchestrator.

This is the only public entry point for the AI layer.
Called by cli.py after the rule-based pipeline completes.

Flow
----
1. Load AIConfig from corvida.yaml (or explicit path).
2. Check privacy policy.
3. Build context from Report.
4. Check cache; if hit, return cached result.
5. Call summariser → validate output.
6. Run deterministic validators on claims.
7. Call verifier (different model if possible) → enrich claims.
8. Write result to cache.
9. Return AIResult.

If ANY step fails (config missing, all models exhausted, …), returns None
and sets a human-readable error message — the caller must degrade gracefully.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from corvida.core.config import Config
from corvida.core.errors import AIConfigError, ProviderError
from corvida.core.models import Report

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class AIResult:
    """All AI-layer outputs for one analysis run."""

    summary:         str
    likely_vulns:    list[dict[str, Any]]   = field(default_factory=list)
    """Vulnerability claims with verification status attached."""

    next_steps:      list[str]              = field(default_factory=list)
    confidence:      str                    = "low"

    summarizer_model:  str                  = ""
    summarizer_provider: str                = ""
    verifier_model:    str                  = ""
    verifier_provider: str                  = ""

    fallback_log:    list[str]              = field(default_factory=list)
    truncation_notes: list[str]             = field(default_factory=list)

    verified_count:  int                    = 0
    total_claims:    int                    = 0

    from_cache:      bool                   = False

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for JSON output."""
        return {
            "summary":           self.summary,
            "likely_vulns":      self.likely_vulns,
            "next_steps":        self.next_steps,
            "confidence":        self.confidence,
            "verification":      {
                "verified":  self.verified_count,
                "total":     self.total_claims,
            },
            "models_used": {
                "summarizer": f"{self.summarizer_provider}/{self.summarizer_model}",
                "verifier":   f"{self.verifier_provider}/{self.verifier_model}",
            },
            "fallback_log":       self.fallback_log,
            "truncation_notes":   self.truncation_notes,
            "from_cache":         self.from_cache,
        }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_ai(report: Report, config: Config) -> AIResult | None:
    """
    Run the full AI analysis layer on *report*.

    Returns None (never raises) if:
    - AI is disabled (config.ai_enabled is False)
    - Config file is missing
    - All providers fail

    The caller is responsible for degrading gracefully and notifying the user.
    """
    if not config.ai_enabled:
        return None

    try:
        return _run_ai_inner(report, config)
    except AIConfigError as exc:
        logger.warning("AI layer: config error: %s", exc)
        _print_ai_unavailable(str(exc))
        return None
    except Exception as exc:
        logger.warning("AI layer: unexpected error: %s", exc, exc_info=True)
        _print_ai_unavailable(f"Unexpected error: {exc}")
        return None


def _run_ai_inner(report: Report, config: Config) -> AIResult | None:
    from corvida.model import cache
    from corvida.model.client import build_provider
    from corvida.model.config import load_ai_config
    from corvida.model.context_builder import build_context
    from corvida.model.router import Router
    from corvida.model.summarizer import run_summarizer
    from corvida.model.verifier import run_verifier

    # 1. Load config
    ai_cfg = load_ai_config(config.ai_config_path)

    # 2. Build providers
    providers = {
        name: build_provider(pcfg, debug=config.ai_debug)
        for name, pcfg in ai_cfg.providers.items()
    }

    # 3. Build router
    router = Router(
        ai_config=ai_cfg,
        providers=providers,
        local_only=config.ai_local_only,
        debug=config.ai_debug,
        yes=config.ai_yes,
    )

    # 4. Build context
    ctx = build_context(
        report=report,
        max_tokens=ai_cfg.policy.max_context_tokens,
        exclude_strings=config.ai_exclude_strings,
    )

    # 5. Check cache
    cache_key: str | None = None
    if ai_cfg.policy.cache and not config.ai_no_cache:
        # We use a lightweight key based on context + role combo
        # Prompt version is fetched lazily
        try:
            from corvida.model.prompts import load_prompt
            _, pv_sum = load_prompt("summarizer")
            _, pv_ver = load_prompt("verifier")
            chain_sum = ai_cfg.roles.get("summarizer", [])
            first_model = chain_sum[0].model if chain_sum else "unknown"
            first_prov  = chain_sum[0].provider if chain_sum else "unknown"
            cache_key = cache.make_key(
                context=ctx,
                role="full",
                model=first_model,
                prompt_version=f"{pv_sum}+{pv_ver}",
                provider=first_prov,
            )
            cached = cache.read(cache_key)
            if cached:
                logger.info("AI layer: cache HIT")
                return _from_cache(cached)
        except Exception as exc:  # noqa: BLE001
            logger.debug("cache check failed: %s", exc)

    # 6. Run summariser
    try:
        summary_dict, sum_result = run_summarizer(ctx, router)
    except ProviderError as exc:
        _print_ai_unavailable(f"Summariser: {exc}")
        return None
    except ValueError as exc:
        _print_ai_unavailable(f"Summariser output invalid: {exc}")
        return None

    # 7. Run verifier
    enriched_claims: list[dict[str, Any]] = []
    ver_result = None
    try:
        enriched_claims, ver_result = run_verifier(
            context=ctx,
            summary=summary_dict,
            report=report,
            router=router,
            summary_provider=sum_result.provider_name,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Verifier failed (non-fatal): %s", exc)

    # 8. Build result
    verified_count = sum(
        1 for c in enriched_claims if c.get("verified") == "supported"
    )
    total_claims   = len(enriched_claims)

    result = AIResult(
        summary=summary_dict.get("summary", ""),
        likely_vulns=enriched_claims,
        next_steps=summary_dict.get("next_steps", []),
        confidence=summary_dict.get("confidence", "low"),
        summarizer_model=sum_result.model,
        summarizer_provider=sum_result.provider_name,
        verifier_model=ver_result.model if ver_result else "",
        verifier_provider=ver_result.provider_name if ver_result else "",
        fallback_log=(sum_result.fallback_log
                      + (ver_result.fallback_log if ver_result else [])),
        truncation_notes=ctx.get("truncation_notes", []),
        verified_count=verified_count,
        total_claims=total_claims,
    )

    # 9. Write to cache
    if cache_key and ai_cfg.policy.cache and not config.ai_no_cache:
        try:
            cache.write(cache_key, result.to_dict())
        except Exception as exc:  # noqa: BLE001
            logger.debug("cache write failed: %s", exc)

    return result


def _from_cache(data: dict[str, Any]) -> AIResult:
    """Reconstruct AIResult from cached dict."""
    likely_vulns = data.get("likely_vulns", [])
    verified_count = sum(1 for c in likely_vulns if c.get("verified") == "supported")
    models = data.get("models_used", {})
    sum_mv = models.get("summarizer", "/").split("/", 1)
    ver_mv = models.get("verifier",   "/").split("/", 1)
    return AIResult(
        summary=data.get("summary", ""),
        likely_vulns=likely_vulns,
        next_steps=data.get("next_steps", []),
        confidence=data.get("confidence", "low"),
        summarizer_provider=sum_mv[0] if len(sum_mv) > 1 else "",
        summarizer_model=sum_mv[1] if len(sum_mv) > 1 else sum_mv[0],
        verifier_provider=ver_mv[0] if len(ver_mv) > 1 else "",
        verifier_model=ver_mv[1] if len(ver_mv) > 1 else ver_mv[0],
        fallback_log=data.get("fallback_log", []),
        truncation_notes=data.get("truncation_notes", []),
        verified_count=verified_count,
        total_claims=len(likely_vulns),
        from_cache=True,
    )


def _print_ai_unavailable(reason: str) -> None:
    import sys
    print(
        f"\n[corvida] AI layer unavailable: {reason}\n"
        "         Rule-based results shown above are still valid.\n",
        file=sys.stderr,
    )
