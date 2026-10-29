"""
model/router.py — Model selection, fallback chain, retry/backoff logic.

Responsibilities
----------------
* For a given role, try each (provider, model) pair in order.
* Move to the next pair on: timeout, HTTP 4xx/5xx, or invalid JSON output.
* Respect Retry-After header on 429 responses.
* Exponential backoff with a configurable cap for transient errors (5xx / network).
* 404 (model not found) and 401/403 (auth) are never retried — move to next.
* Record which model was ultimately used (for transparency in output).
* Never crash the caller — on full exhaustion raise ProviderError.

The router is intentionally stateless between calls; a new Router instance
should be created for each analysis run.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from corvida.core.errors import ProviderError
from corvida.model.client import (
    Provider,
    ProviderHTTPError,
    ProviderTimeoutError,
)
from corvida.model.config import AIConfig, ModelRef
from corvida.model.privacy import check_privacy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class RouterResult:
    """Outcome of a router.call() invocation."""
    content:       str
    provider_name: str
    model:         str
    attempts:      int
    fallback_log:  list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Retry configuration
# ---------------------------------------------------------------------------

_BASE_BACKOFF_S:  float = 1.0
_MAX_BACKOFF_S:   float = 30.0
_MAX_ATTEMPTS_PER_PROVIDER: int = 2  # tries per model before giving up on it

# Error kinds that should NOT be retried; move immediately to next model
_NO_RETRY_KINDS = frozenset({"auth_failed", "model_unavailable"})


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

class Router:
    """
    Routes AI calls through a chain of (provider, model) pairs per role.

    Parameters
    ----------
    ai_config:
        Validated AIConfig loaded from corvida.yaml.
    providers:
        Mapping provider_name → Provider instance.
        Inject MockProvider here during tests.
    local_only:
        If True, cloud providers are refused before the HTTP call.
    debug:
        If True, emit verbose DEBUG-level log lines for every attempt.
    """

    def __init__(
        self,
        ai_config:  AIConfig,
        providers:  dict[str, Provider],
        local_only: bool = False,
        debug:      bool = False,
        yes:        bool = False,
    ) -> None:
        self._cfg        = ai_config
        self._providers  = providers
        self._local_only = local_only
        self._debug      = debug
        self._yes        = yes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def call(
        self,
        role:        str,
        messages:    list[dict[str, str]],
        temperature: float | None = None,
        timeout:     int          = 60,
    ) -> RouterResult:
        """
        Call the model chain for *role* and return the first successful result.

        Parameters
        ----------
        role:
            One of the roles defined in corvida.yaml (e.g. "summarizer").
        messages:
            OpenAI-style message list (role/content dicts).
        temperature:
            Override policy temperature for this call.

        Raises
        ------
        ProviderError
            When every entry in the fallback chain has been exhausted.
        KeyError
            When *role* is not defined in the config.
        """
        chain = self._cfg.roles.get(role)
        if chain is None:
            raise KeyError(f"Role '{role}' is not defined in corvida.yaml")

        temp         = temperature if temperature is not None else self._cfg.policy.temperature
        fallback_log: list[str] = []
        total_attempts = 0

        for ref in chain:
            provider = self._providers.get(ref.provider)
            if provider is None:
                fallback_log.append(f"skip {ref.provider}/{ref.model}: provider not instantiated")
                continue

            # Privacy gate
            try:
                check_privacy(
                    provider,
                    self._local_only,
                    self._cfg.policy.sensitive_local_only,
                    yes=self._yes,
                )
            except Exception as exc:  # noqa: BLE001
                fallback_log.append(f"skip {ref.provider}/{ref.model}: {exc}")
                continue

            result = self._try_model(
                provider=provider,
                ref=ref,
                messages=messages,
                temperature=temp,
                timeout=timeout,
                fallback_log=fallback_log,
            )
            total_attempts += result["attempts"]

            if result["ok"]:
                return RouterResult(
                    content=result["content"],
                    provider_name=ref.provider,
                    model=ref.model,
                    attempts=total_attempts,
                    fallback_log=fallback_log,
                )

        raise ProviderError(
            f"All providers exhausted for role '{role}'. "
            f"Failures: {'; '.join(fallback_log)}"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _try_model(
        self,
        provider:     Provider,
        ref:          ModelRef,
        messages:     list[dict[str, str]],
        temperature:  float,
        timeout:      int,
        fallback_log: list[str],
    ) -> dict[str, Any]:
        """
        Try a single model up to _MAX_ATTEMPTS_PER_PROVIDER times.

        Returns a dict with keys: ok, content, attempts.
        """
        backoff = _BASE_BACKOFF_S
        for attempt in range(1, _MAX_ATTEMPTS_PER_PROVIDER + 1):
            try:
                if self._debug:
                    logger.debug(
                        "AI DEBUG: router attempt %d — %s/%s",
                        attempt, ref.provider, ref.model,
                    )
                content = provider.chat(
                    messages=messages,
                    model=ref.model,
                    temperature=temperature,
                    timeout=timeout,
                )
                logger.debug(
                    "Router: %s/%s succeeded on attempt %d",
                    ref.provider, ref.model, attempt,
                )
                return {"ok": True, "content": content, "attempts": attempt}

            except ProviderTimeoutError as exc:
                msg = (
                    f"{ref.provider}/{ref.model}: request timed out "
                    f"(attempt {attempt}) — {exc}"
                )
                logger.warning(msg)
                fallback_log.append(msg)

            except ProviderHTTPError as exc:
                kind   = getattr(exc, "kind", "client_error")
                status = exc.status
                snippet = exc.body_snippet[:120] if exc.body_snippet else ""

                if kind == "rate_limited" and exc.retry_after is not None:
                    wait = min(exc.retry_after, _MAX_BACKOFF_S)
                    msg  = (
                        f"{ref.provider}/{ref.model}: rate-limited (429); "
                        f"waiting {wait:.1f}s (Retry-After={exc.retry_after})"
                    )
                    logger.warning(msg)
                    fallback_log.append(msg)
                    time.sleep(wait)
                    continue

                elif kind == "model_unavailable":
                    msg = (
                        f"{ref.provider}/{ref.model}: model not found (HTTP 404) — "
                        f"check the model name in corvida.yaml. "
                        f"Run `corvida ai doctor --list-models {ref.provider}` to see available models."
                    )
                    logger.warning(msg)
                    fallback_log.append(msg)
                    # No retry — model does not exist
                    return {"ok": False, "content": "", "attempts": attempt}

                elif kind == "auth_failed":
                    key_hint = (
                        f"set env var {getattr(provider, '_cfg', None) and provider._cfg.key_env}"
                        if hasattr(provider, "_cfg") and getattr(provider._cfg, "key_env", None)
                        else "check your API key"
                    )
                    msg = (
                        f"{ref.provider}/{ref.model}: authentication failed (HTTP {status}) — "
                        f"{key_hint}"
                    )
                    logger.warning(msg)
                    fallback_log.append(msg)
                    # No retry — key will not change mid-run
                    return {"ok": False, "content": "", "attempts": attempt}

                elif kind in ("server_error", "network_error"):
                    msg = (
                        f"{ref.provider}/{ref.model}: {kind} "
                        f"(HTTP {status}, attempt {attempt})"
                        + (f" — {snippet}" if snippet else "")
                    )
                    logger.warning(msg)
                    fallback_log.append(msg)
                    # Retry with backoff (handled below)

                else:
                    # Other 4xx client errors — no retry
                    msg = (
                        f"{ref.provider}/{ref.model}: client error HTTP {status} "
                        f"({kind}): giving up"
                        + (f" — {snippet}" if snippet else "")
                    )
                    logger.warning(msg)
                    fallback_log.append(msg)
                    return {"ok": False, "content": "", "attempts": attempt}

            except Exception as exc:  # noqa: BLE001
                msg = (
                    f"{ref.provider}/{ref.model}: unexpected error "
                    f"({type(exc).__name__}): {exc}"
                )
                logger.warning(msg)
                fallback_log.append(msg)

            # Exponential backoff before retry
            if attempt < _MAX_ATTEMPTS_PER_PROVIDER:
                time.sleep(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF_S)

        return {"ok": False, "content": "", "attempts": _MAX_ATTEMPTS_PER_PROVIDER}

    # ------------------------------------------------------------------
    # Utility: find a different provider than the one already used
    # ------------------------------------------------------------------

    def pick_different_provider(self, role: str, used_provider: str) -> str | None:
        """
        Return the name of the first provider in *role*'s chain that is
        different from *used_provider*.  Returns None if no alternative exists.
        """
        chain = self._cfg.roles.get(role, [])
        for ref in chain:
            if ref.provider != used_provider:
                return ref.provider
        return None
