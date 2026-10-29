"""
tests/unit/ai/test_router.py — Unit tests for model/router.py

Covers:
 - Success on first model
 - Fallback on server error / timeout
 - 404 (model_unavailable) → no retry, immediate fallback
 - 401/403 (auth_failed) → no retry, immediate fallback
 - 429 with Retry-After → wait and retry same model
 - All providers exhausted → ProviderError
 - Unknown role → KeyError
 - local_only skips cloud providers
 - doctor status check helpers
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from corvida.core.errors import ProviderError
from corvida.model.client import (
    MockProvider,
    ProviderHTTPError,
    ProviderTimeoutError,
)
from corvida.model.config import AIConfig, ModelRef, PolicyConfig, ProviderConfig
from corvida.model.router import Router


def _make_config(roles: dict | None = None) -> AIConfig:
    if roles is None:
        roles = {
            "summarizer": [
                {"provider": "primary",   "model": "model-1"},
                {"provider": "secondary", "model": "model-2"},
            ],
            "verifier": [
                {"provider": "secondary", "model": "model-2"},
            ],
        }

    return AIConfig(
        providers={
            "primary":   ProviderConfig(name="primary",   base_url="http://p/v1", key_env=""),
            "secondary": ProviderConfig(name="secondary", base_url="http://s/v1", key_env=""),
            "cloud":     ProviderConfig(name="cloud",     base_url="https://cloud/v1", key_env="CLOUD_KEY"),
        },
        roles={
            rn: [ModelRef(provider=m["provider"], model=m["model"]) for m in chain]
            for rn, chain in roles.items()
        },
        policy=PolicyConfig(),
    )


def _http_err(status: int, kind: str | None = None) -> ProviderHTTPError:
    from corvida.model.client import _classify_status
    k = kind or _classify_status(status, "")
    return ProviderHTTPError(status=status, message="err", kind=k)


class TestRouterSuccess:
    def test_first_model_succeeds(self) -> None:
        cfg = _make_config()
        p1 = MockProvider(responses=['{"summary": "p1 success"}'], name="primary")
        p2 = MockProvider(responses=['{"summary": "p2 success"}'], name="secondary")

        router = Router(ai_config=cfg, providers={"primary": p1, "secondary": p2})
        result = router.call("summarizer", [{"role": "user", "content": "test"}])

        assert result.content == '{"summary": "p1 success"}'
        assert result.provider_name == "primary"
        assert result.model == "model-1"
        assert result.attempts == 1
        assert len(result.fallback_log) == 0
        assert len(p1.calls) == 1
        assert len(p2.calls) == 0


class TestRouterFallback:
    def test_fallback_on_server_error(self) -> None:
        cfg = _make_config()
        p1 = MockProvider(responses=[_http_err(500)], name="primary")
        p2 = MockProvider(responses=['{"summary": "p2"}'], name="secondary")

        with patch("time.sleep"):
            router = Router(ai_config=cfg, providers={"primary": p1, "secondary": p2})
            result = router.call("summarizer", [{"role": "user", "content": "test"}])

        assert result.provider_name == "secondary"
        assert len(result.fallback_log) >= 1

    def test_fallback_on_timeout(self) -> None:
        cfg = _make_config()
        p1 = MockProvider(
            responses=[ProviderTimeoutError("t1"), ProviderTimeoutError("t2")],
            name="primary",
        )
        p2 = MockProvider(responses=['{"summary": "ok"}'], name="secondary")

        with patch("time.sleep"):
            router = Router(ai_config=cfg, providers={"primary": p1, "secondary": p2})
            result = router.call("summarizer", [{"role": "user", "content": "test"}])

        assert result.provider_name == "secondary"

    def test_fallback_on_network_error(self) -> None:
        cfg = _make_config()
        p1 = MockProvider(responses=[_http_err(0, "network_error")], name="primary")
        p2 = MockProvider(responses=['{"summary": "p2"}'], name="secondary")

        with patch("time.sleep"):
            router = Router(ai_config=cfg, providers={"primary": p1, "secondary": p2})
            result = router.call("summarizer", [{"role": "user", "content": "test"}])

        assert result.provider_name == "secondary"
        assert any("network_error" in log for log in result.fallback_log)


class TestRouterNoRetry:
    def test_404_no_retry_immediate_fallback(self) -> None:
        """model_unavailable (404) must not be retried — move to next model immediately."""
        cfg = _make_config()
        p1 = MockProvider(responses=[_http_err(404, "model_unavailable")], name="primary")
        p2 = MockProvider(responses=['{"summary": "p2"}'], name="secondary")

        router = Router(ai_config=cfg, providers={"primary": p1, "secondary": p2})
        result = router.call("summarizer", [{"role": "user", "content": "test"}])

        assert result.provider_name == "secondary"
        # p1 should have been called exactly ONCE (no retry)
        assert len(p1.calls) == 1
        assert any("404" in log or "model not found" in log.lower() for log in result.fallback_log)

    def test_401_no_retry_immediate_fallback(self) -> None:
        """auth_failed (401) must not be retried."""
        cfg = _make_config()
        p1 = MockProvider(responses=[_http_err(401, "auth_failed")], name="primary")
        p2 = MockProvider(responses=['{"summary": "p2"}'], name="secondary")

        router = Router(ai_config=cfg, providers={"primary": p1, "secondary": p2})
        result = router.call("summarizer", [{"role": "user", "content": "test"}])

        assert result.provider_name == "secondary"
        assert len(p1.calls) == 1  # no retry
        assert any("auth" in log.lower() or "401" in log for log in result.fallback_log)

    def test_403_no_retry(self) -> None:
        cfg = _make_config()
        p1 = MockProvider(responses=[_http_err(403, "auth_failed")], name="primary")
        p2 = MockProvider(responses=['{"summary": "p2"}'], name="secondary")

        router = Router(ai_config=cfg, providers={"primary": p1, "secondary": p2})
        result = router.call("summarizer", [])

        assert result.provider_name == "secondary"
        assert len(p1.calls) == 1


class TestRouterRateLimit:
    def test_retry_on_429_with_retry_after(self) -> None:
        cfg = _make_config()
        err429 = ProviderHTTPError(429, "Rate limited", kind="rate_limited")
        err429.retry_after = 1.0

        p1 = MockProvider(
            responses=[err429, '{"summary": "p1 retry success"}'],
            name="primary",
        )
        p2 = MockProvider(responses=[], name="secondary")

        with patch("time.sleep") as mock_sleep:
            router = Router(ai_config=cfg, providers={"primary": p1, "secondary": p2})
            result = router.call("summarizer", [{"role": "user", "content": "test"}])

        assert result.content == '{"summary": "p1 retry success"}'
        assert result.attempts == 2
        mock_sleep.assert_called_once_with(1.0)

    def test_retry_after_capped_at_max_backoff(self) -> None:
        from corvida.model.router import _MAX_BACKOFF_S
        cfg = _make_config()
        err429 = ProviderHTTPError(429, "rate limited", kind="rate_limited")
        err429.retry_after = 9999.0  # very large

        p1 = MockProvider(
            responses=[err429, '{"summary": "ok"}'],
            name="primary",
        )
        p2 = MockProvider(responses=[], name="secondary")

        with patch("time.sleep") as mock_sleep:
            router = Router(ai_config=cfg, providers={"primary": p1, "secondary": p2})
            router.call("summarizer", [])

        called_with = mock_sleep.call_args[0][0]
        assert called_with <= _MAX_BACKOFF_S


class TestRouterExhausted:
    def test_all_exhausted_raises_provider_error(self) -> None:
        cfg = _make_config()
        p1 = MockProvider(responses=[_http_err(500)], name="primary")
        p2 = MockProvider(responses=[_http_err(503)], name="secondary")

        with patch("time.sleep"), pytest.raises(ProviderError) as exc_info:
            router = Router(ai_config=cfg, providers={"primary": p1, "secondary": p2})
            router.call("summarizer", [])
        assert "exhausted" in str(exc_info.value).lower()

    def test_unknown_role_raises_key_error(self) -> None:
        cfg = _make_config()
        router = Router(ai_config=cfg, providers={})
        with pytest.raises(KeyError) as exc_info:
            router.call("nonexistent_role", [])
        assert "not defined" in str(exc_info.value).lower()

    def test_missing_provider_skipped(self) -> None:
        """Provider in config but not in providers dict → skip, try next."""
        cfg = _make_config()
        # Only provide secondary, not primary
        p2 = MockProvider(responses=['{"summary": "secondary only"}'], name="secondary")

        router = Router(ai_config=cfg, providers={"secondary": p2})
        result = router.call("summarizer", [])
        assert result.provider_name == "secondary"


class TestRouterLocalOnly:
    def test_local_only_skips_cloud(self) -> None:
        cfg = _make_config({
            "summarizer": [
                {"provider": "cloud",   "model": "cloud-model"},
                {"provider": "primary", "model": "local-model"},
            ],
            "verifier": [{"provider": "primary", "model": "local-model"}],
        })
        p_cloud = MockProvider(responses=['{"summary": "cloud"}'], name="cloud", local=False)
        p_local = MockProvider(responses=['{"summary": "local"}'], name="primary", local=True)

        router = Router(
            ai_config=cfg,
            providers={"cloud": p_cloud, "primary": p_local},
            local_only=True,
        )
        result = router.call("summarizer", [])

        assert result.provider_name == "primary"
        assert result.content == '{"summary": "local"}'
        assert len(p_cloud.calls) == 0
        assert len(p_local.calls) == 1


class TestRouterPickDifferent:
    def test_pick_different_provider(self) -> None:
        cfg = _make_config()
        router = Router(ai_config=cfg, providers={})
        alt = router.pick_different_provider("summarizer", "primary")
        assert alt == "secondary"

    def test_pick_different_provider_none_when_only_one(self) -> None:
        cfg = _make_config({"summarizer": [{"provider": "primary", "model": "m"}],
                            "verifier": [{"provider": "primary", "model": "m"}]})
        router = Router(ai_config=cfg, providers={})
        alt = router.pick_different_provider("summarizer", "primary")
        assert alt is None
