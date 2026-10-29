"""
tests/unit/ai/test_client.py — Unit tests for model/client.py

Covers:
 - MockProvider: sequence, exception raise
 - HttpProvider: success, timeout, network error, 429, 404, 401, 5xx, malformed response
 - Error classification (kind attribute)
 - list_models() endpoint
 - ProviderHTTPError.from_network()
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from corvida.model.client import (
    HttpProvider,
    MockProvider,
    ProviderHTTPError,
    ProviderTimeoutError,
    build_provider,
    _classify_status,
)
from corvida.model.config import ProviderConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg(key_env: str = "") -> ProviderConfig:
    return ProviderConfig(name="test", base_url="http://example.com/v1", key_env=key_env)


def _mock_resp(status: int, body: str = "", headers: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.reason_phrase = "Mock Reason"
    r.headers = headers or {}
    r.json.return_value = {"choices": [{"message": {"content": body}}]}
    return r


# ---------------------------------------------------------------------------
# MockProvider
# ---------------------------------------------------------------------------

class TestMockProvider:
    def test_sequence(self) -> None:
        p = MockProvider(responses=["hello", "world"], name="test_mock", local=True)
        assert p.name == "test_mock"
        assert p.is_local() is True

        r1 = p.chat([{"role": "user", "content": "hi"}], model="test-m")
        assert r1 == "hello"
        assert len(p.calls) == 1
        assert p.calls[0]["model"] == "test-m"

        r2 = p.chat([{"role": "user", "content": "again"}], model="test-m")
        assert r2 == "world"
        assert len(p.calls) == 2

        with pytest.raises(StopIteration):
            p.chat([{"role": "user", "content": "third"}], model="test-m")

    def test_raises_configured_exception(self) -> None:
        err = ProviderHTTPError(500, "Internal Server Error", kind="server_error")
        p = MockProvider(responses=[err])
        with pytest.raises(ProviderHTTPError) as exc_info:
            p.chat([], model="test-m")
        assert exc_info.value.status == 500
        assert exc_info.value.kind == "server_error"

    def test_raises_timeout(self) -> None:
        p = MockProvider(responses=[ProviderTimeoutError("timeout")])
        with pytest.raises(ProviderTimeoutError):
            p.chat([], model="m")

    def test_list_models(self) -> None:
        p = MockProvider(responses=[])
        models = p.list_models()
        assert isinstance(models, list)
        assert len(models) > 0


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------

class TestErrorClassification:
    def test_401_is_auth_failed(self) -> None:
        assert _classify_status(401, "") == "auth_failed"

    def test_403_is_auth_failed(self) -> None:
        assert _classify_status(403, "") == "auth_failed"

    def test_404_is_model_unavailable(self) -> None:
        assert _classify_status(404, "") == "model_unavailable"

    def test_429_is_rate_limited(self) -> None:
        assert _classify_status(429, "") == "rate_limited"

    def test_500_is_server_error(self) -> None:
        assert _classify_status(500, "") == "server_error"

    def test_503_is_server_error(self) -> None:
        assert _classify_status(503, "") == "server_error"

    def test_400_is_client_error(self) -> None:
        assert _classify_status(400, "") == "client_error"

    def test_from_network(self) -> None:
        import httpx
        exc = httpx.ConnectError("Connection refused")
        err = ProviderHTTPError.from_network(exc)
        assert err.status == 0
        assert err.kind == "network_error"
        assert "ConnectError" in str(err)


# ---------------------------------------------------------------------------
# HttpProvider.chat
# ---------------------------------------------------------------------------

class TestHttpProvider:
    def test_is_local_flag(self) -> None:
        local_cfg = ProviderConfig(name="ollama", base_url="http://localhost:11434/v1", key_env="")
        cloud_cfg = ProviderConfig(name="groq", base_url="https://api.groq.com/openai/v1", key_env="GROQ_API_KEY")
        assert build_provider(local_cfg).is_local() is True
        assert build_provider(cloud_cfg).is_local() is False

    def test_chat_success(self) -> None:
        p = HttpProvider(_cfg("TEST_KEY"))
        resp = _mock_resp(200, '{"summary": "ok"}')
        resp.json.return_value = {"choices": [{"message": {"content": '{"summary": "ok"}'}}]}

        with patch.dict(os.environ, {"TEST_KEY": "secret123"}), \
             patch("httpx.post", return_value=resp) as mock_post:
            res = p.chat([{"role": "user", "content": "ping"}], model="model-a")
            assert res == '{"summary": "ok"}'
            _, kwargs = mock_post.call_args
            assert kwargs["headers"]["Authorization"] == "Bearer secret123"
            assert kwargs["json"]["model"] == "model-a"

    def test_chat_no_key_no_auth_header(self) -> None:
        p = HttpProvider(_cfg(""))
        resp = _mock_resp(200)
        resp.json.return_value = {"choices": [{"message": {"content": "hi"}}]}

        with patch("httpx.post", return_value=resp) as mock_post:
            p.chat([], model="m")
            _, kwargs = mock_post.call_args
            assert "Authorization" not in kwargs["headers"]

    def test_chat_timeout(self) -> None:
        import httpx
        p = HttpProvider(_cfg())

        with patch("httpx.post", side_effect=httpx.TimeoutException("Timed out")), \
             pytest.raises(ProviderTimeoutError):
            p.chat([], model="model-a")

    def test_chat_network_error_is_kind_network_error(self) -> None:
        import httpx
        p = HttpProvider(_cfg())

        with patch("httpx.post", side_effect=httpx.ConnectError("Failed to connect")):
            with pytest.raises(ProviderHTTPError) as exc_info:
                p.chat([], model="model-a")
            err = exc_info.value
            assert err.status == 0
            assert err.kind == "network_error"

    def test_chat_404_is_model_unavailable(self) -> None:
        p = HttpProvider(_cfg())
        with patch("httpx.post", return_value=_mock_resp(404, "Not Found")):
            with pytest.raises(ProviderHTTPError) as exc_info:
                p.chat([], model="nonexistent-model")
            assert exc_info.value.kind == "model_unavailable"
            assert exc_info.value.status == 404

    def test_chat_401_is_auth_failed(self) -> None:
        p = HttpProvider(_cfg("MY_KEY"))
        with patch("httpx.post", return_value=_mock_resp(401, "Unauthorized")):
            with pytest.raises(ProviderHTTPError) as exc_info:
                p.chat([], model="model-a")
            assert exc_info.value.kind == "auth_failed"

    def test_chat_429_sets_retry_after(self) -> None:
        p = HttpProvider(_cfg())
        resp = _mock_resp(429, "Too Many Requests", headers={"Retry-After": "12.5"})
        with patch("httpx.post", return_value=resp):
            with pytest.raises(ProviderHTTPError) as exc_info:
                p.chat([], model="model-a")
            err = exc_info.value
            assert err.status == 429
            assert err.kind == "rate_limited"
            assert err.retry_after == 12.5

    def test_chat_429_default_retry_after(self) -> None:
        p = HttpProvider(_cfg())
        resp = _mock_resp(429, "Too Many Requests", headers={})
        with patch("httpx.post", return_value=resp):
            with pytest.raises(ProviderHTTPError) as exc_info:
                p.chat([], model="m")
            assert exc_info.value.retry_after == 5.0

    def test_chat_500_is_server_error(self) -> None:
        p = HttpProvider(_cfg())
        with patch("httpx.post", return_value=_mock_resp(500, "Server Error")):
            with pytest.raises(ProviderHTTPError) as exc_info:
                p.chat([], model="m")
            assert exc_info.value.kind == "server_error"

    def test_chat_malformed_response(self) -> None:
        p = HttpProvider(_cfg())
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        resp.json.return_value = {"error": "bad format"}

        with patch("httpx.post", return_value=resp):
            with pytest.raises(ProviderHTTPError) as exc_info:
                p.chat([], model="model-a")
            assert exc_info.value.status == 200

    def test_body_snippet_not_empty_on_http_error(self) -> None:
        p = HttpProvider(_cfg())
        body = "Something went wrong in the API"
        with patch("httpx.post", return_value=_mock_resp(503, body)):
            with pytest.raises(ProviderHTTPError) as exc_info:
                p.chat([], model="m")
            assert exc_info.value.body_snippet  # non-empty


# ---------------------------------------------------------------------------
# HttpProvider.list_models
# ---------------------------------------------------------------------------

class TestListModels:
    def test_list_models_success(self) -> None:
        p = HttpProvider(_cfg("KEY"))
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        resp.json.return_value = {
            "data": [{"id": "model-a"}, {"id": "model-b"}]
        }

        with patch.dict(os.environ, {"KEY": "mykey"}), \
             patch("httpx.get", return_value=resp):
            models = p.list_models()
        assert "model-a" in models
        assert "model-b" in models

    def test_list_models_404_returns_empty(self) -> None:
        p = HttpProvider(_cfg())
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "Not Found"

        with patch("httpx.get", return_value=resp):
            models = p.list_models()
        assert models == []

    def test_list_models_timeout_raises(self) -> None:
        import httpx
        p = HttpProvider(_cfg())
        with patch("httpx.get", side_effect=httpx.TimeoutException("timeout")):
            with pytest.raises(ProviderTimeoutError):
                p.list_models()

    def test_list_models_network_error_raises(self) -> None:
        import httpx
        p = HttpProvider(_cfg())
        with patch("httpx.get", side_effect=httpx.ConnectError("refused")):
            with pytest.raises(ProviderHTTPError) as exc_info:
                p.list_models()
            assert exc_info.value.kind == "network_error"
