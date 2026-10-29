"""
model/client.py — OpenAI-compatible HTTP client and provider abstraction.

Design
------
* All providers use the same /chat/completions endpoint format.
* The Provider protocol defines the interface; HttpProvider implements it
  using httpx (sync); MockProvider is used in tests.
* Secrets are read from environment variables at call time — never stored,
  logged, or printed.

Provider protocol (for future tool-calling / MCP extension):

    class Provider(Protocol):
        @property
        def name(self) -> str: ...
        def chat(self, messages, model, temperature, timeout) -> str: ...
        def is_local(self) -> bool: ...

Only the attributes above are used by the router, so adding tool-calling
support later only requires extending this interface without breaking
existing providers.

Error Classification
--------------------
ProviderHTTPError carries a ``kind`` attribute with one of:
  - "auth_failed"       : HTTP 401/403 — key is wrong or missing
  - "model_unavailable" : HTTP 404 — model name not found on provider
  - "rate_limited"      : HTTP 429 — quota exceeded; retry_after is set
  - "server_error"      : HTTP 5xx — transient provider-side error
  - "client_error"      : Other HTTP 4xx
  - "network_error"     : Pre-response failure (DNS, connection refused, etc.)

ProviderTimeoutError is raised when the request times out before any response.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Protocol, runtime_checkable

from corvida.model.config import ProviderConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class Provider(Protocol):
    """Minimal interface all model providers must implement."""

    @property
    def name(self) -> str:
        """Short provider identifier (matches corvida.yaml key)."""
        ...

    def is_local(self) -> bool:
        """True if this provider runs locally (no data leaves the machine)."""
        ...

    def chat(
        self,
        messages:    list[dict[str, str]],
        model:       str,
        temperature: float = 0.2,
        timeout:     int   = 60,
    ) -> str:
        """
        Call /chat/completions and return the assistant message content.

        Raises
        ------
        ProviderHTTPError
            On HTTP 4xx/5xx or pre-response network failure.
            Check `.kind` for error classification.
        ProviderTimeoutError
            When the request times out.
        """
        ...


# ---------------------------------------------------------------------------
# Exceptions from provider calls
# ---------------------------------------------------------------------------

class ProviderHTTPError(Exception):
    """
    HTTP (or network-level) error from a provider.

    Attributes
    ----------
    status : int
        HTTP status code, or 0 for pre-response network failures.
    kind : str
        Machine-readable classification of the failure:
        "auth_failed" | "model_unavailable" | "rate_limited" |
        "server_error" | "client_error" | "network_error"
    retry_after : float | None
        Seconds to wait before retrying (set for 429 responses).
    body_snippet : str
        First 300 chars of the response body (for diagnostics; no secrets).
    """

    def __init__(
        self,
        status:       int,
        message:      str,
        kind:         str = "client_error",
        body_snippet: str = "",
    ) -> None:
        super().__init__(f"[{kind}] HTTP {status}: {message}")
        self.status       = status
        self.kind         = kind
        self.retry_after: float | None = None
        self.body_snippet = body_snippet[:300]

    @classmethod
    def from_network(cls, exc: Exception) -> "ProviderHTTPError":
        """Construct a network-error instance from a connection-level exception."""
        exc_type = type(exc).__name__
        err = cls(
            status=0,
            message=f"{exc_type}: {exc}",
            kind="network_error",
        )
        return err


class ProviderTimeoutError(Exception):
    """The provider did not respond within the timeout."""


# ---------------------------------------------------------------------------
# HttpProvider — real implementation (httpx)
# ---------------------------------------------------------------------------

def _require_httpx() -> Any:
    try:
        import httpx
        return httpx
    except ImportError:
        raise ImportError(
            "httpx is required for the AI layer.  "
            "Install it with: pip install 'corvida[ai]'"
        ) from None


def _classify_status(status: int, body: str) -> str:
    """Return a machine-readable error kind for the given HTTP status code."""
    if status in (401, 403):
        return "auth_failed"
    if status == 404:
        return "model_unavailable"
    if status == 429:
        return "rate_limited"
    if status >= 500:
        return "server_error"
    return "client_error"


class HttpProvider:
    """
    OpenAI-compatible provider backed by httpx (synchronous).

    The API key is read from the environment at call time.
    It is NEVER stored as an instance attribute.
    """

    def __init__(self, cfg: ProviderConfig, debug: bool = False) -> None:
        self._cfg   = cfg
        self._name  = cfg.name
        self._debug = debug

    @property
    def name(self) -> str:
        return self._name

    def is_local(self) -> bool:
        return not bool(self._cfg.key_env)

    def chat(
        self,
        messages:    list[dict[str, str]],
        model:       str,
        temperature: float = 0.2,
        timeout:     int   = 60,
    ) -> str:
        httpx = _require_httpx()

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._cfg.key_env:
            api_key = os.environ.get(self._cfg.key_env, "")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            # If key is missing we still try — provider will return 401/403

        payload: dict[str, Any] = {
            "model":       model,
            "messages":    messages,
            "temperature": temperature,
        }

        url = self._cfg.base_url.rstrip("/") + "/chat/completions"

        if self._debug:
            logger.debug(
                "AI DEBUG: POST %s model=%s messages=%d",
                url, model, len(messages),
            )

        try:
            resp = httpx.post(
                url,
                json=payload,
                headers=headers,
                timeout=float(timeout),
            )
        except httpx.TimeoutException as exc:
            if self._debug:
                logger.debug("AI DEBUG: timeout — %s: %s", type(exc).__name__, exc)
            raise ProviderTimeoutError(
                f"{self._name}/{model}: request timed out after {timeout}s "
                f"({type(exc).__name__})"
            ) from exc
        except httpx.RequestError as exc:
            # Pre-response: DNS, connection refused, SSL, etc.
            if self._debug:
                logger.debug("AI DEBUG: network error — %s: %s", type(exc).__name__, exc)
            err = ProviderHTTPError.from_network(exc)
            err.__cause__ = exc
            raise err from exc

        body_snippet = resp.text[:300] if resp.text else ""

        if self._debug:
            logger.debug(
                "AI DEBUG: response HTTP %d body_snippet=%r",
                resp.status_code, body_snippet,
            )

        if resp.status_code >= 400:
            kind = _classify_status(resp.status_code, body_snippet)
            err  = ProviderHTTPError(
                status=resp.status_code,
                message=body_snippet or resp.reason_phrase,
                kind=kind,
                body_snippet=body_snippet,
            )
            if resp.status_code == 429:
                try:
                    err.retry_after = float(resp.headers.get("Retry-After", "5"))
                except (TypeError, ValueError):
                    err.retry_after = 5.0
            raise err

        data = resp.json()
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderHTTPError(
                status=200,
                message=f"Unexpected response shape: {str(data)[:200]}",
                kind="client_error",
            ) from exc

    # ------------------------------------------------------------------
    # Doctor helpers — used by `corvida ai doctor`
    # ------------------------------------------------------------------

    def list_models(self, timeout: int = 10) -> list[str]:
        """
        Query the provider's /models endpoint and return a list of model IDs.

        Raises ProviderHTTPError on failure; raises ProviderTimeoutError on timeout.
        Returns an empty list if the endpoint is not supported (404).
        """
        httpx = _require_httpx()

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._cfg.key_env:
            api_key = os.environ.get(self._cfg.key_env, "")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

        url = self._cfg.base_url.rstrip("/") + "/models"

        try:
            resp = httpx.get(url, headers=headers, timeout=float(timeout))
        except httpx.TimeoutException as exc:
            raise ProviderTimeoutError(f"list_models timed out: {exc}") from exc
        except httpx.RequestError as exc:
            raise ProviderHTTPError.from_network(exc) from exc

        if resp.status_code == 404:
            return []   # endpoint not supported

        if resp.status_code >= 400:
            kind = _classify_status(resp.status_code, resp.text[:300])
            raise ProviderHTTPError(
                status=resp.status_code,
                message=resp.text[:200],
                kind=kind,
                body_snippet=resp.text[:300],
            )

        try:
            data = resp.json()
            ids = [m.get("id", "") for m in data.get("data", [])]
            return [m for m in ids if m]
        except Exception:  # noqa: BLE001
            return []


# ---------------------------------------------------------------------------
# MockProvider — for tests; no network
# ---------------------------------------------------------------------------

class MockProvider:
    """
    Fake provider for unit/integration tests.

    Responses are configured at construction time as a list of return values
    or exceptions to raise in order.  Raise StopIteration if exhausted.
    """

    def __init__(
        self,
        responses: list[str | Exception],
        name:      str  = "mock",
        local:     bool = True,
    ) -> None:
        self._responses = list(responses)
        self._name      = name
        self._local     = local
        self.calls:     list[dict[str, Any]] = []  # recorded calls for assertions

    @property
    def name(self) -> str:
        return self._name

    def is_local(self) -> bool:
        return self._local

    def chat(
        self,
        messages:    list[dict[str, str]],
        model:       str,
        temperature: float = 0.2,
        timeout:     int   = 60,
    ) -> str:
        self.calls.append({
            "messages":    messages,
            "model":       model,
            "temperature": temperature,
            "timeout":     timeout,
        })
        if not self._responses:
            raise StopIteration("MockProvider: no more responses configured")
        result = self._responses.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def list_models(self, timeout: int = 10) -> list[str]:
        """Return a static list for tests (no network)."""
        return ["mock-model-1", "mock-model-2"]


def build_provider(cfg: ProviderConfig, debug: bool = False) -> HttpProvider:
    """Construct a real HttpProvider from a ProviderConfig."""
    return HttpProvider(cfg, debug=debug)
