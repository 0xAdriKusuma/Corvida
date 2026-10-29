"""
model/cache.py — File-based cache for AI responses.

Cache key
---------
SHA-256 of: context_json + role + model + prompt_version + provider

Storage
-------
~/.cache/corvida/ai/<hex_key>.json   (cross-platform via pathlib)

Security notes
--------------
* The cached value is the AI response text — never the API key.
* Binary content is never written to cache.
* On any read/write error, the cache is silently bypassed (degraded mode).
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cache directory
# ---------------------------------------------------------------------------

def _default_cache_dir() -> Path:
    return Path.home() / ".cache" / "corvida" / "ai"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def make_key(
    context:        dict[str, Any],
    role:           str,
    model:          str,
    prompt_version: str,
    provider:       str,
) -> str:
    """
    Compute a deterministic cache key.

    The key is a SHA-256 hex digest of the concatenated fields.
    """
    raw = (
        json.dumps(context, sort_keys=True, ensure_ascii=False)
        + f"|{role}|{model}|{prompt_version}|{provider}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def read(key: str, cache_dir: Path | None = None) -> dict[str, Any] | None:
    """
    Load a cached response.

    Returns None on miss or any error (silent degraded mode).
    """
    path = _entry_path(key, cache_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        logger.debug("cache: HIT %s", key[:12])
        return data
    except Exception as exc:  # noqa: BLE001
        logger.debug("cache: read error for %s: %s", key[:12], exc)
        return None


def write(key: str, value: dict[str, Any], cache_dir: Path | None = None) -> None:
    """
    Persist *value* under *key*.

    On any error (disk full, permission denied, …) the failure is logged
    and silently swallowed — never raised to caller.
    """
    path = _entry_path(key, cache_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.debug("cache: WRITE %s", key[:12])
    except Exception as exc:  # noqa: BLE001
        logger.debug("cache: write error for %s: %s", key[:12], exc)


def _entry_path(key: str, cache_dir: Path | None) -> Path:
    base = cache_dir or _default_cache_dir()
    return base / f"{key}.json"
