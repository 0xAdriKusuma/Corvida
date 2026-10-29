"""
tests/unit/ai/test_cache.py — Unit tests for model/cache.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from corvida.model import cache


class TestCache:
    def test_make_key_deterministic(self) -> None:
        ctx1 = {"target": {"name": "vuln"}, "findings": [{"id": "F0001"}]}
        ctx2 = {"findings": [{"id": "F0001"}], "target": {"name": "vuln"}}  # same keys, different order

        k1 = cache.make_key(ctx1, role="summarizer", model="m1", prompt_version="1.0", provider="ollama")
        k2 = cache.make_key(ctx2, role="summarizer", model="m1", prompt_version="1.0", provider="ollama")
        assert k1 == k2

        k3 = cache.make_key(ctx1, role="summarizer", model="m2", prompt_version="1.0", provider="ollama")
        assert k1 != k3

    def test_write_and_read_hit(self, tmp_path: Path) -> None:
        key = "abc123def456"
        val = {"summary": "Cached result", "confidence": "high"}

        cache.write(key, val, cache_dir=tmp_path)
        loaded = cache.read(key, cache_dir=tmp_path)
        assert loaded == val

    def test_read_miss(self, tmp_path: Path) -> None:
        assert cache.read("nonexistent_key", cache_dir=tmp_path) is None

    def test_read_corrupted_file(self, tmp_path: Path) -> None:
        key = "corrupted_key"
        file_path = tmp_path / f"{key}.json"
        file_path.write_text("{bad: json: [", encoding="utf-8")

        # Must silently return None without crashing
        assert cache.read(key, cache_dir=tmp_path) is None

    def test_write_error_silent(self, tmp_path: Path) -> None:
        key = "key1"
        val = {"summary": "test"}

        # Patch Path.mkdir to raise an OSError
        with patch.object(Path, "mkdir", side_effect=OSError("Disk full")):
            # Should not raise
            cache.write(key, val, cache_dir=tmp_path)
