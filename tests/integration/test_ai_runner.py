"""
tests/integration/test_ai_runner.py — Integration tests for run_ai orchestrator.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from corvida.core.config import Config
from corvida.core.models import (
    Category,
    Confidence,
    Finding,
    Report,
    Severity,
    Target,
)
from corvida.model import run_ai
from corvida.model.client import MockProvider


def _setup_config_file(tmp_path: Path) -> Path:
    cfg_data = {
        "providers": {
            "local": {"base_url": "http://localhost:11434/v1", "key_env": ""},
            "cloud": {"base_url": "https://api.groq.com/openai/v1", "key_env": "GROQ_API_KEY"},
        },
        "roles": {
            "summarizer": [{"provider": "local", "model": "phi4-mini"}],
            "verifier":   [{"provider": "local", "model": "qwen3:4b"}],
        },
        "policy": {
            "cache": True,
            "max_context_tokens": 4000,
            "temperature": 0.2,
        },
    }
    cfg_file = tmp_path / "corvida.yaml"
    cfg_file.write_text(yaml.dump(cfg_data), encoding="utf-8")
    return cfg_file


@pytest.fixture
def sample_report(tmp_path: Path) -> Report:
    bin_file = tmp_path / "binary"
    bin_file.write_bytes(b"\x7fELF" + b"\x00" * 60)
    target = Target(path=bin_file, file_type="ELF", arch="x86_64", bits=64)
    report = Report(target=target)

    f1 = Finding(
        title="gets buffer overflow",
        category=Category.DANGEROUS_FUNC,
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        location="0x401156",
        evidence=["call gets"],
        extra={"func_name": "gets"},
    )
    f1.score = 9.0
    report.add(f1)
    return report


class TestAIRunner:
    def test_run_ai_disabled_returns_none(self, sample_report: Report) -> None:
        cfg = Config(ai_enabled=False)
        assert run_ai(sample_report, cfg) is None

    def test_run_ai_missing_config_returns_none(self, sample_report: Report, tmp_path: Path) -> None:
        cfg = Config(ai_enabled=True, ai_config_path=tmp_path / "nonexistent.yaml")
        # Should not raise exception
        result = run_ai(sample_report, cfg)
        assert result is None

    def test_run_ai_success_and_cache(self, sample_report: Report, tmp_path: Path) -> None:
        cfg_file = _setup_config_file(tmp_path)
        cache_dir = tmp_path / "cache"

        summarizer_resp = json.dumps({
            "summary": "Detected buffer overflow via gets() at 0x401156.",
            "likely_vulns": [
                {"finding_id": "F0001", "description": "Buffer overflow at 0x401156"}
            ],
            "next_steps": ["check cyclic offset"],
            "confidence": "high",
        })

        verifier_resp = json.dumps({
            "claims": [
                {"finding_id": "F0001", "description": "Buffer overflow at 0x401156", "status": "supported"}
            ]
        })

        mock_local = MockProvider(
            responses=[summarizer_resp, verifier_resp],
            name="local",
            local=True,
        )

        cfg = Config(
            ai_enabled=True,
            ai_config_path=cfg_file,
            ai_no_cache=False,
        )

        with patch("corvida.model.client.build_provider", return_value=mock_local), \
             patch("corvida.model.cache._default_cache_dir", return_value=cache_dir):

            # First run: should execute providers and cache result
            res1 = run_ai(sample_report, cfg)
            assert res1 is not None
            assert res1.from_cache is False
            assert res1.confidence == "high"
            assert res1.verified_count == 1
            assert res1.total_claims == 1
            assert res1.summarizer_model == "phi4-mini"

            # Check to_dict()
            d = res1.to_dict()
            assert d["confidence"] == "high"
            assert d["verification"]["verified"] == 1
            assert d["models_used"]["summarizer"] == "local/phi4-mini"

            # Second run: should hit cache
            res2 = run_ai(sample_report, cfg)
            assert res2 is not None
            assert res2.from_cache is True
            assert res2.summary == res1.summary
            assert res2.verified_count == 1

            # Third run with ai_no_cache=True: should bypass cache
            # Add new responses for the 3rd run
            mock_local._responses.extend([summarizer_resp, verifier_resp])
            cfg_no_cache = Config(
                ai_enabled=True,
                ai_config_path=cfg_file,
                ai_no_cache=True,
            )
            res3 = run_ai(sample_report, cfg_no_cache)
            assert res3 is not None
            assert res3.from_cache is False

    def test_run_ai_provider_failure_returns_none(self, sample_report: Report, tmp_path: Path) -> None:
        cfg_file = _setup_config_file(tmp_path)
        mock_local = MockProvider(
            responses=[Exception("Network down")],
            name="local",
            local=True,
        )
        cfg = Config(
            ai_enabled=True,
            ai_config_path=cfg_file,
            ai_no_cache=True,
        )

        with patch("corvida.model.client.build_provider", return_value=mock_local):
            result = run_ai(sample_report, cfg)
            assert result is None
