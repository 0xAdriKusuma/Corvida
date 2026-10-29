"""
tests/unit/ai/test_summarizer_verifier.py — Unit tests for summarizer and verifier roles.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from corvida.core.models import (
    Category,
    Confidence,
    Finding,
    Report,
    Severity,
    Target,
)
from corvida.model.client import MockProvider
from corvida.model.config import AIConfig, ModelRef, PolicyConfig, ProviderConfig
from corvida.model.router import Router
from corvida.model.summarizer import run_summarizer
from corvida.model.verifier import run_verifier


def _make_router(responses: list[str]) -> Router:
    cfg = AIConfig(
        providers={
            "local": ProviderConfig(name="local", base_url="http://localhost:11434/v1", key_env=""),
        },
        roles={
            "summarizer": [ModelRef(provider="local", model="m1")],
            "verifier":   [ModelRef(provider="local", model="m2")],
        },
        policy=PolicyConfig(),
    )
    p = MockProvider(responses=responses, name="local", local=True)
    return Router(ai_config=cfg, providers={"local": p})


@pytest.fixture
def test_report(tmp_path: Path) -> Report:
    bin_file = tmp_path / "target"
    bin_file.write_bytes(b"\x7fELF" + b"\x00" * 60)
    target = Target(path=bin_file)
    report = Report(target=target)

    f1 = Finding(
        title="gets buffer overflow",
        category=Category.DANGEROUS_FUNC,
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        id="F0001",
        location="0x401156",
        extra={"func_name": "gets"},
    )
    f1.score = 9.5
    report.add(f1)
    return report


class TestSummarizer:
    def test_run_summarizer_markdown_codeblock(self) -> None:
        raw_output = """Here is the summary:
```json
{
  "summary": "Classic ret2win scenario with gets() at 0x401156.",
  "likely_vulns": [
    {
      "finding_id": "F0001",
      "description": "Buffer overflow via gets() at 0x401156"
    }
  ],
  "next_steps": ["check cyclic offset"],
  "confidence": "high"
}
```
Hope this helps!"""
        router = _make_router([raw_output])
        ctx = {"target": {"name": "target"}, "findings": [{"id": "F0001"}]}

        validated, result = run_summarizer(ctx, router)
        assert validated["confidence"] == "high"
        assert "ret2win" in validated["summary"]
        assert len(validated["likely_vulns"]) == 1
        assert result.provider_name == "local"

    def test_run_summarizer_invalid_json_raises(self) -> None:
        router = _make_router(["not json at all, no braces"])
        ctx = {"target": {}, "findings": []}
        with pytest.raises(ValueError) as exc_info:
            run_summarizer(ctx, router)
        assert "could not parse" in str(exc_info.value)


class TestVerifier:
    def test_empty_claims_returns_immediately(self, test_report: Report) -> None:
        router = _make_router([])
        enriched, res = run_verifier(
            context={},
            summary={"likely_vulns": []},
            report=test_report,
            router=router,
            summary_provider="local",
        )
        assert enriched == []
        assert res is None

    def test_valid_claim_verified_by_llm(self, test_report: Report) -> None:
        verifier_response = json.dumps({
            "claims": [
                {"finding_id": "F0001", "description": "Buffer overflow", "status": "supported"}
            ]
        })
        router = _make_router([verifier_response])

        summary = {
            "likely_vulns": [
                {"finding_id": "F0001", "description": "Buffer overflow via gets at 0x401156"}
            ]
        }
        ctx = {"target": {}, "findings": [{"id": "F0001"}]}

        enriched, _res = run_verifier(
            context=ctx,
            summary=summary,
            report=test_report,
            router=router,
            summary_provider="local",
        )

        assert len(enriched) == 1
        assert enriched[0]["finding_id"] == "F0001"
        assert enriched[0]["det_valid"] is True
        assert enriched[0]["llm_status"] == "supported"
        assert enriched[0]["verified"] == "supported"

    def test_invalid_claim_forced_unsupported(self, test_report: Report) -> None:
        # LLM claims it's supported, but deterministic check fails (hallucinated address)
        verifier_response = json.dumps({
            "claims": [
                {"finding_id": "F0001", "description": "Vuln at 0xdeadbeef", "status": "supported"}
            ]
        })
        router = _make_router([verifier_response])

        summary = {
            "likely_vulns": [
                {"finding_id": "F0001", "description": "Vuln at 0xdeadbeef"}
            ]
        }
        ctx = {"target": {}, "findings": [{"id": "F0001"}]}

        enriched, _ = run_verifier(
            context=ctx,
            summary=summary,
            report=test_report,
            router=router,
            summary_provider="local",
        )

        assert len(enriched) == 1
        assert enriched[0]["det_valid"] is False
        assert enriched[0]["llm_status"] == "supported"
        assert enriched[0]["verified"] == "unsupported"  # Deterministic check takes precedence

    def test_llm_failure_gracefully_degrades(self, test_report: Report) -> None:
        # LLM returns invalid JSON or fails
        router = _make_router(["invalid non json"])

        summary = {
            "likely_vulns": [
                {"finding_id": "F0001", "description": "Buffer overflow at 0x401156"}
            ]
        }
        ctx = {"target": {}, "findings": [{"id": "F0001"}]}

        # Must not raise
        enriched, _res = run_verifier(
            context=ctx,
            summary=summary,
            report=test_report,
            router=router,
            summary_provider="local",
        )

        assert len(enriched) == 1
        assert enriched[0]["det_valid"] is True
        assert enriched[0]["llm_status"] == "unclear"
        assert enriched[0]["verified"] == "unclear"
