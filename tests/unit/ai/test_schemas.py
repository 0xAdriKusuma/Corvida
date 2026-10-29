"""
tests/unit/ai/test_schemas.py — Unit tests for model/schemas.py
"""

from __future__ import annotations

import pytest

from corvida.model.schemas import (
    _fallback_validate_summary,
    _fallback_validate_verifier,
    validate_summary,
    validate_verifier,
)


class TestValidateSummary:
    def test_valid_summary(self) -> None:
        data = {
            "summary": "This binary has a classic buffer overflow in gets().",
            "likely_vulns": [
                {
                    "finding_id": "F0001",
                    "description": "Buffer overflow in vuln function via gets",
                    "how_to_verify": "Check input length at 0x401156",
                    "extra_ignored_field": 123,
                }
            ],
            "next_steps": ["craft exploit with cyclic pattern", "check gadgets"],
            "confidence": "HIGH",
            "unrelated_field": "ignore_me",
        }

        res = validate_summary(data)
        assert res["summary"] == data["summary"]
        assert len(res["likely_vulns"]) == 1
        assert res["likely_vulns"][0]["finding_id"] == "F0001"
        assert res["confidence"] == "high"
        assert "unrelated_field" not in res

    def test_confidence_normalization(self) -> None:
        assert validate_summary({"summary": "ok", "confidence": "Medium"})["confidence"] == "medium"
        assert validate_summary({"summary": "ok", "confidence": "INVALID"})["confidence"] == "low"

    def test_missing_summary_raises(self) -> None:
        with pytest.raises((ValueError, Exception)):
            validate_summary({"confidence": "high"})

    def test_invalid_type_raises(self) -> None:
        with pytest.raises((ValueError, Exception)):
            validate_summary(["not a dict"])  # type: ignore

    def test_fallback_summary(self) -> None:
        data = {
            "summary": "Fallback summary test",
            "likely_vulns": [{"finding_id": "F0001", "description": "desc"}],
            "next_steps": ["step1"],
            "confidence": "MEDIUM",
        }
        res = _fallback_validate_summary(data)
        assert res["summary"] == "Fallback summary test"
        assert res["confidence"] == "medium"
        assert len(res["likely_vulns"]) == 1

        with pytest.raises((ValueError, TypeError)):
            _fallback_validate_summary("not a dict")  # type: ignore
        with pytest.raises(ValueError):
            _fallback_validate_summary({})


class TestValidateVerifier:
    def test_valid_verifier(self) -> None:
        data = {
            "claims": [
                {"finding_id": "F0001", "description": "Buffer overflow", "status": "supported"},
                {"finding_id": "F0002", "description": "Command injection", "status": "unsupported"},
                {"finding_id": "F0003", "description": "Format string", "status": "UNKNOWN_VALUE"},
            ]
        }
        res = validate_verifier(data)
        claims = res["claims"]
        assert len(claims) == 3
        assert claims[0]["status"] == "supported"
        assert claims[1]["status"] == "unsupported"
        assert claims[2]["status"] == "unclear"

    def test_fallback_verifier(self) -> None:
        data = {
            "claims": [
                {"finding_id": "F0001", "description": "Buffer overflow", "status": "supported"},
            ]
        }
        res = _fallback_validate_verifier(data)
        assert len(res["claims"]) == 1
        assert res["claims"][0]["status"] == "supported"

        with pytest.raises((ValueError, TypeError)):
            _fallback_validate_verifier("not a dict")  # type: ignore
