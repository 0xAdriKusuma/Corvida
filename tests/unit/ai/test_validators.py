"""
tests/unit/ai/test_validators.py — Unit tests for model/validators.py
"""

from __future__ import annotations

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
from corvida.model.validators import validate_claims


@pytest.fixture
def sample_report(tmp_path: Path) -> Report:
    bin_file = tmp_path / "test_bin"
    bin_file.write_bytes(b"\x7fELF" + b"\x00" * 60)
    target = Target(path=bin_file)
    report = Report(target=target)

    f1 = Finding(
        title="gets() call detected",
        category=Category.DANGEROUS_FUNC,
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        id="F0001",
        location="0x401156",
        evidence=["call 0x401030 <gets@plt>"],
        extra={"func_name": "gets"},
    )
    report.add(f1)

    f2 = Finding(
        title="No Canary protection found",
        category=Category.PROTECTIONS,
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        id="F0002",
        extra={"canary": False},
    )
    report.add(f2)

    return report


class TestValidators:
    def test_valid_claim(self, sample_report: Report) -> None:
        claims = [
            {
                "finding_id": "F0001",
                "description": "Buffer overflow at 0x401156 via gets function",
            }
        ]
        results = validate_claims(claims, sample_report)
        assert len(results) == 1
        assert results[0].valid is True
        assert len(results[0].flags) == 0

    def test_invalid_finding_id(self, sample_report: Report) -> None:
        claims = [
            {
                "finding_id": "F9999",
                "description": "Exploit something",
            }
        ]
        results = validate_claims(claims, sample_report)
        assert len(results) == 1
        assert results[0].valid is False
        assert any("finding_id 'F9999' not found" in f for f in results[0].flags)

    def test_hallucinated_address(self, sample_report: Report) -> None:
        claims = [
            {
                "finding_id": "F0001",
                "description": "Buffer overflow at 0xdeadbeef",
            }
        ]
        results = validate_claims(claims, sample_report)
        assert len(results) == 1
        assert results[0].valid is False
        assert any("0xdeadbeef" in f for f in results[0].flags)

    def test_hallucinated_dangerous_function(self, sample_report: Report) -> None:
        claims = [
            {
                "finding_id": "F0001",
                "description": "Execution hijacked via system at 0x401156",
            }
        ]
        results = validate_claims(claims, sample_report)
        assert len(results) == 1
        assert results[0].valid is False
        assert any("system" in f for f in results[0].flags)
