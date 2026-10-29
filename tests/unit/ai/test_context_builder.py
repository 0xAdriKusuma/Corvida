"""
tests/unit/ai/test_context_builder.py — Unit tests for model/context_builder.py
"""

from __future__ import annotations

from pathlib import Path

from corvida.core.models import (
    Category,
    Confidence,
    Finding,
    Report,
    Severity,
    Target,
)
from corvida.model.context_builder import build_context


def _make_report(tmp_path: Path, findings_count: int = 3) -> Report:
    bin_file = tmp_path / "vuln"
    bin_file.write_bytes(b"\x7fELF" + b"\x00" * 60)
    target = Target(
        path=bin_file,
        file_type="ELF",
        arch="x86_64",
        bits=64,
        endian="little",
        is_stripped=False,
        is_pie=False,
    )
    report = Report(target=target)

    # Add protections
    f1 = Finding(
        title="NX disabled (executable stack)",
        category=Category.PROTECTIONS,
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        extra={"nx": False},
    )
    f1.score = 8.5
    report.add(f1)

    # Add dangerous funcs with multiple evidence lines
    f2 = Finding(
        title="gets() called without bounds check",
        category=Category.DANGEROUS_FUNC,
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        location="0x401156",
        evidence=["call gets", "buf at rbp-0x40", "no size check", "extra ev 4"],
        advice="Replace with fgets",
        extra={"func_name": "gets"},
    )
    f2.score = 9.5
    report.add(f2)

    # Add string finding
    f3 = Finding(
        title="Found '/bin/sh' string",
        category=Category.STRINGS,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        location="0x402008",
        evidence=["/bin/sh"],
        extra={"value": "/bin/sh"},
    )
    f3.score = 3.0
    report.add(f3)

    # Add more findings if requested
    for i in range(findings_count - 3):
        f_extra = Finding(
            title=f"Extra finding {i}",
            category=Category.DANGEROUS_FUNC,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
        )
        f_extra.score = 1.0 + (i * 0.1)
        report.add(f_extra)

    return report


class TestContextBuilder:
    def test_assigns_ids_in_score_order(self, tmp_path: Path) -> None:
        report = _make_report(tmp_path, 3)
        build_context(report)

        # The highest score finding was gets() with score 9.5
        gets_finding = next(f for f in report.findings if "gets" in f.title)
        assert gets_finding.id == "F0001"

        nx_finding = next(f for f in report.findings if "NX" in f.title)
        assert nx_finding.id == "F0002"

        strings_finding = next(f for f in report.findings if "/bin/sh" in f.title)
        assert strings_finding.id == "F0003"

    def test_evidence_truncated_to_max_two(self, tmp_path: Path) -> None:
        report = _make_report(tmp_path, 3)
        ctx = build_context(report)

        gets_ctx = next(f for f in ctx["findings"] if "gets" in f["title"])
        assert len(gets_ctx["evidence"]) <= 2
        assert gets_ctx["evidence"] == ["call gets", "buf at rbp-0x40"]

    def test_strings_sample_included_and_can_be_excluded(self, tmp_path: Path) -> None:
        report = _make_report(tmp_path, 3)

        # Included by default
        ctx1 = build_context(report, exclude_strings=False)
        assert len(ctx1["strings_sample"]) > 0
        assert any("/bin/sh" in s for s in ctx1["strings_sample"])

        # Excluded when requested
        ctx2 = build_context(report, exclude_strings=True)
        assert len(ctx2["strings_sample"]) == 0

    def test_token_budget_truncation(self, tmp_path: Path) -> None:
        report = _make_report(tmp_path, findings_count=30)
        # Give a very tiny token budget (e.g. 100 tokens ~ 400 chars)
        ctx = build_context(report, max_tokens=100)

        assert len(ctx["findings"]) < 30
        assert len(ctx["truncation_notes"]) > 0
        assert any("budget" in n.lower() or "omitted" in n.lower() for n in ctx["truncation_notes"])

    def test_no_raw_binary_content_present(self, tmp_path: Path) -> None:
        report = _make_report(tmp_path, 3)
        ctx = build_context(report)

        import json
        dumped = json.dumps(ctx)
        # Check basic target fields
        assert ctx["target"]["name"] == "vuln"
        assert ctx["target"]["arch"] == "x86_64"
        assert "bytes" not in ctx["target"]
        assert "\\x" not in dumped
