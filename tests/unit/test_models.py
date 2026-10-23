"""
tests/unit/test_models.py — Unit tests for core data models.
"""

import pytest
from corvida.core.models import (
    Category, Confidence, Finding, Report, Severity, Target,
    _default_score,
)
from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_binary(tmp_path: Path) -> Path:
    """Create a minimal fake binary file for Target construction."""
    p = tmp_path / "fake_binary"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)  # fake ELF header
    return p


@pytest.fixture
def sample_target(tmp_binary: Path) -> Target:
    return Target(path=tmp_binary)


# ---------------------------------------------------------------------------
# Target tests
# ---------------------------------------------------------------------------

class TestTarget:
    def test_target_creation(self, tmp_binary: Path) -> None:
        t = Target(path=tmp_binary)
        assert t.path == tmp_binary
        assert t.size > 0
        assert len(t.sha256) == 64

    def test_target_name(self, tmp_binary: Path) -> None:
        t = Target(path=tmp_binary)
        assert t.name == "fake_binary"

    def test_target_sha256_consistent(self, tmp_binary: Path) -> None:
        t1 = Target(path=tmp_binary)
        t2 = Target(path=tmp_binary)
        assert t1.sha256 == t2.sha256

    def test_target_optional_fields_default_none(self, tmp_binary: Path) -> None:
        t = Target(path=tmp_binary)
        assert t.arch is None
        assert t.bits is None
        assert t.is_stripped is None
        assert t.is_pie is None


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------

class TestFinding:
    def test_finding_defaults(self) -> None:
        f = Finding(title="Test finding", category=Category.BINARY_INFO)
        assert f.severity == Severity.INFO
        assert f.confidence == Confidence.MEDIUM
        assert f.location is None
        assert f.evidence == []
        assert f.advice is None

    def test_finding_score_computed(self) -> None:
        f = Finding(
            title="test",
            category=Category.DANGEROUS_FUNC,
            severity=Severity.CRITICAL,
            confidence=Confidence.CERTAIN,
        )
        assert f.score == 1.0

    def test_finding_score_settable(self) -> None:
        f = Finding(title="t", category=Category.INFO)
        f.score = 0.42
        assert f.score == pytest.approx(0.42)

    def test_finding_to_dict(self) -> None:
        f = Finding(
            title="Shell found",
            category=Category.STRINGS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            location="0x401234",
            evidence=["raw evidence"],
            advice="check this",
        )
        d = f.to_dict()
        assert d["title"] == "Shell found"
        assert d["category"] == "strings"
        assert d["severity"] == "high"
        assert d["confidence"] == "high"
        assert "score" in d
        assert d["location"] == "0x401234"

    def test_finding_extra_preserved(self) -> None:
        f = Finding(
            title="t", category=Category.PROTECTIONS,
            extra={"key": "nx", "value": True},
        )
        assert f.extra["key"] == "nx"
        assert f.extra["value"] is True


# ---------------------------------------------------------------------------
# Report tests
# ---------------------------------------------------------------------------

class TestReport:
    def test_report_add_finding(self, sample_target: Target) -> None:
        r = Report(target=sample_target)
        f = Finding(title="test", category=Category.BINARY_INFO)
        r.add(f)
        assert len(r.findings) == 1

    def test_report_by_category(self, sample_target: Target) -> None:
        r = Report(target=sample_target)
        r.add(Finding(title="A", category=Category.BINARY_INFO))
        r.add(Finding(title="B", category=Category.PROTECTIONS))
        r.add(Finding(title="C", category=Category.BINARY_INFO))
        bi = r.by_category(Category.BINARY_INFO)
        assert len(bi) == 2
        assert all(f.category == Category.BINARY_INFO for f in bi)

    def test_report_sorted_by_score(self, sample_target: Target) -> None:
        r = Report(target=sample_target)
        r.add(Finding(title="low",  category=Category.INFO, severity=Severity.LOW,  confidence=Confidence.LOW))
        r.add(Finding(title="high", category=Category.INFO, severity=Severity.HIGH, confidence=Confidence.HIGH))
        r.add(Finding(title="crit", category=Category.INFO, severity=Severity.CRITICAL, confidence=Confidence.CERTAIN))
        sorted_f = r.sorted_by_score()
        assert sorted_f[0].title == "crit"
        assert sorted_f[-1].title == "low"

    def test_report_to_dict_schema(self, sample_target: Target) -> None:
        r = Report(target=sample_target)
        d = r.to_dict()
        assert d["schema_version"] == "1.0"
        assert "target" in d
        assert "findings" in d
        assert "errors" in d
        assert d["target"]["sha256"] == sample_target.sha256

    def test_report_add_error(self, sample_target: Target) -> None:
        r = Report(target=sample_target)
        r.add_error("something went wrong")
        assert "something went wrong" in r.errors


# ---------------------------------------------------------------------------
# Scoring helper
# ---------------------------------------------------------------------------

class TestDefaultScore:
    def test_critical_certain(self) -> None:
        assert _default_score(Severity.CRITICAL, Confidence.CERTAIN) == pytest.approx(1.0)

    def test_info_any_is_zero(self) -> None:
        assert _default_score(Severity.INFO, Confidence.CERTAIN) == pytest.approx(0.0)

    def test_score_ordering(self) -> None:
        s_high   = _default_score(Severity.HIGH, Confidence.HIGH)
        s_medium = _default_score(Severity.MEDIUM, Confidence.MEDIUM)
        s_low    = _default_score(Severity.LOW, Confidence.LOW)
        assert s_high > s_medium > s_low
