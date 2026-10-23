"""
tests/unit/test_advisor.py — Tests for the rules advisor.
"""

import pytest
from pathlib import Path

from corvida.advisors.rules import RulesAdvisor
from corvida.core.config import Config
from corvida.core.models import (
    Category, Confidence, Finding, Report, Severity, Target,
)


@pytest.fixture
def tmp_binary(tmp_path: Path) -> Path:
    p = tmp_path / "fake"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    return p


@pytest.fixture
def config() -> Config:
    return Config()


def _make_prot(key: str, value) -> Finding:
    on = isinstance(value, bool) and value
    off = isinstance(value, bool) and not value
    return Finding(
        title=f"{key}: {'on' if on else 'off' if off else value}",
        category=Category.PROTECTIONS,
        severity=Severity.INFO,
        confidence=Confidence.CERTAIN,
        extra={"key": key, "value": value},
    )


def _make_dfunc(func_name: str, tags: list) -> Finding:
    return Finding(
        title=f"Dangerous import: {func_name}()",
        category=Category.DANGEROUS_FUNC,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        extra={"func_name": func_name, "tags": tags},
    )


class TestRulesAdvisor:
    def _build_report(self, tmp_binary: Path, findings: list[Finding]) -> Report:
        t = Target(path=tmp_binary)
        r = Report(target=t)
        for f in findings:
            r.add(f)
        return r

    def test_ret2win_fires(self, tmp_binary: Path, config: Config) -> None:
        report = self._build_report(tmp_binary, [
            _make_prot("canary", False),
            _make_prot("pie",    False),
            _make_prot("nx",     True),
            _make_dfunc("gets",  ["stack_overflow", "ret2win"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        titles = [f.title for f in findings]
        assert any("ret2win" in t.lower() for t in titles)

    def test_shellcode_fires_when_nx_off(self, tmp_binary: Path, config: Config) -> None:
        report = self._build_report(tmp_binary, [
            _make_prot("nx",     False),
            _make_prot("canary", False),
            _make_dfunc("gets",  ["stack_overflow"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        titles = [f.title for f in findings]
        assert any("shellcode" in t.lower() for t in titles)

    def test_no_false_positives_all_on(self, tmp_binary: Path, config: Config) -> None:
        """When all protections are on and no dangerous funcs, advisor should be quiet."""
        report = self._build_report(tmp_binary, [
            _make_prot("nx",     True),
            _make_prot("canary", True),
            _make_prot("pie",    True),
            _make_prot("relro",  "full"),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        # Should still be quiet (no dangerous funcs → no attack paths fired)
        dangerous_titles = [
            f.title for f in findings
            if any(kw in f.title.lower() for kw in ("shellcode", "ret2win", "ret2libc"))
        ]
        assert dangerous_titles == []

    def test_format_string_fires(self, tmp_binary: Path, config: Config) -> None:
        report = self._build_report(tmp_binary, [
            _make_dfunc("printf", ["format_string", "info_leak"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        titles = [f.title for f in findings]
        assert any("format string" in t.lower() for t in titles)

    def test_advisory_category(self, tmp_binary: Path, config: Config) -> None:
        report = self._build_report(tmp_binary, [
            _make_prot("canary", False),
            _make_prot("pie",    False),
            _make_dfunc("gets",  ["stack_overflow"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        for f in findings:
            assert f.category == Category.ADVISORY
