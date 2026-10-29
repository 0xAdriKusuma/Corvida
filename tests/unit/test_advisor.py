"""
tests/unit/test_advisor.py — Tests for the rules advisor.

Includes both basic rule tests and tests for the vuln-binary scenario
(32-bit ELF, gets/strcpy/printf, NX on, no canary, PIE on/off).
"""

import pytest
from pathlib import Path

from corvida.advisors.rules import RulesAdvisor, _has_stack_overflow_func
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_prot(key: str, value) -> Finding:
    on  = isinstance(value, bool) and value
    off = isinstance(value, bool) and not value
    return Finding(
        title=f"{key}: {'on' if on else 'off' if off else value}",
        category=Category.PROTECTIONS,
        severity=Severity.INFO,
        confidence=Confidence.CERTAIN,
        extra={"key": key, "value": value},
    )


def _make_dfunc(func_name: str, tags: list, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        title=f"Dangerous import: {func_name}()",
        category=Category.DANGEROUS_FUNC,
        severity=severity,
        confidence=Confidence.HIGH,
        extra={"func_name": func_name, "tags": tags},
    )


def _make_bits(bits: int) -> Finding:
    return Finding(
        title=f"Architecture: x86 ({bits}-bit)",
        category=Category.BINARY_INFO,
        severity=Severity.INFO,
        confidence=Confidence.CERTAIN,
        extra={"key": "bits", "value": bits},
    )


def _make_string(s: str) -> Finding:
    return Finding(
        title=f"String: {s!r}",
        category=Category.STRINGS,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        extra={"string": s},
    )


class TestRulesAdvisor:
    def _build_report(self, tmp_binary: Path, findings: list[Finding],
                      interpreter: str | None = "/lib/ld-linux.so.2") -> Report:
        from corvida.core.models import Target
        t = Target(path=tmp_binary)
        t.interpreter = interpreter
        r = Report(target=t)
        for f in findings:
            r.add(f)
        return r

    # ------------------------------------------------------------------
    # Basic rule tests
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Exploitability confidence tests
    # ------------------------------------------------------------------

    def test_printf_has_low_exploitability_confidence(self, tmp_binary: Path, config: Config) -> None:
        """printf import alone gets LOW exploitability confidence."""
        report = self._build_report(tmp_binary, [
            _make_dfunc("printf", ["format_string", "info_leak"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        fmt_findings = [f for f in findings if "format string" in f.title.lower()]
        assert fmt_findings, "format_string rule should fire"
        for f in fmt_findings:
            exp_conf = f.extra.get("exploitability_confidence")
            assert exp_conf == "low", (
                f"printf import alone should have low exploitability, got: {exp_conf}"
            )

    def test_gets_has_high_exploitability_confidence(self, tmp_binary: Path, config: Config) -> None:
        """gets + no canary + NX + system should fire ret2libc rule with high exploitability."""
        report = self._build_report(tmp_binary, [
            _make_prot("nx",     True),
            _make_prot("canary", False),
            _make_prot("pie",    False),
            _make_bits(64),
            _make_dfunc("gets",   ["stack_overflow", "ret2win", "ret2libc"]),
            _make_dfunc("system", ["ret2win", "ret2libc", "exec"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        # Check that at least one advisory has high exploitability
        high_exploit = [
            f for f in findings
            if f.extra.get("exploitability_confidence") in ("high", "certain")
        ]
        assert high_exploit, (
            f"Expected at least one advisory with high exploitability. "
            f"Got findings: {[f.title for f in findings]}"
        )

    # ------------------------------------------------------------------
    # 32-bit specific tests (vuln binary scenario)
    # ------------------------------------------------------------------

    def test_32bit_rop_rule_fires(self, tmp_binary: Path, config: Config) -> None:
        """32-bit + no canary + NX + gets → 32-bit ROP rule should fire."""
        report = self._build_report(tmp_binary, [
            _make_bits(32),
            _make_prot("nx",     True),
            _make_prot("canary", False),
            _make_prot("pie",    True),
            _make_prot("relro",  "full"),
            _make_dfunc("gets",  ["stack_overflow", "ret2win", "ret2libc"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        titles   = [f.title for f in findings]
        rules    = [f.extra.get("rule") for f in findings]
        assert "stack_overflow_rop_32bit" in rules, (
            f"32-bit ROP rule should fire. Titles: {titles}"
        )

    def test_32bit_context_note_cdecl(self, tmp_binary: Path, config: Config) -> None:
        """32-bit context notes should mention cdecl/stack args."""
        report = self._build_report(tmp_binary, [
            _make_bits(32),
            _make_prot("nx",     True),
            _make_prot("canary", False),
            _make_dfunc("gets",  ["stack_overflow"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        # Any finding from 32-bit scenario should include cdecl context
        found_cdecl = any(
            "cdecl" in f.advice.lower() or
            any("cdecl" in n.lower() for n in f.extra.get("context_notes", []))
            for f in findings
        )
        assert found_cdecl, "32-bit advisory should mention cdecl calling convention"

    def test_full_relro_context_note(self, tmp_binary: Path, config: Config) -> None:
        """Full RELRO context note should say GOT overwrite is not viable."""
        report = self._build_report(tmp_binary, [
            _make_bits(32),
            _make_prot("nx",     True),
            _make_prot("canary", False),
            _make_prot("relro",  "full"),
            _make_dfunc("gets",  ["stack_overflow"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        found_relro_note = any(
            any("full relro" in n.lower() or "got is read-only" in n.lower()
                for n in f.extra.get("context_notes", []))
            for f in findings
        )
        assert found_relro_note, "Should note full RELRO blocks GOT overwrite"

    def test_pie_context_note_leak_needed(self, tmp_binary: Path, config: Config) -> None:
        """PIE context note should mention needing a leak."""
        report = self._build_report(tmp_binary, [
            _make_prot("nx",     True),
            _make_prot("canary", False),
            _make_prot("pie",    True),
            _make_dfunc("gets",   ["stack_overflow"]),
            _make_dfunc("system", ["ret2win", "ret2libc", "exec"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        # Any of the context notes should mention PIE + leak
        found_pie_note = any(
            any("pie" in n.lower() and "leak" in n.lower()
                for n in f.extra.get("context_notes", []))
            for f in findings
        )
        assert found_pie_note, (
            f"PIE advisory should mention leaking address first. "
            f"Findings: {[(f.title, f.extra.get('context_notes')) for f in findings]}"
        )

    def test_no_pie_context_note_fixed_addresses(self, tmp_binary: Path, config: Config) -> None:
        """No-PIE context note should mention fixed addresses."""
        report = self._build_report(tmp_binary, [
            _make_prot("nx",     True),
            _make_prot("canary", False),
            _make_prot("pie",    False),
            _make_dfunc("gets",  ["stack_overflow"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        found_no_pie = any(
            any("no pie" in n.lower() and "fixed" in n.lower()
                for n in f.extra.get("context_notes", []))
            for f in findings
        )
        assert found_no_pie, "No-PIE advisory should mention fixed base address"

    # ------------------------------------------------------------------
    # _has_stack_overflow_func helper
    # ------------------------------------------------------------------

    def test_has_stack_overflow_excludes_puts(self, tmp_binary: Path) -> None:
        """puts/printf alone should NOT be counted as stack overflow capable."""
        t = Target(path=tmp_binary)
        r = Report(target=t)
        r.add(_make_dfunc("puts",   ["info_leak", "ret2plt"]))
        r.add(_make_dfunc("printf", ["format_string", "info_leak"]))
        # No high-risk overflow func
        assert not _has_stack_overflow_func(r)

    def test_has_stack_overflow_detects_gets(self, tmp_binary: Path) -> None:
        t = Target(path=tmp_binary)
        r = Report(target=t)
        r.add(_make_dfunc("gets", ["stack_overflow", "ret2win"]))
        assert _has_stack_overflow_func(r)

    def test_has_stack_overflow_detects_strcpy(self, tmp_binary: Path) -> None:
        t = Target(path=tmp_binary)
        r = Report(target=t)
        r.add(_make_dfunc("strcpy", ["stack_overflow"]))
        assert _has_stack_overflow_func(r)

    # ------------------------------------------------------------------
    # /bin/sh hint
    # ------------------------------------------------------------------

    def test_bin_sh_hint_fires(self, tmp_binary: Path, config: Config) -> None:
        report = self._build_report(tmp_binary, [
            _make_string("/bin/sh"),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        titles = [f.title for f in findings]
        assert any("/bin/sh" in t for t in titles)

    def test_got_overwrite_fires_partial_relro(self, tmp_binary: Path, config: Config) -> None:
        report = self._build_report(tmp_binary, [
            _make_prot("relro", "partial"),
            _make_dfunc("printf", ["format_string"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        titles = [f.title for f in findings]
        assert any("got overwrite" in t.lower() for t in titles)

    def test_got_overwrite_does_not_fire_full_relro(self, tmp_binary: Path, config: Config) -> None:
        report = self._build_report(tmp_binary, [
            _make_prot("relro", "full"),
            _make_dfunc("printf", ["format_string"]),
        ])
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        titles = [f.title for f in findings]
        assert not any("got overwrite" in t.lower() for t in titles)

    # ------------------------------------------------------------------
    # Static binary
    # ------------------------------------------------------------------

    def test_static_binary_rop_fires(self, tmp_binary: Path, config: Config) -> None:
        report = self._build_report(tmp_binary, [
            _make_prot("canary", False),
            _make_dfunc("gets",  ["stack_overflow"]),
        ], interpreter=None)
        advisor = RulesAdvisor(config)
        findings = advisor.advise(report)
        rules = [f.extra.get("rule") for f in findings]
        assert "static_binary_rop" in rules
