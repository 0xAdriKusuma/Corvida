"""
tests/unit/test_strings_analyzer.py — Tests for the strings analyzer.

Regression tests include verifying that virtual addresses match
the output of ``strings -t x`` (file-offset mode) for known binary layouts.
"""

import struct
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from corvida.analyzers.common.strings import (
    StringsAnalyzer,
    _score_string,
    _scan_binary,
    _scan_elf_sections,
)
from corvida.core.config import Config
from corvida.core.models import Category, Target


@pytest.fixture
def tmp_binary(tmp_path: Path) -> Path:
    p = tmp_path / "testbin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    return p


@pytest.fixture
def target(tmp_binary: Path) -> Target:
    t = Target(path=tmp_binary)
    t.file_type = "ELF"
    return t


@pytest.fixture
def config() -> Config:
    return Config(max_strings=20, min_string_len=4)


# ---------------------------------------------------------------------------
# _score_string
# ---------------------------------------------------------------------------

class TestScoreString:
    def test_shell_scores_high(self) -> None:
        score, label, sev, conf = _score_string("/bin/sh")
        assert score >= 0.9
        assert "shell" in label.lower() or "Shell" in label

    def test_flag_pattern_scores_high(self) -> None:
        score, label, sev, conf = _score_string("flag{this_is_a_flag}")
        assert score >= 0.8

    def test_ordinary_string_scores_zero(self) -> None:
        score, label, sev, conf = _score_string("hello world")
        assert score == 0.0

    def test_password_scores_medium(self) -> None:
        score, _, _, _ = _score_string("Enter password:")
        assert score >= 0.5

    def test_bin_sh_not_confused_with_empty(self) -> None:
        score, _, _, _ = _score_string("")
        assert score == 0.0


# ---------------------------------------------------------------------------
# _scan_binary
# ---------------------------------------------------------------------------

class TestScanBinary:
    def test_finds_strings(self, tmp_path: Path) -> None:
        p = tmp_path / "bin"
        p.write_bytes(b"\x00\x00" + b"hello world\x00" + b"\x00\x00")
        results = _scan_binary(p, min_len=4)
        strings = [r["string"] for r in results]
        assert any("hello world" in s for s in strings)

    def test_respects_min_len(self, tmp_path: Path) -> None:
        p = tmp_path / "bin"
        p.write_bytes(b"hi\x00" + b"hello world\x00")
        results = _scan_binary(p, min_len=5)
        strings = [r["string"] for r in results]
        assert not any(s == "hi" for s in strings)

    def test_null_bytes_separate_strings(self, tmp_path: Path) -> None:
        """Null bytes must terminate strings — two strings should be found, not one."""
        p = tmp_path / "bin"
        p.write_bytes(b"flag{aaa}\x00flag{bbb}\x00")
        results = _scan_binary(p, min_len=4)
        strings = [r["string"] for r in results]
        assert len(strings) >= 2

    def test_vaddr_is_file_offset(self, tmp_path: Path) -> None:
        """For raw binary scan, vaddr should equal file_offset (strings -t x compat)."""
        p = tmp_path / "bin"
        prefix = b"\x00" * 16
        p.write_bytes(prefix + b"flag{test}\x00")
        results = _scan_binary(p, min_len=4)
        flag_results = [r for r in results if "flag{" in r["string"]]
        assert flag_results, "should find the flag string"
        r = flag_results[0]
        assert r["vaddr"] == r["file_offset"]
        assert r["vaddr"] == len(prefix), (
            f"Expected vaddr={len(prefix):#x}, got {r['vaddr']:#x}"
        )

    def test_finding_has_length(self, tmp_path: Path) -> None:
        p = tmp_path / "bin"
        p.write_bytes(b"\x00" + b"password_here\x00")
        results = _scan_binary(p, min_len=4)
        pw_results = [r for r in results if "password" in r["string"]]
        assert pw_results
        assert pw_results[0]["length"] == len("password_here")


# ---------------------------------------------------------------------------
# _scan_elf_sections
# ---------------------------------------------------------------------------

class TestScanElfSections:
    def test_falls_back_gracefully_on_non_elf(self, tmp_path: Path) -> None:
        """Non-ELF binary should not crash; returns raw scan results or empty."""
        p = tmp_path / "notelf"
        p.write_bytes(b"MZ" + b"\x00" * 16 + b"flag{win}\x00")
        results = _scan_elf_sections(p, min_len=4)
        # Should not raise; may or may not find strings
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# StringsAnalyzer integration
# ---------------------------------------------------------------------------

class TestStringsAnalyzer:
    def test_returns_findings_no_backend(self, target: Target, config: Config) -> None:
        target.path.write_bytes(b"\x7fELF" + b"\x00" * 20 + b"/bin/sh\x00" + b"\x00" * 30)
        analyzer = StringsAnalyzer()
        findings = analyzer.analyze(target=target, config=config, backend=None)
        titles = [f.title for f in findings]
        assert any("/bin/sh" in t for t in titles)

    def test_respects_max_strings(self, target: Target, config: Config) -> None:
        config.max_strings = 3
        data = b"\x7fELF" + b"\x00" * 4
        for i in range(20):
            data += f"flag{{item_{i}}}\x00".encode()
        target.path.write_bytes(data)
        analyzer = StringsAnalyzer()
        findings = analyzer.analyze(target=target, config=config, backend=None)
        assert len(findings) <= 3

    def test_category_is_strings(self, target: Target, config: Config) -> None:
        target.path.write_bytes(b"\x7fELF" + b"/bin/sh\x00")
        analyzer = StringsAnalyzer()
        findings = analyzer.analyze(target=target, config=config, backend=None)
        for f in findings:
            assert f.category == Category.STRINGS

    def test_finding_has_vaddr_extra(self, target: Target, config: Config) -> None:
        target.path.write_bytes(b"\x7fELF" + b"\x00" * 4 + b"/bin/sh\x00")
        analyzer = StringsAnalyzer()
        findings = analyzer.analyze(target=target, config=config, backend=None)
        sh_findings = [f for f in findings if "/bin/sh" in str(f.extra.get("string", ""))]
        assert sh_findings
        assert "vaddr" in sh_findings[0].extra

    def test_uses_backend_when_available(self, target: Target, config: Config) -> None:
        backend = MagicMock()
        backend.strings.return_value = [
            {"string": "/bin/sh", "vaddr": 0x1000, "section": ".rodata"},
            {"string": "flag{from_backend}", "vaddr": 0x1010, "section": ".rodata"},
        ]
        analyzer = StringsAnalyzer()
        findings = analyzer.analyze(target=target, config=config, backend=backend)
        backend.strings.assert_called_once_with(min_len=config.min_string_len)
        titles = [f.title for f in findings]
        assert any("/bin/sh" in t for t in titles)
        assert any("flag{" in t for t in titles)

    def test_falls_back_when_backend_raises(self, target: Target, config: Config) -> None:
        backend = MagicMock()
        backend.strings.side_effect = RuntimeError("rizin crashed")
        target.path.write_bytes(b"\x7fELF" + b"\x00" * 4 + b"/bin/sh\x00")
        analyzer = StringsAnalyzer()
        # Should not raise; falls back to pyelftools/raw scan
        findings = analyzer.analyze(target=target, config=config, backend=backend)
        assert isinstance(findings, list)

    def test_finding_location_has_address(self, target: Target, config: Config) -> None:
        target.path.write_bytes(b"\x7fELF" + b"\x00" * 4 + b"/bin/sh\x00")
        analyzer = StringsAnalyzer()
        findings = analyzer.analyze(target=target, config=config, backend=None)
        sh_findings = [f for f in findings if "/bin/sh" in str(f.extra.get("string", ""))]
        if sh_findings:
            loc = sh_findings[0].location
            assert loc  # location should be non-empty string


# ---------------------------------------------------------------------------
# Null-separator regression (key regression for vuln binary testing)
# ---------------------------------------------------------------------------

class TestNullSeparatorRegression:
    """
    Regression tests: null bytes must separate strings.
    Previously the raw scanner included b'\x00' in printable set, causing
    adjacent strings to merge and incorrect offsets.
    """

    def test_two_adjacent_strings_separated_by_null(self, tmp_path: Path) -> None:
        """Null byte separates two strings; both should be found independently."""
        p = tmp_path / "bin"
        s1 = b"flag{first}"
        s2 = b"flag{second}"
        p.write_bytes(s1 + b"\x00" + s2 + b"\x00")
        results = _scan_binary(p, min_len=4)
        strings = [r["string"] for r in results]
        assert "flag{first}"  in strings
        assert "flag{second}" in strings

    def test_offset_is_correct_after_null(self, tmp_path: Path) -> None:
        """Verify file offset of second string accounts for the null separator."""
        p = tmp_path / "bin"
        s1 = b"password_abc"          # len=12
        null = b"\x00"
        s2 = b"flag{second}"
        p.write_bytes(s1 + null + s2)
        results = _scan_binary(p, min_len=6)
        flag_results = [r for r in results if "flag{second}" in r["string"]]
        assert flag_results, "Should find second string"
        expected_offset = len(s1) + len(null)
        assert flag_results[0]["file_offset"] == expected_offset, (
            f"Expected offset {expected_offset:#x}, got {flag_results[0]['file_offset']:#x}"
        )
