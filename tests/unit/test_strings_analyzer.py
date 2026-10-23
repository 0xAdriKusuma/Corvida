"""
tests/unit/test_strings_analyzer.py — Tests for the strings analyzer.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from corvida.analyzers.common.strings import StringsAnalyzer, _score_string, _scan_binary
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
        # "hi" (len 2) should not appear
        assert not any(s == "hi" for s in strings)


class TestStringsAnalyzer:
    def test_returns_findings_no_backend(self, target: Target, config: Config, tmp_path: Path) -> None:
        # Write an ELF-like binary with an interesting string
        target.path.write_bytes(b"\x7fELF" + b"\x00" * 20 + b"/bin/sh\x00" + b"\x00" * 30)
        analyzer = StringsAnalyzer()
        findings = analyzer.analyze(target=target, config=config, backend=None)
        # Should find /bin/sh
        titles = [f.title for f in findings]
        assert any("/bin/sh" in t for t in titles)

    def test_respects_max_strings(self, target: Target, config: Config) -> None:
        config.max_strings = 3
        # Fill binary with many interesting strings
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
