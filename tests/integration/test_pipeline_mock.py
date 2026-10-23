"""
tests/integration/test_pipeline_mock.py — Integration tests using a mock backend.

These tests run the full pipeline on a synthetic ELF-like binary and a
fully mocked backend so they work on any OS without rizin installed.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from corvida.core.config import Config
from corvida.core.models import Category, Report


def _make_elf_binary(tmp_path: Path, extra_data: bytes = b"") -> Path:
    """Write a syntactically valid ELF64 header for testing."""
    import struct

    elf = bytearray(64)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2
    elf[5] = 1
    elf[6] = 1
    elf[7] = 0
    struct.pack_into("<H", elf, 16, 2)
    struct.pack_into("<H", elf, 18, 62)
    struct.pack_into("<I", elf, 20, 1)
    struct.pack_into("<H", elf, 52, 64)

    p = tmp_path / "mock_elf"
    p.write_bytes(bytes(elf) + extra_data)
    return p


class TestPipelineWithMockBackend:
    @pytest.fixture
    def elf_path(self, tmp_path: Path) -> Path:
        return _make_elf_binary(tmp_path, extra_data=b"/bin/sh\x00gets\x00system\x00")

    @pytest.fixture
    def config(self) -> Config:
        return Config(max_strings=20, verbose=False)

    def test_pipeline_returns_report(self, elf_path: Path, config: Config) -> None:
        from corvida.core.pipeline import run
        report = run(elf_path, config)
        assert isinstance(report, Report)

    def test_report_has_binary_info(self, elf_path: Path, config: Config) -> None:
        from corvida.core.pipeline import run
        report = run(elf_path, config)
        bi = report.by_category(Category.BINARY_INFO)
        assert len(bi) > 0, "Binary info findings should be present"

    def test_report_has_protections(self, elf_path: Path, config: Config) -> None:
        from corvida.core.pipeline import run
        report = run(elf_path, config)
        prot = report.by_category(Category.PROTECTIONS)
        assert len(prot) > 0, "Protections findings should be present"

    def test_report_has_strings(self, elf_path: Path, config: Config) -> None:
        from corvida.core.pipeline import run
        report = run(elf_path, config)
        strings = report.by_category(Category.STRINGS)
        # /bin/sh is in the binary — should be found
        assert any("/bin/sh" in f.title for f in strings), (
            f"Expected /bin/sh in strings. Got: {[f.title for f in strings]}"
        )

    def test_json_output_is_valid(self, elf_path: Path, config: Config) -> None:
        from corvida.core.pipeline import run
        report = run(elf_path, config)
        d = report.to_dict()
        # Re-serialise and parse to confirm it's valid JSON
        raw = json.dumps(d)
        parsed = json.loads(raw)
        assert parsed["schema_version"] == "1.0"
        assert parsed["target"]["name"] == elf_path.name

    def test_target_arch_detected(self, elf_path: Path, config: Config) -> None:
        from corvida.core.pipeline import run
        report = run(elf_path, config)
        assert report.target.arch == "x86_64"
        assert report.target.bits == 64

    def test_target_not_pie(self, elf_path: Path, config: Config) -> None:
        from corvida.core.pipeline import run
        report = run(elf_path, config)
        assert report.target.is_pie is False   # ET_EXEC, not ET_DYN

    def test_no_crash_on_stripped(self, tmp_path: Path, config: Config) -> None:
        """Pipeline must not crash on a stripped binary (no .symtab)."""
        elf_path = _make_elf_binary(tmp_path, extra_data=b"")
        from corvida.core.pipeline import run
        report = run(elf_path, config)
        # Should complete without exception
        assert report is not None

    def test_report_to_dict_findings_sorted(self, elf_path: Path, config: Config) -> None:
        from corvida.core.pipeline import run
        report = run(elf_path, config)
        d = report.to_dict()
        scores = [f["score"] for f in d["findings"]]
        # Should be sorted descending
        assert scores == sorted(scores, reverse=True), "Findings not sorted by score"


class TestPipelineUnsupportedFormat:
    def test_non_elf_returns_error_report(self, tmp_path: Path) -> None:
        """A PE file should trigger UnsupportedFormatError → error in report."""
        pe_path = tmp_path / "fake.exe"
        pe_path.write_bytes(b"MZ" + b"\x00" * 100)

        from corvida.core.pipeline import run
        config = Config()
        report = run(pe_path, config)
        # Pipeline should not crash, just log an error
        assert report is not None
        assert len(report.errors) > 0
