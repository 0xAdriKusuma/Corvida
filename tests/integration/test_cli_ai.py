"""
tests/integration/test_cli_ai.py — Integration tests for CLI with AI options.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import yaml
from typer.testing import CliRunner

from corvida.cli import app
from corvida.core.models import (
    Category,
    Finding,
    Report,
    Severity,
    Target,
)
from corvida.model._runner import AIResult

runner = CliRunner()


def _make_mock_elf(tmp_path: Path) -> Path:
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
    p.write_bytes(bytes(elf) + b"/bin/sh\x00gets\x00")
    return p


def _make_clean_report(elf: Path) -> Report:
    target = Target(path=elf, file_type="ELF", arch="x86_64", bits=64)
    rep = Report(target=target)
    f = Finding(
        title="gets() called without check",
        category=Category.DANGEROUS_FUNC,
        severity=Severity.CRITICAL,
        location="0x401156",
    )
    rep.add(f)
    return rep


def _make_ai_config(tmp_path: Path) -> Path:
    cfg_data = {
        "providers": {
            "local": {"base_url": "http://localhost:11434/v1", "key_env": ""},
        },
        "roles": {
            "summarizer": [{"provider": "local", "model": "phi4-mini"}],
            "verifier":   [{"provider": "local", "model": "qwen3:4b"}],
        },
        "policy": {
            "cache": False,
            "max_context_tokens": 4000,
            "temperature": 0.2,
        },
    }
    cfg_file = tmp_path / "corvida.yaml"
    cfg_file.write_text(yaml.dump(cfg_data), encoding="utf-8")
    return cfg_file


class TestCLIAI:
    def test_cli_without_ai_flag_does_not_render_ai(self, tmp_path: Path) -> None:
        elf = _make_mock_elf(tmp_path)
        clean_rep = _make_clean_report(elf)

        with patch("corvida.core.pipeline.run", return_value=clean_rep):
            result = runner.invoke(app, [str(elf)])
            assert result.exit_code == 0
            assert "AI Summary" not in result.stdout

    def test_cli_with_ai_flag_renders_ai_panel(self, tmp_path: Path) -> None:
        elf = _make_mock_elf(tmp_path)
        cfg_file = _make_ai_config(tmp_path)
        clean_rep = _make_clean_report(elf)

        mock_ai_result = AIResult(
            summary="Vulnerable to stack overflow via gets.",
            likely_vulns=[
                {"finding_id": "F0001", "description": "gets() buffer overflow", "verified": "supported"}
            ],
            next_steps=["generate cyclic pattern"],
            confidence="high",
            summarizer_model="phi4-mini",
            summarizer_provider="local",
            verifier_model="qwen3:4b",
            verifier_provider="local",
            verified_count=1,
            total_claims=1,
        )

        with patch("corvida.core.pipeline.run", return_value=clean_rep), \
             patch("corvida.model.run_ai", return_value=mock_ai_result):
            result = runner.invoke(app, [str(elf), "--ai", "--ai-config", str(cfg_file)])
            assert result.exit_code == 0
            assert "AI Summary" in result.stdout
            assert "gets() buffer overflow" in result.stdout
            assert "1/1 claims" in result.stdout or "1/1" in result.stdout

    def test_cli_with_ai_and_json(self, tmp_path: Path) -> None:
        elf = _make_mock_elf(tmp_path)
        cfg_file = _make_ai_config(tmp_path)
        clean_rep = _make_clean_report(elf)

        mock_ai_result = AIResult(
            summary="Vulnerable to stack overflow.",
            likely_vulns=[],
            next_steps=[],
            confidence="medium",
            summarizer_model="phi4-mini",
            summarizer_provider="local",
            verifier_model="qwen3:4b",
            verifier_provider="local",
        )

        with patch("corvida.core.pipeline.run", return_value=clean_rep), \
             patch("corvida.model.run_ai", return_value=mock_ai_result):
            result = runner.invoke(app, [str(elf), "--ai", "--ai-config", str(cfg_file), "--json"])
            assert result.exit_code == 0
            data = json.loads(result.stdout)
            assert "ai" in data
            assert data["ai"]["summary"] == "Vulnerable to stack overflow."
            assert data["ai"]["confidence"] == "medium"

    def test_cli_ai_doctor(self, tmp_path: Path) -> None:
        cfg_file = _make_ai_config(tmp_path)
        # Mock connectivity check to avoid network dependency in tests
        with patch("corvida.cli._check_connectivity", return_value="OK"):
            result = runner.invoke(app, ["ai", "doctor", "--ai-config", str(cfg_file)])
            assert result.exit_code == 0
            assert "CORVIDA AI Doctor" in result.stdout
            assert "local" in result.stdout
            assert "phi4-mini" in result.stdout
