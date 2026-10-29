#!/usr/bin/env python3
"""
scripts/ai_benchmark.py — Benchmark AI providers, latency, and verification rates.

Usage
-----
    python scripts/ai_benchmark.py [options]

Options
-------
    --binary PATH     Path to binary to analyse (optional; creates synthetic binary if omitted)
    --ai-config PATH  Path to corvida.yaml (default: auto-discover)
    --mock            Use mock providers for deterministic performance measurement
    --runs N          Number of iterations to run (default: 3)
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

from corvida.core.config import Config
from corvida.core.models import (
    Category,
    Confidence,
    Finding,
    Report,
    Severity,
    Target,
)
from corvida.model import run_ai
from corvida.model.client import MockProvider
from corvida.model.context_builder import build_context


def _build_synthetic_report(tmp_dir: Path) -> Report:
    bin_file = tmp_dir / "bench_target"
    # Write basic ELF
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
    bin_file.write_bytes(bytes(elf) + b"/bin/sh\x00gets\x00system\x00")

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

    f1 = Finding(
        title="NX disabled (stack execution permitted)",
        category=Category.PROTECTIONS,
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        extra={"nx": False},
    )
    f1.score = 8.5
    report.add(f1)

    f2 = Finding(
        title="gets() called without boundary checks",
        category=Category.DANGEROUS_FUNC,
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        location="0x401156",
        evidence=["call 0x401030 <gets@plt>", "buffer size: 64 bytes"],
        advice="Replace gets with fgets()",
        extra={"func_name": "gets"},
    )
    f2.score = 9.5
    report.add(f2)

    f3 = Finding(
        title="Found '/bin/sh' string literal",
        category=Category.STRINGS,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        location="0x402008",
        evidence=["/bin/sh"],
        extra={"value": "/bin/sh"},
    )
    f3.score = 3.0
    report.add(f3)

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Corvida AI Layer Benchmark")
    parser.add_argument("--binary", type=Path, default=None, help="Binary file to triage")
    parser.add_argument("--ai-config", type=Path, default=None, help="Path to corvida.yaml")
    parser.add_argument("--mock", action="store_true", help="Run with mock provider")
    parser.add_argument("--runs", type=int, default=3, help="Number of benchmark iterations")
    args = parser.parse_args()

    # Use ASCII box on Windows to prevent cp1252 charmap encoding errors
    console = Console(safe_box=True)
    console.print("=== CORVIDA AI Benchmark ===")

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        if args.binary and args.binary.is_file():
            from corvida.core.pipeline import run as run_pipeline
            report = run_pipeline(args.binary, Config())
        else:
            report = _build_synthetic_report(tmp_dir)

        ctx = build_context(report)
        token_estimate = len(json.dumps(ctx)) // 4
        console.print(f"Target: {report.target.name} ({report.target.arch} {report.target.bits}-bit)")
        console.print(f"Findings Count: {len(report.findings)}")
        console.print(f"Estimated Context Tokens: {token_estimate}\n")

        # If --mock and no config given, write a mock config
        ai_cfg_path = args.ai_config
        if args.mock and ai_cfg_path is None:
            mock_cfg_data = {
                "providers": {
                    "mock": {"base_url": "http://localhost:11434/v1", "key_env": ""},
                },
                "roles": {
                    "summarizer": [{"provider": "mock", "model": "bench-summarizer"}],
                    "verifier":   [{"provider": "mock", "model": "bench-verifier"}],
                },
                "policy": {
                    "cache": False,
                    "max_context_tokens": 4000,
                    "temperature": 0.2,
                },
            }
            import yaml
            ai_cfg_path = tmp_dir / "bench_corvida.yaml"
            ai_cfg_path.write_text(yaml.dump(mock_cfg_data), encoding="utf-8")

        table = Table(title="Benchmark Results", box=box.ASCII)
        table.add_column("Iteration", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("Latency (s)", justify="right")
        table.add_column("Claims", justify="center")
        table.add_column("Verified Rate", justify="right")
        table.add_column("Models Used")

        latencies: list[float] = []
        verified_rates: list[float] = []

        cfg = Config(
            ai_enabled=True,
            ai_config_path=ai_cfg_path,
            ai_no_cache=True,
            ai_yes=True,
        )

        for i in range(1, args.runs + 1):
            t0 = time.monotonic()
            if args.mock:
                from unittest.mock import patch
                mock_sum = json.dumps({
                    "summary": "Mock benchmark summary",
                    "likely_vulns": [
                        {"finding_id": "F0001", "description": "Buffer overflow via gets at 0x401156"}
                    ],
                    "next_steps": ["craft exploit payload"],
                    "confidence": "high",
                })
                mock_ver = json.dumps({
                    "claims": [
                        {"finding_id": "F0001", "description": "Buffer overflow via gets at 0x401156", "status": "supported"}
                    ]
                })
                provider = MockProvider(responses=[mock_sum, mock_ver], name="mock")
                with patch("corvida.model.client.build_provider", return_value=provider):
                    res = run_ai(report, cfg)
            else:
                res = run_ai(report, cfg)

            elapsed = time.monotonic() - t0
            latencies.append(elapsed)

            if res is not None:
                rate = (res.verified_count / res.total_claims * 100) if res.total_claims else 0.0
                verified_rates.append(rate)
                models = f"{res.summarizer_model} + {res.verifier_model}"
                table.add_row(
                    f"#{i}",
                    "[green]OK[/green]",
                    f"{elapsed:.3f}",
                    f"{res.verified_count}/{res.total_claims}",
                    f"{rate:.1f}%",
                    models,
                )
            else:
                table.add_row(
                    f"#{i}",
                    "[red]FAIL[/red]",
                    f"{elapsed:.3f}",
                    "0/0",
                    "0.0%",
                    "None (unavailable/failed)",
                )

        console.print(table)
        console.print()

        avg_lat = statistics.mean(latencies) if latencies else 0.0
        avg_rate = statistics.mean(verified_rates) if verified_rates else 0.0
        console.print(f"[bold]Average Latency:[/bold] {avg_lat:.3f}s")
        if verified_rates:
            console.print(f"[bold]Average Verification Rate:[/bold] {avg_rate:.1f}%")
        console.print("=" * 30)

    return 0


if __name__ == "__main__":
    sys.exit(main())
