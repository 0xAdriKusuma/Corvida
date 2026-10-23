"""
core/pipeline.py — Orchestrates the full analysis flow.

Flow
----
  file path
    → detect() → pick loader → Target
    → open backend (rizin)
    → run all registered analyzers (in order, filtered by file_type)
    → run advisors
    → apply scores
    → return Report

The pipeline is intentionally boring: it delegates everything to the
registered components and focuses only on sequencing and error handling.
"""

from __future__ import annotations

import traceback
from pathlib import Path

from corvida.core.config import Config
from corvida.core.errors import BackendUnavailableError, UnsupportedFormatError
from corvida.core.models import Category, Confidence, Finding, Report, Severity, Target
from corvida.core.registry import _import_all, analyzer_registry, backend_registry, loader_registry
from corvida.core.scoring import apply_scores
from corvida.loaders.detect import detect_loader


def run(path: Path, config: Config) -> Report:
    """
    Entry point: analyse *path* and return a Report.

    Never raises (errors are captured in report.errors).
    """
    # Ensure all modules are imported so registries are populated
    _import_all()

    # ------------------------------------------------------------------
    # 1. Load target metadata
    # ------------------------------------------------------------------
    try:
        loader_cls = detect_loader(path)
        target = loader_cls().load(path)
    except UnsupportedFormatError as exc:
        # Can't do anything useful — return a minimal error report
        dummy_target = _dummy_target(path)
        report = Report(target=dummy_target)
        report.add_error(str(exc))
        return report
    except Exception as exc:             # noqa: BLE001
        dummy_target = _dummy_target(path)
        report = Report(target=dummy_target)
        report.add_error(f"Loader error: {exc}")
        return report

    report = Report(target=target)

    # ------------------------------------------------------------------
    # 2. Open backend
    # ------------------------------------------------------------------
    backend = None
    backend_cls = backend_registry.get("rizin") if "rizin" in backend_registry else None

    if backend_cls:
        try:
            backend = backend_cls(path, timeout=config.rzpipe_timeout)
            backend.open()
        except BackendUnavailableError as exc:
            report.add_error(str(exc))
            backend = None
        except Exception as exc:         # noqa: BLE001
            report.add_error(f"Backend init error: {exc}")
            backend = None

    # ------------------------------------------------------------------
    # 3. Run analyzers
    # ------------------------------------------------------------------
    for analyzer_cls in analyzer_registry.all():
        analyzer = analyzer_cls()

        # Skip if analyzer doesn't support this file type
        if analyzer.supports and target.file_type not in analyzer.supports:
            continue

        # Skip if analyzer needs a backend but we have none
        if analyzer.requires_backend and backend is None:
            report.add_error(
                f"Analyzer '{analyzer.name}' skipped: no backend available. "
                "Install rizin and rzpipe: https://rizin.re"
            )
            continue

        try:
            findings = analyzer.analyze(target=target, config=config, backend=backend)
            for f in findings:
                report.add(f)
        except Exception as exc:         # noqa: BLE001
            tb = traceback.format_exc()
            report.add_error(f"Analyzer '{analyzer.name}' crashed: {exc}")
            if config.verbose:
                report.add_error(tb)

    # ------------------------------------------------------------------
    # 4. Run advisors
    # ------------------------------------------------------------------
    try:
        from corvida.advisors.rules import RulesAdvisor
        advisor = RulesAdvisor(config)
        advisory_findings = advisor.advise(report)
        for f in advisory_findings:
            report.add(f)
    except Exception as exc:             # noqa: BLE001
        report.add_error(f"Advisor error: {exc}")

    # ------------------------------------------------------------------
    # 5. Score
    # ------------------------------------------------------------------
    apply_scores(report)

    # ------------------------------------------------------------------
    # 6. Close backend
    # ------------------------------------------------------------------
    if backend is not None:
        try:
            backend.close()
        except Exception:                # noqa: BLE001
            pass

    return report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dummy_target(path: Path) -> Target:
    """Create a minimal Target when loading fails (so Report still has one)."""
    try:
        return Target(path=path)
    except Exception:                    # noqa: BLE001
        # Even stat() failed — very unusual
        import os
        class _FakeTarget:               # type: ignore[no-redef]
            path = Path(path)
            sha256 = "unknown"
            size = 0
            name = Path(path).name
            arch = file_type = endian = interpreter = None
            bits = is_stripped = is_pie = None
        return _FakeTarget()             # type: ignore[return-value]
