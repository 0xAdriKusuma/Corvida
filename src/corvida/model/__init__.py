"""
corvida/model/__init__.py — AI analysis layer for Corvida.

Public API
----------
    from corvida.model import run_ai, AIResult

    result = run_ai(report, config)   # returns None if AI disabled or all providers fail
"""

from __future__ import annotations

from corvida.model._runner import AIResult, run_ai

__all__ = ["AIResult", "run_ai"]
