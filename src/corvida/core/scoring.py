"""
core/scoring.py — Adjusts Finding.score after all analyzers have run.

Scoring is intentionally kept *separate* from analyzers so that the
weighting logic can evolve independently.  Analyzers produce raw findings;
this module re-weights them based on cross-finding context.

Current implementation: simple additive boosts based on combination rules.
"""

from __future__ import annotations

from corvida.core.models import Category, Confidence, Finding, Report, Severity


_SEV_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH:     0.75,
    Severity.MEDIUM:   0.5,
    Severity.LOW:      0.25,
    Severity.INFO:     0.0,
}
_CONF_WEIGHT = {
    Confidence.CERTAIN: 1.0,
    Confidence.HIGH:    0.8,
    Confidence.MEDIUM:  0.6,
    Confidence.LOW:     0.4,
}


def apply_scores(report: Report) -> None:
    """
    Mutate Finding.score for all findings in *report* using cross-context rules.

    Called by the pipeline after all analyzers finish.
    """
    _apply_base_scores(report)
    _apply_context_boosts(report)


def _apply_base_scores(report: Report) -> None:
    for f in report.findings:
        if f._score is None:
            f.score = _SEV_WEIGHT[f.severity] * _CONF_WEIGHT[f.confidence]


def _apply_context_boosts(report: Report) -> None:
    prot_findings = {
        f.extra.get("key"): f
        for f in report.by_category(Category.PROTECTIONS)
        if "key" in f.extra
    }

    nx_off      = prot_findings.get("nx")      and not prot_findings["nx"].extra.get("value", True)
    canary_off  = prot_findings.get("canary")  and not prot_findings["canary"].extra.get("value", True)
    pie_off     = prot_findings.get("pie")     and not prot_findings["pie"].extra.get("value", True)
    relro_full  = prot_findings.get("relro")   and prot_findings["relro"].extra.get("value") == "full"

    for f in report.findings:
        if f.category != Category.DANGEROUS_FUNC:
            continue
        boost = 0.0
        if nx_off:
            boost += 0.05
        if canary_off:
            boost += 0.10
        if pie_off:
            boost += 0.05
        if boost:
            f.score = min(1.0, f.score + boost)
