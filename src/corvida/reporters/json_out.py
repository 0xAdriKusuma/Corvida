"""
reporters/json_out.py — JSON reporter.

Serialises the full Report to stdout as a single JSON document.
Schema version is embedded in the output so downstream consumers
can detect breaking changes.
"""

from __future__ import annotations

import json
import sys

from corvida.core.config import Config
from corvida.core.models import Report
from corvida.core.registry import register_reporter
from corvida.reporters.base import BaseReporter


@register_reporter
class JsonReporter(BaseReporter):
    """Outputs the full Report as JSON to stdout."""

    name = "json"

    def render(self, report: Report, config: Config) -> None:
        data = report.to_dict()
        # Attach AI section if the AI layer ran
        if "ai" in report.metadata:
            data["ai"] = report.metadata["ai"]
        # Pretty-print for human readability; downstream tools can minify
        print(json.dumps(data, indent=2, ensure_ascii=False))
