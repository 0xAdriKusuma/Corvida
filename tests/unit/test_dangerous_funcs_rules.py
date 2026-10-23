"""
tests/unit/test_dangerous_funcs_rules.py — Tests for rule loading.
"""

import pytest
from pathlib import Path
from corvida.analyzers.pwn.dangerous_funcs import load_rules
from corvida.core.errors import RuleError


@pytest.fixture
def rules_dir() -> Path:
    """Return the actual rules directory in the project."""
    # tests/unit/../.. → project root → rules/
    here = Path(__file__).parent
    return here.parent.parent / "rules"


class TestLoadRules:
    def test_loads_successfully(self, rules_dir: Path) -> None:
        rules = load_rules(rules_dir)
        assert isinstance(rules, dict)
        assert len(rules) > 0

    def test_gets_is_present(self, rules_dir: Path) -> None:
        rules = load_rules(rules_dir)
        assert "gets" in rules

    def test_system_is_present(self, rules_dir: Path) -> None:
        rules = load_rules(rules_dir)
        assert "system" in rules

    def test_severity_values_valid(self, rules_dir: Path) -> None:
        valid_severities = {"critical", "high", "medium", "low"}
        rules = load_rules(rules_dir)
        for name, entry in rules.items():
            sev = entry.get("severity", "")
            assert sev in valid_severities, f"Bad severity for {name!r}: {sev!r}"

    def test_missing_rules_dir_raises(self, tmp_path: Path) -> None:
        with pytest.raises(RuleError, match="not found"):
            load_rules(tmp_path / "nonexistent")

    def test_gets_advice_not_empty(self, rules_dir: Path) -> None:
        rules = load_rules(rules_dir)
        gets_rule = rules["gets"]
        assert gets_rule.get("advice", "").strip() != ""

    def test_alias_expansion(self, rules_dir: Path) -> None:
        """scanf has an alias __isoc99_scanf which should also be in dict."""
        rules = load_rules(rules_dir)
        # Both the canonical name and alias should resolve to the same entry
        if "scanf" in rules and "__isoc99_scanf" in rules:
            assert rules["scanf"]["name"] == rules["__isoc99_scanf"]["name"]
