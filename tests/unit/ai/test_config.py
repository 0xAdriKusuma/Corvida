"""
tests/unit/ai/test_config.py — Unit tests for model/config.py

All tests run without network access and without a real corvida.yaml.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data), encoding="utf-8")


def _minimal_config() -> dict:
    return {
        "providers": {
            "local": {"base_url": "http://localhost:11434/v1", "key_env": ""},
        },
        "roles": {
            "summarizer": [{"provider": "local", "model": "phi4-mini"}],
            "verifier":   [{"provider": "local", "model": "qwen3:4b"}],
        },
        "policy": {
            "cache": True,
            "max_context_tokens": 4000,
            "temperature": 0.2,
        },
    }


class TestLoadAIConfig:
    def test_valid_minimal_config(self, tmp_path: Path) -> None:
        cfg_path = tmp_path / "corvida.yaml"
        _write_yaml(cfg_path, _minimal_config())

        from corvida.model.config import load_ai_config
        cfg = load_ai_config(cfg_path)

        assert "local" in cfg.providers
        assert cfg.providers["local"].base_url == "http://localhost:11434/v1"
        assert "summarizer" in cfg.roles
        assert "verifier"   in cfg.roles

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        from corvida.core.errors import AIConfigError
        from corvida.model.config import load_ai_config
        with pytest.raises(AIConfigError, match="not found"):
            load_ai_config(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        cfg_path = tmp_path / "corvida.yaml"
        cfg_path.write_text("{\nnot: valid: yaml: [\n", encoding="utf-8")

        from corvida.core.errors import AIConfigError
        from corvida.model.config import load_ai_config
        with pytest.raises(AIConfigError, match="not valid YAML|YAML"):
            load_ai_config(cfg_path)

    def test_missing_providers_raises(self, tmp_path: Path) -> None:
        data = _minimal_config()
        del data["providers"]
        cfg_path = tmp_path / "corvida.yaml"
        _write_yaml(cfg_path, data)

        from corvida.core.errors import AIConfigError
        from corvida.model.config import load_ai_config
        with pytest.raises(AIConfigError, match="providers"):
            load_ai_config(cfg_path)

    def test_missing_required_role_raises(self, tmp_path: Path) -> None:
        data = _minimal_config()
        del data["roles"]["verifier"]
        cfg_path = tmp_path / "corvida.yaml"
        _write_yaml(cfg_path, data)

        from corvida.core.errors import AIConfigError
        from corvida.model.config import load_ai_config
        with pytest.raises(AIConfigError, match="verifier"):
            load_ai_config(cfg_path)

    def test_unknown_provider_in_role_raises(self, tmp_path: Path) -> None:
        data = _minimal_config()
        data["roles"]["summarizer"] = [{"provider": "nonexistent", "model": "x"}]
        cfg_path = tmp_path / "corvida.yaml"
        _write_yaml(cfg_path, data)

        from corvida.core.errors import AIConfigError
        from corvida.model.config import load_ai_config
        with pytest.raises(AIConfigError, match="nonexistent"):
            load_ai_config(cfg_path)

    def test_policy_defaults(self, tmp_path: Path) -> None:
        data = _minimal_config()
        del data["policy"]
        cfg_path = tmp_path / "corvida.yaml"
        _write_yaml(cfg_path, data)

        from corvida.model.config import load_ai_config
        cfg = load_ai_config(cfg_path)
        assert cfg.policy.max_context_tokens == 6000
        assert cfg.policy.temperature == 0.2
        assert cfg.policy.cache is True

    def test_multiple_providers_and_roles(self, tmp_path: Path) -> None:
        data = _minimal_config()
        data["providers"]["groq"] = {
            "base_url": "https://api.groq.com/openai/v1",
            "key_env":  "GROQ_API_KEY",
        }
        data["roles"]["code_explainer"] = [
            {"provider": "groq", "model": "llama-3.1-70b"},
        ]
        cfg_path = tmp_path / "corvida.yaml"
        _write_yaml(cfg_path, data)

        from corvida.model.config import load_ai_config
        cfg = load_ai_config(cfg_path)
        assert "groq" in cfg.providers
        assert "code_explainer" in cfg.roles
