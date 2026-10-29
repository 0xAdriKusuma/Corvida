"""
tests/unit/ai/test_privacy.py — Unit tests for model/privacy.py
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from corvida.core.errors import PrivacyError
from corvida.model.client import MockProvider
from corvida.model.privacy import check_privacy, reset_confirmed_providers


@pytest.fixture(autouse=True)
def _reset_privacy() -> None:
    reset_confirmed_providers()


class TestPrivacy:
    def test_local_provider_always_allowed(self) -> None:
        p = MockProvider(responses=[], name="ollama", local=True)
        # Should never raise, even with local_only=True
        check_privacy(p, local_only=True, sensitive_local_only=True, yes=False)

    def test_cloud_provider_rejected_when_local_only(self) -> None:
        p = MockProvider(responses=[], name="groq", local=False)
        with pytest.raises(PrivacyError) as exc_info:
            check_privacy(p, local_only=True, sensitive_local_only=False, yes=True)
        assert "--local-only" in str(exc_info.value)

    def test_cloud_provider_rejected_when_sensitive_local_only(self) -> None:
        p = MockProvider(responses=[], name="groq", local=False)
        with pytest.raises(PrivacyError) as exc_info:
            check_privacy(p, local_only=False, sensitive_local_only=True, yes=True)
        assert "sensitive_local_only" in str(exc_info.value)

    def test_cloud_provider_with_yes_flag(self) -> None:
        p = MockProvider(responses=[], name="groq", local=False)
        # Should not prompt when yes=True
        with patch("builtins.input") as mock_input:
            check_privacy(p, local_only=False, sensitive_local_only=False, yes=True)
            mock_input.assert_not_called()

    def test_cloud_provider_prompt_user_accepts(self) -> None:
        p = MockProvider(responses=[], name="groq", local=False)
        with patch("builtins.input", return_value="y") as mock_input:
            check_privacy(p, local_only=False, sensitive_local_only=False, yes=False)
            mock_input.assert_called_once()

        # Second call in same session should not re-prompt
        with patch("builtins.input") as mock_input2:
            check_privacy(p, local_only=False, sensitive_local_only=False, yes=False)
            mock_input2.assert_not_called()

    def test_cloud_provider_prompt_user_declines(self) -> None:
        p = MockProvider(responses=[], name="groq", local=False)
        with patch("builtins.input", return_value="n"):
            with pytest.raises(PrivacyError) as exc_info:
                check_privacy(p, local_only=False, sensitive_local_only=False, yes=False)
            assert "declined" in str(exc_info.value).lower()
