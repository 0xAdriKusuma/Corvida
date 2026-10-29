"""
model/privacy.py — Privacy policy enforcement.

Rules
-----
1. If local_only (CLI flag --local-only or config sensitive_local_only),
   cloud providers are rejected with a clear PrivacyError.
2. On first call to a cloud provider in a session, print a one-line warning
   and ask for confirmation (skip with --yes / ai_yes=True).
3. The check is side-effect-free (no network) — pure policy logic.
"""

from __future__ import annotations

from corvida.core.errors import PrivacyError
from corvida.model.client import Provider

# Track which providers the user has already been warned about this session
_confirmed_providers: set[str] = set()


def check_privacy(
    provider:           Provider,
    local_only:         bool,
    sensitive_local_only: bool,
    yes:                bool = False,
) -> None:
    """
    Raise PrivacyError if *provider* is not allowed under current policy.

    Parameters
    ----------
    provider:
        The candidate provider.
    local_only:
        CLI --local-only flag.
    sensitive_local_only:
        corvida.yaml policy.sensitive_local_only value.
    yes:
        CLI --yes flag; skips interactive confirmation.

    Raises
    ------
    PrivacyError
        When a cloud provider is used in local-only mode.
    """
    if provider.is_local():
        return  # local providers always allowed

    # Enforce local-only policy
    if local_only or sensitive_local_only:
        reason = "--local-only flag" if local_only else "sensitive_local_only: true in corvida.yaml"
        raise PrivacyError(
            f"Provider '{provider.name}' is a cloud provider but local-only mode is active "
            f"({reason}).  Use a local provider (e.g. Ollama) or disable the restriction."
        )

    # First-time cloud warning
    if provider.name not in _confirmed_providers:
        _warn_cloud(provider.name, yes)
        _confirmed_providers.add(provider.name)


def _warn_cloud(provider_name: str, yes: bool) -> None:
    """Print a one-line cloud-send warning; prompt if not --yes."""
    import sys
    msg = (
        f"\n[corvida] NOTE: Analysis context (text, no binary) will be sent to "
        f"cloud provider '{provider_name}'.\n"
        "         API keys are read from environment variables and never logged.\n"
    )
    print(msg, file=sys.stderr)

    if yes:
        return

    try:
        answer = input("  Continue? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"

    if answer not in ("y", "yes"):
        raise PrivacyError(
            f"User declined to send data to cloud provider '{provider_name}'. "
            "Use --yes to skip this prompt, or --local-only to use only local providers."
        )


def reset_confirmed_providers() -> None:
    """Clear session confirmation state.  Used in tests."""
    _confirmed_providers.clear()
