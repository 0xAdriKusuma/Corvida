"""
model/config.py — Load and validate corvida.yaml AI configuration.

Schema
------
providers:
  local:
    base_url: "http://localhost:11434/v1"
    key_env: ""                         # empty string = no key needed
    rpm: 60                             # optional: requests per minute
    tpm: 100000                         # optional: tokens per minute
    rpd: 0                              # optional: requests per day (0 = unlimited)
    max_context_tokens: 0              # optional: per-provider context limit (0 = use policy)
  groq:
    base_url: "https://api.groq.com/openai/v1"
    key_env: "GROQ_API_KEY"
    rpm: 30
    tpm: 15000

roles:
  summarizer:
    - {provider: local, model: "phi4-mini"}
    - {provider: groq,  model: "llama-3.1-70b-versatile"}
  verifier:
    - {provider: local, model: "qwen3:4b"}

policy:
  sensitive_local_only: false
  cache: true
  max_context_tokens: 6000
  temperature: 0.2

Validation raises AIConfigError with a clear human-readable message.
Never reads or logs actual key values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from corvida.core.errors import AIConfigError

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ProviderConfig:
    name:     str
    base_url: str
    key_env:  str  # env var name; empty string means no key required

    # Optional per-provider rate-limit / context config
    rpm:                int = 0   # requests per minute (0 = unlimited)
    tpm:                int = 0   # tokens per minute (0 = unlimited)
    rpd:                int = 0   # requests per day (0 = unlimited)
    max_context_tokens: int = 0   # per-provider context limit (0 = use policy)


@dataclass
class ModelRef:
    """A (provider, model) pair in a role's fallback chain."""
    provider: str
    model:    str


@dataclass
class PolicyConfig:
    sensitive_local_only: bool  = False
    cache:                bool  = True
    max_context_tokens:   int   = 6000
    temperature:          float = 0.2


@dataclass
class AIConfig:
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    roles:     dict[str, list[ModelRef]] = field(default_factory=dict)
    policy:    PolicyConfig              = field(default_factory=PolicyConfig)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_SEARCH_PATHS: list[Path] = [
    Path.cwd() / "corvida.yaml",
    Path.home() / ".config" / "corvida" / "corvida.yaml",
    Path(__file__).parent.parent.parent.parent / "corvida.yaml",  # repo root
]


def _load_dotenv() -> None:
    """Load key-value pairs from .env if present into os.environ without overriding."""
    candidates = [Path.cwd() / ".env", Path(__file__).parent.parent.parent.parent / ".env"]
    for env_file in candidates:
        if env_file.is_file():
            try:
                for line in env_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = val
            except Exception:
                pass
            break


def load_ai_config(path: Path | None = None) -> AIConfig:
    """
    Load and validate corvida.yaml.

    Parameters
    ----------
    path:
        Explicit path.  If None, search standard locations in order.

    Raises
    ------
    AIConfigError
        If no config file is found or it fails validation.
    """
    _load_dotenv()
    cfg_path = _resolve_path(path)
    raw      = _read_yaml(cfg_path)
    return _validate(raw, cfg_path)


def _resolve_path(path: Path | None) -> Path:
    if path is not None:
        p = Path(path)
        if not p.exists():
            raise AIConfigError(f"AI config file not found: {p}")
        return p

    for candidate in _SEARCH_PATHS:
        if candidate.exists():
            return candidate

    search_list = "\n  ".join(str(p) for p in _SEARCH_PATHS)
    raise AIConfigError(
        "No corvida.yaml found.  Searched:\n  "
        + search_list
        + "\nCreate one or copy corvida.example.yaml and edit it."
    )


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise AIConfigError(f"corvida.yaml is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise AIConfigError(f"corvida.yaml must be a YAML mapping, got {type(data).__name__}")
    return data


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_REQUIRED_ROLES = {"summarizer", "verifier"}


def _validate(raw: dict[str, Any], path: Path) -> AIConfig:
    providers = _validate_providers(raw.get("providers") or {}, path)
    roles     = _validate_roles(raw.get("roles") or {}, providers, path)
    policy    = _validate_policy(raw.get("policy") or {}, path)
    return AIConfig(providers=providers, roles=roles, policy=policy)


def _validate_providers(
    raw: dict[str, Any], path: Path
) -> dict[str, ProviderConfig]:
    if not raw:
        raise AIConfigError(
            f"{path}: 'providers' section is missing or empty.\n"
            "At minimum define a 'local' provider."
        )
    providers: dict[str, ProviderConfig] = {}
    for name, cfg in raw.items():
        if not isinstance(cfg, dict):
            raise AIConfigError(
                f"{path}: provider '{name}' must be a mapping, got {type(cfg).__name__}"
            )
        base_url = cfg.get("base_url", "")
        if not base_url:
            raise AIConfigError(
                f"{path}: provider '{name}' is missing 'base_url'."
            )
        key_env = cfg.get("key_env", "")

        # Note: We intentionally do NOT warn here about missing keys.
        # The doctor command checks this explicitly. Warnings here cause
        # noisy output even when the provider is not used in any role.

        providers[name] = ProviderConfig(
            name=name,
            base_url=str(base_url),
            key_env=str(key_env),
            rpm=int(cfg.get("rpm", 0)),
            tpm=int(cfg.get("tpm", 0)),
            rpd=int(cfg.get("rpd", 0)),
            max_context_tokens=int(cfg.get("max_context_tokens", 0)),
        )
    return providers


def _validate_roles(
    raw: dict[str, Any],
    providers: dict[str, ProviderConfig],
    path: Path,
) -> dict[str, list[ModelRef]]:
    if not raw:
        raise AIConfigError(
            f"{path}: 'roles' section is missing or empty.\n"
            "At minimum define 'summarizer' and 'verifier' roles."
        )

    roles: dict[str, list[ModelRef]] = {}
    for role_name, chain in raw.items():
        if not isinstance(chain, list) or not chain:
            raise AIConfigError(
                f"{path}: role '{role_name}' must be a non-empty list of "
                "{{provider, model}} mappings."
            )
        refs: list[ModelRef] = []
        for i, entry in enumerate(chain):
            if not isinstance(entry, dict):
                raise AIConfigError(
                    f"{path}: role '{role_name}' entry #{i} must be a mapping."
                )
            provider_name = entry.get("provider")
            model_name    = entry.get("model")
            if not provider_name:
                raise AIConfigError(
                    f"{path}: role '{role_name}' entry #{i} missing 'provider'."
                )
            if not model_name:
                raise AIConfigError(
                    f"{path}: role '{role_name}' entry #{i} missing 'model'."
                )
            if provider_name not in providers:
                available = ", ".join(providers.keys())
                raise AIConfigError(
                    f"{path}: role '{role_name}' entry #{i} references unknown "
                    f"provider '{provider_name}'. Available: {available}"
                )
            refs.append(ModelRef(provider=str(provider_name), model=str(model_name)))
        roles[role_name] = refs

    missing = _REQUIRED_ROLES - roles.keys()
    if missing:
        raise AIConfigError(
            f"{path}: required roles missing: {', '.join(sorted(missing))}.\n"
            "Add them under the 'roles' key."
        )
    return roles


def _validate_policy(raw: dict[str, Any], path: Path) -> PolicyConfig:
    try:
        return PolicyConfig(
            sensitive_local_only = bool(raw.get("sensitive_local_only", False)),
            cache                = bool(raw.get("cache", True)),
            max_context_tokens   = int(raw.get("max_context_tokens", 6000)),
            temperature          = float(raw.get("temperature", 0.2)),
        )
    except (TypeError, ValueError) as exc:
        raise AIConfigError(f"{path}: invalid policy value: {exc}") from exc


def get_used_providers(cfg: AIConfig) -> set[str]:
    """Return the set of provider names actually referenced in any role chain."""
    used: set[str] = set()
    for chain in cfg.roles.values():
        for ref in chain:
            used.add(ref.provider)
    return used
