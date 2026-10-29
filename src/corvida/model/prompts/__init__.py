"""
model/prompts/__init__.py — Prompt loader with version extraction.

Prompts are stored as Markdown files with YAML frontmatter.
The frontmatter version string is included in the cache key so that
updating a prompt invalidates stale cache entries.
"""

from __future__ import annotations

import re
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent

_FRONTMATTER_RE = re.compile(
    r"^---\s*\n(.*?)\n---\s*\n(.*)$",
    re.DOTALL,
)


def load_prompt(name: str) -> tuple[str, str]:
    """
    Load a prompt file by name (without extension).

    Returns
    -------
    (system_prompt, prompt_version)

    The returned text is the prompt content WITHOUT the frontmatter header.
    """
    path = _PROMPTS_DIR / f"{name}.md"
    if not path.exists():
        raise FileNotFoundError(f"Prompt file not found: {path}")

    text = path.read_text(encoding="utf-8")
    m = _FRONTMATTER_RE.match(text)
    if m:
        front  = m.group(1)
        body   = m.group(2).strip()
        version = _extract_version(front)
    else:
        body    = text.strip()
        version = "unknown"

    return body, version


def _extract_version(frontmatter: str) -> str:
    for line in frontmatter.splitlines():
        if line.strip().startswith("prompt_version"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip().strip('"').strip("'")
    return "unknown"
