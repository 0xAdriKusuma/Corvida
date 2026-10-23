"""
loaders/detect.py — Auto-detect which loader to use for a file.

Detection is done by magic bytes first, file extension as fallback.
This keeps detection logic separate from the loaders themselves.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from corvida.core.errors import UnsupportedFormatError

if TYPE_CHECKING:
    from corvida.loaders.base import BaseLoader

# Magic-byte signatures: (offset, bytes) → file-type label
_MAGIC: list[tuple[int, bytes, str]] = [
    (0, b"\x7fELF",          "ELF"),
    (0, b"MZ",               "PE"),
    (0, b"\xca\xfe\xba\xbe", "Mach-O fat"),
    (0, b"\xfe\xed\xfa\xce", "Mach-O 32"),
    (0, b"\xfe\xed\xfa\xcf", "Mach-O 64"),
    (0, b"\xce\xfa\xed\xfe", "Mach-O 32 LE"),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O 64 LE"),
    (0, b"PK\x03\x04",       "ZIP/APK"),
    (0, b"dex\n",             "DEX"),
]

# Ordered list of loaders to try (populated by _import_loaders at call time)
# We do NOT import loaders at module level to avoid circular imports.
_LOADER_ORDER: list[str] = ["elf"]   # extend as more loaders are added


def _sniff(path: Path) -> str | None:
    """Return a file-type label based on magic bytes, or None."""
    try:
        with open(path, "rb") as fh:
            header = fh.read(16)
    except OSError:
        return None

    for offset, magic, label in _MAGIC:
        if header[offset: offset + len(magic)] == magic:
            return label
    return None


def detect_loader(path: Path) -> type:
    """
    Return the best loader class for *path*.

    Raises UnsupportedFormatError if no loader matches.
    """
    from corvida.core.registry import loader_registry

    file_type = _sniff(path)

    # Try each registered loader in priority order
    for name in _LOADER_ORDER:
        cls = loader_registry.get(name)
        if cls is None:
            continue
        if cls.can_load(path):
            return cls

    # Fallback: try remaining registered loaders
    for cls in loader_registry.all():
        if cls.can_load(path):
            return cls

    ft_str = f" (detected type: {file_type})" if file_type else ""
    raise UnsupportedFormatError(
        f"No loader found for '{path.name}'{ft_str}. "
        "Supported formats: ELF. PE/Mach-O support coming soon."
    )
