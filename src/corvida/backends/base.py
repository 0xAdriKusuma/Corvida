"""
backends/base.py — Abstract base class for analysis backends.

A backend wraps an external tool (rizin, pwntools, objdump, …) and provides
a normalised API for querying the binary.  Backends are stateful: they open
a session on construction and close it in ``close()`` / ``__exit__``.

Analyzer code should never call rzpipe or pyelftools directly — always go
through a backend.  This makes backends swappable and mockable in tests.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BaseBackend(ABC):
    """
    Abstract backend.

    Class attributes
    ----------------
    name : str
        Short identifier (e.g. "rizin", "pyelftools").
    """

    name: str = ""

    def __init__(self, path: Path, timeout: int = 30) -> None:
        self.path = path
        self.timeout = timeout

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    @abstractmethod
    def open(self) -> None:
        """Open a session with the underlying tool."""

    @abstractmethod
    def close(self) -> None:
        """Release all resources."""

    def __enter__(self) -> "BaseBackend":
        self.open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # -----------------------------------------------------------------------
    # Query API — return plain Python structures (no rzpipe/pyelftools types)
    # -----------------------------------------------------------------------

    @abstractmethod
    def imports(self) -> list[dict[str, Any]]:
        """
        Return imported symbols.

        Each dict must contain at least:
            ``{"name": str, "plt": int | None, "type": str}``
        """

    @abstractmethod
    def functions(self) -> list[dict[str, Any]]:
        """
        Return known functions.

        Each dict must contain at least:
            ``{"name": str, "offset": int, "size": int}``
        """

    @abstractmethod
    def xrefs_to(self, address: int) -> list[dict[str, Any]]:
        """
        Return cross-references TO *address*.

        Each dict must contain at least:
            ``{"from": int, "type": str}``
        """

    @abstractmethod
    def strings(self, min_len: int = 6) -> list[dict[str, Any]]:
        """
        Return printable strings found in the binary.

        Each dict must contain at least:
            ``{"string": str, "vaddr": int, "section": str | None}``
        """
