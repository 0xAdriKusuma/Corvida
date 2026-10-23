"""
loaders/base.py — Abstract base class for all file format loaders.

A loader is responsible for:
  1. Detecting whether it can handle a given file (``can_load``).
  2. Populating ``Target`` fields (arch, bits, stripped, …) from the file.

Loaders do NOT perform analysis; they only extract structural metadata.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from corvida.core.models import Target


class BaseLoader(ABC):
    """
    Abstract loader.  Subclasses handle one file format (ELF, PE, …).

    Class attributes
    ----------------
    name : str
        Short identifier (e.g. "elf", "pe").  Used as registry key.
    supported_types : list[str]
        File-type strings this loader handles (e.g. ["ELF"]).
    """

    name: str = ""
    supported_types: ClassVar[list[str]] = []

    @classmethod
    @abstractmethod
    def can_load(cls, path: Path) -> bool:
        """
        Return True if this loader believes it can handle *path*.

        Should be fast (magic-byte check, extension check).
        Must NOT raise; return False on any error.
        """

    @abstractmethod
    def load(self, path: Path) -> Target:
        """
        Parse *path* and return a populated Target.

        May raise LoaderError on parse failures.
        """
