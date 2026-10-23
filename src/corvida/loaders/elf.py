"""
loaders/elf.py — ELF file loader using pyelftools.

Responsibilities
----------------
* Confirm the file is a valid ELF.
* Populate Target fields: arch, bits, endian, is_stripped, is_pie, interpreter.
* Do NOT perform security analysis here (checksec belongs in analyzers/).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from corvida.core.errors import BackendUnavailableError, LoaderError
from corvida.core.models import Target
from corvida.core.registry import register_loader
from corvida.loaders.base import BaseLoader


def _get_elftools():
    try:
        from elftools.common.exceptions import ELFError
        from elftools.elf.elffile import ELFFile
        return ELFFile, ELFError
    except ImportError:
        raise BackendUnavailableError(
            "pyelftools is required but not installed.\n"
            "Install it with:  pip install pyelftools"
        )


_ARCH_MAP: dict[str, str] = {
    "EM_386":    "x86",
    "EM_X86_64": "x86_64",
    "EM_ARM":    "arm",
    "EM_AARCH64": "arm64",
    "EM_MIPS":   "mips",
    "EM_PPC":    "ppc",
    "EM_PPC64":  "ppc64",
    "EM_RISCV":  "riscv",
    "EM_S390":   "s390x",
}


@register_loader
class ElfLoader(BaseLoader):
    """Loader for ELF binaries (32-bit and 64-bit)."""

    name = "elf"
    supported_types: ClassVar[list[str]] = ["ELF"]

    @classmethod
    def can_load(cls, path: Path) -> bool:
        try:
            with open(path, "rb") as fh:
                return fh.read(4) == b"\x7fELF"
        except OSError:
            return False

    def load(self, path: Path) -> Target:
        ELFFile, ELFError = _get_elftools()

        try:
            with open(path, "rb") as fh:
                elf = ELFFile(fh)
                return self._parse(path, elf)
        except ELFError as exc:
            raise LoaderError(f"Failed to parse ELF '{path.name}': {exc}") from exc
        except OSError as exc:
            raise LoaderError(f"Cannot open '{path}': {exc}") from exc

    def _parse(self, path: Path, elf: Any) -> Target:
        """Extract all Target fields from an open ELFFile."""
        target = Target(path=path)

        machine = elf.header.e_machine
        target.arch = _ARCH_MAP.get(machine, machine)
        target.bits = elf.elfclass
        target.endian = "little" if elf.little_endian else "big"
        target.file_type = "ELF"
        target.is_pie = (elf.header.e_type == "ET_DYN")
        target.is_stripped = elf.get_section_by_name(".symtab") is None
        target.interpreter = self._get_interpreter(elf)

        return target

    @staticmethod
    def _get_interpreter(elf: Any) -> str | None:
        """Return the PT_INTERP path or None for statically linked binaries."""
        try:
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_INTERP":
                    return seg.get_interp_name()
        except Exception:  # noqa: BLE001, S110
            pass
        return None
