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

from corvida.core.errors import BackendUnavailableError, LoaderError
from corvida.core.models import Target
from corvida.core.registry import register_loader
from corvida.loaders.base import BaseLoader

# ---------------------------------------------------------------------------
# Lazy import guard for pyelftools
# ---------------------------------------------------------------------------

def _get_elftools():
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.common.exceptions import ELFError
        return ELFFile, ELFError
    except ImportError:
        raise BackendUnavailableError(
            "pyelftools is required but not installed.\n"
            "Install it with:  pip install pyelftools"
        )


# ---------------------------------------------------------------------------
# Architecture mapping
# ---------------------------------------------------------------------------

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
    supported_types = ["ELF"]

    # ------------------------------------------------------------------
    # Magic byte check
    # ------------------------------------------------------------------

    @classmethod
    def can_load(cls, path: Path) -> bool:
        try:
            with open(path, "rb") as fh:
                return fh.read(4) == b"\x7fELF"
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Main load
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse(self, path: Path, elf: object) -> Target:
        """Extract all Target fields from an open ELFFile."""
        target = Target(path=path)

        # Architecture
        machine = elf.header.e_machine
        target.arch = _ARCH_MAP.get(machine, machine)
        target.bits = elf.elfclass          # 32 or 64
        target.endian = "little" if elf.little_endian else "big"
        target.file_type = "ELF"

        # PIE: ET_DYN type indicates PIE or shared library
        e_type = elf.header.e_type
        target.is_pie = (e_type == "ET_DYN")

        # Stripped: check for .symtab section
        target.is_stripped = elf.get_section_by_name(".symtab") is None

        # Interpreter (dynamic linker)
        target.interpreter = self._get_interpreter(elf)

        return target

    @staticmethod
    def _get_interpreter(elf: object) -> str | None:
        """Return the PT_INTERP path or None for statically linked binaries."""
        try:
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_INTERP":
                    return seg.get_interp_name()
        except Exception:  # noqa: BLE001
            pass
        return None
