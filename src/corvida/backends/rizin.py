"""
backends/rizin.py — rzpipe backend wrapping rizin.

All rizin calls go through this class so that analyzers are fully
decoupled from rzpipe's API.  If rizin is not installed, every method
that requires it raises BackendUnavailableError with installation help.

Note: rzpipe opens rizin as a subprocess.  We set flags to make it
non-interactive and analysis-safe (no execution).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from corvida.backends.base import BaseBackend
from corvida.core.errors import BackendError, BackendUnavailableError
from corvida.core.registry import register_backend

_INSTALL_HINT = (
    "rizin backend unavailable.\n"
    "Install rizin:  https://rizin.re/install/\n"
    "Install rzpipe: pip install rzpipe"
)


def _import_rzpipe():
    try:
        import rzpipe
        return rzpipe
    except ImportError:
        raise BackendUnavailableError(_INSTALL_HINT)


@register_backend
class RizinBackend(BaseBackend):
    """Backend that delegates to rizin via rzpipe."""

    name = "rizin"

    def __init__(self, path: Path, timeout: int = 30) -> None:
        super().__init__(path, timeout)
        self._rz = None
        self._analysed = False

    def open(self) -> None:
        rzpipe = _import_rzpipe()
        try:
            self._rz = rzpipe.open(str(self.path), flags=["-2"])
        except Exception as exc:
            raise BackendUnavailableError(
                f"rzpipe failed to open '{self.path.name}': {exc}\n{_INSTALL_HINT}"
            ) from exc

        self._cmd("aa")
        self._analysed = True

    def close(self) -> None:
        if self._rz is not None:
            try:
                self._rz.quit()
            except Exception:   # noqa: BLE001
                pass
            self._rz = None

    def _cmd(self, cmd: str) -> str:
        """Run a rizin command and return raw output."""
        if self._rz is None:
            raise BackendError("Backend not opened. Call open() first.")
        result = self._rz.cmd(cmd)
        return result or ""

    def _cmdj(self, cmd: str) -> Any:
        """Run a rizin JSON command and parse the result."""
        if self._rz is None:
            raise BackendError("Backend not opened. Call open() first.")
        try:
            return self._rz.cmdj(cmd) or []
        except Exception as exc:   # noqa: BLE001
            raise BackendError(f"rzpipe cmdj failed for '{cmd}': {exc}") from exc

    def imports(self) -> list[dict[str, Any]]:
        """
        Return list of imported symbols.

        rzpipe 'iij' → list of import records.
        """
        try:
            raw = self._cmdj("iij")
            if not isinstance(raw, list):
                return []
            result = []
            for item in raw:
                result.append({
                    "name": item.get("name", ""),
                    "plt":  item.get("plt"),       # PLT address (int or None)
                    "type": item.get("type", ""),
                    "bind": item.get("bind", ""),
                })
            return result
        except BackendError:
            return []

    def functions(self) -> list[dict[str, Any]]:
        """
        Return list of analysed functions.

        rzpipe 'aflj' → list of function records.
        """
        try:
            raw = self._cmdj("aflj")
            if not isinstance(raw, list):
                return []
            result = []
            for item in raw:
                result.append({
                    "name":   item.get("name", ""),
                    "offset": item.get("offset", 0),
                    "size":   item.get("size", 0),
                })
            return result
        except BackendError:
            return []

    def xrefs_to(self, address: int) -> list[dict[str, Any]]:
        """
        Return cross-references TO *address*.

        rzpipe 'axtj <addr>' → list of xref records.
        """
        try:
            raw = self._cmdj(f"axtj {address:#x}")
            if not isinstance(raw, list):
                return []
            result = []
            for item in raw:
                result.append({
                    "from": item.get("from", 0),
                    "type": item.get("type", ""),
                    "fcn_name": item.get("fcn_name", ""),
                })
            return result
        except BackendError:
            return []

    def strings(self, min_len: int = 6) -> list[dict[str, Any]]:
        """
        Return strings found in the binary.

        rzpipe 'izj' → strings in data sections.
        rzpipe 'izzj' → strings across the whole binary (fallback).
        """
        try:
            raw = self._cmdj("izj")
            if not isinstance(raw, list) or len(raw) == 0:
                raw = self._cmdj("izzj") or []
            if not isinstance(raw, list):
                return []
            result = []
            for item in raw:
                s = item.get("string", "")
                length = item.get("length", len(s))
                if length < min_len:
                    continue
                result.append({
                    "string":  s,
                    "vaddr":   item.get("vaddr", 0),
                    "section": item.get("section", None),
                    "length":  length,
                })
            return result
        except BackendError:
            return []

    # ------------------------------------------------------------------
    # Extra — binary info (used by checksec fallback if needed)
    # ------------------------------------------------------------------

    def binary_info(self) -> dict[str, Any]:
        """Return rizin's 'iIj' (binary info) as a dict."""
        try:
            info = self._cmdj("iIj")
            return info if isinstance(info, dict) else {}
        except BackendError:
            return {}
