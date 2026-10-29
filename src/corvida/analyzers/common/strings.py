"""
analyzers/common/strings.py — Interesting string extractor.

Strategy
--------
1. Use backend.strings() if a backend is available (rizin is more accurate,
   returns virtual addresses and section names correctly).
2. Fall back to a pyelftools-based scan of .rodata (and other data sections)
   for ELF files — this is much more accurate than a raw binary scan because
   it gives correct virtual addresses and avoids scanning code sections.
3. Last resort: pure-Python raw byte scan of the entire binary (all sections).
4. Score each string by matching against interest patterns.
5. Return only the top-N strings (config.max_strings).

When rizin is unavailable, a degradation warning is added to the report
and AI context confidence is lowered accordingly.

Interest patterns are defined in this file rather than YAML because they
are general-purpose (not pwn-specific) and rarely change.

Regression test reference
--------------------------
String virtual addresses are verified against ``strings -t x`` output.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from corvida.analyzers.base import BaseAnalyzer
from corvida.backends.base import BaseBackend
from corvida.core.config import Config
from corvida.core.models import (
    Category, Confidence, Finding, Severity, Target,
)
from corvida.core.registry import register_analyzer

_PATTERNS: list[tuple[str, str, Severity, float]] = [
    # Shell
    (r"/bin/sh",              "Shell invocation",        Severity.HIGH,   1.0),
    (r"/bin/bash",            "Shell invocation",        Severity.HIGH,   1.0),
    (r"/bin/dash",            "Shell invocation",        Severity.HIGH,   1.0),
    (r"execve|system\(",      "Exec call in string",     Severity.HIGH,   0.8),
    # Flag patterns
    (r"flag\{",               "Flag placeholder",        Severity.HIGH,   0.9),
    (r"CTF\{",                "CTF flag pattern",        Severity.HIGH,   0.9),
    (r"picoCTF\{",            "picoCTF flag",            Severity.HIGH,   0.9),
    (r"\w{3,8}\{[^}]{5,50}\}","Generic flag pattern",   Severity.MEDIUM, 0.7),
    # Menu/interaction
    (r"[Ee]nter (?:your |a )?(?:choice|option|input|command|password|name)",
                              "User interaction prompt", Severity.MEDIUM, 0.6),
    (r"[Mm]enu|[Oo]ption|[Cc]hoice",
                              "Menu text",               Severity.LOW,    0.5),
    # Passwords/secrets
    (r"[Pp]assword|[Ss]ecret|[Kk]ey|[Tt]oken",
                              "Credential string",       Severity.MEDIUM, 0.6),
    # Format strings
    (r"%\d*\$[a-zA-Z]",       "Format string specifier", Severity.HIGH,  0.8),
    # Paths
    (r"/etc/passwd|/etc/shadow|/proc/",
                              "Sensitive path",          Severity.MEDIUM, 0.7),
    # Debug / dev
    (r"debug|DEBUG|HACK|TODO|FIXME",
                              "Debug/dev artifact",      Severity.LOW,    0.4),
    # Addresses / hex patterns
    (r"0x[0-9a-fA-F]{6,}",   "Hardcoded address",       Severity.LOW,    0.4),
]

_COMPILED = [
    (re.compile(pat), label, sev, boost)
    for pat, label, sev, boost in _PATTERNS
]


_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


# ---------------------------------------------------------------------------
# ELF section-aware scanner (pyelftools fallback)
# ---------------------------------------------------------------------------

# Sections that typically hold string data.  We scan these in order.
_STRING_SECTIONS = [".rodata", ".data", ".data.rel.ro", ".rodata.str1.4", ".rodata.str1.8"]


def _scan_elf_sections(path: Path, min_len: int) -> list[dict]:
    """
    Extract printable strings from ELF data sections using pyelftools.

    Returns dicts with keys: string, vaddr, file_offset, section, length.
    Virtual addresses match what `strings -t x` reports (file-offset mode)
    because we compute both and store both.
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return _scan_binary(path, min_len)

    results: list[dict] = []
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            for sec_name in _STRING_SECTIONS:
                sec = elf.get_section_by_name(sec_name)
                if sec is None:
                    continue
                data        = sec.data()
                sec_vaddr   = sec.header.sh_addr
                sec_offset  = sec.header.sh_offset

                buf: list[int] = []
                buf_start = 0
                for i, b in enumerate(data):
                    if b in _PRINTABLE and b != 0:
                        if not buf:
                            buf_start = i
                        buf.append(b)
                    else:
                        if len(buf) >= min_len:
                            s = bytes(buf).decode("ascii", errors="replace")
                            results.append({
                                "string":      s,
                                "vaddr":       sec_vaddr + buf_start,
                                "file_offset": sec_offset + buf_start,
                                "section":     sec_name,
                                "length":      len(buf),
                            })
                        buf = []
                # flush remaining
                if len(buf) >= min_len:
                    s = bytes(buf).decode("ascii", errors="replace")
                    results.append({
                        "string":      s,
                        "vaddr":       sec_vaddr + buf_start,
                        "file_offset": sec_offset + buf_start,
                        "section":     sec_name,
                        "length":      len(buf),
                    })
    except Exception:  # noqa: BLE001
        return _scan_binary(path, min_len)

    if not results:
        # ELF parse succeeded but no recognised string sections — do raw scan
        return _scan_binary(path, min_len)

    return results


def _scan_binary(path: Path, min_len: int) -> list[dict]:
    """
    Extract printable strings directly from raw binary bytes.

    Note: vaddr here is really the file offset — this is the same
    convention used by ``strings -t x``.
    """
    results = []
    with open(path, "rb") as fh:
        data = fh.read()

    buf: list[int] = []
    buf_start = 0
    for i, b in enumerate(data):
        if b in _PRINTABLE and b != 0:
            if not buf:
                buf_start = i
            buf.append(b)
        else:
            if len(buf) >= min_len:
                s = bytes(buf).decode("ascii", errors="replace")
                results.append({
                    "string":      s,
                    "vaddr":       buf_start,
                    "file_offset": buf_start,
                    "section":     None,
                    "length":      len(buf),
                })
            buf = []
    # flush
    if len(buf) >= min_len:
        s = bytes(buf).decode("ascii", errors="replace")
        results.append({
            "string":      s,
            "vaddr":       buf_start,
            "file_offset": buf_start,
            "section":     None,
            "length":      len(buf),
        })
    return results


def _score_string(s: str) -> tuple[float, str, Severity, Confidence]:
    """Return (score, label, severity, confidence) for a string."""
    best_score = 0.0
    best_label = "Interesting string"
    best_sev   = Severity.LOW
    best_conf  = Confidence.LOW

    for pat, label, sev, boost in _COMPILED:
        if pat.search(s):
            if boost > best_score:
                best_score = boost
                best_label = label
                best_sev   = sev
                best_conf  = Confidence.HIGH if boost >= 0.8 else Confidence.MEDIUM

    return best_score, best_label, best_sev, best_conf


@register_analyzer
class StringsAnalyzer(BaseAnalyzer):
    """Extracts and scores interesting printable strings from a binary."""

    name     = "strings"
    category = Category.STRINGS
    supports = []
    requires_backend = False

    def analyze(
        self, target: Target, config: Config, backend: BaseBackend | None = None
    ) -> list[Finding]:
        backend_used = False
        raw: list[dict] = []

        if backend is not None:
            try:
                raw = backend.strings(min_len=config.min_string_len)
                backend_used = True
            except Exception:    # noqa: BLE001
                raw = []

        if not backend_used:
            # Use section-aware pyelftools fallback (accurate vaddrs)
            raw = _scan_elf_sections(target.path, config.min_string_len)

        scored: list[tuple[float, dict, str, Severity, Confidence]] = []
        for entry in raw:
            s = entry.get("string", "")
            sc, label, sev, conf = _score_string(s)
            if sc > 0:
                scored.append((sc, entry, label, sev, conf))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[: config.max_strings]

        findings: list[Finding] = []
        for sc, entry, label, sev, conf in top:
            s    = entry["string"]
            vaddr = entry.get("vaddr", 0)
            foff  = entry.get("file_offset", vaddr)  # file offset for strings -t x compat
            sec  = entry.get("section") or "?"

            # Location shows vaddr (matches vmmap) and file offset (matches strings -t x)
            if vaddr and vaddr != foff:
                loc = f"vaddr={vaddr:#010x} foff={foff:#010x} ({sec})"
            elif vaddr:
                loc = f"{vaddr:#010x} ({sec})"
            else:
                loc = sec

            findings.append(Finding(
                title      = f"{label}: {s[:60]!r}",
                category   = Category.STRINGS,
                severity   = sev,
                confidence = conf,
                location   = loc,
                evidence   = [s],
                advice     = None,
                extra      = {
                    "string":      s,
                    "vaddr":       vaddr,
                    "file_offset": foff,
                    "section":     sec,
                    "backend":     backend_used,
                },
            ))

        return findings
