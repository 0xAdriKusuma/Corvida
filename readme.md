# Corvida

**CTF binary triage tool — one command, curated summary.**

Corvida analyses ELF binaries and produces a prioritised, one-screen
triage report — instead of dumping every byte of metadata at you.

```
$ corvida ./vuln

─────────────────────── CORVIDA  vuln ────────────────────────
  sha256: deadbeef...  size: 8,192 bytes

┌─ Binary Info ──────────────────────────────────────────────┐
│ Format   ELF                                                │
│ Arch     x86_64  64-bit  little-endian                     │
│ Stripped YES                                                │
│ Type     executable (ET_EXEC)                               │
│ Linker   /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2        │
└────────────────────────────────────────────────────────────┘

┌─ Protections ──────────────────────────────────────────────┐
│ NX        ON    │ Stack Canary  OFF  │ PIE       OFF       │
│ RELRO  PARTIAL  │ FORTIFY  not detected                    │
└────────────────────────────────────────────────────────────┘

┌─ Dangerous Functions ──────────────────────────────────────┐
│ gets()     CRITICAL  certain   PLT @ 0x00401020            │
│ system()   CRITICAL  certain   PLT @ 0x00401030            │
└────────────────────────────────────────────────────────────┘

┌─ Attack Path Suggestions ──────────────────────────────────┐
│ HIGH  high   Attack path: ret2win candidate                 │
│   No canary + no PIE = predictable addresses. Overflow ...  │
└────────────────────────────────────────────────────────────┘
```

---

## Installation

```bash
# From the project directory
pip install -e .

# Verify
corvida --help
```

**Dependencies auto-installed:**
- `typer[all]` + `rich` — CLI & terminal rendering
- `pyelftools` — ELF parsing & checksec
- `PyYAML` — rules database

**Optional (for cross-reference / deeper analysis):**
```bash
# 1. Install rizin:  https://rizin.re/install/
# 2. Install rzpipe:
pip install rzpipe
```

---

## Usage

```bash
# Terminal summary (default)
corvida ./binary

# JSON output (for AI agents / scripting)
corvida ./binary --json

# More details
corvida ./binary --verbose

# Disable colour (for piping)
corvida ./binary --no-color

# Limit strings
corvida ./binary --max-strings 10

# Print version
corvida version
```

### JSON output schema

```jsonc
{
  "schema_version": "1.0",
  "target": { "path": "...", "sha256": "...", "arch": "x86_64", ... },
  "findings": [
    {
      "title": "Dangerous import: gets()",
      "category": "dangerous_func",
      "severity": "critical",
      "confidence": "certain",
      "score": 1.0,
      "location": "PLT @ 0x00401020",
      "evidence": ["Reads unlimited bytes from stdin..."],
      "advice": "Classic stack overflow — look for ret2win...",
      "extra": { "func_name": "gets", "tags": ["stack_overflow"] }
    }
  ],
  "errors": [],
  "metadata": { "analysis_time_s": 0.42, "corvida_version": "0.1.0" }
}
```

---

## Development

```bash
# Install with dev extras
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=corvida --cov-report=term-missing

# Type check
mypy src/

# Lint
ruff check src/
```

---

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full design.

**Quick summary:** `file → loader → backend → analyzers → advisors → reporter`

Adding a new analyzer = one new file. See [`docs/adding_an_analyzer.md`](docs/adding_an_analyzer.md).

---

## Roadmap (not yet implemented)

- PE/DLL support (loader + analyzer stubs are ready)
- APK / DEX support
- HTML report output
- Full call-graph analysis
- Decompilation integration (Ghidra bridge)

---

## License

MIT
