# Corvida Architecture

## Overview

Corvida follows a strict **pipeline pattern** with clearly separated concerns:

```
Binary File
    │
    ▼
┌─────────────┐
│  detect.py  │  Magic-byte detection → choose loader
└──────┬──────┘
       │
    ▼
┌─────────────┐
│   Loader    │  Populate Target (arch, bits, stripped, pie, interp)
│  (ELF, …)   │  Does NOT perform analysis
└──────┬──────┘
       │  Target
    ▼
┌─────────────┐
│   Backend   │  Open rizin session, expose normalised API
│  (rizin, …) │  (imports, xrefs, strings, functions)
└──────┬──────┘
       │  Backend handle
    ▼
┌─────────────────────────────────────────────┐
│               Analyzers                     │
│  binary_info │ checksec │ strings │ …       │
│  Each produces list[Finding]                │
└──────┬──────────────────────────────────────┘
       │  list[Finding]
    ▼
┌─────────────┐
│   Advisor   │  Cross-correlates findings → advisory Findings
│ (rules.py)  │  "NX off + gets → shellcode candidate"
└──────┬──────┘
       │
    ▼
┌─────────────┐
│   Scoring   │  Assigns/adjusts Finding.score with context boosts
│ (scoring.py)│
└──────┬──────┘
       │  Report
    ▼
┌─────────────┐
│  Reporter   │  Render to terminal (rich) or JSON (stdout)
│  (terminal/ │
│   json_out) │
└─────────────┘
```

---

## Key Data Structures

### `Target` (`core/models.py`)
Represents the binary being analysed. Populated by the loader.
Immutable after creation (by convention).

### `Finding` (`core/models.py`)
Atomic unit of information from any analyzer.
Fields: `title`, `category`, `severity`, `confidence`, `location`,
`evidence[]`, `advice`, `extra{}`, `score`.

### `Report` (`core/models.py`)
Container: one `Target` + list of `Finding` objects + errors list.
Serialisable via `to_dict()`.

---

## Registry System (`core/registry.py`)

Four separate registries, each keyed by component `name`:

| Registry           | Decorator             | Base class       |
|--------------------|-----------------------|------------------|
| `loader_registry`  | `@register_loader`    | `BaseLoader`     |
| `backend_registry` | `@register_backend`   | `BaseBackend`    |
| `analyzer_registry`| `@register_analyzer`  | `BaseAnalyzer`   |
| `reporter_registry`| `@register_reporter`  | `BaseReporter`   |

Components self-register via decorator at import time.
`_import_all()` in `registry.py` imports all modules explicitly at startup.

---

## Directory Layout

```
src/corvida/
├── __init__.py, __main__.py, cli.py
├── core/
│   ├── models.py       — Target, Finding, Report
│   ├── pipeline.py     — Orchestrator
│   ├── registry.py     — 4 registries + _import_all
│   ├── config.py       — Config dataclass
│   ├── scoring.py      — Post-analysis score adjustment
│   └── errors.py       — Typed exception hierarchy
├── loaders/
│   ├── base.py         — BaseLoader (abstract)
│   ├── detect.py       — Magic-byte format detection
│   └── elf.py          — ELF loader (pyelftools)
├── backends/
│   ├── base.py         — BaseBackend (abstract, normalised API)
│   └── rizin.py        — rzpipe backend
├── analyzers/
│   ├── base.py         — BaseAnalyzer (abstract)
│   ├── common/
│   │   └── strings.py  — Interesting string extractor
│   └── pwn/
│       ├── binary_info.py    — Basic ELF metadata
│       ├── checksec.py       — NX/PIE/Canary/RELRO/FORTIFY
│       └── dangerous_funcs.py— Dangerous import detector
├── advisors/
│   └── rules.py        — Rule-based attack path advisor
├── reporters/
│   ├── base.py         — BaseReporter (abstract)
│   ├── terminal.py     — Rich terminal reporter
│   └── json_out.py     — JSON stdout reporter
└── utils/              — (reserved for shared utilities)

rules/
└── dangerous_functions.yaml  — All dangerous function rules
```

---

## Design Decisions

### Why separate loader / backend / analyzer?
- Loader = format detection (ELF/PE/APK)
- Backend = tool wrapper (rizin/pwntools/objdump)
- Analyzer = analysis logic

A PE analyzer can reuse the rizin backend without touching the ELF loader.
A new backend (e.g. Ghidra) can be swapped in without rewriting analyzers.

### Why rules in YAML?
Dangerous function lists change frequently (new CVEs, new patterns).
Keeping them in YAML means:
- Non-programmer contributors can add rules
- Rules can be overridden per-project without changing code
- Rules can be versioned separately

### Why dataclass rules in advisors/rules.py (not YAML)?
Advisory rules express *relationships between findings* (if X and Y then Z).
That requires logic, not just data. A YAML DSL would be harder to read,
test, and debug than explicit Python conditions.

### Why no global state?
`Config` is passed explicitly through every function.
Registries are module-level singletons (acceptable for a CLI tool).
This makes testing straightforward — pass a custom Config, inject mock backend.
