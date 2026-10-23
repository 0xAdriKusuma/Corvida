# Adding a New Analyzer to Corvida

This guide proves that adding a new analyzer requires **one file** and
**one registration line** — no changes to existing code.

---

## Prerequisites

- You know Python dataclasses and can read the existing analyzers.
- You've read `docs/architecture.md` (5 minutes).

---

## Step 1: Create the analyzer file

Create `src/corvida/analyzers/<category>/<your_name>.py`.

Example: adding a **ROP gadget counter** (`analyzers/pwn/rop_gadgets.py`):

```python
# src/corvida/analyzers/pwn/rop_gadgets.py

from __future__ import annotations

from corvida.analyzers.base import BaseAnalyzer
from corvida.backends.base import BaseBackend
from corvida.core.config import Config
from corvida.core.models import Category, Confidence, Finding, Severity, Target
from corvida.core.registry import register_analyzer   # ← import the decorator


@register_analyzer                                     # ← ONE line to register
class RopGadgetsAnalyzer(BaseAnalyzer):
    """Counts ROP gadgets (ret/jmp instructions) as a rough exploitability signal."""

    name     = "rop_gadgets"          # must be unique
    category = Category.BINARY_INFO   # or define a new Category value
    supports = ["ELF"]                # file types this handles
    requires_backend = True           # needs rizin for disassembly

    def analyze(
        self,
        target:  Target,
        config:  Config,
        backend: BaseBackend | None = None,
    ) -> list[Finding]:
        if backend is None:
            return []   # graceful degradation

        try:
            # Use the backend's normalised API — never call rzpipe directly
            functions = backend.functions()
            ret_count = sum(1 for f in functions if "ret" in f.get("name", ""))

            sev = Severity.HIGH if ret_count > 100 else Severity.MEDIUM

            return [Finding(
                title      = f"ROP surface: ~{ret_count} potential gadgets",
                category   = Category.BINARY_INFO,
                severity   = sev,
                confidence = Confidence.LOW,   # heuristic!
                evidence   = [f"{ret_count} functions with 'ret' in name"],
                advice     = "Run ROPgadget or ropper for precise gadget count.",
            )]
        except Exception as exc:
            return [self._error_finding("rop_gadgets error", str(exc))]
```

**Rules:**
- Decorate with `@register_analyzer` — that's all.
- Return `list[Finding]` — never raise.
- Use `backend.*` methods; never import rzpipe directly.
- Lower confidence for heuristics.

---

## Step 2: Register the module in `_import_all`

Open `src/corvida/core/registry.py` and add your module to the list:

```python
MODULES = [
    ...
    # Analyzers — pwn
    "corvida.analyzers.pwn.binary_info",
    "corvida.analyzers.pwn.checksec",
    "corvida.analyzers.pwn.dangerous_funcs",
    "corvida.analyzers.pwn.rop_gadgets",   # ← add this line
    ...
]
```

That's it. No other code changes.

---

## Step 3: Test it

```bash
# Smoke test
corvida ./some_elf --verbose

# Unit test (create tests/unit/test_rop_gadgets.py)
pytest tests/unit/test_rop_gadgets.py -v
```

---

## Step 4: (Optional) Add YAML rules

If your analyzer uses configurable data (function names, patterns, thresholds),
add a YAML file in `rules/` and load it with `yaml.safe_load()`.

See `analyzers/pwn/dangerous_funcs.py` + `rules/dangerous_functions.yaml`
for the established pattern.

---

## Checklist

- [ ] New file in `src/corvida/analyzers/<category>/`
- [ ] `@register_analyzer` decorator applied
- [ ] Unique `name` class attribute
- [ ] `supports` list correctly set
- [ ] `analyze()` never raises (catches and returns error Finding)
- [ ] Module added to `MODULES` list in `registry.py`
- [ ] Unit test written
- [ ] (If rule-based) YAML in `rules/`

---

## What you did NOT change

- `core/pipeline.py` — pipeline discovers analyzers automatically
- `core/models.py` — Finding/Report schema is shared, unchanged
- `reporters/terminal.py` — renders any Finding by category
- Any existing analyzer — zero modification needed
