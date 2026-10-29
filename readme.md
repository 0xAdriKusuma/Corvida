# Corvida

**CTF binary triage tool — one command, curated summary.**

Corvida analyses binaries and produces a prioritised, one-screen triage report — instead of dumping overwhelming metadata at you. It combines a fast, deterministic rule-based analysis pipeline with an optional **multi-model AI reasoning layer** that cross-verifies claims against extracted facts.

```
$ corvida ./vuln --ai

─────────────────────── CORVIDA  vuln ────────────────────────
  sha256: 4f1a2b...  size: 8,192 bytes

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

┌─ AI Summary (heuristic, verification: 2/2 claims) ─────────┐
│ Confidence: high  Verification: 2/2 claims supported       │
│                                                            │
│ Summary:                                                   │
│   Vulnerable 64-bit ELF binary with stack canary disabled. │
│   Unbounded input via gets() allows direct ret2win hijack. │
│                                                            │
│ AI Claims:                                                 │
│   [F0001] ✓ verified  Buffer overflow in gets() at 0x401020 │
│   [F0002] ✓ verified  Predictable system() address         │
│                                                            │
│ Suggested Next Steps:                                      │
│   → Calculate return address offset with cyclic pattern    │
│   → Check if /bin/sh string is present or supply via stdin │
│                                                            │
│ Models: summarizer=groq/llama-3.3-70b  verifier=local/qwen3 │
└────────────────────────────────────────────────────────────┘
```

---

## Features

- **Instant Rule-Based Triage**: Analyzes ELF metadata, checksec mitigations, dangerous library imports, and interesting strings deterministically.
- **Attack Path Advisor**: Heuristic rule engine that correlates facts (e.g., `NX disabled + gets → shellcode injection candidate`).
- **Verifiable AI Layer (`--ai`)**:
  - **Facts as Ground Truth**: The AI reasons strictly over extracted facts, never raw binary bytes.
  - **Two-Model Cross-Verification**: A summarizer model proposes attack vectors, followed by deterministic pre-validation and an independent verifier model.
  - **Zero Leaks Privacy**: Enforce local-only execution (`--local-only`) via Ollama/LM Studio with no cloud calls.
  - **Fallback & Backoff**: Automatic fallback chains across providers (e.g. cloud primary → local fallback) with exponential backoff on HTTP 429.
  - **Smart Caching**: SHA-256 keyed file cache (`~/.cache/corvida/ai/`) ensures fast, cost-effective re-runs.
- **Machine-Readable JSON**: `--json` flag exports structured data for automated workflows and external AI agents.

---

## Installation

### Standard Installation (Rule-based)

```bash
# Clone and install in editable mode
git clone https://github.com/your-org/corvida.git
cd corvida
pip install -e .

# Verify installation
corvida --help
```

### Installation with AI Layer Support

Install the optional `ai` dependencies (`httpx` and `pydantic`):

```bash
pip install -e ".[ai]"
```

### Optional Deep Analysis Backend (Rizin)

For symbol cross-references and advanced disasm:
1. Install [Rizin](https://rizin.re/install/)
2. Install Python bindings: `pip install rzpipe`

---

## Quick Start & AI Setup

### 1. Configure AI Providers (`corvida.yaml`)

Copy the example configuration to your working directory or `~/.config/corvida/`:

```bash
cp corvida.example.yaml corvida.yaml
```

Edit `corvida.yaml` to specify your preferred local or cloud endpoints:

```yaml
providers:
  local:
    base_url: "http://localhost:11434/v1"
    key_env: ""                         # Empty = local, no API key needed
  groq:
    base_url: "https://api.groq.com/openai/v1"
    key_env: "GROQ_API_KEY"

roles:
  summarizer:
    - provider: "groq"
      model: "llama-3.3-70b-versatile"
    - provider: "local"
      model: "phi4-mini"

  verifier:
    - provider: "local"
      model: "qwen3:4b"
    - provider: "groq"
      model: "llama-3.1-8b-instant"

policy:
  cache: true
  sensitive_local_only: false
  max_context_tokens: 4000
  temperature: 0.2
```

### 2. Check Provider Connectivity (`corvida ai doctor`)

Run the built-in diagnostic tool to test configuration and connectivity without leaking API keys:

```bash
corvida ai doctor
```

---

## CLI Usage

### Basic Analysis

```bash
# Terminal summary (default)
corvida ./binary

# JSON output for scripting or external agents
corvida ./binary --json

# Verbose output (stack traces, detailed evidence)
corvida ./binary --verbose

# Limit number of strings shown
corvida ./binary --max-strings 10

# Disable terminal colors (ideal for piping or CI logs)
corvida ./binary --no-color

# Show version
corvida version
```

### AI-Enhanced Analysis

```bash
# Run triage with AI reasoning layer
corvida ./binary --ai

# Enforce local-only models (blocks all cloud requests)
corvida ./binary --ai --local-only

# Bypass local response cache
corvida ./binary --ai --no-cache

# Skip interactive cloud-send confirmation
corvida ./binary --ai --yes

# Exclude extracted strings from LLM context (saves tokens & privacy)
corvida ./binary --ai --ai-exclude-strings

# Specify explicit configuration file
corvida ./binary --ai --ai-config /path/to/corvida.yaml

# Output structured JSON including full AI findings and verification status
corvida ./binary --ai --json
```

---

## Output Schema

When `--json` is supplied, Corvida outputs valid JSON to stdout. When `--ai` is enabled, the `"ai"` key is populated:

```jsonc
{
  "schema_version": "1.0",
  "target": {
    "path": "/path/to/vuln",
    "name": "vuln",
    "sha256": "4f1a2b...",
    "size": 8192,
    "arch": "x86_64",
    "bits": 64,
    "endian": "little",
    "file_type": "ELF",
    "stripped": true,
    "pie": false,
    "interpreter": "/lib64/ld-linux-x86-64.so.2"
  },
  "findings": [
    {
      "id": "F0001",
      "title": "gets() called without boundary checks",
      "category": "dangerous_func",
      "severity": "critical",
      "confidence": "certain",
      "score": 1.0,
      "location": "PLT @ 0x00401020",
      "evidence": ["call 0x00401020 <gets@plt>"],
      "advice": "Replace gets with fgets()",
      "extra": { "func_name": "gets" }
    }
  ],
  "errors": [],
  "metadata": {
    "analysis_time_s": 0.42,
    "corvida_version": "0.1.0"
  },
  "ai": {
    "summary": "Vulnerable 64-bit ELF binary with stack canary disabled...",
    "likely_vulns": [
      {
        "finding_id": "F0001",
        "description": "Buffer overflow via gets() at 0x401020",
        "det_valid": true,
        "det_flags": [],
        "llm_status": "supported",
        "verified": "supported"
      }
    ],
    "next_steps": [
      "Calculate return address offset with cyclic pattern",
      "Check if /bin/sh string is present"
    ],
    "confidence": "high",
    "verification": {
      "verified": 1,
      "total": 1
    },
    "models_used": {
      "summarizer": "groq/llama-3.3-70b-versatile",
      "verifier": "local/qwen3:4b"
    },
    "fallback_log": [],
    "truncation_notes": [],
    "from_cache": false
  }
}
```

---

## AI Grounding & Privacy

Corvida adheres to strict security and verification guarantees:

1. **Deterministic Pre-Validation**: Every vulnerability claim generated by an LLM is checked against the report's facts. If an LLM hallucinates non-existent `finding_id`s, memory addresses, or dangerous function names, the claim is immediately flagged and marked `unsupported`.
2. **Two-Model Verification**: Claims are independently cross-checked by a verifier role model (preferably running on a different architecture or provider).
3. **No Secret Leaks**: API keys are read strictly from environment variables at call time. They are never saved to disk, written to cache files, or shown in terminal outputs.
4. **Local-Only Guardrail**: With `--local-only` or `sensitive_local_only: true`, any request to a cloud endpoint raises a `PrivacyError` before initiating network activity.

---

## Benchmarking

Evaluate model latency, context token consumption, and claim verification rates using the benchmark script:

```bash
# Benchmark using mock provider (instant, no API keys needed)
python scripts/ai_benchmark.py --mock --runs 3

# Benchmark real configured providers on a target binary
python scripts/ai_benchmark.py --binary ./challenges/vuln --runs 3
```

---

## Development & Testing

```bash
# Install development dependencies
pip install -e ".[dev,ai]"

# Run full test suite (110+ unit & integration tests)
pytest

# Run tests with coverage report
pytest --cov=corvida --cov-report=term-missing

# Lint and check style
ruff check src/ tests/ scripts/

# Type checking
mypy src/
```

---

## Documentation

- [Architecture Overview](docs/architecture.md) — Core pipeline design and data structures.
- [AI Layer Architecture & Guide](docs/ai_layer.md) — Comprehensive design, verification pipeline, and configuration.
- [Adding an Analyzer](docs/adding_an_analyzer.md) — Step-by-step guide to writing custom analyzers.

---

## License

MIT
