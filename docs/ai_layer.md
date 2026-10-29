# Corvida AI Layer Architecture & Guide

## 1. Overview

Corvida is designed as a fast, deterministic binary triage tool for CTF players and reverse engineers. The **AI layer** is an optional post-analysis enhancement that ingests the facts extracted by the rule-based pipeline and produces a concise summary, prioritized attack paths, and suggested next steps.

```
Rule-based Pipeline
[Binary] → Loaders → Backend → Analyzers → Advisors → Scoring → Report
                                                                   │
                                                                   ▼
AI Layer (Optional: --ai)
Report ──► context_builder ──► Cache Check
                                    │ (miss)
                                    ▼
                             Summarizer Role (LLM 1)
                                    │ claims + summary
                                    ▼
                        Deterministic Pre-Validator
                         (checks finding_id, addrs, funcs)
                                    │
                                    ▼
                              Verifier Role (LLM 2)
                                    │ cross-check
                                    ▼
                             Result Aggregation
                                    │
                             Cache Write & Render
```

---

## 2. Core Design Principles

1. **Rule-based facts are ground truth**: Corvida's loaders, analyzers, and advisors extract deterministic facts (e.g. checksec flags, exported symbols, string references). The AI does not re-analyze the binary bytes; it synthesizes and reasons about the structured `Report`.
2. **Every AI claim is verifiable**: The context builder assigns unique, stable finding identifiers (`F0001`, `F0002`, ...). AI vulnerability claims must cite finding IDs.
3. **Two-model cross-verification**:
   - **Summarizer**: Analyzes the context and proposes likely vulnerabilities and next steps.
   - **Deterministic Validator**: Immediately flags claims referencing nonexistent finding IDs, unverified hexadecimal addresses, or unreferenced dangerous function names.
   - **Verifier**: A second model (optionally from a different provider) independently audits each claim against the context.
4. **Zero network leaks in local mode**: When `--local-only` or `sensitive_local_only: true` is configured, cloud providers are rejected immediately without network requests.
5. **No raw binary transmission**: Only structured, token-budgeted text metadata is sent to LLM providers.
6. **Graceful degradation**: If AI models timeout, return 4xx/5xx, or produce invalid JSON, Corvida logs a warning and displays the rule-based triage output unaffected.

---

## 3. Configuration (`corvida.yaml`)

Corvida searches for `corvida.yaml` in:
1. `--ai-config <path>` (CLI override)
2. Current working directory (`./corvida.yaml`)
3. User config directory (`~/.config/corvida/corvida.yaml`)

### Example Configuration

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

### Provider Schema

- `base_url`: Any OpenAI-compatible `/chat/completions` endpoint (Ollama, LM Studio, vLLM, Groq, OpenAI, Together, DeepSeek, etc.).
- `key_env`: Environment variable name holding the API key. Corvida reads keys from the environment at call time; keys are **never** stored in files, cache, or output logs.

### Role Chains & Fallback

Each role defines an ordered list of `(provider, model)` pairs. If the primary pair fails (connection timeout, HTTP 429 rate limit, 5xx server error, or invalid JSON output), the router automatically moves to the next pair in the chain.

---

## 4. CLI Usage

### Running with AI Analysis

```bash
# Terminal triage with AI summary
corvida ./vuln --ai

# Enforce local-only models (reject cloud providers)
corvida ./vuln --ai --local-only

# Bypass response cache
corvida ./vuln --ai --no-cache

# Skip interactive confirmation when calling cloud providers
corvida ./vuln --ai --yes

# Exclude extracted string samples from AI context (privacy or token saving)
corvida ./vuln --ai --ai-exclude-strings

# Output structured JSON for automation or upstream agents
corvida ./vuln --ai --json
```

### Health Check: `corvida ai doctor`

Verify your configuration, environment keys, and endpoint connectivity without sending analysis data or printing secrets:

```bash
corvida ai doctor
```

Output displays:
- Provider connection status (`OK` / `FAIL`)
- API key detection status (`YES` / `NO` / `N/A`)
- Configured role fallback chains
- Policy settings

---

## 5. Claim Verification Pipeline

Claims made by the summarizer undergo two-stage verification:

1. **Deterministic Validation (`model/validators.py`)**:
   - Matches referenced `finding_id` against `report.findings`.
   - Scans claim text for hexadecimal addresses (e.g., `0x401156`) and checks if they exist in finding locations or disasm evidence.
   - Cross-checks mentioned dangerous functions against detected imports/symbols.
   - Any failure marks the claim as `unsupported` immediately with diagnostic flags.

2. **LLM Verification (`model/verifier.py`)**:
   - Receives only verified facts and claim statements.
   - Evaluates whether the claim logically follows from the evidence.
   - Returns status: `supported`, `unsupported`, or `unclear`.

In the final report:
- `✓ verified`: Claim passed deterministic validation and was confirmed by verifier.
- `✗ unverified`: Claim was refuted by verifier or cited non-existent facts/addresses.
- `? unclear`: Insufficient evidence to confirm.

---

## 6. Response Caching

Responses are cached locally under `~/.cache/corvida/ai/`.

- **Cache Key**: SHA-256 digest of:
  `JSON(context) + role + model + prompt_version + provider`
- **Cache Invalidation**: Any change to prompt templates (version bump in frontmatter), binary analysis findings, or model configuration automatically produces a new key.
- **Degraded Mode**: Any filesystem error (permissions, read-only media, disk full) silently bypasses cache without aborting analysis.

---

## 7. Benchmarking

Use `scripts/ai_benchmark.py` to evaluate provider latency, context token sizing, and verification rates:

```bash
# Benchmark against synthetic binary with mock provider
python scripts/ai_benchmark.py --mock --runs 3

# Benchmark real configured providers against a target binary
python scripts/ai_benchmark.py --binary ./challenges/pwn1 --runs 3
```
