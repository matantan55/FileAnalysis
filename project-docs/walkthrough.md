# MalOwn — Changelog

This document summarises the latest changes and new features.

---

## 1. Interactive CLI Menu

When you run the tool without any file arguments (`python -m fileanalysis.cli`), it now launches the **MalOwn Interactive Console** instead of printing a usage error.

The console acts as a persistent workspace:
- Paste any file path at the prompt to load it into the workspace buffer.
- The workspace tracks all loaded files in a numbered index table.
- Once files are loaded, choose between:
  - **1 – Standard File Analysis** — full ML + heuristic scan
  - **2 – Interactive Binary Research** — interactive hex viewer
  - **3 – Clear Files** — wipe the workspace buffer
  - **4 / q – Quit**

> [!NOTE]
> Backward compatibility is maintained. If you supply a file path argument (e.g. `python -m fileanalysis.cli my_malware.exe`), the menu is bypassed and the tool runs in one-shot mode exactly as before.

**New CLI flags:**
| Flag | Description |
|------|-------------|
| `--research` | Opens the interactive hex viewer directly for a given file |
| `--yara-rules <dir>` | Custom directory of `.yar` / `.yara` rules (unchanged) |
| `--json` | Output results as JSON (unchanged) |

**Files changed:** [`cli.py`](../fileanalysis/cli.py)

---

## 2. Binary Research: Hex Viewer (`hex_viewer.py`)

A brand-new interactive hex viewer was added at `fileanalysis/research/hex_viewer.py` (1 167 lines of new code).

### Features
- **Auto-detection** of PE / ELF format and CPU architecture (x86, x64, ARM64).
- **Real-time Capstone disassembly** — when navigating code sections a dedicated Assembly column shows human-readable instructions alongside raw hex.
- **Assembly Threat Hunting** — automatically flags malicious patterns inline:
  - Anti-debugging traps (`cpuid`, `rdtsc`, `int3`, `icebp`, `int 2d`, trap-flag manipulation `pushfd`/`popfd`)
  - Dynamic API resolution via PEB/TEB (`fs:0x30`, `gs:0x60`) and API hashing (`ror 13`)
  - Shellcode decoding loops, stack pivots (ROP chains), and process injection (`call rax`/`call rbx` to heap)
  - VM/sandbox evasion (`in eax, dx`, `pause`), packer stubs (`pushad`/`popad`), and carry-flag anti-disassembly tricks
- **Control Flow Graph (CFG)** — press **c** (or type `c <offset>`) to render a terminal-native, colour-coded CFG of any function with True/False jump annotations.

> [!WARNING]
> Flagged assembly instructions are highlighted **bold red** with a threat label in the annotation column.

**Files added:** [`fileanalysis/research/hex_viewer.py`](../fileanalysis/research/hex_viewer.py), [`fileanalysis/research/__init__.py`](../fileanalysis/research/__init__.py)

---

## 3. AI Assembly Insights (`asm_insights.py`)

A new local LLM wrapper at `fileanalysis/intelligence/asm_insights.py` provides on-device AI explanations of assembly code blocks inside the hex viewer.

- Uses **Qwen/Qwen2.5-Coder-0.5B-Instruct** loaded from the local HuggingFace cache (no internet required at inference time).
- Model is **lazily loaded** — only initialised on first use to avoid slowing down the standard scan path.
- Automatically selects the best available device: Apple MPS → CUDA → CPU.
- Provides two methods:
  - `generate_insight(asm_code)` — 1–2 sentence explanation of a single block.
  - `generate_behavioral_mapping(all_blocks)` — short summary of the entire CFG's behaviour.

**Files added:** [`fileanalysis/intelligence/asm_insights.py`](../fileanalysis/intelligence/asm_insights.py)

---

## 4. ML Training Pipeline — Separated Flags (`sandbox_train.py`)

The training pipeline now accepts two independent flags so you can retrain each model without touching the other.

### CLI Flags

```bash
# Retrain only the Neural Network (MalConv) — incremental fine-tuning
python -m fileanalysis.scoring.sandbox_train --train

# Retrain only the LightGBM decision tree
python -m fileanalysis.scoring.sandbox_train --tree

# Retrain both (default when no flags given)
python -m fileanalysis.scoring.sandbox_train
```

### GitHub Actions Integration
Include the flags in your **commit message** to trigger the correct pipeline on any branch:

```
fix: improve detection --tree        # rebuilds LightGBM only
feat: new training data --train      # fine-tunes MalConv only
feat: full retrain --tree --train    # retrains both
```

The workflow (`training.yml`) now fires on pushes to **all branches** (previously `main` only).

### Key Training Fixes

| Issue | Fix |
|-------|-----|
| LightGBM degraded every training run | The `feature_scaler.npz` is now **frozen** — loaded from disk on every run, never recalculated. Prevents the normalisation drift that was corrupting old tree splits. |
| Model rebuilt from scratch each run | Incremental `init_model` is now always used when `threat_model_lgb.txt` exists (previously also required new files to be present). |
| LightGBM overfitting on unchanged data | Added `early_stopping(stopping_rounds=10)` — training automatically stops when the validation loss stops improving. |
| `UnboundLocalError: val_true_np` when running `--tree` only | LightGBM evaluation now uses `y_val` (always available) instead of `val_true_np` (only defined after NN training). |
| `UnboundLocalError: model` / `lgb_model` when only one flag is set | Save section now conditionally saves each model only if it was actually trained. |
| Scaler overwritten on every run | Scaler is only written to disk if `feature_scaler.npz` does not already exist. |

**Files changed:** [`sandbox_train.py`](../fileanalysis/scoring/sandbox_train.py), [`ml_model.py`](../fileanalysis/scoring/ml_model.py), [`.github/workflows/training.yml`](../.github/workflows/training.yml)

---

## 5. Analyser Refinements

### `dll_analyzer.py`
- Expanded `HIJACKABLE_DLLS` and `KNOWN_DLLS` sets with additional commonly-abused Windows libraries.

### `elf_analyzer.py`
- Refactored `has_canary` detection and NX check loops into Pythonic `any()`/`next()` expressions — functionally identical, cleaner code.

### `macho_analyzer.py`
- Moved `EntropyAnalyzer` import to the top of the file (was lazily imported inside a method).
- Refactored `_check_code_signature` loop to `any()`.

### `pe_analyzer.py`
- Section name decode now falls back to `""` instead of `continue` so the suspicious-section-names check still runs on empty-name sections.
- Updated `RegDeleteKey` description text for clarity.

### `strings.py`
- Replaced `continue` inside `except` blocks with `pass` (correct idiom for non-loop contexts).
- IP address validation, suspicious command/API scanning loops refactored into `any()` / `next()` one-liners — same logic, reduced nesting.

---

## 6. Dependency Updates

New packages added to `requirements.txt` / `pyproject.toml`:

| Package | Purpose |
|---------|---------|
| `prompt_toolkit` | Arrow-key navigation in the interactive menu |
| `capstone` | Assembly disassembly in the hex viewer |
| `transformers` | Local Qwen LLM for AI assembly insights |

---

## How to Run

### Interactive mode
```bash
cd /Users/matanmishali/AntiGravity/FileAnalysis
source .venv/bin/activate
python -m fileanalysis.cli
```

### One-shot scan
```bash
python -m fileanalysis.cli /path/to/file.exe
```

### Hex viewer / research mode
```bash
python -m fileanalysis.cli /path/to/file.exe --research
```

### Trigger training via commit message
```
git commit -m "your message --tree"   # rebuild LightGBM
git commit -m "your message --train"  # fine-tune MalConv
```

---

## 7. Model Context Protocol (MCP) Server

MalOwn now includes a production-grade MCP server using the official low-level `mcp` SDK, allowing AI agents to connect and use its analysis tools directly.

### Dual-Transport Support
- **Local Execution:** Uses standard `stdio` transport.
- **Remote Execution:** Uses Server-Sent Events (SSE) via `SseServerTransport` and `uvicorn`/`starlette`.

### Available Tools
- `analyze_file(file_path, yara_rules)`: Runs the full scanning pipeline.
- `get_binary_annotations(file_path)`: Extracts suspicious byte patterns and strings.
- `extract_control_flow_graph(file_path, start_offset)`: Computes an intra-procedural CFG.
- `get_hex_dump(file_path, offset, size)`: Generates a raw hex dump.

### Usage
```bash
# Local Mode (Default)
uv run fileanalysis-mcp --transport stdio

# Remote Mode (SSE)
uv run fileanalysis-mcp --transport sse --port 8000
```

---

## 8. MCP Server Hardening & Pipeline Extraction

The MCP server was refactored for production quality:

### Shared Pipeline (`pipeline.py`)
The analysis logic that was duplicated between `cli.py` and `mcp_server.py` was extracted into a new `fileanalysis/pipeline.py` module with a single `run_pipeline()` function. Both entry points now call this shared function, eliminating the DRY violation.

### Improvements Applied
| Change | Description |
|--------|-------------|
| **Error handling** | All tool handlers return structured JSON error responses instead of crashing the server |
| **Hex dump bug fix** | Fixed escaped `\\n` that rendered hex dumps as a single line |
| **Logging** | Added `malown.mcp` and `malown.pipeline` loggers with configurable `--log-level` flag |
| **Path validation** | File paths are resolved and validated before any I/O |
| **Richer schemas** | Tool input schemas include `description` fields on every parameter |
| **SSE security** | Disabled `debug=True` on the Starlette app to prevent stack trace leaks |

**Files added:** [`pipeline.py`](../fileanalysis/pipeline.py)
**Files changed:** [`mcp_server.py`](../fileanalysis/mcp_server.py), [`cli.py`](../fileanalysis/cli.py)

