# FileAnalysis — Implementation Guide

> A comprehensive technical reference for developers working on the FileAnalysis malware detection and threat assessment tool.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Package Structure](#package-structure)
4. [Analysis Pipeline](#analysis-pipeline)
5. [Analyzers Deep Dive](#analyzers-deep-dive)
6. [Intelligence Layer](#intelligence-layer)
7. [Scoring System](#scoring-system)
8. [Neural Network Model](#neural-network-model)
9. [Reporting](#reporting)
10. [CLI Interface](#cli-interface)
11. [Adding New Analyzers](#adding-new-analyzers)
12. [Training the NN Model on Real Data](#training-the-nn-model-on-real-data)
13. [Dependencies](#dependencies)

---

## Project Overview

FileAnalysis is a Python CLI tool that performs **static analysis** on files to determine:
- Whether a file is potentially **malicious**
- What **capabilities** the malware has (mapped to MITRE ATT&CK)
- How it could **affect the target environment**

It supports PE (EXE/DLL), ELF, Mach-O, scripts, and documents. It produces a threat score (0–100) using either a hand-tuned heuristic scorer or a neural network model.

---

## Architecture

```
                    ┌──────────────┐
                    │   CLI (cli.py)│
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  File Loader  │  ← Type detection, metadata extraction
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼──┐  ┌─────▼──┐  ┌─────▼──────┐
        │ Common │  │Format- │  │Intelligence│
        │Analyzers│  │Specific│  │   Layer    │
        └────┬───┘  └────┬───┘  └─────┬──────┘
             │           │            │
             └─────┬─────┘            │
                   │                  │
            ┌──────▼───────┐   ┌─────▼──────┐
            │ AnalysisResult│◄──┤YARA+Caps+VT│
            └──────┬───────┘   └────────────┘
                   │
          ┌────────┼────────┐
          │                 │
   ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
   │  Heuristic  │  │  Neural Net │  │  LightGBM   │
   │   Scorer    │  │   Scorer    │  │   Scorer    │
   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
          │                │                │
          └────────┬───────┴────────────────┘
                   │
            ┌──────▼───────┐
            │   Reporter   │  ← Terminal (Rich) + AI Insights (Gemini) or JSON
            └──────────────┘
```

---

## Package Structure

```
FileAnalysis/
├── pyproject.toml              # Project config, dependencies, entry points
├── requirements.txt            # Pip-compatible dependency list
├── rules/                      # Built-in YARA rule files (.yar)
│
└── fileanalysis/               # Main Python package
    ├── __init__.py
    ├── cli.py                  # Click CLI entry point
    ├── loader.py               # File loading, type detection, metadata
    │
    ├── analyzers/              # All analysis modules
    │   ├── base.py             # AnalysisResult, dataclasses, BaseAnalyzer ABC
    │   ├── hashing.py          # MD5, SHA-1, SHA-256, ssdeep, imphash
    │   ├── entropy.py          # Shannon entropy analysis
    │   ├── strings.py          # String extraction and classification
    │   ├── pe_analyzer.py      # Windows PE (EXE) analysis
    │   ├── dll_analyzer.py     # DLL-specific threat analysis
    │   ├── elf_analyzer.py     # Linux ELF analysis
    │   ├── macho_analyzer.py   # macOS Mach-O analysis
    │   ├── script_analyzer.py  # Script file analysis (Python, PS, Bash, etc.)
    │   └── document_analyzer.py # Office/PDF document analysis
    │
    ├── intelligence/           # Threat intelligence modules
    │   ├── yara_scanner.py     # YARA rule matching engine
    │   ├── capability_mapper.py # MITRE ATT&CK capability mapping
    │
    ├── scoring/                # Threat scoring engines
    │   ├── scorer.py           # Heuristic threat scorer
    │   ├── features.py         # Feature extraction for ML models
    │   ├── nn_model.py         # ThreatNet MLP model + inference wrapper
    │   ├── ml_model.py         # LightGBM tree model + inference wrapper
    │   ├── sandbox_train.py    # Real malware training (Docker)
    │   ├── threat_model.pt     # Pre-trained NN weights
    │   └── threat_model_lgb.txt# Pre-trained LightGBM weights
    │
    └── reporting/              # Output formatting
        ├── terminal_report.py  # Rich terminal output
        └── json_report.py      # JSON export
```

---

## Analysis Pipeline

The full analysis runs in **8 sequential stages** (see `cli.py`):

```
Stage 1: File Loading          → loader.load_file()
Stage 2: Common Analyzers      → HashAnalyzer, EntropyAnalyzer, StringAnalyzer
Stage 3: Format-Specific       → PEAnalyzer / ELFAnalyzer / MachOAnalyzer / etc.
Stage 4: YARA Scanning         → YaraScanner.scan()
Stage 5: Capability Mapping    → CapabilityMapper.map_capabilities()
Stage 7: Scoring               → ThreatScorer or NNThreatScorer
Stage 8: Reporting             → TerminalReporter or JsonReporter
```

### Data Flow

Every analyzer populates the **same `AnalysisResult` dataclass** (defined in `analyzers/base.py`). This is the central data structure that flows through the entire pipeline.

Key fields in `AnalysisResult`:

| Field | Type | Populated By |
|-------|------|-------------|
| `metadata` | `FileMetadata` | `loader.py` |
| `hashes` | `HashResult` | `HashAnalyzer` |
| `entropy` | `EntropyResult` | `EntropyAnalyzer` |
| `strings` | `StringCategory` | `StringAnalyzer` |
| `sections` | `list[SectionInfo]` | PE/ELF/Mach-O analyzers |
| `indicators` | `list[Indicator]` | All analyzers |
| `capabilities` | `list[Capability]` | `CapabilityMapper` |
| `yara_matches` | `list[YaraMatch]` | `YaraScanner` |
| `risk_score` | `float` | Scorer (heuristic or NN) |
| `risk_level` | `RiskLevel` | Scorer |
| `scoring_method` | `str` | Scorer (`"heuristic"` or `"neural_network"`) |
| `nn_confidence` | `float` | `NNThreatScorer` only |
| `format_info` | `dict` | Format-specific analyzers |
| `environment_impact` | `list[str]` | `CapabilityMapper` |
| `errors` | `list[str]` | Any stage (non-fatal errors) |

---

## Analyzers Deep Dive

### BaseAnalyzer (Abstract)

All analyzers extend `BaseAnalyzer` and implement:
```python
def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
    ...
```

Analyzers **mutate the `result` object in-place** rather than returning values. This allows each analyzer to populate the fields it cares about without knowing about other analyzers.

### Common Analyzers (run on every file)

| Analyzer | What It Does |
|----------|-------------|
| **HashAnalyzer** | Computes MD5, SHA-1, SHA-256, ssdeep fuzzy hash, and imphash (PE only) |
| **EntropyAnalyzer** | Calculates Shannon entropy (0–8 scale). Flags >7.0 as packed, >6.5 as suspicious |
| **StringAnalyzer** | Extracts ASCII/Unicode strings, classifies into URLs, IPs, shell commands, APIs, crypto wallets, base64 blobs, registry keys, file paths, emails |

### Format-Specific Analyzers

| Analyzer | File Types | Key Capabilities |
|----------|-----------|-----------------|
| **PEAnalyzer** | `.exe`, `.dll`, `.sys` | PE headers, sections, imports, exports, packer detection, TLS callbacks, digital signatures |
| **DLLAnalyzer** | `.dll` | Extends PE: hijacking detection, proxy DLL detection, COM registration, rundll32 entry points, Known DLL impersonation |
| **ELFAnalyzer** | Linux binaries | ELF headers, sections, symbols, security features (RELRO, NX, PIE, stack canary) |
| **MachOAnalyzer** | macOS binaries | Mach-O headers, load commands, entitlements, code signing |
| **ScriptAnalyzer** | `.py`, `.ps1`, `.sh`, `.js`, `.vbs`, `.bat` | Language detection, obfuscation, dangerous functions, download cradles |
| **DocumentAnalyzer** | `.doc`, `.pdf`, `.xls`, etc. | OLE streams, VBA macros, PDF JavaScript, embedded executables, auto-exec triggers |

### How Indicators Work

Analyzers create `Indicator` objects to flag suspicious findings:

```python
Indicator(
    category=ThreatCategory.DEFENSE_EVASION,  # MITRE ATT&CK category
    name="High Entropy Detected",              # Human-readable name
    description="...",                          # Detailed explanation
    evidence=["Entropy: 7.8432"],              # Supporting evidence
    severity=0.7,                              # 0.0 = benign, 1.0 = critical
)
```

These indicators feed into both the **CapabilityMapper** and the **Scorer**.

---

## Intelligence Layer

### YARA Scanner (`yara_scanner.py`)

- Loads `.yar`/`.yara` rule files from the built-in `rules/` directory
- Supports custom rule directories via `--yara-rules` flag
- Each match produces a `YaraMatch` with rule name, description, tags, and severity

### Capability Mapper (`capability_mapper.py`)

Maps detected APIs + indicators → high-level threat capabilities (MITRE ATT&CK-aligned):

```
CreateRemoteThread API  ──┐
VirtualAllocEx API       ──┼──→  "Process Injection" (T1055)
WriteProcessMemory API   ──┘
```

Rules are defined in `CAPABILITY_RULES` — a list of dicts mapping API names and indicator names to capability metadata. The mapper also generates plain-English **environment impact statements**.

---

## Scoring System

FileAnalysis has **three scoring engines** that run sequentially to provide an ensemble score:

### 1. Heuristic Scorer (`scorer.py`) — Default

A hand-tuned weighted formula:

| Component | Max Points | Logic |
|-----------|-----------|-------|
| Entropy | 15 | packed → 15, elevated → 10 |
| Suspicious strings | 20 | URLs +5, IPs +7, crypto +15, shells +3 each |
| Capabilities | 35 | sum(risk_contribution × 15), capped |
| YARA matches | 30 | critical +30, high +20, medium +10, low +5 |

**Pros:** Transparent, easy to tune, no dependencies.
**Cons:** Linear combinations can't capture complex feature interactions; thresholds are arbitrary.

### 2. Neural Network Scorer (`nn_model.py`)

A 4-layer MLP that processes 30 features extracted from the `AnalysisResult`. See the [Neural Network Model](#neural-network-model) section below.

### 3. LightGBM Scorer (`ml_model.py`)

A Gradient Boosting Decision Tree model trained on the same 30 features as the Neural Network. It is highly robust to tabular data (which is what the features represent) and typically outperforms Neural Networks on these types of structured features.
*Note: To prevent OpenMP threading conflicts between LightGBM and PyTorch on macOS, `OMP_NUM_THREADS=1` and `KMP_DUPLICATE_LIB_OK=TRUE` are set at the top of the CLI.*

### Risk Levels (all scorers use the same thresholds)

| Score | Level | Meaning |
|-------|-------|---------|
| 0–20 | 🟢 CLEAN | No indicators found |
| 21–40 | 🟡 LOW | Minor suspicious indicators |
| 41–60 | 🟠 MODERATE | Multiple suspicious indicators |
| 61–80 | 🔴 HIGH | Strong malware indicators |
| 81–100 | ⛔ CRITICAL | Almost certainly malicious |

---

## Neural Network Model

### Overview

The NN scoring system has three components:

```
features.py   →  nn_model.py   →  threat_model.pt
                 ml_model.py   →  threat_model_lgb.txt
(extraction)     (architecture)    (trained weights)
```

### Feature Extraction (`features.py`)

The `FeatureExtractor` class converts an `AnalysisResult` into a **30-dimensional float vector**:

```python
extractor = FeatureExtractor()
features = extractor.extract(result)  # → np.ndarray of shape (31,)
```

Features are organized into 9 groups:

| Group | Features | Indices |
|-------|----------|---------|
| File metadata | size (log), entropy | [0–1] |
| Entropy flags | is_packed, max section entropy | [2–3] |
| Section anomalies | suspicious count, total count | [4–5] |
| String counts | URLs, IPs, crypto, shells, APIs, b64, registry, email, paths | [6–14] |
| Indicators | count, max severity, mean severity | [15–17] |
| Capabilities | count, max risk, sum risk | [18–20] |
| YARA | count, has_critical, has_high, severity score | [21–24] |
| File type | one-hot (PE, ELF, script, document, Mach-O) | [25–29] |

Normalization strategies:
- **Log-scaling** for file size (`log1p`)
- **Capping** for count features (prevents outlier domination)
- **Binary flags** for boolean features
- **One-hot encoding** for file type

### Model Architecture (`nn_model.py`)

**ThreatNet** — a simple but effective MLP:

```
Input (30) → Linear(64) → ReLU → Dropout(0.3)
           → Linear(32) → ReLU → Dropout(0.3)
           → Linear(16) → ReLU
           → Linear(1)  → Sigmoid → output ∈ [0, 1]
```

The output is scaled to 0–100 for the threat score.

**Why this architecture:**
- **4 layers** provide enough depth to learn non-linear feature interactions
- **Dropout (0.3)** prevents overfitting on training data
- **Sigmoid output** naturally bounds predictions to [0, 1]
- **Decreasing width** (64→32→16→1) acts as an information bottleneck, forcing the model to learn compressed representations

### Inference Wrapper (`NNThreatScorer`)

```python
from fileanalysis.scoring.nn_model import NNThreatScorer

scorer = NNThreatScorer()                    # Loads pre-trained weights
scorer.calculate_score(result)               # Same API as ThreatScorer
# result.risk_score = 73.4
# result.risk_level = RiskLevel.HIGH
# result.scoring_method = "neural_network"
# result.nn_confidence = 0.734
```

Key design decisions:
- **Lazy torch import** — `torch` is only imported when `NNThreatScorer` is instantiated, keeping the default CLI lightweight
- **CPU-only inference** — No GPU required; inference on a single feature vector is instant
- **Same API** — `calculate_score(result)` matches `ThreatScorer` so they're drop-in replacements
- **Graceful fallback** — If torch is missing or weights aren't found, the CLI catches the error and falls back to heuristic scoring

### Training Pipeline (`train.py`)

```bash
# Train with defaults (50k samples, 200 epochs)
python -m fileanalysis.scoring.train

# Custom training
python -m fileanalysis.scoring.train --samples 100000 --epochs 300 --lr 0.0005
```

**How synthetic data is generated:**

The training data generator creates feature vectors with three archetypes:
- **Benign (40%)** — Low entropy, few strings, no capabilities, no YARA
- **Suspicious (30%)** — Medium entropy, some strings/capabilities, occasional YARA
- **Malicious (30%)** — High entropy, packed, many APIs/strings, YARA critical matches

Target scores are computed using the **same logic as the heuristic scorer**, plus Gaussian noise for generalization. This means the NN initially learns to replicate the heuristic, but with smoother interpolation.

**Training details:**
- **Loss function:** MSE (Mean Squared Error) — regression task
- **Optimizer:** Adam (lr=0.001)
- **Early stopping:** Patience of 15 epochs on validation loss
- **Train/val split:** 80/20
- **Output:** `threat_model.pt` saved alongside `nn_model.py`

### Cloud Training Pipeline (`sandbox_train.py` & `.github/workflows/training.yml`)

The model is retrained automatically using a robust CI/CD pipeline:
- **GitHub Actions Caching**: Features and labels are cached locally in `/workspace/dataset_cache.npz` and persisted across workflow runs using `actions/cache` to skip redundant downloading/extraction.
- **GitHub Actions**: A cron job triggers the `training.yml` workflow at midnight, spinning up a Docker sandbox and running `sandbox_train.py`.
- **Automated Releases**: If the model accuracy improves, the workflow automatically commits `threat_model.pt` and `feature_scaler.npz`, and creates a new versioned GitHub Release.

### Retraining on Real Data

To retrain on your own labeled dataset, see [Training the NN Model on Real Data](#training-the-nn-model-on-real-data).

---

## Reporting

### Terminal Report (`terminal_report.py`)

Uses the **Rich** library to produce colorful, structured console output:
- Header panel with file metadata
- Color-coded risk score badge (with Neural Network and LightGBM indicators)
- **AI Executive Insights**: Powered by Google Gemini to summarize key threat vectors
- Hash table
- Entropy gauge
- Capabilities list (MITRE ATT&CK-aligned)
- Environment impact statements
- YARA matches table

### JSON Report (`json_report.py`)

Serializes the entire `AnalysisResult` to JSON for programmatic consumption. Includes:
- `"scoring_method"`: `"heuristic"` or `"neural_network"`
- `"nn_confidence"`: Raw sigmoid output when NN scoring is used
- All indicators, capabilities, YARA matches, etc.

---

## CLI Interface

```bash
# Basic scan
fileanalysis scan suspicious.exe

# JSON output
fileanalysis scan suspicious.exe --json

# Custom YARA rules
fileanalysis scan suspicious.exe --yara-rules /path/to/rules/

# Combine flags
fileanalysis scan suspicious.exe --json
```

All flags:

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON instead of Rich terminal |
| `--yara-rules DIR` | Custom YARA rules directory |

---

## Adding New Analyzers

### Step 1: Create the analyzer

```python
# fileanalysis/analyzers/my_analyzer.py
from fileanalysis.analyzers.base import (
    AnalysisResult, BaseAnalyzer, Indicator, ThreatCategory
)

class MyAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "My Analyzer"

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        # Your analysis logic here
        # Populate result.indicators, result.format_info, etc.
        if something_suspicious:
            result.indicators.append(Indicator(
                category=ThreatCategory.EXECUTION,
                name="Something Suspicious",
                description="Found a suspicious pattern.",
                evidence=["detail1", "detail2"],
                severity=0.6,
            ))
```

### Step 2: Register it in the CLI

```python
# In cli.py, add to the appropriate stage:
from fileanalysis.analyzers.my_analyzer import MyAnalyzer

# In the cli() function:
MyAnalyzer().analyze(file_path, file_bytes, result)
```

### Step 3: (Optional) Add to CapabilityMapper

If your analyzer detects APIs or indicators that map to MITRE ATT&CK techniques, add mapping rules to `CAPABILITY_RULES` in `capability_mapper.py`.

### Step 4: (Optional) Add features for NN scoring

If your analyzer produces new signals, extend `FeatureExtractor.extract()` in `features.py`:
1. Add new features to the vector
2. Update `NUM_FEATURES` constant
3. Retrain the model: `python -m fileanalysis.scoring.train`

---

## Training the NN Model on Real Data

The synthetic training pipeline works well as a starting point, but the model will perform significantly better when trained on **real labeled malware/benignware samples**.

### Step 1: Collect labeled samples

Create a directory structure:
```
training_data/
├── malicious/     # Known malware samples
└── benign/        # Known clean files
```

### Step 2: Generate feature datasets

Write a script that runs the full analysis pipeline on each file and extracts features:

```python
from fileanalysis.loader import load_file
from fileanalysis.analyzers.entropy import EntropyAnalyzer
from fileanalysis.analyzers.strings import StringAnalyzer
from fileanalysis.analyzers.hashing import HashAnalyzer
# ... import other analyzers as needed
from fileanalysis.intelligence.capability_mapper import CapabilityMapper
from fileanalysis.intelligence.yara_scanner import YaraScanner
from fileanalysis.scoring.features import FeatureExtractor

extractor = FeatureExtractor()

# For each file:
file_bytes, result = load_file(file_path)
HashAnalyzer().analyze(file_path, file_bytes, result)
EntropyAnalyzer().analyze(file_path, file_bytes, result)
StringAnalyzer().analyze(file_path, file_bytes, result)
# ... run format-specific analyzers
YaraScanner().scan(file_path, result)
CapabilityMapper().map_capabilities(result)

features = extractor.extract(result)  # 30-dim vector
label = 1.0 if is_malware else 0.0    # binary label
```

### Step 3: Modify `train.py`

Replace the synthetic data generator with your real dataset loader. The training loop, model architecture, and early stopping logic remain the same.

### Step 4: Retrain

```bash
python -m fileanalysis.scoring.train --epochs 300 --lr 0.0005
```

---

## Dependencies

### Core (always required)

| Package | Purpose |
|---------|---------|
| `rich` | Beautiful terminal output |
| `click` | CLI framework |
| `pefile` | PE binary parsing |
| `yara-python` | YARA rule matching |
| `puremagic` | MIME type detection |
| `lief` | Cross-platform binary parsing |
| `ppdeep` | Fuzzy hashing (ssdeep) |
| `numpy` | Feature vector computation |

### Optional (NN scoring only)

| Package | Purpose |
|---------|---------|
| `torch` | PyTorch — neural network inference and training |
| `lightgbm` | LightGBM — gradient boosting tree inference and training |
| `google-genai` | Gemini — AI Executive Insights |

Install with: `pip install fileanalysis[nn]` or `pip install torch>=2.0`

---

## Design Principles

1. **Single data structure** — `AnalysisResult` is the shared state object; all analyzers write to it, the scorer reads from it.
2. **Analyzers are independent** — Each analyzer runs in isolation; they don't depend on each other's output (except `CapabilityMapper` which reads indicators).
3. **Optional heavy dependencies** — PyTorch is lazy-imported only when `--nn` is used.
4. **Graceful degradation** — If any analyzer fails, the error is logged to `result.errors` and the pipeline continues.
5. **Dual scoring** — Heuristic and NN scorers have the same API (`calculate_score(result)`) and are interchangeable.
