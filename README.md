# ⚡ FileAnalysis — Malware Threat Analysis Tool

A CLI-based malware file analysis and threat assessment tool that combines heuristic rules with a neural network trained on real malware samples.

## Quick Start

### 1. Clone & Setup

```bash
git clone <repo-url>
cd FileAnalysis

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Install PyTorch for neural network scoring
pip install torch>=2.0
```

### 2. Scan a File

> **Important:** You must run the command from the `FileAnalysis/` project root directory.

```bash
# Activate the virtual environment
source .venv/bin/activate

# Scan a file
python -m fileanalysis.cli /path/to/suspicious/file.exe
```

**Example:**
```bash
python -m fileanalysis.cli /usr/bin/zip
```

**Output:**
```
╭─────────────────────────────────────────╮
│ ⚡ FileAnalysis — Malware Threat Report │
╰─────────────────────────────────────────╯
📁 File: zip
📊 Type: Java bytecode (application/java)
📏 Size: 396.5 KB (405,984 bytes)

╭───────────────────────────────────────────────────────────────────╮
│ 🏆 Best Score (Ensemble): 70.3/100 — HIGH                         │
│                                                                   │
│ 📊 Heuristic: 34.0/100 — LOW                                      │
│ 🧠 Neural Net: 100.0/100 — CRITICAL  (100.0% confident malicious) │
│ 🌲 LightGBM: 50.5/100 — MODERATE  (50.5% confident malicious)     │
╰───────────────────────────────────────────────────────────────────╯

╭────────────────── 💡 AI Executive Insights ───────────────────╮
│ The model classified this file as malicious primarily due to: │
│ • Embedded URLs (Value: 0)                                    │
│ • Windows Registry Keys (Value: 1)                            │
│ • Script File Format (Value: 0)                               │
│                                                               │
│ Final ML Score: 50.5/100 (50.5% confidence)                   │
╰───────────────────────────────────────────────────────────────╯

🔒 File Hashes
  MD5:    a2c7a2266a2d82193aa0a4cc3fbae24e
  SHA-256: 0f01117851dbfb49407e3e06be5d4b9d...

🔥 File Entropy: 5.5282/8.0

🎯 Threat Capabilities
  • Command & Control (T1071) — ...
```

### 3. CLI Options

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |

| `--yara-rules DIR` | Path to custom YARA rules directory |

**Examples:**
```bash
# JSON output (for scripting)
python -m fileanalysis.cli suspicious.exe --json



# Custom YARA rules
python -m fileanalysis.cli suspicious.exe --yara-rules /path/to/rules/

# Combine flags
python -m fileanalysis.cli suspicious.exe --json
```

---

## How It Works

FileAnalysis runs a multi-stage pipeline on every file:

1. **Load** — Reads the file, detects type (PE, ELF, Mach-O, script, document)
2. **Analyze** — Runs format-specific analyzers (hashing, entropy, advanced strings including CVE/Registry patterns, imports, sections)
3. **Intelligence** — YARA signature matching + MITRE ATT&CK capability mapping (e.g., Exploitation, Persistence)
4. **Score** — Triple scoring with heuristic rules, a neural network, and a LightGBM decision tree model
5. **Report** — Rich terminal output or JSON

### Dual Scoring System

Every scan produces **independent threat scores** and an ensemble score:

| Scorer | How it works |
|--------|-------------|
| **📊 Heuristic** | Hand-tuned weighted formula (entropy + strings + capabilities + YARA) |
| **🧠 Neural Net** | 4-layer MLP trained on real malware/benign samples |
| **🌲 LightGBM** | Gradient boosting decision tree trained on the same feature set |
| **💡 AI Insights** | Google Gemini LLM generates an executive summary of the primary threat vectors |

### Risk Levels

| Score | Level | Meaning |
|-------|-------|---------|
| 0–20 | 🟢 CLEAN | No indicators found |
| 21–40 | 🟡 LOW | Minor suspicious indicators |
| 41–60 | 🟠 MODERATE | Multiple suspicious indicators |
| 61–80 | 🔴 HIGH | Strong malware indicators |
| 81–100 | ⛔ CRITICAL | Almost certainly malicious |

---

## Retraining the Neural Network (Incremental Learning)

The model can be retrained on real malware inside a **Docker sandbox** (no malware touches your local machine):

```bash
# Build the sandbox
docker build -t fileanalysis-sandbox -f Dockerfile.sandbox .

# Run training (fetches dataset, extracts features, trains model)
docker run --rm -v "$(pwd)":/workspace fileanalysis-sandbox
```

This will:
1. Clone multiple curated cybersecurity datasets (DikeDataset, theZoo, vx-underground, Das Malwerk, Endermanch MalwareDatabase) inside the container
2. **Incremental Extraction**: Skip files already cached in `dataset_cache.npz` and extract 30-dimensional features only from new files
3. **Replay-Buffer Fine-Tuning**: Load the existing `threat_model_malconv.pt` weights and fine-tune using 100% of new data + a 10% replay buffer of old data to prevent catastrophic forgetting
4. Train ThreatNet (PyTorch) and LightGBM models
5. Save `threat_model_malconv.pt`, `threat_model_lgb.txt` and `feature_scaler.npz` to your local project
6. Destroy the container (and all malware) when done

---

## Project Structure

```
FileAnalysis/
├── fileanalysis/
│   ├── cli.py                    # Main CLI entry point
│   ├── loader.py                 # File loading & type detection
│   ├── analyzers/                # Format-specific analyzers
│   │   ├── base.py               # AnalysisResult data structure
│   │   ├── entropy.py            # Entropy analysis
│   │   ├── hashing.py            # Cryptographic hashing
│   │   ├── strings.py            # String extraction & categorization
│   │   ├── pe_analyzer.py        # Windows PE analysis
│   │   ├── elf_analyzer.py       # Linux ELF analysis
│   │   ├── macho_analyzer.py     # macOS Mach-O analysis
│   │   ├── script_analyzer.py    # Script file analysis
│   │   ├── document_analyzer.py  # Document file analysis
│   │   └── dll_analyzer.py       # DLL-specific analysis
│   ├── intelligence/
│   │   ├── yara_scanner.py       # YARA rule matching
│   │   └── capability_mapper.py  # MITRE ATT&CK mapping
│   ├── scoring/
│   │   ├── scorer.py             # Heuristic threat scorer
│   │   ├── nn_model.py           # ThreatNet neural network
│   │   ├── ml_model.py           # LightGBM tree model
│   │   ├── features.py           # 30-dim feature extraction
│   │   ├── sandbox_train.py      # Real malware training (Docker)
│   │   ├── threat_model.pt       # Trained NN weights
│   │   └── threat_model_lgb.txt  # Trained LightGBM weights
│   └── reporting/
│       ├── terminal_report.py    # Rich terminal output
│       └── json_report.py        # JSON output
├── Dockerfile.sandbox            # Docker sandbox for safe training
├── requirements.txt              # Python dependencies
└── pyproject.toml                # Project configuration
```

---

## Dependencies

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
| `torch` *(optional)* | Neural network inference |

---

## License

See [LICENSE](LICENSE) for details.

## Cloud Integration & CI/CD

To ensure the neural network continually stays ahead of zero-day threats, the entire training and release lifecycle is fully automated using **GitHub Actions**:

- **Continuous Model Retraining**: A GitHub Actions workflow (`.github/workflows/training.yml`) automatically triggers the Docker sandbox training pipeline using `workflow_dispatch` or pushes with `--train`.
- **Incremental Dataset Caching**: The training pipeline uses the `actions/cache` GitHub action to persist and automatically download pre-computed dataset features (`dataset_cache.npz`) between runs. This skips the massive repository cloning and extraction phases for already processed files, extracting features only for newly pushed malware.
- **Automated Versioning & Releases**: Upon a successful run, if the model weights (`threat_model_malconv.pt`) have improved/changed, the CI/CD pipeline automatically commits the updates back to the `main` branch and publishes a new versioned GitHub Release.
