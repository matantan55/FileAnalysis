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

╭───────────────────────────────────────────────────────────╮
│ 📊 Heuristic: 19.5/100 — CLEAN                            │
│ 🧠 Neural Net: 0.0/100 — CLEAN  (100.0% confident benign) │
╰───────────────────────────────────────────────────────────╯

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
4. **Score** — Dual scoring with both heuristic rules and a neural network
5. **Report** — Rich terminal output or JSON

### Dual Scoring System

Every scan produces **two independent threat scores**:

| Scorer | How it works |
|--------|-------------|
| **📊 Heuristic** | Hand-tuned weighted formula (entropy + strings + capabilities + YARA) |
| **🧠 Neural Net** | 4-layer MLP trained on ~4,000 real malware/benign samples from multiple datasets (DikeDataset, theZoo, InQuest, PMAT, fabrimagic72) |

### Risk Levels

| Score | Level | Meaning |
|-------|-------|---------|
| 0–20 | 🟢 CLEAN | No indicators found |
| 21–40 | 🟡 LOW | Minor suspicious indicators |
| 41–60 | 🟠 MODERATE | Multiple suspicious indicators |
| 61–80 | 🔴 HIGH | Strong malware indicators |
| 81–100 | ⛔ CRITICAL | Almost certainly malicious |

---

## Retraining the Neural Network

The model can be retrained on real malware inside a **Docker sandbox** (no malware touches your local machine):

```bash
# Build the sandbox
docker build -t fileanalysis-sandbox -f Dockerfile.sandbox .

# Run training (fetches dataset, extracts features, trains model)
docker run --rm -v "$(pwd)":/workspace fileanalysis-sandbox
```

This will:
1. Clone multiple curated cybersecurity datasets (DikeDataset, theZoo, InQuest, PMAT, fabrimagic72) inside the container
2. Extract 30-dimensional feature vectors from nearly 4,000 real files
3. Train ThreatNet for 200 epochs
4. Save `threat_model.pt` to your local project
5. Destroy the container (and all malware) when done

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
│   │   ├── features.py           # 30-dim feature extraction
│   │   ├── train.py              # Synthetic data training
│   │   ├── sandbox_train.py      # Real malware training (Docker)
│   │   └── threat_model.pt       # Trained model weights
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

---

## Roadmap & Future Work

To further scale and automate the malware detection capabilities, the following initiatives are on our future roadmap:

- **Continuous Model Retraining**: Establish an automated, continuous training pipeline that runs daily, ensuring the model stays up-to-date with zero-day behaviors. 
- **Cloud-Based Data Collection**: Migrate the data collection and feature extraction processes to a centralized cloud environment.
- **Cloud Storage for Datasets**: Persist all processed datasets and extracted feature vectors in cloud storage (e.g., AWS S3). This eliminates the need to recursively fetch old data on every training run, vastly speeding up the training pipeline.
- **Automated Versioning & Releases**: Automatically tag and publish a new version of the ThreatNet model alongside each successful daily training run.
