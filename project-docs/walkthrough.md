# MalOwn Interactive CLI Menu & Binary Research Upgrades

We have implemented an interactive, menu-driven command-line interface for the project and significantly upgraded the binary research capabilities with assembly disassembly and threat detection.

## What's New

### 1. Interactive Menu
When you run the tool without any file arguments (`python -m fileanalysis.cli`), it now launches the **MalOwn Interactive Console**. 

The console acts as a persistent workspace. You can seamlessly load files by pasting their paths directly into the main prompt. The workspace tracks all loaded files in an index table.

Once you have files loaded, you can choose between:
- **Standard File Analysis** (Full machine-learning & heuristic scan)
- **Interactive Binary Research** (The interactive hex viewer)
- **Clear Files** (Clear your workspace buffer)

The console safely handles file paths with quotes and provides non-blocking, instant visual feedback for errors or successful loads without slowing you down with "Press Enter" prompts.

> [!NOTE]
> Backward compatibility is maintained. If you supply a file path argument (e.g. `python -m fileanalysis.cli my_malware.exe`), it automatically bypasses the menu and runs in one-shot mode as it did previously.

### 2. Capstone Disassembly Engine
The Hex Viewer now automatically detects if a binary is PE or ELF, determines the architecture (x86, x64, ARM64), and disassembles all executable code sections using the `capstone` library.

When navigating through code sections in the hex viewer, a brand new **Assembly** column translates the raw hex into human-readable instructions in real-time.

### 3. Assembly Threat Hunting
The viewer actively hunts for malicious shellcode indicators and obfuscation tricks while you read the assembly:
- Detects anti-debugging traps (`cpuid`, `rdtsc`, `int3`).
- Detects process injection and dynamic API resolutions (indirect calls via RAX, RBX, memory).
- Detects shellcode decoding loops and stack pivots (ROP chains).

> [!WARNING]
> If a malicious pattern is detected in the assembly, the instruction is highlighted in **bold red** and a threat label is attached to the annotation column (e.g. `⚠ Call-to-self (shellcode decoder)`).

### 4. Terminal-Native Control Flow Graph (CFG)
You can now visualize the assembly execution paths directly within the terminal interface, avoiding the need for messy ASCII diagrams or external tools.
- Press **c** (or type `c <offset>`) in the Hex Viewer to generate a sleek, hierarchical Control Flow Graph.
- The CFG intelligently splits the code into Basic Blocks and renders them as `rich` panels linked by a beautiful tree layout.
- Conditionals (True/False) and jumps are color-coded to instantly show you exactly where the malicious code leads.

---

# Walkthrough: Sandboxed Malware Training
## What Was Done

Trained the `MalConv` neural network (on raw bytes) and `LightGBMThreatScorer` gradient boosting model on **real malware samples** from multiple datasets (DikeDataset, theZoo, vx-underground).
Implemented a highly efficient **Incremental Learning Pipeline** in a Docker sandbox that caches extracted features and fine-tunes the PyTorch model with a replay buffer to prevent catastrophic forgetting.
Added an **Anti-False-Positive Filter** into the ensemble scoring to ensure innocent documents and empty files are not hallucinated as malware.

## How to Run FileAnalysis

> **You must be in the project root directory** (`FileAnalysis/`) for all commands to work.

### Step 1: Activate the virtual environment

```bash
cd /Users/matanmishali/AntiGravity/FileAnalysis
source .venv/bin/activate
```

### Step 2: Scan a file

```bash
python -m fileanalysis.cli /path/to/file
```

**Example:**
```bash
python -m fileanalysis.cli /usr/bin/zip
python -m fileanalysis.cli ~/Downloads/suspicious.exe
```

### Common mistakes

|  Wrong |  Right |
|---------|---------|
| Running from `~/` or any other directory | `cd` into `FileAnalysis/` first |
| `python -m fileanalysis.cli` (without venv) | `source .venv/bin/activate` first |
| `fileanalysis scan file.exe` (package not pip-installed) | Use `python -m fileanalysis.cli file.exe` |

---

## Files Created/Modified

### [Dockerfile.sandbox](Dockerfile.sandbox)
- Python 3.11 slim image with git, build-essential, libmagic
- Creates `/app/dataset` (isolated from host mount) for malware storage
- Installs CPU-only PyTorch + all project dependencies
- Sets `PYTHONPATH=/workspace` to make `fileanalysis` importable

### [sandbox_train.py](fileanalysis/scoring/sandbox_train.py)
- Clones multiple real malware datasets into `/app/dataset` (inside container only)
- Uses **Incremental Feature Extraction** to only process brand-new files not already in `dataset_cache.npz`
- Extracts 30-dimensional feature vectors via `FeatureExtractor`
- Automatically fine-tunes MalConv (PyTorch) using a **10% Replay Buffer** of historical data
- Saves `threat_model_malconv.pt`, `threat_model_lgb.txt`, and `feature_scaler.npz` to the mounted workspace

### [requirements-sandbox.txt](requirements-sandbox.txt)
- Pinned CPU-only PyTorch via `--extra-index-url` to avoid downloading ~900MB of CUDA libraries

## Training Results

| Metric | Value |
|--------|-------|
| Benign files | 200 |
| Malware files | 200 |
| Total feature vectors | 400 |
| Epochs | 50 |
| Final loss | 0.0299 |
| Model size | 22KB |

The models are able to effectively distinguish benign from malicious files by looking at structural metadata, strings, and entropy without relying solely on traditional YARA signatures.

## How to Re-train

```bash
cd /Users/matanmishali/AntiGravity/FileAnalysis
docker build -t fileanalysis-sandbox -f Dockerfile.sandbox .
docker run --rm -v "$(pwd)":/workspace fileanalysis-sandbox
```

## Security Notes
- All malware files existed **only inside the Docker container** — they were never written to your Mac's filesystem
- When the container finished, it was destroyed (`--rm`), deleting all malware with it
- Only the safe `threat_model_malconv.pt`, `threat_model_lgb.txt` and `feature_scaler.npz` weights files were written to your local disk
