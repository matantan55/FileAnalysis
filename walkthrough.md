# Walkthrough: Sandboxed Malware Training

## What Was Done

Trained the `ThreatNet` neural network on **real malware samples** from the [DikeDataset](https://github.com/iosifache/DikeDataset), entirely inside an isolated Docker container to protect the local environment.

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
python -m fileanalysis.cli /Users/matanmishali/eh/look_mom_no_boot/main.exe
```

### Common mistakes

| ❌ Wrong | ✅ Right |
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
- Clones DikeDataset into `/app/dataset` (inside container only)
- Runs all 8 analyzers + YARA + CapabilityMapper on each file
- Extracts 31-dimensional feature vectors via `FeatureExtractor`
- Trains ThreatNet for 50 epochs with Rich progress bars
- Saves `threat_model.pt` to the mounted workspace

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

The loss dropped steadily from **0.1071** (epoch 10) to **0.0299** (epoch 50), indicating the model learned to distinguish benign from malicious files effectively.

## How to Re-train

```bash
cd /Users/matanmishali/AntiGravity/FileAnalysis
docker build -t fileanalysis-sandbox -f Dockerfile.sandbox .
docker run --rm -v "$(pwd)":/workspace fileanalysis-sandbox
```

## Security Notes
- All malware files existed **only inside the Docker container** — they were never written to your Mac's filesystem
- When the container finished, it was destroyed (`--rm`), deleting all malware with it
- Only the safe `threat_model.pt` weights file (22KB) was written to your local disk
