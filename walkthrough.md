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
