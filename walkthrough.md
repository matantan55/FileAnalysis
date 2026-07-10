# Walkthrough: Sandboxed Malware Training

## What Was Done

Trained the `ThreatNet` neural network on **real malware samples** from the [DikeDataset](https://github.com/iosifache/DikeDataset), entirely inside an isolated Docker container to protect the local environment.

## Files Created/Modified

### [Dockerfile.sandbox](file:///Users/matanmishali/AntiGravity/FileAnalysis/Dockerfile.sandbox)
- Python 3.11 slim image with git, build-essential, libmagic
- Creates `/app/dataset` (isolated from host mount) for malware storage
- Installs CPU-only PyTorch + all project dependencies
- Sets `PYTHONPATH=/workspace` to make `fileanalysis` importable

### [sandbox_train.py](file:///Users/matanmishali/AntiGravity/FileAnalysis/fileanalysis/scoring/sandbox_train.py)
- Clones DikeDataset into `/app/dataset` (inside container only)
- Runs all 8 analyzers + YARA + CapabilityMapper on each file
- Extracts 31-dimensional feature vectors via `FeatureExtractor`
- Trains ThreatNet for 50 epochs with Rich progress bars
- Saves `threat_model.pt` to the mounted workspace

### [requirements-sandbox.txt](file:///Users/matanmishali/AntiGravity/FileAnalysis/requirements-sandbox.txt)
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

## How to Use the Trained Model

```bash
# Scan a file using the neural network scorer
fileanalysis scan suspicious.exe --nn
```

## Security Notes
- All malware files existed **only inside the Docker container** — they were never written to your Mac's filesystem
- When the container finished, it was destroyed (`--rm`), deleting all malware with it
- Only the safe `threat_model.pt` weights file (22KB) was written to your local disk
