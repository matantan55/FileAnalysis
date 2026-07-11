"""Sandboxed training script — runs inside Docker container.

Fetches malware from 3 sources:
  1. DikeDataset (GitHub) — ~1000 malware + ~1000 benign PE files
  2. theZoo (GitHub) — curated malware samples in password-protected zips
  3. MalwareBazaar (abuse.ch API) — recent PE malware samples

All malware lives ONLY inside the container at /app/dataset.
Only the trained model weights are saved to the host via /workspace mount.
"""

import os
import random
import subprocess
import sys
import concurrent.futures
import multiprocessing
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

import numpy as np
import torch
import torch.nn as nn
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from torch.utils.data import DataLoader, TensorDataset

from fileanalysis.analyzers.document_analyzer import DocumentAnalyzer
from fileanalysis.analyzers.elf_analyzer import ELFAnalyzer
from fileanalysis.analyzers.entropy import EntropyAnalyzer
from fileanalysis.analyzers.hashing import HashAnalyzer
from fileanalysis.analyzers.macho_analyzer import MachOAnalyzer
from fileanalysis.analyzers.pe_analyzer import PEAnalyzer
from fileanalysis.analyzers.script_analyzer import ScriptAnalyzer
from fileanalysis.analyzers.strings import StringAnalyzer
from fileanalysis.intelligence.capability_mapper import CapabilityMapper
from fileanalysis.intelligence.yara_scanner import YaraScanner
from fileanalysis.loader import load_file
from fileanalysis.scoring.features import FeatureExtractor
from fileanalysis.scoring.nn_model import ThreatNet

# ──────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────
DIKE_REPO = "https://github.com/iosifache/DikeDataset.git"
ZOO_REPO = "https://github.com/ytisf/theZoo.git"
INQUEST_REPO = "https://github.com/InQuest/malware-samples.git"
FABRI_REPO = "https://github.com/fabrimagic72/malware-samples.git"
JSTROSCH_REPO = "https://github.com/jstrosch/malware-samples.git"

DATASET_ROOT = Path("/app/dataset")
DIKE_DIR = DATASET_ROOT / "DikeDataset"
ZOO_DIR = DATASET_ROOT / "theZoo"
INQUEST_DIR = DATASET_ROOT / "inquest"
FABRI_DIR = DATASET_ROOT / "fabri"
JSTROSCH_DIR = DATASET_ROOT / "jstrosch"
ULTIMATE_RAT_DIR = DATASET_ROOT / "ultimate_rat"
AWS_SAMPLES_DIR = DATASET_ROOT / "aws_samples"

MAX_DIKE_PER_CLASS = 1000
MAX_ZOO_FILES = 500
MAX_GITHUB_FILES = 500

WORKSPACE_MODEL_PATH = Path("/workspace/fileanalysis/scoring/threat_model.pt")
WORKSPACE_SCALER_PATH = Path("/workspace/fileanalysis/scoring/feature_scaler.npz")

console = Console()


# ──────────────────────────────────────────────────────────────
# Dataset fetchers
# ──────────────────────────────────────────────────────────────
def clone_dike():
    """Clone DikeDataset (benign + malware PE files)."""
    if not DIKE_DIR.exists():
        console.print("[bold cyan]📦 Cloning DikeDataset…[/]")
        DIKE_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", DIKE_REPO, str(DIKE_DIR)],
            check=True,
        )
    else:
        console.print("[green]✓ DikeDataset already present.[/]")


def clone_zoo():
    """Clone theZoo and extract password-protected malware zips."""
    if not ZOO_DIR.exists():
        console.print("[bold cyan]📦 Cloning theZoo…[/]")
        ZOO_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", ZOO_REPO, str(ZOO_DIR)],
            check=True,
        )
    else:
        console.print("[green]✓ theZoo already present.[/]")

    # Extract password-protected zips (password = "infected")
    extract_dir = DATASET_ROOT / "zoo_extracted"
    if extract_dir.exists() and any(extract_dir.iterdir()):
        console.print("[green]✓ theZoo samples already extracted.[/]")
        return extract_dir

    extract_dir.mkdir(parents=True, exist_ok=True)
    malware_dir = ZOO_DIR / "malware" / "Binaries"
    if not malware_dir.exists():
        console.print("[yellow]⚠ theZoo Binaries directory not found.[/]")
        return extract_dir

    zips = list(malware_dir.rglob("*.zip"))
    console.print(f"[bold]Found {len(zips)} zips in theZoo to extract.[/]")

    extracted = 0
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold yellow]Extracting theZoo"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
    ) as progress:
        task_zoo = progress.add_task("Extracting...", total=min(len(zips), MAX_ZOO_FILES))
        for zf in zips:
            if extracted >= MAX_ZOO_FILES:
                break
            out_dir = extract_dir / zf.stem
            out_dir.mkdir(exist_ok=True)
            try:
                subprocess.run(
                    ["7z", "x", "-r", "-pinfected", "-y", f"-o{out_dir}", str(zf)],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
                extracted += 1
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            finally:
                progress.update(task_zoo, advance=1)

    console.print(f"[green]✓ Extracted {extracted} theZoo archives.[/]")
    return extract_dir


def fetch_github_datasets():
    """Clone new GitHub malware datasets."""
    datasets = [
        ("InQuest", INQUEST_REPO, INQUEST_DIR),
        ("fabrimagic72", FABRI_REPO, FABRI_DIR),
        ("jstrosch (PMAT)", JSTROSCH_REPO, JSTROSCH_DIR),
        ("Ultimate-RAT-Collection", "https://github.com/Cryakl/Ultimate-RAT-Collection.git", ULTIMATE_RAT_DIR),
    ]

    for name, repo_url, target_dir in datasets:
        if not target_dir.exists():
            console.print(f"[bold cyan]📦 Cloning {name}…[/]")
            target_dir.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
                check=True,
            )
        else:
            console.print(f"[green]✓ {name} already present.[/]")

    # Extract password-protected zips (password = "infected") if any exist
    extract_dir = DATASET_ROOT / "github_extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    
    # We'll just collect the files in collect_files later, but if there are zips:
    zips = []
    for d in [INQUEST_DIR, FABRI_DIR, JSTROSCH_DIR, ULTIMATE_RAT_DIR]:
        zips.extend(list(d.rglob("*.zip")))
        zips.extend(list(d.rglob("*.7z")))
        zips.extend(list(d.rglob("*.rar")))
    
    if zips:
        extracted = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold yellow]Extracting GitHub zips"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
        ) as progress:
            task_gh = progress.add_task("Extracting...", total=len(zips))
            for zf in zips:
                out_dir = extract_dir / zf.stem
                out_dir.mkdir(exist_ok=True)
                try:
                    subprocess.run(
                        ["7z", "x", "-r", "-pinfected", "-y", f"-o{out_dir}", str(zf)],
                        check=True,
                        capture_output=True,
                        timeout=15,
                    )
                    extracted += 1
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass
                finally:
                    progress.update(task_gh, advance=1)
        if extracted > 0:
            console.print(f"[green]✓ Extracted {extracted} GitHub archives.[/]")

def fetch_aws_samples():
    """Fetch raw malware samples collected by the AWS Data Collector from S3."""
    bucket = os.environ.get("AWS_S3_BUCKET")
    if not bucket or not boto3:
        console.print("[dim]Skipping AWS samples fetch (boto3 or AWS_S3_BUCKET missing)[/]")
        return
        
    console.print(f"[bold cyan]📦 Fetching AWS data collector samples from s3://{bucket}/raw_samples/…[/]")
    AWS_SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    
    try:
        s3 = boto3.client('s3')
        paginator = s3.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket, Prefix="raw_samples/")
        
        count = 0
        for page in pages:
            for obj in page.get('Contents', []):
                key = obj['Key']
                if key.endswith('/'):
                    continue
                    
                local_path = AWS_SAMPLES_DIR / key.split('/')[-1]
                if not local_path.exists():
                    s3.download_file(bucket, key, str(local_path))
                    count += 1
                    
        console.print(f"[green]✓ Downloaded {count} raw samples from AWS S3.[/]")
    except Exception as e:
        console.print(f"[bold red]Failed to fetch AWS samples:[/] {e}")

# ──────────────────────────────────────────────────────────────
# Feature extraction
# ──────────────────────────────────────────────────────────────
def _process_worker(fpath, label, q):
    extractor = FeatureExtractor()
    analyzers = [
        HashAnalyzer(),
        EntropyAnalyzer(),
        StringAnalyzer(),
        PEAnalyzer(),
        ELFAnalyzer(),
        MachOAnalyzer(),
        ScriptAnalyzer(),
        DocumentAnalyzer(),
    ]
    yara_scanner = YaraScanner()
    capability_mapper = CapabilityMapper()

    try:
        file_bytes, result = load_file(str(fpath))
        for analyzer in analyzers:
            try:
                analyzer.analyze(str(fpath), file_bytes, result)
            except Exception:
                pass
        yara_scanner.scan(str(fpath), result)
        capability_mapper.map_capabilities(result)

        feat_vec = extractor.extract(result)
        q.put((feat_vec, [label]))
    except Exception:
        pass


def _process_file(fpath, label, progress, task):
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_process_worker, args=(fpath, label, q))
    p.start()
    p.join(5.0)

    feat, lbl = None, None
    if p.is_alive():
        p.terminate()
        p.join()
    else:
        if not q.empty():
            try:
                feat, lbl = q.get_nowait()
            except Exception:
                pass

    progress.update(task, advance=1)
    return feat, lbl


def extract_features(file_paths, label, progress, task):
    """Run full analysis pipeline on each file and extract feature vectors in parallel."""
    features_list = []
    labels_list = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        futures = [
            executor.submit(_process_file, fpath, label, progress, task)
            for fpath in file_paths
        ]
        for future in concurrent.futures.as_completed(futures):
            feat, lbl = future.result()
            if feat is not None:
                features_list.append(feat)
                labels_list.append(lbl)

    return features_list, labels_list


def collect_files(directory: Path, max_files: int = 10000) -> list[Path]:
    """Recursively collect files from a directory, skipping directories and tiny files."""
    files = []
    if not directory.exists():
        return files
    for f in directory.rglob("*"):
        if f.is_file() and f.stat().st_size > 100:  # skip empty/tiny files
            files.append(f)
            if len(files) >= max_files:
                break
    return files


# ──────────────────────────────────────────────────────────────
# Training
# ──────────────────────────────────────────────────────────────
def main():
    console.rule("[bold cyan]⚡ ThreatNet Multi-Dataset Training[/]")

    bucket_name = os.environ.get("AWS_S3_BUCKET")
    cache_file = "dataset_cache.npz"
    local_cache_path = DATASET_ROOT / cache_file

    X, y = [], []
    used_cache = False

    if bucket_name:
        console.print(f"[bold cyan]☁️ Checking S3 bucket ({bucket_name}) for cached dataset…[/]")
        try:
            s3 = boto3.client('s3')
            s3.download_file(bucket_name, cache_file, str(local_cache_path))
            console.print("[bold green]✓ Downloaded cached dataset from S3![/]")
            
            data = np.load(local_cache_path)
            X = data['X']
            y = data['y']
            used_cache = True
            console.print(f"[bold green]✓ Loaded {len(X)} feature vectors from cache. Skipping extraction![/]")
        except ClientError as e:
            if e.response['Error']['Code'] == "404":
                console.print("[yellow]⚠ Cache not found in S3. Will extract from scratch.[/]")
            else:
                console.print(f"[bold red]Error accessing S3: {e}[/]")
        except Exception as e:
            console.print(f"[bold red]Failed to load cache: {e}[/]")

    if not used_cache:
        # 1. Fetch all datasets
        clone_dike()
        clone_zoo()
        fetch_github_datasets()
        fetch_aws_samples()

        # 2. Collect file paths
        console.rule("[bold]Collecting files")

        # Benign files (DikeDataset only)
        dike_benign = list((DIKE_DIR / "files" / "benign").glob("*"))[:MAX_DIKE_PER_CLASS]

        # Malware files from all sources
        dike_malware = list((DIKE_DIR / "files" / "malware").glob("*"))[:MAX_DIKE_PER_CLASS]
        zoo_malware = collect_files(DATASET_ROOT / "zoo_extracted", MAX_ZOO_FILES)
        github_malware = collect_files(DATASET_ROOT / "github_extracted", MAX_GITHUB_FILES)
        github_malware += collect_files(INQUEST_DIR, MAX_GITHUB_FILES)
        github_malware += collect_files(FABRI_DIR, MAX_GITHUB_FILES)
        github_malware += collect_files(JSTROSCH_DIR, MAX_GITHUB_FILES)
        
        rat_files = collect_files(ULTIMATE_RAT_DIR, 10000)
        if len(rat_files) > 20:
            rat_files = random.sample(rat_files, 20)
        github_malware += rat_files
        
        aws_malware = collect_files(AWS_SAMPLES_DIR, MAX_GITHUB_FILES)
        
        # Dedup and trim
        github_malware = list(set(github_malware))[:MAX_GITHUB_FILES * 4]

        all_malware = dike_malware + zoo_malware + github_malware + aws_malware

        console.print(f"  Benign:  [green]{len(dike_benign)}[/] (DikeDataset)")
        console.print(f"  Malware: [red]{len(dike_malware)}[/] (DikeDataset) + "
                      f"[red]{len(zoo_malware)}[/] (theZoo) + "
                      f"[red]{len(github_malware)}[/] (GitHub) + "
                      f"[red]{len(aws_malware)}[/] (AWS OSINT) = "
                      f"[bold red]{len(all_malware)}[/] total")

        # 3. Extract features
        console.rule("[bold]Extracting features")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
        ) as progress:
            task_b = progress.add_task("[green]Benign files…", total=len(dike_benign))
            f, lbls = extract_features(dike_benign, 0.0, progress, task_b)
            X.extend(f)
            y.extend(lbls)

            task_m = progress.add_task("[red]Malware files…", total=len(all_malware))
            f, lbls = extract_features(all_malware, 1.0, progress, task_m)
            X.extend(f)
            y.extend(lbls)

        if len(X) < 10:
            console.print("[bold red]Too few feature vectors extracted. Exiting.[/]")
            sys.exit(1)

        X = np.array(X, dtype=np.float32)
        y = np.array(y, dtype=np.float32)

        console.print(f"[bold green]✓ Extracted {len(X)} feature vectors "
                      f"({int(np.sum(y == 0))} benign, {int(np.sum(y == 1))} malware)[/]")

        # Upload cache to S3
        if bucket_name:
            console.print(f"[bold cyan]☁️ Uploading extracted dataset to S3 ({bucket_name})…[/]")
            try:
                local_cache_path.parent.mkdir(parents=True, exist_ok=True)
                np.savez(local_cache_path, X=X, y=y)
                s3 = boto3.client('s3')
                s3.upload_file(str(local_cache_path), bucket_name, cache_file)
                console.print("[bold green]✓ Uploaded dataset cache to S3![/]")
            except Exception as e:
                console.print(f"[bold red]Failed to upload cache to S3: {e}[/]")

    # 4. Normalize features (StandardScaler)
    feat_mean = X.mean(axis=0)
    feat_std = X.std(axis=0)
    feat_std[feat_std < 1e-8] = 1.0  # avoid division by zero for constant features
    X_norm = (X - feat_mean) / feat_std

    # 5. Train/validation split (80/20, stratified)
    np.random.seed(42)
    benign_idx = np.where(y.flatten() == 0)[0]
    malware_idx = np.where(y.flatten() == 1)[0]
    np.random.shuffle(benign_idx)
    np.random.shuffle(malware_idx)

    val_b = benign_idx[:len(benign_idx) // 5]
    train_b = benign_idx[len(benign_idx) // 5:]
    val_m = malware_idx[:len(malware_idx) // 5]
    train_m = malware_idx[len(malware_idx) // 5:]

    train_idx = np.concatenate([train_b, train_m])
    val_idx = np.concatenate([val_b, val_m])
    np.random.shuffle(train_idx)
    np.random.shuffle(val_idx)

    X_train, y_train = X_norm[train_idx], y[train_idx]
    X_val, y_val = X_norm[val_idx], y[val_idx]

    console.print(f"  Train: {len(X_train)} | Val: {len(X_val)}")

    # 6. Train
    model = ThreatNet()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)
    criterion = nn.BCELoss()
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=200)

    train_ds = TensorDataset(torch.tensor(X_train), torch.tensor(y_train))
    train_loader = DataLoader(train_ds, batch_size=64, shuffle=True)

    val_tensor_X = torch.tensor(X_val)
    val_tensor_y = torch.tensor(y_val)

    epochs = 200
    best_val_acc = 0.0
    best_state = None
    console.rule(f"[bold cyan]Training for {epochs} epochs")

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
    ) as progress:
        train_task = progress.add_task("Training…", total=epochs)

        for epoch in range(epochs):
            model.train()
            total_loss = 0
            for batch_X, batch_y in train_loader:
                optimizer.zero_grad()
                out = model(batch_X)
                loss = criterion(out, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

            avg_loss = total_loss / len(train_loader)
            scheduler.step()

            # Validation accuracy
            model.eval()
            with torch.no_grad():
                val_out = model(val_tensor_X)
                val_preds = (val_out >= 0.5).float()
                val_acc = (val_preds == val_tensor_y).float().mean().item() * 100

            if val_acc > best_val_acc:
                best_val_acc = val_acc
                best_state = {k: v.clone() for k, v in model.state_dict().items()}

            lr = optimizer.param_groups[0]["lr"]
            progress.update(
                train_task,
                advance=1,
                description=f"Epoch {epoch+1}/{epochs} | Loss: {avg_loss:.4f} | Val Acc: {val_acc:.1f}% | LR: {lr:.6f}",
            )

    # Load best model
    if best_state:
        model.load_state_dict(best_state)

    # 7. Final evaluation
    console.rule("[bold]Final Evaluation")
    model.eval()
    with torch.no_grad():
        val_out = model(val_tensor_X)
        val_preds = (val_out >= 0.5).float().squeeze()
        val_true = val_tensor_y.squeeze()

    tp = ((val_preds == 1) & (val_true == 1)).sum().item()
    tn = ((val_preds == 0) & (val_true == 0)).sum().item()
    fp = ((val_preds == 1) & (val_true == 0)).sum().item()
    fn = ((val_preds == 0) & (val_true == 1)).sum().item()

    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1) * 100
    precision = tp / max(tp + fp, 1) * 100
    recall = tp / max(tp + fn, 1) * 100
    f1 = 2 * precision * recall / max(precision + recall, 1)

    metrics_table = Table(title="📊 Validation Metrics")
    metrics_table.add_column("Metric", style="bold")
    metrics_table.add_column("Value", style="cyan")
    metrics_table.add_row("Accuracy", f"{accuracy:.1f}%")
    metrics_table.add_row("Precision", f"{precision:.1f}%")
    metrics_table.add_row("Recall", f"{recall:.1f}%")
    metrics_table.add_row("F1 Score", f"{f1:.1f}%")
    metrics_table.add_row("Best Val Acc", f"{best_val_acc:.1f}%")
    console.print(metrics_table)

    cm_table = Table(title="🔢 Confusion Matrix")
    cm_table.add_column("", style="bold")
    cm_table.add_column("Pred Benign", style="green")
    cm_table.add_column("Pred Malware", style="red")
    cm_table.add_row("Actual Benign", str(tn), str(fp))
    cm_table.add_row("Actual Malware", str(fn), str(tp))
    console.print(cm_table)

    # 8. Save model and scaler
    console.rule("[bold]Saving")
    WORKSPACE_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), WORKSPACE_MODEL_PATH)
    console.print(f"[bold green]✓ Model saved to {WORKSPACE_MODEL_PATH}[/]")

    np.savez(WORKSPACE_SCALER_PATH, mean=feat_mean, std=feat_std)
    console.print(f"[bold green]✓ Scaler saved to {WORKSPACE_SCALER_PATH}[/]")

    console.rule("[bold green]✓ Training complete!")


if __name__ == "__main__":
    main()
