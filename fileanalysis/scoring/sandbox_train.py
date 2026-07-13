"""Sandboxed training script — runs inside Docker container.

Fetches malware and benign files from many sources:
  Malware:
    1. DikeDataset (GitHub) — labeled malware PE files
    2. theZoo (GitHub) — curated malware in password-protected zips
    3. InQuest / fabrimagic72 / jstrosch / Ultimate-RAT (GitHub)
    4. URLhaus (abuse.ch) — live malware URLs
    5. MalwareBazaar (abuse.ch) — bulk recent PE/ELF/doc malware
    6. vx-underground (GitHub) — malware source code & samples
    7. Das Malwerk (GitHub) — curated malware samples
  Benign:
    1. DikeDataset (GitHub) — labeled benign PE files
    2. System binaries (/usr/bin, /usr/lib, etc.) from Docker container

All malware lives ONLY inside the container at /app/dataset.
Only the trained model weights are saved to the host via /workspace mount.
"""

import os
import subprocess
import sys
import concurrent.futures
import hashlib
import json
import multiprocessing
from pathlib import Path

import csv
import urllib.request
import urllib.error
import urllib.parse

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
from fileanalysis.scoring.nn_model import MalConv, MAX_LEN
from torch.utils.data import Dataset
import lightgbm as lgb

# ──────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────
DIKE_REPO = "https://github.com/iosifache/DikeDataset.git"
ZOO_REPO = "https://github.com/ytisf/theZoo.git"
INQUEST_REPO = "https://github.com/InQuest/malware-samples.git"
FABRI_REPO = "https://github.com/fabrimagic72/malware-samples.git"
JSTROSCH_REPO = "https://github.com/jstrosch/malware-samples.git"
VXUG_REPO = "https://github.com/vxunderground/MalwareSourceCode.git"
DAS_MALWERK_REPO = "https://github.com/dasmalwerk/malware-samples.git"

DATASET_ROOT = Path("/app/dataset")
DIKE_DIR = DATASET_ROOT / "DikeDataset"
ZOO_DIR = DATASET_ROOT / "theZoo"
INQUEST_DIR = DATASET_ROOT / "inquest"
FABRI_DIR = DATASET_ROOT / "fabri"
JSTROSCH_DIR = DATASET_ROOT / "jstrosch"
ULTIMATE_RAT_DIR = DATASET_ROOT / "ultimate_rat"
VXUG_DIR = DATASET_ROOT / "vxunderground"
DAS_MALWERK_DIR = DATASET_ROOT / "das_malwerk"
URLHAUS_DIR = DATASET_ROOT / "urlhaus"
BAZAAR_DIR = DATASET_ROOT / "bazaar"
SYSTEM_BENIGN_DIR = DATASET_ROOT / "system_benign"

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
MAX_URLHAUS_DOWNLOADS = 5000
MAX_BAZAAR_DOWNLOADS = 2000
TIMEOUT_SEC = 15

MAX_DIKE_PER_CLASS = 10000
MAX_ZOO_FILES = 10000
MAX_GITHUB_FILES = 10000

# Workarounds for sandbox paths
WORKSPACE_DIR = Path("/workspace")
WORKSPACE_MODEL_PATH = WORKSPACE_DIR / "threat_model_malconv.pt"
WORKSPACE_LGB_MODEL_PATH = WORKSPACE_DIR / "threat_model_lgb.txt"
WORKSPACE_SCALER_PATH = WORKSPACE_DIR / "feature_scaler.npz"

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
    """Clone GitHub malware datasets."""
    datasets = [
        ("InQuest", INQUEST_REPO, INQUEST_DIR),
        ("fabrimagic72", FABRI_REPO, FABRI_DIR),
        ("jstrosch (PMAT)", JSTROSCH_REPO, JSTROSCH_DIR),
        ("Ultimate-RAT-Collection", "https://github.com/Cryakl/Ultimate-RAT-Collection.git", ULTIMATE_RAT_DIR),
        ("vx-underground", VXUG_REPO, VXUG_DIR),
        ("Das Malwerk", DAS_MALWERK_REPO, DAS_MALWERK_DIR),
    ]

    for name, repo_url, target_dir in datasets:
        if not target_dir.exists():
            console.print(f"[bold cyan]📦 Cloning {name}…[/]")
            target_dir.parent.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
                    check=True,
                    timeout=300,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                console.print(f"[yellow]⚠ Failed to clone {name}: {e}[/]")
        else:
            console.print(f"[green]✓ {name} already present.[/]")

    # Extract password-protected zips (password = "infected") if any exist
    extract_dir = DATASET_ROOT / "github_extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    
    zips = []
    for d in [INQUEST_DIR, FABRI_DIR, JSTROSCH_DIR, ULTIMATE_RAT_DIR, VXUG_DIR, DAS_MALWERK_DIR]:
        if d.exists():
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
                        timeout=30,
                    )
                    extracted += 1
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass
                finally:
                    progress.update(task_gh, advance=1)
        if extracted > 0:
            console.print(f"[green]✓ Extracted {extracted} GitHub archives.[/]")


def fetch_bazaar_samples():
    """Fetch recent malware samples from MalwareBazaar bulk API."""
    console.print("[bold cyan]📦 Fetching recent malware from MalwareBazaar…[/]")
    BAZAAR_DIR.mkdir(parents=True, exist_ok=True)

    # Query recent samples by file type
    tags_to_query = ["exe", "dll", "elf", "doc", "docx", "xls", "pdf", "js", "vbs", "ps1", "msi", "apk"]
    success_count = 0

    for tag in tags_to_query:
        if success_count >= MAX_BAZAAR_DOWNLOADS:
            break
        try:
            data = urllib.parse.urlencode({"query": "get_taginfo", "tag": tag, "limit": 200}).encode()
            req = urllib.request.Request(BAZAAR_API, data=data, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as response:
                result = json.loads(response.read().decode('utf-8'))

            if result.get("query_status") != "ok":
                continue

            for entry in result.get("data", []):
                if success_count >= MAX_BAZAAR_DOWNLOADS:
                    break
                sha256 = entry.get("sha256_hash", "")
                if not sha256:
                    continue

                local_path = BAZAAR_DIR / sha256
                if local_path.exists():
                    success_count += 1
                    continue

                # Download the sample via the download endpoint
                try:
                    dl_data = urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha256}).encode()
                    dl_req = urllib.request.Request(BAZAAR_API, data=dl_data, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(dl_req, timeout=TIMEOUT_SEC) as dl_resp:
                        payload = dl_resp.read()
                    if payload and len(payload) > 100:
                        with open(local_path, "wb") as f:
                            f.write(payload)
                        success_count += 1
                except Exception:
                    pass

        except Exception as e:
            console.print(f"[yellow]⚠ MalwareBazaar tag '{tag}': {e}[/]")

    console.print(f"[green]✓ Fetched {success_count} samples from MalwareBazaar.[/]")


def collect_system_benign():
    """Collect real benign files from the Docker container's OS.
    
    These are known-clean system binaries, libraries, scripts, and docs
    that give the model a realistic sense of what benign files look like.
    """
    console.print("[bold cyan]📦 Collecting system binaries as benign samples…[/]")
    SYSTEM_BENIGN_DIR.mkdir(parents=True, exist_ok=True)

    # Directories containing known-good files inside a typical Ubuntu Docker image
    system_dirs = [
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/usr/lib"),
        Path("/usr/lib64"),
        Path("/usr/share/doc"),
        Path("/usr/share/man"),
        Path("/bin"),
        Path("/sbin"),
        Path("/lib"),
        Path("/lib64"),
        Path("/etc"),
    ]

    collected = 0
    seen_hashes = set()
    for sdir in system_dirs:
        if not sdir.exists():
            continue
        for f in sdir.rglob("*"):
            if not f.is_file():
                continue
            try:
                size = f.stat().st_size
                if size < 100 or size > 100_000_000:  # skip trivially small or huge files
                    continue
                # Deduplicate by content hash
                file_hash = hashlib.md5(f.read_bytes()).hexdigest()
                if file_hash in seen_hashes:
                    continue
                seen_hashes.add(file_hash)

                dest = SYSTEM_BENIGN_DIR / f"{file_hash}_{f.name}"
                if not dest.exists():
                    dest.symlink_to(f)  # symlink to avoid copying gigabytes
                collected += 1
            except Exception:
                pass
            if collected >= 5000:
                break
        if collected >= 5000:
            break

    console.print(f"[green]✓ Collected {collected} system benign files.[/]")

def fetch_urlhaus_samples():
    """Fetch raw malware samples directly from URLhaus instead of AWS."""
    console.print("[bold cyan]📦 Fetching recent malware samples from URLhaus…[/]")
    URLHAUS_DIR.mkdir(parents=True, exist_ok=True)
    
    urls = []
    try:
        req = urllib.request.Request(URLHAUS_CSV, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as response:
            text = response.read().decode('utf-8')
            
        lines = text.splitlines()
        reader = csv.reader(lines)
        for row in reader:
            if not row or row[0].startswith('#'):
                continue
            if len(row) > 3 and row[3] == "online":
                urls.append(row[2])
                
    except Exception as e:
        console.print(f"[bold red]Failed to fetch URLhaus feed: {e}[/]")
        return
        
    success_count = 0
    for url in urls:
        if success_count >= MAX_URLHAUS_DOWNLOADS:
            break
            
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as response:
                payload = response.read()
                
            if not payload:
                continue
                
            filename = url.split('/')[-1]
            if not filename or '?' in filename:
                filename = f"payload_{success_count}.bin"
                
            local_path = URLHAUS_DIR / filename
            if not local_path.exists():
                with open(local_path, "wb") as f:
                    f.write(payload)
                
            success_count += 1
            
        except Exception:
            pass
            
    console.print(f"[green]✓ Downloaded {success_count} recent samples from URLhaus.[/]")

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
        q.put((feat_vec, label, str(fpath)))
    except Exception:
        pass


def _process_file(fpath, label, progress, task):
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_process_worker, args=(fpath, label, q))
    p.start()
    p.join(5.0)

    feat, lbl, fp_str = None, None, None
    if p.is_alive():
        p.terminate()
        p.join()
    else:
        if not q.empty():
            try:
                feat, lbl, fp_str = q.get_nowait()
            except Exception:
                pass

    progress.update(task, advance=1)
    return feat, lbl, fp_str


def extract_features(file_paths, label, progress, task):
    """Run full analysis pipeline on each file and extract feature vectors in parallel."""
    features_list = []
    labels_list = []
    paths_list = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        futures = [
            executor.submit(_process_file, fpath, label, progress, task)
            for fpath in file_paths
        ]
        for future in concurrent.futures.as_completed(futures):
            feat, lbl, fp_str = future.result()
            if feat is not None:
                features_list.append(feat)
                labels_list.append(lbl)
                paths_list.append(fp_str)

    return features_list, labels_list, paths_list


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

    cache_file = "dataset_cache.npz"
    local_cache_path = DATASET_ROOT / cache_file

    X, y, paths = [], [], []
    used_cache = False

    if local_cache_path.exists():
        console.print(f"[bold cyan]📦 Checking local disk for cached dataset…[/]")
        try:
            data = np.load(local_cache_path, allow_pickle=True)
            X = data['X']
            y = data['y']
            paths = data['paths'] if 'paths' in data else np.array(["unknown"] * len(X))
            used_cache = True
            console.print(f"[bold green]✓ Loaded {len(X)} feature vectors from cache. Skipping extraction![/]")
        except Exception as e:
            console.print(f"[yellow]⚠ Failed to load cache: {e}. Will extract from scratch.[/]")

    if not used_cache:
        # 1. Fetch all datasets
        clone_dike()
        clone_zoo()
        fetch_github_datasets()
        fetch_urlhaus_samples()
        fetch_bazaar_samples()
        collect_system_benign()

        # 2. Collect file paths
        console.rule("[bold]Collecting files")

        # Benign files from multiple sources
        dike_benign = list((DIKE_DIR / "files" / "benign").glob("*"))[:MAX_DIKE_PER_CLASS]
        system_benign = collect_files(SYSTEM_BENIGN_DIR, 5000)
        all_benign = dike_benign + system_benign

        # Malware files from all sources
        dike_malware = list((DIKE_DIR / "files" / "malware").glob("*"))[:MAX_DIKE_PER_CLASS]
        zoo_malware = collect_files(DATASET_ROOT / "zoo_extracted", MAX_ZOO_FILES)
        github_malware = collect_files(DATASET_ROOT / "github_extracted", MAX_GITHUB_FILES)
        github_malware += collect_files(INQUEST_DIR, MAX_GITHUB_FILES)
        github_malware += collect_files(FABRI_DIR, MAX_GITHUB_FILES)
        github_malware += collect_files(JSTROSCH_DIR, MAX_GITHUB_FILES)
        github_malware += collect_files(ULTIMATE_RAT_DIR, MAX_GITHUB_FILES)
        github_malware += collect_files(VXUG_DIR, MAX_GITHUB_FILES)
        github_malware += collect_files(DAS_MALWERK_DIR, MAX_GITHUB_FILES)
        
        urlhaus_malware = collect_files(URLHAUS_DIR, MAX_GITHUB_FILES)
        bazaar_malware = collect_files(BAZAAR_DIR, MAX_BAZAAR_DOWNLOADS)
        
        # Dedup
        github_malware = list(set(github_malware))

        all_malware = dike_malware + zoo_malware + github_malware + urlhaus_malware + bazaar_malware

        console.print(f"  Benign:  [green]{len(dike_benign)}[/] (DikeDataset) + "
                      f"[green]{len(system_benign)}[/] (System) = "
                      f"[bold green]{len(all_benign)}[/] total")
        console.print(f"  Malware: [red]{len(dike_malware)}[/] (DikeDataset) + "
                      f"[red]{len(zoo_malware)}[/] (theZoo) + "
                      f"[red]{len(github_malware)}[/] (GitHub+vxug+DasMalwerk) + "
                      f"[red]{len(urlhaus_malware)}[/] (URLhaus) + "
                      f"[red]{len(bazaar_malware)}[/] (MalwareBazaar) = "
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
            task_b = progress.add_task("[green]Benign files…", total=len(all_benign))
            f, lbls, pths = extract_features(all_benign, 0.0, progress, task_b)
            X.extend(f)
            y.extend(lbls)
            paths.extend(pths)

            task_m = progress.add_task("[red]Malware files…", total=len(all_malware))
            f, lbls, pths = extract_features(all_malware, 1.0, progress, task_m)
            X.extend(f)
            y.extend(lbls)
            paths.extend(pths)

        if len(X) < 10:
            console.print("[bold red]Too few feature vectors extracted. Exiting.[/]")
            sys.exit(1)

        X = np.array(X, dtype=np.float32)
        y = np.array(y, dtype=np.float32)
        paths = np.array(paths, dtype=str)

        console.print(f"[bold green]✓ Extracted {len(X)} feature vectors "
                      f"({int(np.sum(y == 0))} benign, {int(np.sum(y == 1))} malware)[/]")

        # Save cache locally
        console.print(f"[bold cyan]📦 Saving extracted dataset locally…[/]")
        try:
            local_cache_path.parent.mkdir(parents=True, exist_ok=True)
            np.savez(local_cache_path, X=X, y=y, paths=paths)
            console.print("[bold green]✓ Saved dataset cache locally![/]")
        except Exception as e:
            console.print(f"[bold red]Failed to save cache locally: {e}[/]")

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

    X_train, y_train, paths_train = X_norm[train_idx], y[train_idx], paths[train_idx]
    X_val, y_val, paths_val = X_norm[val_idx], y[val_idx], paths[val_idx]

    console.print(f"  Train: {len(X_train)} | Val: {len(X_val)}")

    class RawByteDataset(Dataset):
        def __init__(self, file_paths, labels, max_len=MAX_LEN):
            self.file_paths = file_paths
            self.labels = labels
            self.max_len = max_len
            
        def __len__(self):
            return len(self.file_paths)
            
        def __getitem__(self, idx):
            path = self.file_paths[idx]
            tensor = np.full((self.max_len,), 256, dtype=np.int16)
            try:
                with open(path, "rb") as f:
                    b = f.read(self.max_len)
                    length = len(b)
                    if length > 0:
                        tensor[:length] = np.frombuffer(b, dtype=np.uint8)
            except Exception:
                pass
            lbl = self.labels[idx]
            if isinstance(lbl, np.ndarray) and lbl.ndim > 0:
                lbl = lbl.item()
            return torch.tensor(tensor, dtype=torch.long), torch.tensor(lbl, dtype=torch.float32).view(-1)

    # 6. Train MalConv (PyTorch)
    console.print("[bold cyan]🔥 Training MalConv (Deep Learning) on raw bytes…[/]")
    import torch
    torch.set_num_threads(2) # Prevent CPU thread explosion segfault in Docker
    model = MalConv()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)
    criterion = nn.BCELoss()
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=20) # shorter epochs

    train_ds = RawByteDataset(paths_train, y_train)
    val_ds = RawByteDataset(paths_val, y_val)
    train_loader = DataLoader(train_ds, batch_size=16, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=16, shuffle=False)

    epochs = 10 # MalConv takes longer, fewer epochs
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
            val_correct = 0
            val_total = 0
            with torch.no_grad():
                for v_batch_X, v_batch_y in val_loader:
                    v_out = model(v_batch_X)
                    v_preds = (v_out >= 0.5).float()
                    val_correct += (v_preds == v_batch_y).float().sum().item()
                    val_total += len(v_batch_y)
                    
            val_acc = (val_correct / max(val_total, 1)) * 100

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
    val_preds_list = []
    val_true_list = []
    with torch.no_grad():
        for v_batch_X, v_batch_y in val_loader:
            v_out = model(v_batch_X)
            v_preds = (v_out >= 0.5).float()
            val_preds_list.append(v_preds)
            val_true_list.append(v_batch_y)

    val_preds_np = torch.cat(val_preds_list).view(-1).numpy()
    val_true_np = torch.cat(val_true_list).view(-1).numpy()

    tp = ((val_preds_np == 1) & (val_true_np == 1)).sum().item()
    tn = ((val_preds_np == 0) & (val_true_np == 0)).sum().item()
    fp = ((val_preds_np == 1) & (val_true_np == 0)).sum().item()
    fn = ((val_preds_np == 0) & (val_true_np == 1)).sum().item()

    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1) * 100
    precision = tp / max(tp + fp, 1) * 100
    recall = tp / max(tp + fn, 1) * 100
    f1 = 2 * precision * recall / max(precision + recall, 1)
    fpr = fp / max(fp + tn, 1) * 100
    fnr = fn / max(fn + tp, 1) * 100
    specificity = tn / max(tn + fp, 1) * 100

    metrics_table = Table(title="📊 Validation Metrics")
    metrics_table.add_column("Metric", style="bold")
    metrics_table.add_column("Value", style="cyan")
    metrics_table.add_row("Accuracy", f"{accuracy:.1f}%")
    metrics_table.add_row("Precision", f"{precision:.1f}%")
    metrics_table.add_row("Recall", f"{recall:.1f}%")
    metrics_table.add_row("F1 Score", f"{f1:.1f}%")
    metrics_table.add_row("False Positive Rate (FPR)", f"{fpr:.1f}%")
    metrics_table.add_row("False Negative Rate (FNR)", f"{fnr:.1f}%")
    metrics_table.add_row("Specificity (TNR)", f"{specificity:.1f}%")
    metrics_table.add_row("Best Val Acc", f"{best_val_acc:.1f}%")
    console.print(metrics_table)

    cm_table = Table(title="🔢 Confusion Matrix")
    cm_table.add_column("", style="bold")
    cm_table.add_column("Pred Benign", style="green")
    cm_table.add_column("Pred Malware", style="red")
    cm_table.add_row("Actual Benign", str(tn), str(fp))
    cm_table.add_row("Actual Malware", str(fn), str(tp))
    console.print(cm_table)

    fp_mask = (val_preds_np == 1) & (val_true_np == 0)
    fn_mask = (val_preds_np == 0) & (val_true_np == 1)
    
    fp_paths = paths_val[fp_mask]
    fn_paths = paths_val[fn_mask]
    
    fp_file = DATASET_ROOT / "false_positives.txt"
    fn_file = DATASET_ROOT / "false_negatives.txt"
    
    with open(fp_file, "w") as f:
        f.write("\n".join(fp_paths))
    with open(fn_file, "w") as f:
        f.write("\n".join(fn_paths))
        
    console.print(f"[bold yellow]⚠ Exported {len(fp_paths)} false positives to {fp_file}[/]")
    console.print(f"[bold yellow]⚠ Exported {len(fn_paths)} false negatives to {fn_file}[/]")

    # 8. Train LightGBM model
    console.rule("[bold]Training LightGBM Baseline")
    lgb_train = lgb.Dataset(X_train, y_train)
    lgb_val = lgb.Dataset(X_val, y_val, reference=lgb_train)

    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'learning_rate': 0.05,
        'num_leaves': 31,
        'verbose': -1
    }

    # Train LightGBM with early stopping
    evals_result = {}
    lgb_model = lgb.train(
        params,
        lgb_train,
        num_boost_round=1000,
        valid_sets=[lgb_train, lgb_val],
        callbacks=[
            lgb.early_stopping(stopping_rounds=50),
            lgb.record_evaluation(evals_result)
        ]
    )

    # 9. Evaluate LightGBM
    console.rule("[bold]LightGBM Final Evaluation")
    val_preds_lgb_prob = lgb_model.predict(X_val)
    val_preds_lgb = (val_preds_lgb_prob >= 0.5).astype(int)

    tp_lgb = ((val_preds_lgb == 1) & (val_true_np == 1)).sum().item()
    tn_lgb = ((val_preds_lgb == 0) & (val_true_np == 0)).sum().item()
    fp_lgb = ((val_preds_lgb == 1) & (val_true_np == 0)).sum().item()
    fn_lgb = ((val_preds_lgb == 0) & (val_true_np == 1)).sum().item()

    acc_lgb = (tp_lgb + tn_lgb) / max(tp_lgb + tn_lgb + fp_lgb + fn_lgb, 1) * 100
    prec_lgb = tp_lgb / max(tp_lgb + fp_lgb, 1) * 100
    rec_lgb = tp_lgb / max(tp_lgb + fn_lgb, 1) * 100
    f1_lgb = 2 * prec_lgb * rec_lgb / max(prec_lgb + rec_lgb, 1)
    fpr_lgb = fp_lgb / max(fp_lgb + tn_lgb, 1) * 100
    fnr_lgb = fn_lgb / max(fn_lgb + tp_lgb, 1) * 100
    spec_lgb = tn_lgb / max(tn_lgb + fp_lgb, 1) * 100

    metrics_table_lgb = Table(title="🌲 LightGBM Validation Metrics")
    metrics_table_lgb.add_column("Metric", style="bold")
    metrics_table_lgb.add_column("Value", style="cyan")
    metrics_table_lgb.add_row("Accuracy", f"{acc_lgb:.1f}%")
    metrics_table_lgb.add_row("Precision", f"{prec_lgb:.1f}%")
    metrics_table_lgb.add_row("Recall", f"{rec_lgb:.1f}%")
    metrics_table_lgb.add_row("F1 Score", f"{f1_lgb:.1f}%")
    metrics_table_lgb.add_row("False Positive Rate (FPR)", f"{fpr_lgb:.1f}%")
    metrics_table_lgb.add_row("False Negative Rate (FNR)", f"{fnr_lgb:.1f}%")
    metrics_table_lgb.add_row("Specificity (TNR)", f"{spec_lgb:.1f}%")
    console.print(metrics_table_lgb)

    # 10. Save models and scaler
    console.rule("[bold]Saving")
    WORKSPACE_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), WORKSPACE_MODEL_PATH)
    console.print(f"[bold green]✓ PyTorch Model saved to {WORKSPACE_MODEL_PATH}[/]")

    lgb_model.save_model(str(WORKSPACE_LGB_MODEL_PATH))
    console.print(f"[bold green]✓ LightGBM Model saved to {WORKSPACE_LGB_MODEL_PATH}[/]")

    np.savez(WORKSPACE_SCALER_PATH, mean=feat_mean, std=feat_std)
    console.print(f"[bold green]✓ Scaler saved to {WORKSPACE_SCALER_PATH}[/]")

    console.rule("[bold green]✓ Training complete!")


if __name__ == "__main__":
    main()
