import os
import sys
import subprocess
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from fileanalysis.loader import load_file
from fileanalysis.analyzers.hashing import HashAnalyzer
from fileanalysis.analyzers.entropy import EntropyAnalyzer
from fileanalysis.analyzers.strings import StringAnalyzer
from fileanalysis.analyzers.pe_analyzer import PEAnalyzer
from fileanalysis.analyzers.elf_analyzer import ELFAnalyzer
from fileanalysis.analyzers.macho_analyzer import MachOAnalyzer
from fileanalysis.analyzers.script_analyzer import ScriptAnalyzer
from fileanalysis.analyzers.document_analyzer import DocumentAnalyzer
from fileanalysis.intelligence.yara_scanner import YaraScanner
from fileanalysis.intelligence.capability_mapper import CapabilityMapper
from fileanalysis.scoring.features import FeatureExtractor
from fileanalysis.scoring.nn_model import ThreatNet
from rich.progress import Progress

# Config
REPO_URL = "https://github.com/iosifache/DikeDataset.git"
DATASET_DIR = Path("/app/dataset/DikeDataset")
MAX_FILES_PER_CLASS = 200  # Subset to keep training fast for testing
WORKSPACE_MODEL_PATH = Path("/workspace/fileanalysis/scoring/threat_model.pt")

def clone_dataset():
    if not DATASET_DIR.exists():
        print(f"Cloning {REPO_URL} into {DATASET_DIR}...")
        DATASET_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, str(DATASET_DIR)], check=True)
    else:
        print("Dataset already cloned.")

def extract_features(file_paths, label, progress, task):
    features_list = []
    labels_list = []
    
    extractor = FeatureExtractor()
    analyzers = [
        HashAnalyzer(), EntropyAnalyzer(), StringAnalyzer(),
        PEAnalyzer(), ELFAnalyzer(), MachOAnalyzer(),
        ScriptAnalyzer(), DocumentAnalyzer()
    ]
    yara_scanner = YaraScanner()
    capability_mapper = CapabilityMapper()

    for idx, fpath in enumerate(file_paths):
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
            features_list.append(feat_vec)
            labels_list.append([label])
        except Exception as e:
            # Skip files that can't be loaded or analyzed
            pass
        finally:
            progress.update(task, advance=1)
            
    return features_list, labels_list

def main():
    clone_dataset()
    
    benign_dir = DATASET_DIR / "files" / "benign"
    malware_dir = DATASET_DIR / "files" / "malware"
    
    # Grab files
    benign_files = list(benign_dir.glob("*"))[:MAX_FILES_PER_CLASS]
    malware_files = list(malware_dir.glob("*"))[:MAX_FILES_PER_CLASS]
    
    print(f"Found {len(benign_files)} benign and {len(malware_files)} malware files to process.")
    
    X = []
    y = []
    
    with Progress() as progress:
        task_b = progress.add_task("[green]Extracting Benign...", total=len(benign_files))
        f, l = extract_features(benign_files, 0.0, progress, task_b)
        X.extend(f)
        y.extend(l)
        
        task_m = progress.add_task("[red]Extracting Malware...", total=len(malware_files))
        f, l = extract_features(malware_files, 1.0, progress, task_m)
        X.extend(f)
        y.extend(l)
        
    if not X:
        print("No features extracted. Exiting.")
        sys.exit(1)
        
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.float32)
    
    print(f"Extracted {len(X)} feature vectors.")
    
    # Train
    model = ThreatNet()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.MSELoss()
    
    ds = TensorDataset(torch.tensor(X), torch.tensor(y))
    loader = DataLoader(ds, batch_size=32, shuffle=True)
    
    print("Training model...")
    epochs = 50
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        for batch_X, batch_y in loader:
            optimizer.zero_grad()
            out = model(batch_X)
            loss = criterion(out, batch_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            
        if (epoch + 1) % 10 == 0:
            print(f"Epoch {epoch+1}/{epochs} | Loss: {total_loss/len(loader):.4f}")
            
    print(f"Saving model to {WORKSPACE_MODEL_PATH}...")
    WORKSPACE_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), WORKSPACE_MODEL_PATH)
    print("Done!")

if __name__ == "__main__":
    main()
