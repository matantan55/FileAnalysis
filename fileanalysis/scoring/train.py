"""Training pipeline for ThreatNet — generates synthetic data and trains the model.

Usage:
    python -m fileanalysis.scoring.train [--epochs 200] [--samples 50000] [--output threat_model.pt]

The synthetic data generator mirrors the logic of the heuristic ThreatScorer,
producing realistic (feature_vector, threat_score) pairs. The trained model
learns to replicate and interpolate these scores, enabling smoother predictions
and better generalization to edge cases.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

from fileanalysis.scoring.features import NUM_FEATURES


def _generate_synthetic_dataset(n_samples: int, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic training data mimicking real analysis outputs.

    Each sample is a plausible 31-dimensional feature vector paired with
    a target score (0-1) computed via heuristic rules similar to ThreatScorer.

    Returns:
        (X, y) where X has shape (n_samples, 31) and y has shape (n_samples, 1).
    """
    rng = np.random.default_rng(seed)
    X = np.zeros((n_samples, NUM_FEATURES), dtype=np.float32)
    y = np.zeros((n_samples, 1), dtype=np.float32)

    for i in range(n_samples):
        # Decide sample archetype: ~40% benign, ~30% suspicious, ~30% malicious
        archetype = rng.choice(["benign", "suspicious", "malicious"], p=[0.4, 0.3, 0.3])

        if archetype == "benign":
            # Low-risk file: normal entropy, few strings, no capabilities
            file_size_log = rng.uniform(5.0, 15.0)          # [0]
            entropy = rng.uniform(2.0, 6.0)                  # [1]
            is_packed = 0.0                                  # [2]
            max_section_entropy = rng.uniform(0.0, 6.5)      # [3]
            suspicious_sections = 0.0                        # [4]
            section_count = rng.uniform(0, 10)               # [5]
            url_count = rng.choice([0, 0, 0, 1, 2])          # [6]
            ip_count = rng.choice([0, 0, 0, 0, 1])           # [7]
            crypto_count = 0.0                               # [8]
            shell_count = rng.choice([0, 0, 0, 1])           # [9]
            api_count = rng.uniform(0, 8)                    # [10]
            b64_count = rng.choice([0, 0, 1])                # [11]
            reg_count = rng.choice([0, 0, 1, 2])             # [12]
            email_count = rng.choice([0, 0, 1])              # [13]
            path_count = rng.uniform(0, 5)                   # [14]
            indicator_count = rng.choice([0, 0, 0, 1])       # [15]
            max_severity = rng.uniform(0, 0.3)               # [16]
            mean_severity = rng.uniform(0, 0.2)              # [17]
            cap_count = 0.0                                  # [18]
            max_cap_risk = 0.0                               # [19]
            sum_cap_risk = 0.0                               # [20]
            yara_count = 0.0                                 # [21]
            has_critical_yara = 0.0                          # [22]
            has_high_yara = 0.0                              # [23]
            yara_severity = 0.0                              # [24]
            vt_detected = 0.0                                # [25]

        elif archetype == "suspicious":
            file_size_log = rng.uniform(8.0, 16.0)
            entropy = rng.uniform(5.5, 7.2)
            is_packed = rng.choice([0.0, 0.0, 1.0])
            max_section_entropy = rng.uniform(5.0, 7.5)
            suspicious_sections = rng.choice([0, 0, 1, 2])
            section_count = rng.uniform(3, 15)
            url_count = rng.uniform(0, 5)
            ip_count = rng.uniform(0, 3)
            crypto_count = rng.choice([0, 0, 0, 1])
            shell_count = rng.uniform(0, 5)
            api_count = rng.uniform(3, 20)
            b64_count = rng.uniform(0, 5)
            reg_count = rng.uniform(0, 5)
            email_count = rng.choice([0, 0, 1, 2])
            path_count = rng.uniform(1, 10)
            indicator_count = rng.uniform(1, 6)
            max_severity = rng.uniform(0.3, 0.7)
            mean_severity = rng.uniform(0.2, 0.5)
            cap_count = rng.uniform(0, 3)
            max_cap_risk = rng.uniform(0.2, 0.6)
            sum_cap_risk = rng.uniform(0.2, 1.5)
            yara_count = rng.choice([0, 0, 1, 2])
            has_critical_yara = 0.0
            has_high_yara = rng.choice([0.0, 0.0, 1.0])
            yara_severity = rng.uniform(0, 6)
            vt_detected = 0.0

        else:  # malicious
            file_size_log = rng.uniform(8.0, 18.0)
            entropy = rng.uniform(6.5, 7.99)
            is_packed = rng.choice([0.0, 1.0, 1.0])
            max_section_entropy = rng.uniform(6.5, 7.99)
            suspicious_sections = rng.uniform(1, 5)
            section_count = rng.uniform(4, 20)
            url_count = rng.uniform(2, 15)
            ip_count = rng.uniform(1, 10)
            crypto_count = rng.uniform(0, 5)
            shell_count = rng.uniform(3, 20)
            api_count = rng.uniform(10, 50)
            b64_count = rng.uniform(1, 10)
            reg_count = rng.uniform(2, 15)
            email_count = rng.uniform(0, 3)
            path_count = rng.uniform(5, 25)
            indicator_count = rng.uniform(4, 15)
            max_severity = rng.uniform(0.6, 1.0)
            mean_severity = rng.uniform(0.4, 0.8)
            cap_count = rng.uniform(2, 7)
            max_cap_risk = rng.uniform(0.5, 1.0)
            sum_cap_risk = rng.uniform(1.0, 5.0)
            yara_count = rng.uniform(1, 8)
            has_critical_yara = rng.choice([0.0, 0.0, 1.0, 1.0])
            has_high_yara = rng.choice([0.0, 1.0, 1.0])
            yara_severity = rng.uniform(3, 20)
            vt_detected = rng.choice([0.0, 0.0, 1.0, 1.0])

        # File type one-hot (random)
        ft_idx = rng.choice(5)
        ft_onehot = [0.0] * 5
        ft_onehot[ft_idx] = 1.0

        # Assemble feature vector
        vec = [
            file_size_log, entropy, is_packed, max_section_entropy,
            suspicious_sections, section_count,
            url_count, ip_count, crypto_count, shell_count,
            api_count, b64_count, reg_count, email_count, path_count,
            indicator_count, max_severity, mean_severity,
            cap_count, max_cap_risk, sum_cap_risk,
            yara_count, has_critical_yara, has_high_yara, yara_severity,
            vt_detected,
            *ft_onehot,
        ]
        X[i] = vec

        # Compute heuristic-like target score (mimics ThreatScorer logic)
        score = 0.0

        # Entropy component (max 15)
        if is_packed > 0.5:
            score += 15.0
        elif entropy > 6.5:
            score += 10.0

        # String component (max 20)
        str_pts = 0.0
        if url_count > 0:
            str_pts += 5.0
        if ip_count > 0:
            str_pts += 7.0
        if crypto_count > 0:
            str_pts += 15.0
        str_pts += min(shell_count * 3, 10.0)
        score += min(str_pts, 20.0)

        # Capabilities (max 35)
        cap_pts = sum_cap_risk * 15
        score += min(cap_pts, 35.0)

        # YARA (max 30)
        yara_pts = 0.0
        if has_critical_yara > 0.5:
            yara_pts += 30.0
        elif has_high_yara > 0.5:
            yara_pts += 20.0
        else:
            yara_pts += yara_severity * 2
        score += min(yara_pts, 30.0)

        # VirusTotal boost
        if vt_detected > 0.5:
            score = max(score, 75.0)
            score += 10.0

        # Add some noise for generalization
        noise = rng.normal(0, 2.0)
        score = np.clip(score + noise, 0.0, 100.0)

        y[i] = score / 100.0  # Normalize to [0, 1]

    return X, y


def train(
    n_samples: int = 50_000,
    epochs: int = 200,
    batch_size: int = 256,
    lr: float = 1e-3,
    output_path: str | Path | None = None,
    seed: int = 42,
) -> Path:
    """Train ThreatNet on synthetic data and save weights.

    Args:
        n_samples: Number of synthetic training samples to generate.
        epochs: Number of training epochs.
        batch_size: Mini-batch size.
        lr: Learning rate for Adam optimizer.
        output_path: Where to save the trained model. Defaults to threat_model.pt.
        seed: Random seed for reproducibility.

    Returns:
        Path to the saved model weights.
    """
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError:
        print("ERROR: PyTorch is required for training. Install with: pip install torch>=2.0")
        sys.exit(1)

    from fileanalysis.scoring.nn_model import _build_model

    torch.manual_seed(seed)
    save_path = Path(output_path) if output_path else Path(__file__).parent / "threat_model.pt"

    print(f"🧠 ThreatNet Training Pipeline")
    print(f"   Samples: {n_samples:,}")
    print(f"   Epochs:  {epochs}")
    print(f"   Batch:   {batch_size}")
    print(f"   LR:      {lr}")
    print()

    # Generate data
    print("📊 Generating synthetic training data...")
    X, y = _generate_synthetic_dataset(n_samples, seed=seed)

    # Train/validation split (80/20)
    split_idx = int(0.8 * n_samples)
    X_train, X_val = X[:split_idx], X[split_idx:]
    y_train, y_val = y[:split_idx], y[split_idx:]

    train_ds = TensorDataset(
        torch.tensor(X_train, dtype=torch.float32),
        torch.tensor(y_train, dtype=torch.float32),
    )
    val_ds = TensorDataset(
        torch.tensor(X_val, dtype=torch.float32),
        torch.tensor(y_val, dtype=torch.float32),
    )
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size)

    # Build model
    ThreatNet = _build_model(torch)
    model = ThreatNet()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    # Training loop with early stopping
    best_val_loss = float("inf")
    patience = 15
    patience_counter = 0
    best_state = None

    print("🏋️ Training...")
    for epoch in range(1, epochs + 1):
        # Train
        model.train()
        train_loss = 0.0
        for batch_X, batch_y in train_loader:
            optimizer.zero_grad()
            preds = model(batch_X)
            loss = criterion(preds, batch_y)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * batch_X.size(0)
        train_loss /= len(train_ds)

        # Validate
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for batch_X, batch_y in val_loader:
                preds = model(batch_X)
                loss = criterion(preds, batch_y)
                val_loss += loss.item() * batch_X.size(0)
        val_loss /= len(val_ds)

        if epoch % 20 == 0 or epoch == 1:
            print(f"   Epoch {epoch:>4d}/{epochs}  |  Train Loss: {train_loss:.6f}  |  Val Loss: {val_loss:.6f}")

        # Early stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"\n   ⏹️  Early stopping at epoch {epoch} (patience={patience})")
                break

    # Restore best model
    if best_state is not None:
        model.load_state_dict(best_state)

    # Save
    torch.save(model.state_dict(), save_path)
    print(f"\n✅ Model saved to {save_path}")
    print(f"   Best validation loss: {best_val_loss:.6f}")

    # Quick sanity check
    model.eval()
    with torch.no_grad():
        # Test on a zero vector (should predict low score)
        zero_input = torch.zeros(1, NUM_FEATURES)
        zero_score = model(zero_input).item() * 100
        # Test on a high-threat vector
        high_input = torch.tensor([[
            15.0, 7.8, 1.0, 7.5, 3.0, 10.0,        # file/entropy/sections
            10.0, 5.0, 3.0, 15.0, 30.0, 5.0, 8.0, 1.0, 15.0,  # strings
            10.0, 0.9, 0.7,                           # indicators
            5.0, 0.9, 4.0,                            # capabilities
            5.0, 1.0, 1.0, 15.0,                      # YARA
            1.0,                                       # VT
            1.0, 0.0, 0.0, 0.0, 0.0,                  # file type
        ]], dtype=torch.float32)
        high_score = model(high_input).item() * 100
        print(f"\n🧪 Sanity check:")
        print(f"   Empty file features → Score: {zero_score:.1f}/100")
        print(f"   High-threat features → Score: {high_score:.1f}/100")

    return save_path


def main():
    parser = argparse.ArgumentParser(description="Train ThreatNet malware scoring model")
    parser.add_argument("--epochs", type=int, default=200, help="Training epochs (default: 200)")
    parser.add_argument("--samples", type=int, default=50_000, help="Synthetic samples (default: 50000)")
    parser.add_argument("--batch-size", type=int, default=256, help="Batch size (default: 256)")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate (default: 0.001)")
    parser.add_argument("--output", type=str, default=None, help="Output model path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    args = parser.parse_args()

    train(
        n_samples=args.samples,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        output_path=args.output,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
