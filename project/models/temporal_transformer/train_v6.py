#!/usr/bin/env python3
"""
Train the TemporalTransformer using sqrt-smoothed class weights AND 3x Web Attack oversampling.
Output: models/temporal_transformer/artifacts_v6/
"""

import os
import sys
import json
import shutil
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, accuracy_score
)
import joblib
import yaml
from datetime import datetime
from collections import Counter

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT_DIR)

from models.temporal_transformer.architecture import TemporalTransformer, FocalLoss


# ── Dataset ────────────────────────────────────────────────────────────────
class SequenceDataset(Dataset):
    def __init__(self, X, Y, label_map, horizon='now'):
        self.X = torch.FloatTensor(X)
        self.Y = Y
        self.label_map = label_map
        self.horizon = horizon

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        labels = {}
        for h in self.Y[idx]:
            raw = self.Y[idx][h]
            labels[h] = torch.tensor(self.label_map.get(raw, 0), dtype=torch.long)
        return self.X[idx], labels


# ── Main ───────────────────────────────────────────────────────────────────
def train():
    # Paths
    seq_dir = os.path.join(os.path.dirname(ROOT_DIR), "dataset_v2", "sequences")
    config_path = os.path.join(ROOT_DIR, "configs", "model.yaml")
    label_map_path = os.path.join(ROOT_DIR, "configs", "label_map.json")
    schema_path = os.path.join(ROOT_DIR, "configs", "feature_schema.json")
    output_dir = os.path.join(ROOT_DIR, "models", "temporal_transformer", "artifacts_v6")

    os.makedirs(output_dir, exist_ok=True)

    # Load config
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    with open(label_map_path, 'r') as f:
        label_map = json.load(f)
    with open(schema_path, 'r') as f:
        feature_schema = json.load(f)

    num_classes = len(label_map)
    inv_label_map = {v: k for k, v in label_map.items()}
    horizons = config.get('prediction_horizons', ['now'])

    print("Loading stratified splits...")
    X_train = np.load(os.path.join(seq_dir, "tensors", "train_split_X.npy"))
    X_val   = np.load(os.path.join(seq_dir, "tensors", "val_split_X.npy"))
    X_test  = np.load(os.path.join(seq_dir, "tensors", "test_split_X.npy"))
    
    with open(os.path.join(seq_dir, "labels", "train_split_Y.json"), "r") as f: Y_train = json.load(f)
    with open(os.path.join(seq_dir, "labels", "val_split_Y.json"), "r") as f: Y_val = json.load(f)
    with open(os.path.join(seq_dir, "labels", "test_split_Y.json"), "r") as f: Y_test = json.load(f)

    # ── Oversample Web Attack 3x in TRAIN ONLY ───────────────────────────
    wa_indices = [i for i, y in enumerate(Y_train) if y['now'] == 'Web Attack']
    if wa_indices:
        print(f"Oversampling {len(wa_indices)} Web Attack sequences by 3x (adding 2 copies)...")
        extra_X = X_train[wa_indices]
        extra_Y = [Y_train[i] for i in wa_indices]
        # Append 2 extra copies to achieve 3x total
        X_train = np.concatenate([X_train, extra_X, extra_X], axis=0)
        Y_train.extend(extra_Y)
        Y_train.extend(extra_Y)

    print(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
    print(f"Train labels: {Counter(y['now'] for y in Y_train)}")
    print(f"Val   labels: {Counter(y['now'] for y in Y_val)}")
    print(f"Test  labels: {Counter(y['now'] for y in Y_test)}")

    # ── Fit scaler on training data ONLY ──────────────────────────────────
    N, S, F = X_train.shape
    scaler = StandardScaler()
    X_train_flat = X_train.reshape(-1, F)
    scaler.fit(X_train_flat)

    X_train_scaled = scaler.transform(X_train_flat).reshape(N, S, F)
    X_val_scaled = scaler.transform(X_val.reshape(-1, F)).reshape(X_val.shape)
    X_test_scaled = scaler.transform(X_test.reshape(-1, F)).reshape(X_test.shape)

    # Clamp extremes
    X_train_scaled = np.clip(X_train_scaled, -10, 10)
    X_val_scaled = np.clip(X_val_scaled, -10, 10)
    X_test_scaled = np.clip(X_test_scaled, -10, 10)

    # Replace NaN/Inf
    X_train_scaled = np.nan_to_num(X_train_scaled, nan=0.0, posinf=0.0, neginf=0.0)
    X_val_scaled = np.nan_to_num(X_val_scaled, nan=0.0, posinf=0.0, neginf=0.0)
    X_test_scaled = np.nan_to_num(X_test_scaled, nan=0.0, posinf=0.0, neginf=0.0)

    # ── DataLoaders ───────────────────────────────────────────────────────
    batch_size = config['training']['batch_size']
    train_ds = SequenceDataset(X_train_scaled, Y_train, label_map)
    val_ds = SequenceDataset(X_val_scaled, Y_val, label_map)
    test_ds = SequenceDataset(X_test_scaled, Y_test, label_map)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size)
    test_loader = DataLoader(test_ds, batch_size=batch_size)

    # ── Model ─────────────────────────────────────────────────────────────
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    #device = torch.device("cuda")
    print(f"Device: {device}")
    
    model = TemporalTransformer(
        input_dim=F,
        num_classes=num_classes,
        embedding_dim=config['model']['embedding_dim'],
        num_layers=config['model']['transformer_layers'],
        num_heads=config['model']['attention_heads'],
        ff_dim=config['model']['feed_forward_dim'],
        dropout=config['model']['dropout'],
        seq_len=config['model']['sequence_length'],
        horizons=[h for h in horizons if h != 'now']
    ).to(device)

    # ── Sqrt-smoothed class weights (v5 experiment) ────────────────────────
    train_labels = [label_map.get(y['now'], 0) for y in Y_train]
    class_counts = Counter(train_labels)
    total = sum(class_counts.values())
    raw_weights = torch.zeros(num_classes)
    for cls_id, count in class_counts.items():
        raw_weights[cls_id] = total / (num_classes * count)
    print(f"Raw class weights: {raw_weights.tolist()}")
    # Apply sqrt smoothing
    weights = torch.sqrt(raw_weights)
    # Normalize so mean = 1.0
    weights = weights / weights.mean()
    print(f"Sqrt-smoothed weights (mean-normalized): {weights.tolist()}")

    criterion = FocalLoss(alpha=weights.to(device), gamma=2.0)
    optimizer = torch.optim.AdamW(model.parameters(), lr=config['training']['learning_rate'], weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=config['training']['epochs'])

    # ── Training loop ─────────────────────────────────────────────────────
    epochs = config['training']['epochs']
    patience = config['training']['early_stopping_patience']
    best_val_loss = float('inf')
    patience_counter = 0
    best_epoch = 0

    for epoch in range(1, epochs + 1):
        # Train
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0

        for x_batch, y_batch in train_loader:
            x_batch = x_batch.to(device)
            x_batch = torch.nan_to_num(x_batch, nan=0.0, posinf=0.0, neginf=0.0)
            x_batch = torch.clamp(x_batch, -10.0, 10.0)

            optimizer.zero_grad()
            preds, _ = model(x_batch)

            loss = criterion(preds['now'], y_batch['now'].to(device))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), config['training']['gradient_clip_val'])
            optimizer.step()

            train_loss += loss.item() * x_batch.size(0)
            _, predicted = torch.max(preds['now'].data, 1)
            train_total += y_batch['now'].size(0)
            train_correct += (predicted == y_batch['now'].to(device)).sum().item()

        scheduler.step()
        train_loss /= train_total
        train_acc = 100.0 * train_correct / train_total

        # Validate
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0

        with torch.no_grad():
            for x_batch, y_batch in val_loader:
                x_batch = x_batch.to(device)
                x_batch = torch.nan_to_num(x_batch, nan=0.0, posinf=0.0, neginf=0.0)
                x_batch = torch.clamp(x_batch, -10.0, 10.0)

                preds, _ = model(x_batch)
                loss = criterion(preds['now'], y_batch['now'].to(device))

                val_loss += loss.item() * x_batch.size(0)
                _, predicted = torch.max(preds['now'].data, 1)
                val_total += y_batch['now'].size(0)
                val_correct += (predicted == y_batch['now'].to(device)).sum().item()

        val_loss /= val_total
        val_acc = 100.0 * val_correct / val_total

        print(f"Epoch {epoch:3d}/{epochs} | "
              f"Train Loss: {train_loss:.4f} Acc: {train_acc:.2f}% | "
              f"Val Loss: {val_loss:.4f} Acc: {val_acc:.2f}% | "
              f"LR: {scheduler.get_last_lr()[0]:.6f}")

        # Early stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_epoch = epoch
            patience_counter = 0
            torch.save(model.state_dict(), os.path.join(output_dir, "model.pt"))
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"Early stopping at epoch {epoch}. Best epoch: {best_epoch}")
                break

    # ── Load best model and evaluate on test set ──────────────────────────
    print("\n=== Test Set Evaluation ===")
    model.load_state_dict(torch.load(os.path.join(output_dir, "model.pt"), map_location=device))
    model.eval()

    all_preds = []
    all_labels = []

    with torch.no_grad():
        for x_batch, y_batch in test_loader:
            x_batch = x_batch.to(device)
            x_batch = torch.nan_to_num(x_batch, nan=0.0, posinf=0.0, neginf=0.0)
            x_batch = torch.clamp(x_batch, -10.0, 10.0)

            preds, _ = model(x_batch)
            _, predicted = torch.max(preds['now'].data, 1)
            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(y_batch['now'].numpy())

    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)

    # Metrics
    acc = accuracy_score(all_labels, all_preds)
    prec = precision_score(all_labels, all_preds, average='weighted', zero_division=0)
    rec = recall_score(all_labels, all_preds, average='weighted', zero_division=0)
    f1 = f1_score(all_labels, all_preds, average='weighted', zero_division=0)

    # FPR (for binary: benign=0 vs attack=non-0)
    benign_mask = all_labels == 0
    if benign_mask.sum() > 0:
        fpr = (all_preds[benign_mask] != 0).sum() / benign_mask.sum()
    else:
        fpr = 0.0

    target_names = [inv_label_map.get(i, f"class_{i}") for i in range(num_classes)]
    report = classification_report(all_labels, all_preds, target_names=target_names, zero_division=0)
    cm = confusion_matrix(all_labels, all_preds)

    print(f"\nAccuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print(f"\nPer-class report:\n{report}")
    print(f"Confusion matrix:\n{cm}")

    # ── Save artifacts ────────────────────────────────────────────────────
    joblib.dump(scaler, os.path.join(output_dir, "scaler.pkl"))
    shutil.copy(schema_path, os.path.join(output_dir, "feature_schema.json"))
    shutil.copy(label_map_path, os.path.join(output_dir, "label_map.json"))

    metadata = {
        "model_version": "6.0",
        "input_features": F,
        "sequence_length": config['model']['sequence_length'],
        "state_interval_seconds": 1,
        "embedding_dim": config['model']['embedding_dim'],
        "transformer_layers": config['model']['transformer_layers'],
        "attention_heads": config['model']['attention_heads'],
        "dataset": "CIC-IDS2018 (stratified session-safe splits, sqrt weights, 3x Web Attack oversample)",
        "scaler": "StandardScaler (fit on train split only)",
        "loss": "FocalLoss(gamma=2)",
        "training_timestamp": datetime.now().isoformat(),
        "best_epoch": best_epoch,
        "epochs_trained": epoch,
        "num_classes": num_classes,
        "final_val_loss": best_val_loss,
        "test_accuracy": float(acc),
        "test_precision": float(prec),
        "test_recall": float(rec),
        "test_f1": float(f1),
        "test_fpr": float(fpr),
        "train_samples": len(X_train),
        "val_samples": len(X_val),
        "test_samples": len(X_test),
    }

    with open(os.path.join(output_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=4)

    print(f"\nAll artifacts saved to {output_dir}")


if __name__ == "__main__":
    train()
