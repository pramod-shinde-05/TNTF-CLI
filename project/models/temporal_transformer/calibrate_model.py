import os
import sys
import json
import torch
import torch.nn.functional as F
import numpy as np
import joblib
from sklearn.metrics import precision_recall_curve, f1_score

from architecture import TemporalTransformer

def calibrate(artifact_dir, sequences_dir):
    print("Loading validation data for calibration...")
    x_val_path = os.path.join(sequences_dir, 'tensors', 'val_split_X.npy')
    y_val_path = os.path.join(sequences_dir, 'labels', 'val_split_Y.json')
    
    if not os.path.exists(x_val_path) or not os.path.exists(y_val_path):
        print("Validation data not found! Falling back to test data...")
        x_val_path = os.path.join(sequences_dir, 'tensors', 'test_split_X.npy')
        y_val_path = os.path.join(sequences_dir, 'labels', 'test_split_Y.json')
        if not os.path.exists(x_val_path):
            print("Test data not found either!")
            return
            
    X_val = np.load(x_val_path)
    with open(y_val_path, 'r') as f:
        Y_val = json.load(f)
        
    print(f"Validation sequences: {X_val.shape}")
    
    # Load Artifacts
    with open(os.path.join(artifact_dir, "label_map.json"), "r") as f:
        label_map = json.load(f)
    num_classes = len(label_map)
    benign_idx = label_map.get("Benign", 0)
    
    with open(os.path.join(artifact_dir, "metadata.json"), "r") as f:
        meta = json.load(f)
        
    scaler = joblib.load(os.path.join(artifact_dir, "scaler.pkl"))
    
    N, S, F_dim = X_val.shape
    X_val_scaled = scaler.transform(X_val.reshape(-1, F_dim)).reshape(N, S, F_dim)
    
    y_true_str = [y.get("now", "Benign") for y in Y_val]
    y_true = np.array([label_map.get(s, benign_idx) for s in y_true_str])
    y_true_binary = (y_true != benign_idx).astype(int) # 1 if attack, 0 if benign
    
    # Load Model
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = TemporalTransformer(
        input_dim=meta['input_features'],
        num_classes=num_classes,
        embedding_dim=meta['embedding_dim'],
        num_layers=meta['transformer_layers'],
        num_heads=meta['attention_heads'],
        ff_dim=256,
        dropout=0.1,
        seq_len=meta['sequence_length'],
        horizons=["now", "future_5s", "future_10s", "future_15s", "future_30s", "future_60s"]
    ).to(device)
    
    model.load_state_dict(torch.load(os.path.join(artifact_dir, "model.pt"), map_location=device))
    model.eval()
    
    print("Running inference...")
    batch_size = 256
    X_val_tensor = torch.FloatTensor(X_val_scaled)
    all_probs = []
    
    with torch.no_grad():
        for i in range(0, N, batch_size):
            x_batch = X_val_tensor[i:i+batch_size].to(device)
            x_batch = torch.nan_to_num(x_batch, nan=0.0, posinf=0.0, neginf=0.0)
            x_batch = torch.clamp(x_batch, min=-10.0, max=10.0)
            
            # Index 'now' from the predictions dictionary
            preds, state_preds = model(x_batch)
            probs = F.softmax(preds['now'], dim=-1)
            all_probs.extend(probs.cpu().numpy())
            
    all_probs = np.array(all_probs)
    attack_probs = 1.0 - all_probs[:, benign_idx]
    
    print("Computing optimal decision threshold...")
    precisions, recalls, thresholds = precision_recall_curve(y_true_binary, attack_probs)
    f1_scores = (2 * precisions * recalls) / (precisions + recalls + 1e-10)
    
    best_idx = np.argmax(f1_scores)
    best_threshold = thresholds[best_idx]
    best_f1 = f1_scores[best_idx]
    best_precision = precisions[best_idx]
    best_recall = recalls[best_idx]
    
    print(f"    -> Naive 0.50 Threshold F1: {f1_score(y_true_binary, (attack_probs > 0.50).astype(int)):.4f}")
    print(f"    -> Optimal Threshold Found: {best_threshold:.4f}")
    print(f"    -> Calibrated F1 Score:     {best_f1:.4f}")
    print(f"    -> Precision: {best_precision:.4f}, Recall: {best_recall:.4f}")
    
    calib_path = os.path.join(artifact_dir, "calibration.json")
    calib_data = {
        "operating_threshold": float(best_threshold),
        "f1_score": float(best_f1),
        "precision": float(best_precision),
        "recall": float(best_recall)
    }
    
    with open(calib_path, "w") as f:
        json.dump(calib_data, f, indent=4)
        
    print(f"Saved optimal threshold to {calib_path}")

if __name__ == "__main__":
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    ROOT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
    
    artifact_dir = os.path.join(SCRIPT_DIR, "artifacts_v6")
    sequences_dir = os.path.join(os.path.dirname(ROOT_DIR), "dataset_v2", "sequences")
    
    if not os.path.exists(artifact_dir):
        print(f"Artifact directory not found: {artifact_dir}")
        sys.exit(1)
        
    calibrate(artifact_dir, sequences_dir)
