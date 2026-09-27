import os
import sys
import json
import torch
import torch.nn.functional as F
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

from architecture import TemporalTransformer

def evaluate(artifact_dir, sequences_dir):
    print("Loading test data...")
    x_test_path = os.path.join(sequences_dir, 'tensors', 'test_split_X.npy')
    y_test_path = os.path.join(sequences_dir, 'labels', 'test_split_Y.json')
    
    if not os.path.exists(x_test_path) or not os.path.exists(y_test_path):
        print("Test data not found!")
        return
        
    X_test = np.load(x_test_path)
    with open(y_test_path, 'r') as f:
        Y_test = json.load(f)
        
    print(f"Test sequences: {X_test.shape}")
    
    # Load Artifacts
    with open(os.path.join(artifact_dir, "label_map.json"), "r") as f:
        label_map = json.load(f)
    inv_label_map = {v: k for k, v in label_map.items()}
    num_classes = len(label_map)
    
    with open(os.path.join(artifact_dir, "metadata.json"), "r") as f:
        meta = json.load(f)
        
    scaler = joblib.load(os.path.join(artifact_dir, "scaler.pkl"))
    
    N, S, F_dim = X_test.shape
    X_test_scaled = scaler.transform(X_test.reshape(-1, F_dim)).reshape(N, S, F_dim)
    
    y_true_str = [y.get("now", "Benign") for y in Y_test]
    y_true = np.array([label_map.get(s, label_map.get("Benign", 0)) for s in y_true_str])
    
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
        horizons=["future_5s", "future_10s", "future_15s", "future_30s", "future_60s"]
    ).to(device)
    
    model.load_state_dict(torch.load(os.path.join(artifact_dir, "model.pt"), map_location=device))
    model.eval()
    
    # Inference
    print("Running Inference...")
    all_probs = []
    all_preds = []
    BATCH = 512
    
    for i in range(0, N, BATCH):
        x_batch = torch.FloatTensor(X_test_scaled[i:i+BATCH]).to(device)
        x_batch = torch.nan_to_num(x_batch, nan=0.0, posinf=0.0, neginf=0.0)
        x_batch = torch.clamp(x_batch, min=-10.0, max=10.0)
        
        with torch.no_grad():
            preds, _ = model(x_batch)
            probs = F.softmax(preds['now'], dim=1).cpu().numpy()
            all_probs.append(probs)
            all_preds.append(np.argmax(probs, axis=1))
            
    all_probs = np.vstack(all_probs)
    all_preds = np.concatenate(all_preds)
    
    # Generate Evaluation Report
    report_dict = classification_report(y_true, all_preds, labels=list(range(num_classes)), 
                                        target_names=[inv_label_map[i] for i in range(num_classes)], 
                                        zero_division=0, output_dict=True)
                                        
    report_str = classification_report(y_true, all_preds, labels=list(range(num_classes)), 
                                       target_names=[inv_label_map[i] for i in range(num_classes)], 
                                       zero_division=0)
                                       
    with open(os.path.join(artifact_dir, "evaluation_report.md"), "w") as f:
        f.write("# Temporal Transformer (Lightweight v2) Evaluation\n\n")
        f.write("## Classification Report\n```text\n")
        f.write(report_str)
        f.write("\n```\n")
        
    print("\n--- CLASSIFICATION REPORT ---")
    print(report_str)
    
    # Confusion Matrix Plot
    cm = confusion_matrix(y_true, all_preds, labels=list(range(num_classes)))
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=[inv_label_map[i] for i in range(num_classes)],
                yticklabels=[inv_label_map[i] for i in range(num_classes)])
    plt.title('Confusion Matrix (Now)')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(os.path.join(artifact_dir, 'confusion_matrix.png'))
    plt.close()
    
    # Generate Calibration (Find threshold for 1% FPR on Benign vs Attack)
    print("Generating Calibration...")
    from sklearn.metrics import roc_curve
    benign_idx = label_map.get("Benign", 0)
    
    # Binary classification: 1 if Attack, 0 if Benign
    y_true_binary = (y_true != benign_idx).astype(int)
    
    # Attack probability is 1 - Benign probability
    attack_probs = 1.0 - all_probs[:, benign_idx]
    
    fpr, tpr, thresholds = roc_curve(y_true_binary, attack_probs)
    
    # Target Max FPR of 5%
    target_fpr = 0.05
    valid_idx = np.where(fpr <= target_fpr)[0]
    
    if len(valid_idx) > 0:
        best_idx = valid_idx[-1]
        operating_threshold = float(thresholds[best_idx])
    else:
        operating_threshold = 0.50 # Fallback if ROC fails
        
    # Cap threshold between 0.01 and 0.99
    operating_threshold = max(0.01, min(0.99, operating_threshold))
    
    calib_data = {
        "operating_threshold": operating_threshold,
        "target_fpr": target_fpr,
        "actual_fpr": float(fpr[best_idx]) if len(valid_idx) > 0 else 0.0,
        "tpr_at_threshold": float(tpr[best_idx]) if len(valid_idx) > 0 else 0.0
    }
    
    with open(os.path.join(artifact_dir, "calibration.json"), "w") as f:
        json.dump(calib_data, f, indent=4)
        
    print(f"Calibration saved! Operating Threshold: {operating_threshold:.4f}")
    
    print(f"Evaluation complete. Artifacts saved to {artifact_dir}")

if __name__ == "__main__":
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    ROOT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
    
    artifact_dir = os.path.join(SCRIPT_DIR, "artifacts_v6")
    sequences_dir = os.path.join(os.path.dirname(ROOT_DIR), "dataset_v2", "sequences")
    
    if not os.path.exists(artifact_dir):
        print(f"Artifact directory not found: {artifact_dir}")
        sys.exit(1)
        
    evaluate(artifact_dir, sequences_dir)
