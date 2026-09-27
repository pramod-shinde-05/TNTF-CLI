import os
import sys
import json
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

def train_anomaly_model():
    print("Loading data for Anomaly Detector (Isolation Forest)...")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    splits_dir = os.path.join(base_dir, "dataset_v2", "splits")
    sequences_dir = os.path.join(base_dir, "dataset_v2", "sequences")
    scaler_path = os.path.join(base_dir, "models", "transformer", "checkpoints", "scaler.pkl")
    
    with open(os.path.join(splits_dir, "split_manifest.json"), "r") as f:
        splits = json.load(f)
        
    benign_states = []
    MAX_SAMPLES = 50000 # Memory safety cap for 16GB RAM limit
    
    # We only train on the train split to avoid test leakage
    for file in splits.get("train", []):
        if len(benign_states) >= MAX_SAMPLES:
            break
            
        x_path = os.path.join(sequences_dir, 'tensors', f"{file}_X.npy")
        y_path = os.path.join(sequences_dir, 'labels', f"{file}_Y.json")
        
        if os.path.exists(x_path) and os.path.exists(y_path):
            try:
                X = np.load(x_path)
                with open(y_path, "r") as f:
                    Y = json.load(f)
                    
                # We extract the last timestep of sequences that are Benign 'now'
                for i in range(len(Y)):
                    if Y[i].get('now') == 'Benign':
                        last_state = X[i, -1, :] # The last step of the sequence
                        benign_states.append(last_state)
                        
                        if len(benign_states) >= MAX_SAMPLES:
                            break
            except Exception as e:
                print(f"Error loading {file}: {e}")
                
    print(f"Extracted {len(benign_states)} Benign states for training.")
    
    benign_X = np.vstack(benign_states)
    
    # Scale data exactly as Transformer does
    if os.path.exists(scaler_path):
        print("Applying existing StandardScaler...")
        scaler = joblib.load(scaler_path)
        benign_X = scaler.transform(benign_X)
    else:
        print("Warning: scaler.pkl not found! Isolation Forest will use raw features.")
        
    # Fit Isolation Forest
    print("Fitting Isolation Forest...")
    # contamination=0.01 assumes 1% of the 'benign' data might be outliers
    iso_forest = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)
    iso_forest.fit(benign_X)
    
    # Save model
    out_dir = os.path.join(base_dir, "models", "anomaly")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "iso_forest.pkl")
    
    joblib.dump(iso_forest, out_path)
    print(f"Anomaly model saved to {out_path}")

if __name__ == "__main__":
    train_anomaly_model()
