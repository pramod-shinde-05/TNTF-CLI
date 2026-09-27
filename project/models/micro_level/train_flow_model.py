import os
import sys
import glob
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

DATA_DIR = "../../dataset"
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

FILES = [
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv", # Hulk, SlowHTTPTest
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv", # GoldenEye, Slowloris
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv", # Brute Force Web, XSS, SQL Inj
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", # FTP/SSH Brute Force
]

FEATURES = [
    'Flow Duration',
    'Tot Fwd Pkts',
    'Tot Bwd Pkts',
    'Flow Byts/s',
    'Flow Pkts/s',
    'Flow IAT Mean',
    'Flow IAT Max',
    'SYN Flag Cnt',
    'ACK Flag Cnt',
    'FIN Flag Cnt',
    'RST Flag Cnt'
]

def load_and_subsample():
    print("[*] Assembling Micro-Level dataset...")
    dfs = []
    
    for filename in FILES:
        filepath = os.path.join(DATA_DIR, filename)
        if not os.path.exists(filepath):
            print(f"[-] Missing {filename}, skipping...")
            continue
            
        print(f"[*] Reading {filename}...")
        try:
            # We read only the features we need + Label to save massive RAM
            df = pd.read_csv(filepath, usecols=FEATURES + ['Label'])
        except Exception as e:
            print(f"[-] Error reading {filename}: {e}")
            continue
            
        # Clean invalid data
        df = df.replace([np.inf, -np.inf], np.nan).dropna()
        
        # Subsample to keep it balanced and very fast to train
        # Take 10000 Benign, and 2000 of every attack
        for label in df['Label'].unique():
            subset = df[df['Label'] == label]
            if label == 'Benign':
                n_samples = min(10000, len(subset))
            else:
                n_samples = min(2000, len(subset))
            
            sampled = subset.sample(n=n_samples, random_state=42)
            dfs.append(sampled)
            
    if not dfs:
        print("[-] No data loaded. Exiting.")
        sys.exit(1)
        
    final_df = pd.concat(dfs, ignore_index=True)
    print(f"[*] Dataset assembled! Total rows: {len(final_df)}")
    print("[*] Class distribution:")
    print(final_df['Label'].value_counts())
    
    return final_df

def main():
    df = load_and_subsample()
    
    # Convert all feature columns to numeric, dropping rows with invalid strings (like duplicate headers)
    for col in FEATURES:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    # Drop rows that became NaN due to coercion
    df = df.dropna(subset=FEATURES)
    
    X = df[FEATURES].values
    y = df['Label'].values
    
    print("\n[*] Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print("[*] Training RandomForestClassifier (100 estimators)...")
    # Using n_jobs=-1 for multithreading, max_depth to prevent overfitting and make it fast
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, n_jobs=-1, random_state=42)
    rf.fit(X_scaled, y)
    
    print("[*] Training complete! Evaluating on training set (since this is a quick proxy model):")
    preds = rf.predict(X_scaled)
    print(classification_report(y, preds))
    
    # Save the artifacts
    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path = os.path.join(MODEL_DIR, "flow_rf.pkl")
    scaler_path = os.path.join(MODEL_DIR, "flow_scaler.pkl")
    features_path = os.path.join(MODEL_DIR, "flow_features.json")
    
    joblib.dump(rf, model_path)
    joblib.dump(scaler, scaler_path)
    
    import json
    with open(features_path, "w") as f:
        json.dump({"features": FEATURES}, f)
        
    print(f"\n[+] Successfully saved micro-model to {model_path}")

if __name__ == "__main__":
    main()
