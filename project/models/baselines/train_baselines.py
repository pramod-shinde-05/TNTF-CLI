import os
import json
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
import joblib

def load_data(splits_dir, sequences_dir):
    with open(os.path.join(splits_dir, "split_manifest.json"), "r") as f:
        splits = json.load(f)
        
    data = {"train": {"X": [], "y": []}, "validation": {"X": [], "y": []}, "test": {"X": [], "y": []}}
    
    for split_name, files in splits.items():
        for file in files:
            x_path = os.path.join(sequences_dir, 'tensors', f"{file}_X.npy")
            y_path = os.path.join(sequences_dir, 'labels', f"{file}_Y.json")
            
            if os.path.exists(x_path) and os.path.exists(y_path):
                X = np.load(x_path)
                with open(y_path, "r") as f:
                    Y = json.load(f)
                    
                # Use "now" label for baseline evaluation for fair primary benchmark
                y = [item["now"] for item in Y]
                
                # Do NOT flatten arbitrarily. Use the most recent state (last step) 
                # as the information available at prediction time.
                X_last = X[:, -1, :]
                
                data[split_name]["X"].append(X_last)
                data[split_name]["y"].extend(y)
                
    # Concatenate
    for split in data:
        if data[split]["X"]:
            data[split]["X"] = np.vstack(data[split]["X"])
            data[split]["y"] = np.array(data[split]["y"])
            
    return data

def train_logistic_regression(data, output_dir):
    print("Training Logistic Regression Baseline...")
    clf = LogisticRegression(max_iter=1000, n_jobs=-1, class_weight='balanced')
    clf.fit(data["train"]["X"], data["train"]["y"])
    
    val_preds = clf.predict(data["validation"]["X"])
    report = classification_report(data["validation"]["y"], val_preds, output_dict=True)
    
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(clf, os.path.join(output_dir, "logistic_regression.joblib"))
    
    with open(os.path.join(output_dir, "lr_val_report.json"), "w") as f:
        json.dump(report, f, indent=4)
    print("Logistic Regression trained.")



if __name__ == "__main__":
    import sys
    import os
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    MODELS_DIR = os.path.dirname(SCRIPT_DIR)
    ROOT_DIR = os.path.dirname(MODELS_DIR)
    
    if len(sys.argv) > 1:
        splits_dir = sys.argv[1]
        sequences_dir = sys.argv[2]
        output_dir = sys.argv[3]
    else:
        splits_dir = os.path.join(ROOT_DIR, "dummy_dataset", "splits") if os.path.exists(os.path.join(ROOT_DIR, "dummy_dataset")) else os.path.join(os.path.dirname(ROOT_DIR), "dataset_v2", "splits")
        sequences_dir = os.path.join(ROOT_DIR, "dummy_dataset", "sequences") if os.path.exists(os.path.join(ROOT_DIR, "dummy_dataset")) else os.path.join(os.path.dirname(ROOT_DIR), "dataset_v2", "sequences")
        output_dir = os.path.join(SCRIPT_DIR, "artifacts")
        
    os.makedirs(output_dir, exist_ok=True)
    
    data = load_data(splits_dir, sequences_dir)
    if data["train"]["X"] is not None and len(data["train"]["X"]) > 0:
        
        # Load the canonical scaler from the Transformer artifacts so baseline is trained on the same distribution
        scaler_path = os.path.join(ROOT_DIR, "models", "temporal_transformer", "artifacts_v6", "scaler.pkl")
        if os.path.exists(scaler_path):
            print("Applying canonical StandardScaler to baseline data...")
            scaler = joblib.load(scaler_path)
            for split in ["train", "validation"]:
                if len(data[split]["X"]) > 0:
                    data[split]["X"] = scaler.transform(data[split]["X"])
                    
        print("Running baseline training...")
        train_logistic_regression(data, output_dir)
        print("Baselines trained.")
    else:
        print("No training data found.")
