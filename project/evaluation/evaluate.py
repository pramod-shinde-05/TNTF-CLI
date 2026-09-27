import os
import json
import torch
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve, auc, brier_score_loss
import yaml
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.temporal_transformer.architecture import TemporalTransformer
import joblib

def calculate_metrics(y_true, y_pred, y_prob=None):
    tp = np.sum((y_pred == 1) & (y_true == 1))
    fp = np.sum((y_pred == 1) & (y_true == 0))
    tn = np.sum((y_pred == 0) & (y_true == 0))
    fn = np.sum((y_pred == 0) & (y_true == 1))
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    return {"Precision": precision, "Recall": recall, "F1": f1, "FPR": fpr}

def evaluate_models(config_path, splits_dir, sequences_dir, models_dir, output_dir, artifact_dir=None):
    os.makedirs(output_dir, exist_ok=True)
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
        
    if artifact_dir is None:
        artifact_dir = os.path.join(models_dir, "temporal_transformer", "artifacts_v6")
    
    # Load label map
    label_map_path = os.path.join(artifact_dir, "label_map.json")
    if not os.path.exists(label_map_path):
        print("Label map not found. Please train the transformer first.")
        return
        
    with open(label_map_path, 'r') as f:
        label_map = json.load(f)
    label_map_inverse = {v: k for k, v in label_map.items()}
    num_classes = len(label_map)
    class_names = [label_map_inverse[i] for i in range(num_classes)]
    
    # Load Test Data
    with open(os.path.join(splits_dir, "split_manifest.json"), "r") as f:
        splits = json.load(f)
        
    test_X, test_Y = [], []
    for file in splits.get("test", []):
        x_path = os.path.join(sequences_dir, 'tensors', f"{file}_X.npy")
        y_path = os.path.join(sequences_dir, 'labels', f"{file}_Y.json")
        if os.path.exists(x_path) and os.path.exists(y_path):
            test_X.append(np.load(x_path))
            with open(y_path, "r") as f:
                test_Y.extend(json.load(f))
                
    if not test_X:
        print("No test data found.")
        return
        
    test_X = np.vstack(test_X)
    
    scaler_path = os.path.join(artifact_dir, "scaler.pkl")
    if os.path.exists(scaler_path):
        scaler = joblib.load(scaler_path)
        N_t, S_t, F_t = test_X.shape
        test_X = scaler.transform(test_X.reshape(-1, F_t)).reshape(N_t, S_t, F_t)
    else:
        print("Warning: scaler.pkl not found!")
    
    # Load Validation Data for Calibration
    val_X, val_Y = [], []
    for file in splits.get("validation", []):
        x_path = os.path.join(sequences_dir, 'tensors', f"{file}_X.npy")
        y_path = os.path.join(sequences_dir, 'labels', f"{file}_Y.json")
        if os.path.exists(x_path) and os.path.exists(y_path):
            val_X.append(np.load(x_path))
            with open(y_path, "r") as f:
                val_Y.extend(json.load(f))
    
    if val_X:
        val_X = np.vstack(val_X)
        if scaler:
            N_v, S_v, F_v = val_X.shape
            val_X = scaler.transform(val_X.reshape(-1, F_v)).reshape(N_v, S_v, F_v)
    else:
        print("No validation data found for calibration. Will use test data as fallback (not recommended).")
        val_X = test_X
        val_Y = test_Y
        
    # ---------------------------------------------------------
    # Evaluate Transformer
    # ---------------------------------------------------------
    transformer_path = os.path.join(artifact_dir, "model.pt")
    if os.path.exists(transformer_path):
        print("Evaluating Temporal Transformer...")
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        tf_horizons = [h for h in config['prediction_horizons'] if h != 'now']
        model = TemporalTransformer(
            input_dim=test_X.shape[-1],
            num_classes=num_classes,
            embedding_dim=config['model']['embedding_dim'],
            num_layers=config['model']['transformer_layers'],
            num_heads=config['model']['attention_heads'],
            ff_dim=config['model']['feed_forward_dim'],
            dropout=config['model']['dropout'],
            seq_len=config['model']['sequence_length'],
            horizons=tf_horizons
        ).to(device)
        
        model.load_state_dict(torch.load(transformer_path, map_location=device))
        model.eval()
        
        # Filter test data to only include labels the model was trained on
        valid_indices = [i for i, y in enumerate(test_Y) if y['now'] in label_map]
        test_X = test_X[valid_indices]
        test_Y = [test_Y[i] for i in valid_indices]
        
        # Batch inference
        batch_size = 256
        all_preds = {'now': []}
        all_labels = {'now': [label_map[y['now']] for y in test_Y]}
        
        with torch.no_grad():
            for i in range(0, len(test_X), batch_size):
                batch_x = torch.tensor(test_X[i:i+batch_size], dtype=torch.float32).to(device)
                batch_x = torch.nan_to_num(batch_x, nan=0.0, posinf=0.0, neginf=0.0)
                batch_x = torch.clamp(batch_x, min=-10.0, max=10.0)
                preds, _ = model(batch_x)
                probs = torch.softmax(preds['now'], dim=1)
                all_preds['now'].extend(probs.cpu().numpy())
                
        pred_probs = np.array(all_preds['now'])
        pred_classes = np.argmax(pred_probs, axis=1)
        true_classes = np.array(all_labels['now'])
        
        # We also want to compute multi-horizon metrics (P1.9)
        # Re-run inference to collect ALL horizons
        all_horizon_preds = {h: [] for h in config['prediction_horizons']}
        all_horizon_labels = {h: [label_map.get(y[h], 0) for y in test_Y] for h in config['prediction_horizons']}
        
        with torch.no_grad():
            for i in range(0, len(test_X), batch_size):
                batch_x = torch.tensor(test_X[i:i+batch_size], dtype=torch.float32).to(device)
                batch_x = torch.nan_to_num(batch_x, nan=0.0, posinf=0.0, neginf=0.0)
                batch_x = torch.clamp(batch_x, min=-10.0, max=10.0)
                preds, _ = model(batch_x)
                for h in config['prediction_horizons']:
                    h_probs = torch.softmax(preds[h], dim=1)
                    all_horizon_preds[h].extend(h_probs.cpu().numpy())
                    
        # P1.9: Multi-horizon Evaluation
        benign_idx = label_map.get("Benign", 0)
        multi_horizon_metrics = {}
        for h in config['prediction_horizons']:
            h_probs = np.array(all_horizon_preds[h])
            h_preds = np.argmax(h_probs, axis=1)
            h_labels = np.array(all_horizon_labels[h])
            
            # Binary conversion
            h_y_true = (h_labels != benign_idx).astype(int)
            h_y_pred = (h_preds != benign_idx).astype(int)
            
            multi_horizon_metrics[h] = calculate_metrics(h_y_true, h_y_pred)
            
        print("P1.9 Multi-horizon Evaluation Complete.")
        # ---------------------------------------------------------
        # P1.6: Probability Calibration
        # ---------------------------------------------------------
        print("Running Probability Calibration on Validation Set...")
        valid_indices_val = [i for i, y in enumerate(val_Y) if y['now'] in label_map]
        val_X = val_X[valid_indices_val]
        val_Y = [val_Y[i] for i in valid_indices_val]
        
        all_val_preds = []
        with torch.no_grad():
            for i in range(0, len(val_X), batch_size):
                batch_x = torch.tensor(val_X[i:i+batch_size], dtype=torch.float32).to(device)
                batch_x = torch.nan_to_num(batch_x, nan=0.0, posinf=0.0, neginf=0.0)
                batch_x = torch.clamp(batch_x, min=-10.0, max=10.0)
                preds, _ = model(batch_x)
                probs = torch.softmax(preds['now'], dim=1)
                all_val_preds.extend(probs.cpu().numpy())
                
        val_probs = np.array(all_val_preds)
        val_labels = np.array([label_map[y['now']] for y in val_Y])
        
        # Binary: Attack (label > 0) vs Benign (label == 0)
        # Note: Benign is usually label 0. Let's assume label_map["Benign"] == 0
        benign_idx = label_map.get("Benign", 0)
        val_binary_labels = (val_labels != benign_idx).astype(int)
        # Attack probability = 1.0 - p(Benign)
        val_attack_probs = 1.0 - val_probs[:, benign_idx]
        
        brier = brier_score_loss(val_binary_labels, val_attack_probs)
        
        # Check a wide range of thresholds, especially very low ones for anomaly detection of unseen attacks
        thresholds = np.concatenate([np.arange(0.01, 0.1, 0.01), np.arange(0.1, 0.96, 0.05)])
        best_f1 = -1
        best_threshold = 0.50
        calibration_results = []
        
        for t in thresholds:
            preds_t = (val_attack_probs >= t).astype(int)
            tp = np.sum((preds_t == 1) & (val_binary_labels == 1))
            fp = np.sum((preds_t == 1) & (val_binary_labels == 0))
            tn = np.sum((preds_t == 0) & (val_binary_labels == 0))
            fn = np.sum((preds_t == 0) & (val_binary_labels == 1))
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
            
            calibration_results.append({
                "threshold": float(t),
                "precision": float(precision),
                "recall": float(recall),
                "f1": float(f1),
                "fpr": float(fpr),
                "fnr": float(fnr)
            })
            
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = float(t)
                
        calibration_data = {
            "brier_score": float(brier),
            "operating_threshold": best_threshold,
            "threshold_evaluations": calibration_results
        }
        
        with open(os.path.join(output_dir, "calibration.json"), "w") as f:
            json.dump(calibration_data, f, indent=4)
            
        # P1.6: Calibration Curve Plot
        from sklearn.calibration import calibration_curve
        prob_true, prob_pred = calibration_curve(val_binary_labels, val_attack_probs, n_bins=10)
        plt.figure(figsize=(8, 8))
        plt.plot(prob_pred, prob_true, marker='o', linewidth=2, label="Transformer")
        plt.plot([0, 1], [0, 1], linestyle='--', color='gray', label="Perfectly Calibrated")
        plt.xlabel("Mean Predicted Probability")
        plt.ylabel("Fraction of Positives")
        plt.title("Calibration Curve (Attack vs Benign)")
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'calibration_curve.png'))
        plt.close()
        
        # ---------------------------------------------------------
        # P1.7: Evaluate on Test Set using Selected Threshold
        # ---------------------------------------------------------
        print("Evaluating on Test Set...")
        test_attack_probs = 1.0 - pred_probs[:, benign_idx]
        
        # We override pred_classes based on the new threshold
        # If max prob is below threshold and it was predicted as an attack, or just logic:
        # If attack prob < operating_threshold -> Benign
        # If attack prob >= operating_threshold -> multiclass argmax among attack classes
        final_pred_classes = np.zeros_like(pred_classes)
        for i in range(len(test_attack_probs)):
            if test_attack_probs[i] >= best_threshold:
                # Mask out benign class to find the most likely attack class
                masked_probs = pred_probs[i].copy()
                masked_probs[benign_idx] = -1.0 
                final_pred_classes[i] = np.argmax(masked_probs)
            else:
                final_pred_classes[i] = benign_idx
                
        pred_classes = final_pred_classes
        
        # 1. Confusion Matrix
        cm = confusion_matrix(true_classes, pred_classes, labels=range(num_classes))
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=class_names, yticklabels=class_names)
        plt.title(f'Transformer Confusion Matrix (Threshold={best_threshold:.2f})')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'))
        plt.close()
        
        # 2. Classification Report
        report = classification_report(true_classes, pred_classes, labels=range(num_classes), target_names=class_names, output_dict=True, zero_division=0)
        
        # 3. Per-class F1
        classes = []
        f1_scores = []
        for c in class_names:
            if c in report:
                classes.append(c)
                f1_scores.append(report[c]['f1-score'])
                
        plt.figure(figsize=(10, 6))
        sns.barplot(x=f1_scores, y=classes, hue=classes, palette='viridis', legend=False)
        plt.title('Per-Class F1 Score (Temporal Transformer)')
        plt.xlim(0, 1.0)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'per_class_f1.png'))
        plt.close()
        
        # Save metrics JSON
        with open(os.path.join(output_dir, "transformer_metrics.json"), "w") as f:
            json.dump(report, f, indent=4)
            
        print(f"Evaluation complete. Visualizations saved to {output_dir}")
        
        # ---------------------------------------------------------
        # P1.8: Baseline Comparison
        # ---------------------------------------------------------
        # Check in the artifact_dir or the models/baselines/artifacts fallback
        baseline_path = os.path.join(artifact_dir, "logistic_regression.joblib")
        if not os.path.exists(baseline_path):
            baseline_path = os.path.join(models_dir, "baselines", "artifacts", "logistic_regression.joblib")
            
        baseline_metrics = None
        if os.path.exists(baseline_path):
            print("Running Logistic Regression Baseline Evaluation...")
            lr_model = joblib.load(baseline_path)
            # Evaluate using the exact same test dataset and target ('now')
            test_X_last = test_X[:, -1, :] # only information available at prediction time
            
            if hasattr(lr_model, 'n_features_in_') and lr_model.n_features_in_ != test_X_last.shape[-1]:
                print(f"Warning: Logistic Regression expects {lr_model.n_features_in_} features, but test data has {test_X_last.shape[-1]}. Skipping baseline.")
            else:
                test_binary_labels = (true_classes != benign_idx).astype(int)
                lr_preds = lr_model.predict(test_X_last)
            # Assuming LR was trained on 'now' labels (multiclass or binary)
            # We must map LR preds to binary. If LR was trained with label_map indexing:
            # Let's map it: 1 if != benign_idx else 0
            # Wait, train_baselines.py trained LR on string labels.
            # We need to map string labels to binary.
                if isinstance(lr_preds[0], str):
                    lr_binary_preds = (lr_preds != "Benign").astype(int)
                else:
                    lr_binary_preds = (lr_preds != benign_idx).astype(int)
                    
                baseline_metrics = calculate_metrics(test_binary_labels, lr_binary_preds)
                print("Logistic Regression baseline evaluated.")
        else:
            print("Warning: Logistic Regression baseline not found for comparison.")
            
        # ---------------------------------------------------------
        # P1.10: Early Warning Evaluation
        # ---------------------------------------------------------
        print("Running Early Warning Evaluation...")
        warning_lead_times = []
        for file in splits.get("test", []):
            x_path = os.path.join(sequences_dir, 'tensors', f"{file}_X.npy")
            y_path = os.path.join(sequences_dir, 'labels', f"{file}_Y.json")
            if not (os.path.exists(x_path) and os.path.exists(y_path)):
                continue
                
            seq_X = np.load(x_path)
            with open(y_path, "r") as f:
                seq_Y = json.load(f)
                
            if scaler:
                N_s, S_s, F_s = seq_X.shape
                seq_X = scaler.transform(seq_X.reshape(-1, F_s)).reshape(N_s, S_s, F_s)
                
            with torch.no_grad():
                seq_X_tensor = torch.tensor(seq_X, dtype=torch.float32).to(device)
                seq_X_tensor = torch.nan_to_num(seq_X_tensor, nan=0.0, posinf=0.0, neginf=0.0)
                seq_X_tensor = torch.clamp(seq_X_tensor, min=-10.0, max=10.0)
                preds, _ = model(seq_X_tensor)
                now_probs_tensor = torch.softmax(preds['now'], dim=1)
                
            now_probs = now_probs_tensor.cpu().numpy()
            
            attack_onset_time = -1
            for t, y in enumerate(seq_Y):
                if y['now'] != "Benign":
                    attack_onset_time = t
                    break
                    
            if attack_onset_time == -1:
                continue # No attack in this sequence
                
            first_correct_warning_time = -1
            for t in range(len(seq_Y)):
                # We check the attack probability threshold
                attack_prob = 1.0 - now_probs[t][benign_idx]
                if attack_prob >= best_threshold:
                    first_correct_warning_time = t
                    break
                    
            if first_correct_warning_time != -1:
                # Calculate lead time: positive means warning BEFORE onset
                lead_time = attack_onset_time - first_correct_warning_time
                warning_lead_times.append(lead_time)
            else:
                # No warning
                warning_lead_times.append(None)
                
        # Compute early warning stats
        warned = [lt for lt in warning_lead_times if lt is not None]
        no_warn_count = sum(1 for lt in warning_lead_times if lt is None)
        total_attacks = len(warning_lead_times)
        
        warned_before = sum(1 for lt in warned if lt > 0)
        
        early_warning_stats = {
            "Mean early warning time": float(np.mean(warned)) if warned else 0.0,
            "Median early warning time": float(np.median(warned)) if warned else 0.0,
            "Minimum warning time": float(np.min(warned)) if warned else 0.0,
            "Maximum warning time": float(np.max(warned)) if warned else 0.0,
            "% attacks warned before onset": (warned_before / total_attacks) * 100 if total_attacks > 0 else 0.0,
            "% attacks with no warning": (no_warn_count / total_attacks) * 100 if total_attacks > 0 else 0.0
        }
        
        # ---------------------------------------------------------
        # Generate Markdown Report
        # ---------------------------------------------------------
        report_md = "# P1.8 - P1.10 Evaluation Report\n\n"
        
        # P1.8 Baseline
        report_md += "## P1.8 Proper Baseline Comparison\n"
        report_md += "| Model               | Precision | Recall | F1 | FPR |\n"
        report_md += "| ------------------- | --------: | -----: | -: | --: |\n"
        
        tf_test_labels = (true_classes != benign_idx).astype(int)
        tf_metrics = calculate_metrics(tf_test_labels, (pred_classes != benign_idx).astype(int))
        
        if baseline_metrics:
            report_md += f"| Logistic Regression | {baseline_metrics['Precision']:.4f} | {baseline_metrics['Recall']:.4f} | {baseline_metrics['F1']:.4f} | {baseline_metrics['FPR']:.4f} |\n"
        else:
            report_md += "| Logistic Regression | N/A | N/A | N/A | N/A |\n"
            
        report_md += f"| Transformer         | {tf_metrics['Precision']:.4f} | {tf_metrics['Recall']:.4f} | {tf_metrics['F1']:.4f} | {tf_metrics['FPR']:.4f} |\n\n"
        
        # P1.9 Multi-horizon
        report_md += "## P1.9 Multi-horizon Evaluation\n"
        report_md += "| Horizon | Precision | Recall | F1 | FPR |\n"
        report_md += "| ------- | --------: | -----: | -: | --: |\n"
        for h in config['prediction_horizons']:
            m = multi_horizon_metrics[h]
            report_md += f"| {h} | {m['Precision']:.4f} | {m['Recall']:.4f} | {m['F1']:.4f} | {m['FPR']:.4f} |\n"
        report_md += "\n"
        
        # P1.10 Early Warning
        report_md += "## P1.10 Early-warning Evaluation\n"
        report_md += "```text\n"
        report_md += f"Mean early warning time: {early_warning_stats['Mean early warning time']:.2f} steps\n"
        report_md += f"Median early warning time: {early_warning_stats['Median early warning time']:.2f} steps\n"
        report_md += f"Minimum warning time: {early_warning_stats['Minimum warning time']:.2f} steps\n"
        report_md += f"Maximum warning time: {early_warning_stats['Maximum warning time']:.2f} steps\n"
        report_md += f"% attacks warned before onset: {early_warning_stats['% attacks warned before onset']:.1f}%\n"
        report_md += f"% attacks with no warning: {early_warning_stats['% attacks with no warning']:.1f}%\n"
        report_md += "```\n"
        
        with open(os.path.join(output_dir, "evaluation_report.md"), "w") as f:
            f.write(report_md)
            
        print(f"Full evaluation report saved to {os.path.join(output_dir, 'evaluation_report.md')}")
    else:
        print(f"Transformer model not found at {transformer_path}")

if __name__ == "__main__":
    import os
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    ROOT_DIR = os.path.dirname(SCRIPT_DIR)
    
    config_path = os.path.join(ROOT_DIR, "configs", "model.yaml")
    
    # Check if dummy_dataset exists (from test_pipeline.py)
    if os.path.exists(os.path.join(ROOT_DIR, "dummy_dataset")):
        splits_dir = os.path.join(ROOT_DIR, "dummy_dataset", "splits")
        sequences_dir = os.path.join(ROOT_DIR, "dummy_dataset", "sequences")
    else:
        splits_dir = os.path.join(os.path.dirname(ROOT_DIR), "dataset_v2", "splits")
        sequences_dir = os.path.join(os.path.dirname(ROOT_DIR), "dataset_v2", "sequences")
        
    models_dir = os.path.join(ROOT_DIR, "models")
    output_dir = os.path.join(models_dir, "temporal_transformer", "evaluation")
    
    evaluate_models(config_path, splits_dir, sequences_dir, models_dir, output_dir)
