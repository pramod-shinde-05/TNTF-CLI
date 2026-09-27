import torch
import torch.nn.functional as F
import os
import sys
import numpy as np
import collections

from models.temporal_transformer.architecture import TemporalTransformer

class LivePredictor:
    def __init__(self, artifact_dir="models/temporal_transformer/artifacts_v6"):
        
        # Load feature schema dynamically
        import json
        schema_path = os.path.join(artifact_dir, "feature_schema.json")
        if os.path.exists(schema_path):
            with open(schema_path, "r") as f:
                schema = json.load(f)
            self.feature_names = [feat["name"] for feat in schema.get("features", [])]
        else:
            ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            schema_path = os.path.join(ROOT_DIR, "configs", "feature_schema.json")
            with open(schema_path, "r") as f:
                schema = json.load(f)
            self.feature_names = [feat["name"] for feat in schema["features"]]
        
        model_path = os.path.join(artifact_dir, "model.pt")
        scaler_path = os.path.join(artifact_dir, "scaler.pkl")
        
        # Load label map to dynamically determine number of classes
        label_map_path = os.path.join(artifact_dir, "label_map.json")
        if os.path.exists(label_map_path):
            with open(label_map_path, "r") as f:
                self.label_map = json.load(f)
            self.label_map_inverse = {v: k for k, v in self.label_map.items()}
            self.num_classes = len(self.label_map)
        else:
            self.label_map = {"Benign": 0, "Attack": 1}
            self.label_map_inverse = {0: "Benign", 1: "Attack"}
            self.num_classes = 2
            
        # Load MITRE Mapping
        ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        mitre_path = os.path.join(ROOT_DIR, "configs", "mitre_mapping.json")
        if os.path.exists(mitre_path):
            with open(mitre_path, "r") as f:
                self.mitre_mapping = json.load(f)
        else:
            self.mitre_mapping = {}
            
        # Load Calibration Data (P1.6/P1.7)
        if artifact_dir is None:
            artifact_dir = os.path.join(ROOT_DIR, "models", "temporal_transformer", "artifacts_v6")
        self.artifact_dir = artifact_dir
        
        calib_path = os.path.join(self.artifact_dir, "calibration.json")
        self.operating_threshold = 0.50 # Default fallback
        if os.path.exists(calib_path):
            try:
                with open(calib_path, "r") as f:
                    calib_data = json.load(f)
                    self.operating_threshold = calib_data.get("operating_threshold", 0.50)
                print(f"[*] Loaded Calibration operating_threshold: {self.operating_threshold:.3f}")
            except Exception as e:
                print(f"[!] Warning: Failed to load calibration.json: {e}")
        else:
            print("[!] Warning: calibration.json not found, using argmax equivalent (0.50 threshold fallback).")
            
        # Determine Benign index
        self.benign_idx = self.label_map.get("Benign", 0)
            
        self.input_dim = len(self.feature_names)
        
        # Dynamically load sequence_length
        meta_path = os.path.join(self.artifact_dir, "metadata.json")
        self.sequence_length = 60
        if os.path.exists(meta_path):
            with open(meta_path, "r") as f:
                meta = json.load(f)
                self.sequence_length = meta.get("sequence_length", 60)
        
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Load Model
        horizons = ["now", "future_5s", "future_10s", "future_15s", "future_30s", "future_60s"]
        self.model = TemporalTransformer(
            input_dim=self.input_dim,
            num_classes=self.num_classes,
            embedding_dim=128,
            num_layers=4,
            num_heads=4,
            ff_dim=256,
            dropout=0.1,
            seq_len=self.sequence_length,
            horizons=[h for h in horizons if h != 'now']
        ).to(self.device)
        
        if os.path.exists(model_path):
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))
            print("[*] Loaded TemporalForecaster successfully.")
        else:
            print("[!] Warning: Model checkpoint not found.")
            
        self.model.eval()
        
        # Load Scaler
        import joblib
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
            print("[*] Loaded StandardScaler successfully.")
        else:
            self.scaler = None
            print("[!] Warning: Scaler not found.")
            
        # Initialize rolling buffer
        self.state_buffer = collections.deque(maxlen=self.sequence_length)
        self.total_predictions = 0
        
        # P1.5 Explainability
        from explainability.feature_importance import FeatureImportanceExplainer
        self.explainer = FeatureImportanceExplainer(self.model, self.feature_names)
        self.last_explanation_time = 0
        self.explanation_cooldown_ms = 30000  # 30 seconds cooldown
        
    def reset(self):
        """Clears the temporal buffer for a new analysis session."""
        self.state_buffer.clear()
        self.total_predictions = 0
        self.last_explanation_time = 0
        
    def add_state(self, state_dict):
        """
        Adds a new 1-second state to the sliding window buffer.
        """
        feature_vector = [float(state_dict.get(f, 0.0)) for f in self.feature_names]
        self.state_buffer.append(feature_vector)
            
    def predict(self, current_time_ms):
        """
        Runs prediction if buffer is full enough. Returns dict or None.
        """
        self.total_predictions += 1
        
        if len(self.state_buffer) == 0:
            return None
            
        current_len = len(self.state_buffer)
        if current_len < self.sequence_length:
            return {
                "is_warming_up": True,
                "current_count": current_len,
                "required_count": self.sequence_length
            }
            
        buffer_to_use = list(self.state_buffer)
            
        # Scale
        buffer_array = np.array(buffer_to_use)
        if self.scaler:
            buffer_array = self.scaler.transform(buffer_array)
            
        # Convert to tensor
        x = torch.FloatTensor(buffer_array).unsqueeze(0).to(self.device)
        
        # Apply numerical stabilization
        x = torch.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
        x = torch.clamp(x, min=-10.0, max=10.0)
        
        with torch.no_grad():
            with torch.amp.autocast('cuda' if self.device.type == 'cuda' else 'cpu'):
                preds, _ = self.model(x)
                
        # Parse probabilities for UI (Terminal.py expects numpy arrays and specific keys)
        def get_probs(out_tensor):
            return F.softmax(out_tensor.float(), dim=1).cpu().numpy()[0]
            
        result_probs = {}
        for k, v in preds.items():
            result_probs[k] = get_probs(v)
            
        probs = result_probs
        
        # P1.6 / P1.7: Threshold-based decision instead of just argmax
        now_probs = probs['now']
        attack_prob = 1.0 - now_probs[self.benign_idx]
        
        if attack_prob >= self.operating_threshold:
            # Predict the most likely attack class
            masked_probs = now_probs.copy()
            masked_probs[self.benign_idx] = -1.0
            pred_class_idx = int(np.argmax(masked_probs))
        else:
            # Traffic is Benign
            pred_class_idx = self.benign_idx
            
        pred_label = self.label_map_inverse.get(pred_class_idx, "Unknown")
        current_confidence = float(now_probs[pred_class_idx])
        
        # --- LOW TRAFFIC NOISE FILTER REMOVED ---
        # PPS suppression logic removed because it blocked legitimate attacks in low-traffic localhost/VM testbeds.
            
        # Heuristic Threat Level
        threat_level = "Normal"
        if pred_label != "Benign":
            threat_level = f"Suspected Attack ({pred_label})"
            
        # Early Warnings Logic (Checks future horizons)
        early_warnings = []
        for horizon, h_probs in probs.items():
            if horizon == "now":
                continue
            
            h_attack_prob = 1.0 - h_probs[self.benign_idx]
            if h_attack_prob >= self.operating_threshold:
                masked_h_probs = h_probs.copy()
                masked_h_probs[self.benign_idx] = -1.0
                h_pred_idx = int(np.argmax(masked_h_probs))
                h_pred_label = self.label_map_inverse.get(h_pred_idx, "Unknown")
                
                sec_str = horizon.split('_')[1].replace('s', '')
                sec = int(sec_str) if sec_str.isdigit() else 0
                
                early_warnings.append({
                    "attack": h_pred_label,
                    "horizon": horizon,
                    "confidence": float(h_attack_prob),
                    "warning_status": "MANIFESTED" if pred_label == h_pred_label else "PENDING",
                    "early_warning_seconds": sec
                })
                
        # Fast Heuristic Feature Importance (Proxy for Integrated Gradients)
        # We use the absolute deviation of the scaled features in the latest timestep.
        # Features with massive deviations from the baseline (mean=0) drive the model's predictions.
        feature_importance = {}
        if pred_label != "Benign" or early_warnings:
            last_state_scaled = np.abs(buffer_array[-1])
            total_dev = np.sum(last_state_scaled) + 1e-6
            normalized_dev = last_state_scaled / total_dev
            
            for i, feat_name in enumerate(self.feature_names):
                feature_importance[feat_name] = float(normalized_dev[i])
                
            # Sort by highest importance
            feature_importance = dict(sorted(feature_importance.items(), key=lambda item: item[1], reverse=True))
            
        # Debug logging for feature shift diagnosis
        try:
            with open(os.path.join(self.artifact_dir, "live_debug.log"), "a") as f_dbg:
                import json
                raw_feats = {self.feature_names[i]: float(buffer_to_use[-1][i]) for i in range(len(self.feature_names))}
                scaled_feats = {self.feature_names[i]: float(buffer_array[-1][i]) for i in range(len(self.feature_names))}
                horizons_attack_prob = {h: float(1.0 - p[self.benign_idx]) for h, p in probs.items() if h != "now"}
                
                dbg_msg = {
                    "time_ms": current_time_ms,
                    "pred_label": pred_label,
                    "p_attack": float(attack_prob),
                    "raw_features": raw_feats,
                    "scaled_features": scaled_feats,
                    "horizons_p_attack": horizons_attack_prob
                }
                f_dbg.write(json.dumps(dbg_msg) + "\n")
        except Exception:
            pass

        result = {
            "probabilities": probs,
            "label_map_inverse": self.label_map_inverse,
            "current_prediction": pred_label,
            "current_confidence": current_confidence,
            "threat_level": threat_level,
            "detection_source": "Transformer",
            "anomaly_score": (1.0 - float(now_probs[self.benign_idx])) * 100,
            "attack_probability": float(attack_prob),
            "operating_threshold": float(self.operating_threshold),
            "feature_importance": feature_importance,
            "early_warnings": early_warnings,
            "debug": {
                "sequence_count": current_len,
                "total_predictions": self.total_predictions,
                "timestamp": current_time_ms
            }
        }
        
        # P1.5 Explainability
        if pred_label != "Benign":
            if current_time_ms - self.last_explanation_time > self.explanation_cooldown_ms or self.last_explanation_time == 0:
                try:
                    top_3, temporal_exp, _ = self.explainer.explain_prediction(buffer_array, target_class=pred_class_idx, steps=20)
                    result["feature_importance"] = top_3
                    result["temporal_explanation"] = temporal_exp
                    self.last_explanation_time = current_time_ms
                except Exception as e:
                    print(f"[!] Explainer error: {e}")
        
        # P1.3 / P1.4: MITRE and Attack Progression Mapping
        mitre_info = self.mitre_mapping.get(pred_label, self.mitre_mapping.get("Unknown", {}))
        
        if mitre_info:
            result["attack_progression"] = mitre_info.get("progression_stage", "Unknown")
            result["mitre_tactic"] = mitre_info.get("mitre_tactic_name", "Unknown")
            result["mitre_technique"] = mitre_info.get("mitre_technique_name", "Unknown")
        
        # Progression forecast (only if a future stage differs from current)
        forecast_progression = None
        for horizon in ["future_5s", "future_10s", "future_15s", "future_30s", "future_60s"]:
            f_idx = np.argmax(probs[horizon])
            f_label = self.label_map_inverse.get(f_idx, "Unknown")
            if f_label != pred_label:
                f_mitre = self.mitre_mapping.get(f_label, self.mitre_mapping.get("Unknown", {}))
                f_stage = f_mitre.get("progression_stage", "Unknown")
                c_stage = mitre_info.get("progression_stage", "Unknown") if mitre_info else "Unknown"
                if f_stage != c_stage and f_stage != "Normal":
                    forecast_progression = f"{c_stage} -> {f_stage}"
                    break
                    
        if forecast_progression:
            result["progression_forecast"] = forecast_progression

        return result
