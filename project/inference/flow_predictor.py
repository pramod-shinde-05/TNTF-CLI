import os
import joblib
import numpy as np
import json

class FlowPredictor:
    def __init__(self, model_dir):
        self.model_path = os.path.join(model_dir, "flow_rf.pkl")
        self.scaler_path = os.path.join(model_dir, "flow_scaler.pkl")
        self.features_path = os.path.join(model_dir, "flow_features.json")
        
        self.is_loaded = False
        
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path) and os.path.exists(self.features_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                with open(self.features_path, "r") as f:
                    self.features = json.load(f)["features"]
                self.is_loaded = True
            except Exception as e:
                print(f"Error loading FlowPredictor: {e}")
                
    def extract_features(self, flow):
        # Must perfectly match the 11 features we trained on
        # 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'Flow Byts/s', 'Flow Pkts/s', 
        # 'Flow IAT Mean', 'Flow IAT Max', 'SYN Flag Cnt', 'ACK Flag Cnt', 'FIN Flag Cnt', 'RST Flag Cnt'
        
        duration = float(flow.get('duration', 0.0))
        fwd_pkts = float(flow.get('forward_packet_count', 0.0))
        bwd_pkts = float(flow.get('backward_packet_count', 0.0))
        byts_s = float(flow.get('bytes_per_second', 0.0))
        pkts_s = float(flow.get('packets_per_second', 0.0))
        iat_mean = float(flow.get('iat_mean', 0.0))
        iat_max = float(flow.get('iat_max', 0.0))
        syn = float(flow.get('syn_count', 0.0))
        ack = float(flow.get('ack_count', 0.0))
        fin = float(flow.get('fin_count', 0.0))
        rst = float(flow.get('rst_count', 0.0))
        
        return np.array([[duration, fwd_pkts, bwd_pkts, byts_s, pkts_s, iat_mean, iat_max, syn, ack, fin, rst]])

    def predict(self, flow):
        if not self.is_loaded:
            return None
            
        try:
            x = self.extract_features(flow)
            
            # Sanitize infs which might happen on live traffic
            x = np.nan_to_num(x, posinf=0.0, neginf=0.0)
            
            x_scaled = self.scaler.transform(x)
            
            probs = self.model.predict_proba(x_scaled)[0]
            classes = self.model.classes_
            
            best_idx = np.argmax(probs)
            best_class = classes[best_idx]
            confidence = probs[best_idx]
            
            if best_class == 'Benign':
                return None
                
            return {
                'predicted_class': best_class,
                'confidence': confidence
            }
        except Exception:
            return None
