import time

class EarlyWarningTracker:
    def __init__(self, confidence_threshold=0.80):
        self.confidence_threshold = confidence_threshold
        self.active_alerts = {}
        
    def process_prediction(self, current_time_ms, predictions_dict, label_map_inverse):
        """
        predictions_dict: Dictionary mapping horizon (e.g. 'future_30s') to probabilities array.
        label_map_inverse: Mapping from class index to label string.
        """
        metrics = []
        
        # Check future horizons for high confidence attacks
        for horizon, probs in predictions_dict.items():
            if horizon == 'now':
                continue
                
            # Assume probs is a 1D array of probabilities for each class
            for class_idx, prob in enumerate(probs):
                label = label_map_inverse.get(class_idx, "Unknown")
                
                if label != "Benign" and prob >= self.confidence_threshold:
                    if label not in self.active_alerts:
                        # New alert
                        self.active_alerts[label] = {
                            "first_detected_ms": current_time_ms,
                            "predicted_horizon": horizon,
                            "initial_confidence": prob
                        }
                        
                    metrics.append({
                        "attack": label,
                        "horizon": horizon,
                        "confidence": prob,
                        "warning_status": "NEW_ALERT" if self.active_alerts[label]["first_detected_ms"] == current_time_ms else "ACTIVE"
                    })
                    
        # Check if an attack has manifested "now"
        now_probs = predictions_dict.get('now', [])
        for class_idx, prob in enumerate(now_probs):
            label = label_map_inverse.get(class_idx, "Unknown")
            if label != "Benign" and prob >= self.confidence_threshold:
                if label in self.active_alerts:
                    # Attack manifested, calculate early warning time
                    early_warning_ms = current_time_ms - self.active_alerts[label]["first_detected_ms"]
                    metrics.append({
                        "attack": label,
                        "horizon": "now",
                        "confidence": prob,
                        "warning_status": "MANIFESTED",
                        "early_warning_seconds": early_warning_ms / 1000.0
                    })
                    # Clear alert after manifesting
                    del self.active_alerts[label]
                else:
                    # Attack manifested without early warning
                    metrics.append({
                        "attack": label,
                        "horizon": "now",
                        "confidence": prob,
                        "warning_status": "MANIFESTED_NO_WARNING",
                        "early_warning_seconds": 0.0
                    })
                    
        return metrics
