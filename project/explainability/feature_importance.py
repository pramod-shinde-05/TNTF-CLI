import torch
import numpy as np

class FeatureImportanceExplainer:
    def __init__(self, model, feature_names):
        self.model = model
        self.feature_names = feature_names
        
    def explain_prediction(self, input_sequence, target_class=None, steps=50):
        """
        Uses Integrated Gradients to estimate feature importance for a given input sequence.
        input_sequence: (seq_len, num_features)
        """
        self.model.eval()
        
        # Get model device
        device = next(self.model.parameters()).device
        
        # Add batch dimension and require gradients
        x = torch.tensor(input_sequence, dtype=torch.float32).unsqueeze(0).to(device)
        x.requires_grad_(True)
        
        # Baseline (e.g., all zeros)
        baseline = torch.zeros_like(x).to(device)
        
        # Compute scaled inputs
        alphas = torch.linspace(0.0, 1.0, steps=steps).to(device)
        scaled_inputs = [baseline + alpha * (x - baseline) for alpha in alphas]
        
        # Accumulate gradients
        total_gradients = torch.zeros_like(x)
        
        for scaled_input in scaled_inputs:
            # Detach to make it a leaf tensor and require grad
            scaled_input = scaled_input.detach().clone().requires_grad_(True)
            preds = self.model(scaled_input)
            if isinstance(preds, tuple):
                preds = preds[0]
            
            # Use 'now' prediction for importance
            now_pred = preds['now']
            
            if target_class is None:
                target_class = torch.argmax(now_pred, dim=1).item()
                
            score = now_pred[0, target_class]
            self.model.zero_grad()
            score.backward(retain_graph=True)
            
            total_gradients += scaled_input.grad.data
            
        avg_gradients = total_gradients / steps
        integrated_gradients = (x - baseline) * avg_gradients
        
        # Aggregate over the sequence length to get importance per feature
        feature_importance = torch.sum(torch.abs(integrated_gradients), dim=1).squeeze()
        
        # Normalize feature importance
        if torch.sum(feature_importance) > 0:
            feature_importance = feature_importance / torch.sum(feature_importance)
            
        importance_dict = {
            self.feature_names[i]: float(feature_importance[i].item())
            for i in range(len(self.feature_names))
        }
        
        # Sort by importance
        sorted_importance = dict(sorted(importance_dict.items(), key=lambda item: item[1], reverse=True))
        
        # Top 3 features
        top_3 = {k: sorted_importance[k] for k in list(sorted_importance.keys())[:3]}
        
        # P1.5: Temporal Explanation
        # Aggregate over the feature dimension to get importance per timestep
        temporal_importance = torch.sum(torch.abs(integrated_gradients), dim=2).squeeze()
        most_influential_idx = torch.argmax(temporal_importance).item()
        
        # Translate to T - X seconds offset (sequence length is usually 30)
        # S(t) is index 29 (which is T - 0s)
        # S(t-1) is index 28 (which is T - 5s)
        seq_len = temporal_importance.shape[0]
        offset = (seq_len - 1 - most_influential_idx) * 5
        temporal_explanation = f"T - {offset} seconds"
        
        return top_3, temporal_explanation, target_class
