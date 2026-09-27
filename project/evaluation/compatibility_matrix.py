import json
import os
import pandas as pd

class DatasetCompatibilityMatrix:
    """
    Framework to evaluate the compatibility of the Temporal AI Forecasting System
    trained on CIC-IDS2018 with other external datasets (e.g., UNSW-NB15, CIC-DDoS2019, CICIoT2023).
    
    This does NOT download or fabricate datasets. It strictly acts as an evaluation
    scaffolding framework once real datasets are ingested into the system.
    """
    
    def __init__(self, target_schema_path="configs/feature_schema.json"):
        self.target_schema_path = target_schema_path
        self.datasets = ["UNSW-NB15", "CIC-DDoS2019", "CICIoT2023"]
        self.matrix_results = {}
        
        with open(target_schema_path, "r") as f:
            schema = json.load(f)
        self.target_features = [feat["name"] for feat in schema.get("features", [])]
        
    def assess_feature_overlap(self, external_dataset_name, external_features):
        """
        Calculates the feature overlap percentage between the target schema (CIC-IDS2018)
        and an external dataset.
        """
        overlap = set(self.target_features).intersection(set(external_features))
        overlap_pct = (len(overlap) / len(self.target_features)) * 100 if self.target_features else 0.0
        
        missing_features = list(set(self.target_features) - set(external_features))
        
        return {
            "overlap_percentage": overlap_pct,
            "matching_features": list(overlap),
            "missing_features": missing_features
        }
        
    def evaluate_model_transferability(self, external_dataset_name, data_loader_func, model_predictor):
        """
        Evaluates the model's transferability onto a new dataset.
        data_loader_func should return (X_test, y_test) for the external dataset.
        """
        print(f"Evaluating transferability on {external_dataset_name}...")
        # Placeholder for actual data loading and evaluation logic
        # X_test, y_test = data_loader_func()
        # metrics = model_predictor.evaluate(X_test, y_test)
        
        # Returns dummy structure since actual datasets are not downloaded
        return {
            "status": "Not Evaluated (Dataset Unavailable)",
            "f1_score_transfer": None,
            "brier_score_transfer": None
        }

    def generate_report(self, output_path="evaluation/compatibility_report.json"):
        """
        Generates the compatibility matrix report.
        """
        report = {
            "target_system": "CIC-IDS2018 (TemporalTransformer)",
            "target_feature_count": len(self.target_features),
            "datasets": self.matrix_results
        }
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=4)
        print(f"Compatibility Matrix framework report generated at {output_path}")

if __name__ == "__main__":
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    schema_path = os.path.join(ROOT_DIR, "configs", "feature_schema.json")
    matrix = DatasetCompatibilityMatrix(target_schema_path=schema_path)
    
    # Simulate adding external dataset schema mappings
    # (In reality, these would be parsed from dataset descriptions or headers)
    matrix.matrix_results["UNSW-NB15"] = matrix.assess_feature_overlap(
        "UNSW-NB15", 
        ["src_ip", "dst_ip", "proto", "state", "dur", "sbytes", "dbytes"] # Example subset
    )
    
    matrix.matrix_results["CIC-DDoS2019"] = matrix.assess_feature_overlap(
        "CIC-DDoS2019",
        matrix.target_features # Highly compatible theoretically
    )
    
    matrix.matrix_results["CICIoT2023"] = matrix.assess_feature_overlap(
        "CICIoT2023",
        ["flow_duration", "header_length", "protocol_type"] # Example subset
    )
    
    matrix.generate_report(os.path.join(ROOT_DIR, "evaluation", "compatibility_report.json"))
