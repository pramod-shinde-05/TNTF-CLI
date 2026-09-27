import os
import json

def generate_feature_schema(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    schema = {
        "metadata": {
            "version": "2.0",
            "description": "Temporal state feature schema. Packet-level features and IP-based behavioral features are omitted/limited due to CIC-IDS2018 missing Src IP/Dst IP in 90% of the raw CSV files."
        },
        "raw_flow_features_to_keep": [
            "Protocol", "Dst Port", "Flow Duration", 
            "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
            "Pkt Len Mean", "Pkt Len Std", "Pkt Len Max",
            "Flow Pkts/s", "Flow Byts/s", "Flow IAT Mean",
            "SYN Flag Cnt", "RST Flag Cnt"
        ]
    }
    
    with open(os.path.join(output_dir, "feature_schema.json"), "w") as f:
        json.dump(schema, f, indent=4)
        
    print(f"Feature schema generated at {output_dir}/feature_schema.json")

if __name__ == "__main__":
    import os
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(SCRIPT_DIR, "feature_schema")
    generate_feature_schema(output_dir)
