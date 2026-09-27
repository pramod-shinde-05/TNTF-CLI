import os
import pandas as pd
import json
import glob
from pathlib import Path

def audit_datasets(data_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    
    audit_results = {}
    all_columns = set()
    
    for file_path in csv_files:
        file_name = os.path.basename(file_path)
        print(f"Auditing {file_name}...")
        
        # Read only a chunk to get basic stats quickly without using massive RAM
        chunk_iter = pd.read_csv(file_path, chunksize=100000, low_memory=False)
        
        total_rows = 0
        missing_values_count = 0
        infinite_values_count = 0
        columns = []
        dtypes = {}
        labels = {}
        
        try:
            for chunk in chunk_iter:
                if not columns:
                    columns = list(chunk.columns)
                    all_columns.update(columns)
                    dtypes = {col: str(dtype) for col, dtype in chunk.dtypes.items()}
                
                total_rows += len(chunk)
                
                # Check labels
                if 'Label' in chunk.columns:
                    val_counts = chunk['Label'].value_counts().to_dict()
                    for k, v in val_counts.items():
                        labels[str(k)] = labels.get(str(k), 0) + v
                        
        except Exception as e:
            print(f"Error reading {file_name}: {e}")
            audit_results[file_name] = {"error": str(e)}
            continue
            
        audit_results[file_name] = {
            "total_rows": total_rows,
            "columns": columns,
            "column_count": len(columns),
            "dtypes": dtypes,
            "labels": labels
        }
        
    # Generate statistics
    with open(os.path.join(output_dir, "dataset_statistics.json"), "w") as f:
        json.dump(audit_results, f, indent=4)
        
    print(f"Audit completed. Found {len(all_columns)} unique columns across all files.")
    
    # Save a quick report
    with open(os.path.join(output_dir, "dataset_audit_report.md"), "w") as f:
        f.write("# Dataset Audit Report\n\n")
        f.write("## Files Audited\n")
        for file, stats in audit_results.items():
            if "error" in stats:
                f.write(f"- **{file}**: Error - {stats['error']}\n")
            else:
                f.write(f"- **{file}**: {stats['total_rows']} rows, {stats['column_count']} columns\n")
                
        f.write("\n## Label Distribution\n")
        all_labels = {}
        for stats in audit_results.values():
            if "labels" in stats:
                for k, v in stats['labels'].items():
                    all_labels[k] = all_labels.get(k, 0) + v
        for label, count in sorted(all_labels.items(), key=lambda x: x[1], reverse=True):
            f.write(f"- {label}: {count}\n")
            
        f.write("\n## Note on Missing IP/Flow ID Fields\n")
        has_src_ip = any('Src IP' in col or 'Source IP' in col for col in all_columns)
        has_dst_ip = any('Dst IP' in col or 'Destination IP' in col for col in all_columns)
        f.write(f"- Has Source IP: {has_src_ip}\n")
        f.write(f"- Has Destination IP: {has_dst_ip}\n")

if __name__ == "__main__":
    import os
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    ROOT_DIR = os.path.dirname(SCRIPT_DIR)
    data_dir = os.path.join(ROOT_DIR, "dataset")
    output_dir = os.path.join(SCRIPT_DIR, "statistics")
    audit_datasets(data_dir, output_dir)
