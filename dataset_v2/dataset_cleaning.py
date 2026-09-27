import os
import pandas as pd
import numpy as np
import glob
import json
import gc
from multiprocessing import Pool
from functools import partial

def process_file(file_path, cleaned_dir, valid_labels):
    file_name = os.path.basename(file_path)
    out_path = os.path.join(cleaned_dir, file_name)
    
    file_stats = {
        "file_name": file_name,
        "total_rows_before": 0,
        "total_rows_after": 0,
        "removed_by_reason": {
            "empty_rows": 0,
            "duplicate_rows": 0,
            "is_header_row": 0,
            "has_nan": 0,
            "has_inf": 0,
            "invalid_timestamp": 0,
            "invalid_label": 0
        },
        "class_distribution": {label: 0 for label in valid_labels}
    }
    
    # 150k chunks to limit RAM usage
    chunk_iter = pd.read_csv(file_path, chunksize=150000, low_memory=False)
    first_chunk = True
    
    for chunk in chunk_iter:
        initial_len = len(chunk)
        file_stats["total_rows_before"] += initial_len
        
        # 1. Empty rows
        chunk.dropna(how='all', inplace=True)
        file_stats["removed_by_reason"]["empty_rows"] += initial_len - len(chunk)
        
        # 2. Duplicate rows
        len_before_dedup = len(chunk)
        chunk.drop_duplicates(inplace=True)
        file_stats["removed_by_reason"]["duplicate_rows"] += len_before_dedup - len(chunk)
        
        # 3. Header rows
        header_mask = chunk['Label'] == 'Label'
        file_stats["removed_by_reason"]["is_header_row"] += int(header_mask.sum())
        chunk = chunk[~header_mask]
        
        # 4. Normalize Label
        if 'Label' in chunk.columns:
            label_translation = {
                'Infilteration': 'Infiltration',
                'FTP-BruteForce': 'Brute Force',
                'SSH-Bruteforce': 'Brute Force',
                'DoS attacks-GoldenEye': 'DoS',
                'DoS attacks-Slowloris': 'DoS',
                'DoS attacks-SlowHTTPTest': 'DoS',
                'DoS attacks-Hulk': 'DoS',
                'DDoS attacks-LOIC-HTTP': 'DDoS',
                'DDOS attack-LOIC-UDP': 'DDoS',
                'DDOS attack-HOIC': 'DDoS',
                'Brute Force -Web': 'Web Attack',
                'Brute Force -XSS': 'Web Attack',
                'SQL Injection': 'Web Attack',
                'Bot': 'Bot',
                'Benign': 'Benign'
            }
            chunk['Label'] = chunk['Label'].replace(label_translation)
            
        # 5. Invalid labels
        if 'Label' in chunk.columns:
            valid_mask = chunk['Label'].isin(valid_labels)
            file_stats["removed_by_reason"]["invalid_label"] += int((~valid_mask).sum())
            chunk = chunk[valid_mask]
        
        # 6. Specific CIC-IDS2018 Inf/NaN issues
        for col in ['Flow Byts/s', 'Flow Pkts/s']:
            if col in chunk.columns:
                chunk[col] = pd.to_numeric(chunk[col], errors='coerce')
                chunk[col] = chunk[col].replace([np.inf, -np.inf], 0)
                chunk[col] = chunk[col].fillna(0)
                
        # 7. Remaining NaNs
        nan_mask = chunk.isna().any(axis=1)
        file_stats["removed_by_reason"]["has_nan"] += int(nan_mask.sum())
        chunk = chunk[~nan_mask]
        
        # 8. Remaining Infs
        numeric_cols = chunk.select_dtypes(include=[np.number]).columns
        inf_mask = np.isinf(chunk[numeric_cols]).any(axis=1)
        file_stats["removed_by_reason"]["has_inf"] += int(inf_mask.sum())
        chunk = chunk[~inf_mask]
        
        # 9. Timestamps
        if 'Timestamp' in chunk.columns:
            parsed_times = pd.to_datetime(chunk['Timestamp'], errors='coerce', dayfirst=True)
            invalid_time_mask = parsed_times.isna()
            file_stats["removed_by_reason"]["invalid_timestamp"] += int(invalid_time_mask.sum())
            chunk = chunk[~invalid_time_mask]
            
        file_stats["total_rows_after"] += len(chunk)
        
        # Update class distribution
        if 'Label' in chunk.columns:
            counts = chunk['Label'].value_counts().to_dict()
            for k, v in counts.items():
                if k in file_stats["class_distribution"]:
                    file_stats["class_distribution"][k] += v
                    
        # Write
        chunk.to_csv(out_path, mode='w' if first_chunk else 'a', header=first_chunk, index=False)
        first_chunk = False
        gc.collect()
        
    return file_stats

def clean_datasets(raw_dir, cleaned_dir, report_path, valid_labels):
    os.makedirs(cleaned_dir, exist_ok=True)
    csv_files = glob.glob(os.path.join(raw_dir, "*.csv"))
    
    print(f"Found {len(csv_files)} CSV files. Processing using 4 workers...")
    
    process_func = partial(process_file, cleaned_dir=cleaned_dir, valid_labels=valid_labels)
    
    all_stats = []
    with Pool(processes=4) as pool:
        for stat in pool.imap_unordered(process_func, csv_files):
            all_stats.append(stat)
            print(f"Completed {stat['file_name']}: {stat['total_rows_after']}/{stat['total_rows_before']} valid rows.")
            
    # Aggregate stats
    total_before = sum(s['total_rows_before'] for s in all_stats)
    total_after = sum(s['total_rows_after'] for s in all_stats)
    
    agg_reasons = {}
    agg_classes = {label: 0 for label in valid_labels}
    
    for s in all_stats:
        for k, v in s['removed_by_reason'].items():
            agg_reasons[k] = agg_reasons.get(k, 0) + v
        for k, v in s['class_distribution'].items():
            agg_classes[k] += v
            
    # Generate Markdown Report
    with open(report_path, "w") as f:
        f.write("# Dataset Analysis Report\n\n")
        f.write("## Overview\n")
        f.write(f"- **Files Processed:** {len(csv_files)}\n")
        f.write(f"- **Total Rows Before:** {total_before:,}\n")
        f.write(f"- **Total Rows After:** {total_after:,}\n")
        f.write(f"- **Total Rows Removed:** {total_before - total_after:,}\n\n")
        
        f.write("## Removal Reasons\n")
        f.write("| Reason | Count |\n|---|---|\n")
        for k, v in agg_reasons.items():
            f.write(f"| {k} | {v:,} |\n")
            
        f.write("\n## Class Distribution\n")
        f.write("| Class | Count | Percentage |\n|---|---|---|\n")
        for k, v in agg_classes.items():
            pct = (v / total_after * 100) if total_after > 0 else 0
            f.write(f"| {k} | {v:,} | {pct:.2f}% |\n")

if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    ROOT_DIR = os.path.dirname(BASE_DIR)
    
    raw_dir = os.path.join(ROOT_DIR, "dataset")
    cleaned_dir = os.path.join(BASE_DIR, "cleaned")
    
    # Load label map
    label_map_path = os.path.join(ROOT_DIR, "project", "configs", "label_map.json")
    with open(label_map_path, "r") as f:
        label_map = json.load(f)
    valid_labels = set(label_map.keys())
    
    stats_dir = os.path.join(BASE_DIR, "statistics")
    os.makedirs(stats_dir, exist_ok=True)
    report_path = os.path.join(stats_dir, "dataset_analysis_report.md")
    
    clean_datasets(raw_dir, cleaned_dir, report_path, valid_labels)
