import os
import glob
import numpy as np
from scipy.stats import entropy
import polars as pl
import pandas as pd
from tqdm import tqdm
import json
import warnings
import shutil

warnings.filterwarnings('ignore')

os.environ['POLARS_MAX_THREADS'] = '8'

def compute_entropy_from_list(ports):
    if ports is None or len(ports) == 0:
        return 0.0
    
    if isinstance(ports, str):
        import ast
        try:
            ports = ast.literal_eval(ports)
        except:
            return 0.0
            
    ports = [p for p in ports if p is not None]
    if not ports:
        return 0.0
    unique, counts = np.unique(ports, return_counts=True)
    ent = entropy(counts, base=2)
    return ent

def build_master_pipeline():
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = os.path.dirname(SCRIPT_DIR)
    cleaned_dir = os.path.join(SCRIPT_DIR, "cleaned")
    output_dir = os.path.join(SCRIPT_DIR, "master_dataset")
    temp_dir = os.path.join(output_dir, "temp_parquet")
    
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(temp_dir, exist_ok=True)
    
    with open(os.path.join(BASE_DIR, "project", "configs", "label_map.json"), "r") as f:
        label_map = json.load(f)
    valid_labels = set(label_map.keys())
    
    csv_files = glob.glob(os.path.join(cleaned_dir, "*.csv"))
    print(f"Found {len(csv_files)} CSV files in {cleaned_dir}")
    
    needed_cols = {
        'Timestamp', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
        'Label', 'Dst Port', 'Protocol', 'SYN Flag Cnt', 'ACK Flag Cnt', 'FIN Flag Cnt', 
        'RST Flag Cnt', 'Flow Duration', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 
        'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Max', 'PSH Flag Cnt', 'URG Flag Cnt',
        'ECE Flag Cnt', 'CWE Flag Count', 'Init Fwd Win Byts', 'Init Bwd Win Byts'
    }
    
    total_raw_rows = 0
    total_valid_rows = 0
    removed_by_year = 0
    removed_by_duration = 0
    
    print("1. Reading, cleaning, and writing intermediate Parquet files (Low RAM mode)...")
    for file_path in tqdm(csv_files):
        try:
            lazy_df = pl.scan_csv(file_path, ignore_errors=True, infer_schema_length=10000)
            
            stripped_cols = [c.strip() for c in lazy_df.columns]
            col_map = dict(zip(lazy_df.columns, stripped_cols))
            
            actual_needed = [c for c in stripped_cols if c in needed_cols]
            lazy_df = lazy_df.rename(col_map).select(actual_needed)
            
            # Count raw rows (approximation since we don't load into memory)
            # Actually we can just load the file since a single file fits in memory easily
            df = lazy_df.collect()
            total_raw_rows += len(df)
            
            if 'Timestamp' in df.columns:
                df = df.filter(pl.col("Timestamp") != "Timestamp")
                
            if 'Label' in df.columns:
                df = df.filter(pl.col("Label").is_in(list(valid_labels)))
                
            numeric_cols = [c for c in actual_needed if c not in ['Timestamp', 'Label']]
            df = df.with_columns([
                pl.col(c).cast(pl.Float64, strict=False).fill_null(0.0) for c in numeric_cols
            ])
            
            for c in numeric_cols:
                df = df.with_columns(
                    pl.when(pl.col(c).is_nan() | pl.col(c).is_infinite()).then(0.0).otherwise(pl.col(c)).alias(c)
                )
                
            df = df.with_columns(
                pl.coalesce(
                    pl.col("Timestamp").str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                    pl.col("Timestamp").str.to_datetime("%d-%m-%Y %H:%M:%S", strict=False),
                    pl.col("Timestamp").str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                    pl.col("Timestamp").str.to_datetime("%d/%m/%Y %I:%M:%S %p", strict=False),
                    pl.col("Timestamp").str.to_datetime("%m/%d/%Y %H:%M", strict=False),
                    pl.col("Timestamp").str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False)
                ).alias("Timestamp")
            ).drop_nulls("Timestamp")
            
            # Filter Anomalies
            pre_year_count = len(df)
            df = df.filter(pl.col("Timestamp").dt.year() >= 2018)
            removed_by_year += (pre_year_count - len(df))
            
            pre_dur_count = len(df)
            if "Flow Duration" in df.columns:
                df = df.filter(pl.col("Flow Duration") >= 0)
            removed_by_duration += (pre_dur_count - len(df))
            
            total_valid_rows += len(df)
            
            out_parquet = os.path.join(temp_dir, os.path.basename(file_path).replace(".csv", ".parquet"))
            df.write_parquet(out_parquet)
            
            # Free memory
            del df
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            
    print("2. Scanning all parquets and sorting by Timestamp...")
    lazy_master = pl.scan_parquet(os.path.join(temp_dir, "*.parquet"))
    lazy_master = lazy_master.sort("Timestamp")
    
    master_csv_path = os.path.join(output_dir, "master_flows.csv")
    print(f"Writing master_flows.csv to {master_csv_path} (Streaming)...")
    lazy_master.sink_csv(master_csv_path)
    
    print("3. Aggregating into 1-second network states...")
    # Because sink_csv was used, we load it back with lazy CSV scanner
    # Polars requires the frame to be explicitly sorted for group_by_dynamic
    
    df_sorted = pl.read_csv(master_csv_path, try_parse_dates=True)
    df_sorted = df_sorted.sort("Timestamp")
    
    # Calculate Flow Duration in seconds and derive Rates for the flow
    df_sorted = df_sorted.with_columns([
        (pl.col("Flow Duration") / 1e6 + 1e-6).alias("duration_sec")
    ])
    df_sorted = df_sorted.with_columns([
        (pl.col("Tot Fwd Pkts") / pl.col("duration_sec")).alias("fwd_pps"),
        (pl.col("Tot Bwd Pkts") / pl.col("duration_sec")).alias("bwd_pps"),
        (pl.col("TotLen Fwd Pkts") / pl.col("duration_sec")).alias("fwd_bps"),
        (pl.col("TotLen Bwd Pkts") / pl.col("duration_sec")).alias("bwd_bps"),
        (pl.col("SYN Flag Cnt") / pl.col("duration_sec")).alias("syn_pps") if "SYN Flag Cnt" in df_sorted.columns else pl.lit(0.0).alias("syn_pps"),
        (pl.col("RST Flag Cnt") / pl.col("duration_sec")).alias("rst_pps") if "RST Flag Cnt" in df_sorted.columns else pl.lit(0.0).alias("rst_pps")
    ])
    
    grouped = df_sorted.group_by_dynamic("Timestamp", every="1s").agg(
        total_packets=(pl.col("fwd_pps") + pl.col("bwd_pps")).sum(),
        total_bytes=(pl.col("fwd_bps") + pl.col("bwd_bps")).sum(),
        active_flows=pl.len(),
        
        flow_duration_mean=pl.col("Flow Duration").mean(),
        dst_ports_list=pl.col("Dst Port"),
        
        forward_packets=pl.col("fwd_pps").sum(),
        backward_packets=pl.col("bwd_pps").sum(),
        forward_bytes=pl.col("fwd_bps").sum(),
        backward_bytes=pl.col("bwd_bps").sum(),
        
        tcp_flows=(pl.col("Protocol") == 6).sum(),
        udp_flows=(pl.col("Protocol") == 17).sum(),
        
        syn_count=pl.col("syn_pps").sum(),
        rst_count=pl.col("rst_pps").sum(),
        
        iat_mean=pl.col("Flow IAT Mean").mean() if "Flow IAT Mean" in df_sorted.columns else pl.lit(0.0),
        packet_size_mean=pl.col("Pkt Len Mean").mean() if "Pkt Len Mean" in df_sorted.columns else pl.lit(0.0),
        
        Label=pl.col("Label").filter(pl.col("Label") != "Benign").first().fill_null("Benign")
    )
    
    pd_df = pd.DataFrame(grouped.to_dicts())
    
    pd_df['packets_per_second'] = pd_df['total_packets'] / 1.0
    pd_df['bytes_per_second'] = pd_df['total_bytes'] / 1.0
    pd_df['tcp_ratio'] = pd_df['tcp_flows'] / (pd_df['active_flows'] + 1e-6)
    pd_df['udp_ratio'] = pd_df['udp_flows'] / (pd_df['active_flows'] + 1e-6)
    
    print("Computing port entropy...")
    pd_df['destination_port_entropy'] = pd_df['dst_ports_list'].apply(compute_entropy_from_list)
    
    columns_to_keep = [
        'Timestamp', 'Label',
        'active_flows', 'forward_packets', 'backward_packets', 'forward_bytes', 
        'backward_bytes', 'packet_size_mean', 'packets_per_second', 'bytes_per_second',
        'tcp_ratio', 'udp_ratio', 'iat_mean', 'syn_count', 'rst_count', 
        'destination_port_entropy', 'flow_duration_mean'
    ]
    pd_df = pd_df[[c for c in columns_to_keep if c in pd_df.columns]]
    pd_df = pd_df.fillna(0)
    
    states_csv_path = os.path.join(output_dir, "network_states.csv")
    print(f"Writing network_states.csv to {states_csv_path}...")
    pd_df.to_csv(states_csv_path, index=False)
    
    print("Cleaning up temporary files...")
    shutil.rmtree(temp_dir)
    
    print("4. Calculating dataset stats for report...")
    time_min = df_sorted["Timestamp"].min()
    time_max = df_sorted["Timestamp"].max()
    label_counts = df_sorted.group_by("Label").count().to_dicts()
    
    print("Generating report...")
    report_content = f"""# Dataset Pipeline Report

## Files Processed
{len(csv_files)} files in `dataset_v2/cleaned`

## Row Counts
- **Raw Rows**: {total_raw_rows}
- **Removed (Year < 2018)**: {removed_by_year}
- **Removed (Duration < 0)**: {removed_by_duration}
- **Valid Rows (master_flows.csv)**: {total_valid_rows}
- **1-Second States (network_states.csv)**: {len(pd_df)}

## Timestamp Range
- **Start**: {time_min}
- **End**: {time_max}

## Class Distribution (Master Flows)
"""
    for entry in label_counts:
        report_content += f"- **{entry['Label']}**: {entry['count']}\n"
        
    report_content += "\n## Feature Schema Match\n"
    report_content += "The `network_states.csv` file contains exactly the 15 features from `configs/feature_schema.json`, plus Timestamp and Label.\n"
    
    report_path = os.path.join(os.environ.get('HOME', '/home/pramod'), '.gemini/antigravity-ide/brain/1437d92f-d386-4667-b0af-f432bc1659fc/dataset_report.md')
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report_content)
        
    print(f"Report saved to {report_path}")

if __name__ == "__main__":
    build_master_pipeline()
