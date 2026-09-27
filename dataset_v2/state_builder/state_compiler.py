import os
import glob
import numpy as np
from scipy.stats import entropy
import polars as pl
import pandas as pd
from tqdm import tqdm
import warnings

warnings.filterwarnings('ignore')

# Limit Polars to exactly 8 cores as requested by user
os.environ['POLARS_MAX_THREADS'] = '8'

def compute_entropy_from_list(ports):
    if ports is None or len(ports) == 0:
        return 0.0
    # Drop nulls from ports
    ports = [p for p in ports if p is not None]
    if not ports:
        return 0.0
    unique, counts = np.unique(ports, return_counts=True)
    ent = entropy(counts, base=2)
    return ent

def build_states(cleaned_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    csv_files = glob.glob(os.path.join(cleaned_dir, "*.csv"))
    
    needed_cols = {
        'Timestamp', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
        'Label', 'Dst Port', 'Protocol', 'SYN Flag Cnt', 'ACK Flag Cnt', 'FIN Flag Cnt', 
        'RST Flag Cnt', 'Flow Duration', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 
        'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Max', 'PSH Flag Cnt', 'URG Flag Cnt',
        'ECE Flag Cnt', 'CWE Flag Count', 'Init Fwd Win Byts', 'Init Bwd Win Byts'
    }
    
    for file_path in tqdm(csv_files, desc="Building states"):
        file_name = os.path.basename(file_path)
        print(f"\nProcessing {file_name} with Polars (8 threads)...")
        
        # Lazy load to get columns
        lazy_df = pl.scan_csv(file_path, ignore_errors=True, infer_schema_length=10000)
        
        # Strip trailing spaces in headers (common in CIC-IDS dataset)
        stripped_cols = [c.strip() for c in lazy_df.columns]
        col_map = dict(zip(lazy_df.columns, stripped_cols))
        
        # Select only what we need and rename
        actual_needed = [c for c in stripped_cols if c in needed_cols]
        lazy_df = lazy_df.rename(col_map).select(actual_needed)
        
        # Cast metrics to Float64 in case of bad string data
        numeric_cols = [c for c in actual_needed if c not in ['Timestamp', 'Label']]
        lazy_df = lazy_df.with_columns([
            pl.col(c).cast(pl.Float64, strict=False).fill_null(0.0) for c in numeric_cols
        ])
        
        # Parse timestamps aggressively from various CIC-IDS formats
        lazy_df = lazy_df.with_columns(
            pl.coalesce(
                pl.col("Timestamp").str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                pl.col("Timestamp").str.to_datetime("%d-%m-%Y %H:%M:%S", strict=False),
                pl.col("Timestamp").str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                pl.col("Timestamp").str.to_datetime("%d/%m/%Y %I:%M:%S %p", strict=False),
                pl.col("Timestamp").str.to_datetime("%m/%d/%Y %H:%M", strict=False),
                pl.col("Timestamp").str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False)
            ).alias("Timestamp")
        ).drop_nulls("Timestamp")
        
        # Sort by timestamp for group_by_dynamic
        lazy_df = lazy_df.sort("Timestamp")
        
        # Calculate Flow Duration in seconds
        lazy_df = lazy_df.with_columns([
            (pl.col("Flow Duration") / 1e6 + 1e-6).alias("duration_sec")
        ])
        
        # Execute the scan into memory (this runs highly multi-threaded on 8 cores)
        df = lazy_df.collect()
        
        if df.is_empty():
            print(f"Skipping {file_name} (no valid rows).")
            continue
            
        # Group by dynamic 1s windows
        grouped = df.group_by_dynamic("Timestamp", every="1s").agg(
            total_packets=(pl.col("Tot Fwd Pkts") + pl.col("Tot Bwd Pkts")).sum(),
            total_bytes=(pl.col("TotLen Fwd Pkts") + pl.col("TotLen Bwd Pkts")).sum(),
            active_flows=pl.len(),
            
            flow_duration_mean=pl.col("Flow Duration").mean(),
            dst_ports_list=pl.col("Dst Port"), # To calculate entropy later in python
            
            forward_packets=pl.col("Tot Fwd Pkts").sum(),
            backward_packets=pl.col("Tot Bwd Pkts").sum(),
            forward_bytes=pl.col("TotLen Fwd Pkts").sum(),
            backward_bytes=pl.col("TotLen Bwd Pkts").sum(),
            
            tcp_flows=(pl.col("Protocol") == 6).sum(),
            udp_flows=(pl.col("Protocol") == 17).sum(),
            
            syn_count=pl.col("SYN Flag Cnt").sum() if "SYN Flag Cnt" in actual_needed else pl.lit(0.0),
            rst_count=pl.col("RST Flag Cnt").sum() if "RST Flag Cnt" in actual_needed else pl.lit(0.0),
            
            iat_mean=pl.col("Flow IAT Mean").mean() if "Flow IAT Mean" in actual_needed else pl.lit(0.0),
            packet_size_mean=pl.col("Pkt Len Mean").mean() if "Pkt Len Mean" in actual_needed else pl.lit(0.0),
            
            Label=pl.col("Label").filter(pl.col("Label") != "Benign").first().fill_null("Benign")
        )
        
        # Convert to pandas for the final feature derivations without PyArrow
        pd_df = pd.DataFrame(grouped.to_dicts())
        
        # Calculate rates and ratios
        pd_df['packets_per_second'] = pd_df['total_packets'] / 1.0
        pd_df['bytes_per_second'] = pd_df['total_bytes'] / 1.0
        pd_df['tcp_ratio'] = pd_df['tcp_flows'] / (pd_df['active_flows'] + 1e-6)
        pd_df['udp_ratio'] = pd_df['udp_flows'] / (pd_df['active_flows'] + 1e-6)
        
        # Entropy
        pd_df['destination_port_entropy'] = pd_df['dst_ports_list'].apply(compute_entropy_from_list)
        
        # Drop unneeded columns and keep strictly the schema (+ Timestamp & Label)
        columns_to_keep = [
            'Timestamp', 'Label',
            'active_flows', 'forward_packets', 'backward_packets', 'forward_bytes', 
            'backward_bytes', 'packet_size_mean', 'packets_per_second', 'bytes_per_second',
            'tcp_ratio', 'udp_ratio', 'iat_mean', 'syn_count', 'rst_count', 
            'destination_port_entropy', 'flow_duration_mean'
        ]
        pd_df = pd_df[[c for c in columns_to_keep if c in pd_df.columns]]
        
        pd_df = pd_df.fillna(0)
        
        out_path = os.path.join(output_dir, file_name.replace('.csv', '_states.csv'))
        pd_df.to_csv(out_path, index=False)
        print(f"Saved {len(pd_df)} states to {out_path}.")

if __name__ == "__main__":
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = os.path.dirname(SCRIPT_DIR)
    
    cleaned_dir = os.path.join(BASE_DIR, "cleaned")
    output_dir = os.path.join(BASE_DIR, "state_windows")
    
    build_states(cleaned_dir, output_dir)
