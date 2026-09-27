import os
import polars as pl
import pandas as pd
from datetime import datetime

class OfflineProcessor:
    def __init__(self, predictor=None):
        self.predictor = predictor
        
    def process_pcap(self, pcap_path, update_callback=None):
        # We will use the existing PcapCapture and main loop logic for this, 
        # so this is better handled in main.py by swapping PacketCapture for PcapCapture.
        pass

    def process_csv(self, csv_path, update_callback=None):
        """
        Parses a CICFlowMeter CSV file, converts to 1s states, and runs the LivePredictor.
        Returns a summary report for the Results screen.
        """
        if update_callback: update_callback("Loading CSV...", 10)
        
        lazy_df = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=10000)
        stripped_cols = [c.strip() for c in lazy_df.columns]
        col_map = dict(zip(lazy_df.columns, stripped_cols))
        
        needed_cols = {
            'Timestamp', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
            'Dst Port', 'Protocol', 'SYN Flag Cnt', 'ACK Flag Cnt', 'FIN Flag Cnt', 
            'RST Flag Cnt', 'Flow Duration', 'Flow IAT Mean', 'Pkt Len Mean'
        }
        actual_needed = [c for c in stripped_cols if c in needed_cols]
        lazy_df = lazy_df.rename(col_map).select(actual_needed)
        
        numeric_cols = [c for c in actual_needed if c != 'Timestamp']
        lazy_df = lazy_df.with_columns([
            pl.col(c).cast(pl.Float64, strict=False).fill_null(0.0) for c in numeric_cols
        ])
        
        lazy_df = lazy_df.with_columns(
            pl.coalesce(
                pl.col("Timestamp").str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                pl.col("Timestamp").str.to_datetime("%d-%m-%Y %H:%M:%S", strict=False),
                pl.col("Timestamp").str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                pl.col("Timestamp").str.to_datetime("%d/%m/%Y %I:%M:%S %p", strict=False),
                pl.col("Timestamp").str.to_datetime("%m/%d/%Y %H:%M", strict=False),
                pl.col("Timestamp").str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False)
            ).alias("Timestamp")
        ).drop_nulls("Timestamp").sort("Timestamp")
        
        if update_callback: update_callback("Aggregating flows into temporal states...", 40)
        df = lazy_df.collect()
        
        if df.is_empty():
            return {"error": "No valid data or timestamp parsing failed in CSV."}
            
        def entropy(ports):
            import numpy as np
            from scipy.stats import entropy as scipy_entropy
            ports = [p for p in ports if p is not None]
            if not ports: return 0.0
            unique, counts = np.unique(ports, return_counts=True)
            return scipy_entropy(counts, base=2)
            
        grouped = df.group_by_dynamic("Timestamp", every="1s").agg(
            total_packets=(pl.col("Tot Fwd Pkts") + pl.col("Tot Bwd Pkts")).sum(),
            total_bytes=(pl.col("TotLen Fwd Pkts") + pl.col("TotLen Bwd Pkts")).sum(),
            active_flows=pl.len(),
            
            flow_duration_mean=pl.col("Flow Duration").mean(),
            dst_ports_list=pl.col("Dst Port"),
            
            forward_packets=pl.col("Tot Fwd Pkts").sum(),
            backward_packets=pl.col("Tot Bwd Pkts").sum(),
            forward_bytes=pl.col("TotLen Fwd Pkts").sum(),
            backward_bytes=pl.col("TotLen Bwd Pkts").sum(),
            
            tcp_flows=(pl.col("Protocol") == 6).sum(),
            udp_flows=(pl.col("Protocol") == 17).sum(),
            
            syn_count=pl.col("SYN Flag Cnt").sum() if "SYN Flag Cnt" in actual_needed else pl.lit(0),
            rst_count=pl.col("RST Flag Cnt").sum() if "RST Flag Cnt" in actual_needed else pl.lit(0),
            
            iat_mean=pl.col("Flow IAT Mean").mean() if "Flow IAT Mean" in actual_needed else pl.lit(0.0),
            packet_size_mean=pl.col("Pkt Len Mean").mean() if "Pkt Len Mean" in actual_needed else pl.lit(0.0)
        )
        
        if update_callback: update_callback("Running Machine Learning inference...", 70)
        pd_df = pd.DataFrame(grouped.to_dicts())
        
        pd_df['packets_per_second'] = pd_df['total_packets'] / 1.0
        pd_df['bytes_per_second'] = pd_df['total_bytes'] / 1.0
        pd_df['tcp_ratio'] = pd_df['tcp_flows'] / (pd_df['active_flows'] + 1e-6)
        pd_df['udp_ratio'] = pd_df['udp_flows'] / (pd_df['active_flows'] + 1e-6)
        pd_df['destination_port_entropy'] = pd_df['dst_ports_list'].apply(entropy)
        
        pd_df = pd_df.fillna(0)
        
        results = []
        
        if self.predictor:
            self.predictor.state_buffer.clear()
            for idx, row in pd_df.iterrows():
                state_dict = row.to_dict()
                self.predictor.add_state(state_dict)
                timestamp = int(row['Timestamp'].timestamp() * 1000)
                pred = self.predictor.predict(timestamp)
                if pred:
                    pred['timestamp'] = row['Timestamp']
                    results.append(pred)
                    
        if update_callback: update_callback("Finalizing report...", 100)
                    
        return {
            "total_flows": len(df),
            "total_states": len(pd_df),
            "predictions": results
        }
