import os
import pandas as pd
import numpy as np
import json
from tqdm import tqdm

SEQUENCE_LENGTH = 60
FUTURE_HORIZONS = [5, 10, 15, 30, 60]
GAP_THRESHOLD = pd.Timedelta(minutes=5)

def build_sequences():
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = os.path.dirname(SCRIPT_DIR)
    
    states_file = os.path.join(BASE_DIR, "master_dataset", "network_states.csv")
    output_dir = os.path.join(BASE_DIR, "sequences")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, 'tensors'), exist_ok=True)
    os.makedirs(os.path.join(output_dir, 'labels'), exist_ok=True)
    
    print(f"Loading {states_file}...")
    df = pd.read_csv(states_file)
    if df.empty:
        print("Dataset is empty.")
        return
        
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df = df.sort_values('Timestamp')
    
    time_diffs = df['Timestamp'].diff()
    session_starts = time_diffs > GAP_THRESHOLD
    session_starts.iloc[0] = True
    
    df['session_id'] = session_starts.cumsum()
    
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if 'session_id' in numeric_cols:
        numeric_cols = numeric_cols.drop('session_id')
        
    X = []
    Y = []
    
    total_sequences_created = 0
    total_sequences_discarded = 0
    
    session_metadata = []
    
    for session_id, session_df in tqdm(df.groupby('session_id'), desc="Processing sessions"):
        session_df = session_df.set_index('Timestamp')
        
        session_start = session_df.index.min()
        session_end = session_df.index.max()
        
        seq_start_idx = len(X) # Sequence index before processing this session
        
        df_resampled = session_df.resample('1s').asfreq()
        
        df_resampled[numeric_cols] = df_resampled[numeric_cols].fillna(0.0)
        df_resampled['Label'] = df_resampled['Label'].fillna('Benign')
        
        features = df_resampled[numeric_cols].values
        labels = df_resampled['Label'].values
        num_states = len(features)
        
        max_lookahead = FUTURE_HORIZONS[-1] // 1
        
        if num_states < SEQUENCE_LENGTH + max_lookahead:
            total_sequences_discarded += max(0, num_states - SEQUENCE_LENGTH + 1)
            continue
            
        for t in range(SEQUENCE_LENGTH - 1, num_states):
            if t + max_lookahead >= num_states:
                total_sequences_discarded += 1
                continue
                
            seq_x = features[t - SEQUENCE_LENGTH + 1 : t + 1]
            
            future_labels = {
                "now": labels[t],
                "future_5s": labels[t + 5],
                "future_10s": labels[t + 10],
                "future_15s": labels[t + 15],
                "future_30s": labels[t + 30],
                "future_60s": labels[t + 60]
            }
            
            X.append(seq_x)
            Y.append(future_labels)
            total_sequences_created += 1
            
        seq_end_idx = len(X)
        if seq_end_idx > seq_start_idx:
            session_metadata.append({
                "session_id": int(session_id),
                "start_time": str(session_start),
                "end_time": str(session_end),
                "seq_start_idx": seq_start_idx,
                "seq_end_idx": seq_end_idx
            })
            
    if not X:
        print("No sequences could be created!")
        return
        
    X = np.array(X, dtype=np.float32)
    
    np.save(os.path.join(output_dir, 'tensors', "master_flows_X.npy"), X)
    with open(os.path.join(output_dir, 'labels', "master_flows_Y.json"), "w") as f:
        json.dump(Y, f)
    with open(os.path.join(output_dir, 'session_boundaries.json'), "w") as f:
        json.dump(session_metadata, f, indent=4)
        
    print(f"Generated {len(X)} sequences.")
    
    report_path = os.path.join(os.environ.get('HOME', '/home/pramod'), '.gemini/antigravity-ide/brain/1437d92f-d386-4667-b0af-f432bc1659fc/dataset_report.md')
    if os.path.exists(report_path):
        with open(report_path, "a") as f:
            f.write("\n## Sequence Generation Stats\n")
            f.write(f"- **Sequences Created**: {total_sequences_created}\n")
            f.write(f"- **Sequences Discarded (Gap Boundaries)**: {total_sequences_discarded}\n")
            f.write(f"- **Total Distinct Sessions Found (Gap > 5m)**: {len(session_metadata)}\n")
            
            f.write("\n### Session Boundaries\n")
            for sm in session_metadata:
                f.write(f"- Session {sm['session_id']}: `{sm['start_time']}` to `{sm['end_time']}` (Seqs: {sm['seq_start_idx']}-{sm['seq_end_idx']})\n")

if __name__ == "__main__":
    build_sequences()
