import os
import json
import numpy as np

SEQUENCE_LENGTH = 12
GAP = SEQUENCE_LENGTH - 1  # 11

def perform_stratified_split():
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    tensors_dir = os.path.join(SCRIPT_DIR, "sequences", "tensors")
    labels_dir = os.path.join(SCRIPT_DIR, "sequences", "labels")
    
    x_path = os.path.join(tensors_dir, "master_flows_X.npy")
    y_path = os.path.join(labels_dir, "master_flows_Y.json")
    bounds_path = os.path.join(SCRIPT_DIR, "sequences", "session_boundaries.json")
    
    print("Loading data...")
    X = np.load(x_path)
    with open(y_path, "r") as f:
        Y = json.load(f)
    with open(bounds_path, "r") as f:
        sessions = json.load(f)
        
    print(f"Loaded {len(X)} sequences across {len(sessions)} sessions.")
    
    train_indices = []
    val_indices = []
    test_indices = []
    
    # Track allocations to balance small blocks
    # class -> {'train': 0, 'val': 0, 'test': 0}
    allocs = {}
    
    def get_target_split(label):
        if label not in allocs:
            allocs[label] = {'train': 0, 'val': 0, 'test': 0}
        
        counts = allocs[label]
        total = sum(counts.values())
        if total == 0:
            return 'train'
            
        ratios = {
            'train': counts['train'] / total,
            'val': counts['val'] / total,
            'test': counts['test'] / total
        }
        
        targets = {'train': 0.70, 'val': 0.15, 'test': 0.15}
        
        # Find split that is furthest behind its target
        diffs = {k: targets[k] - ratios[k] for k in targets}
        return max(diffs, key=diffs.get)

    for session in sessions:
        start_idx = session['seq_start_idx']
        end_idx = session['seq_end_idx']
        
        # Find contiguous blocks of the same label within the session
        current_label = Y[start_idx]['now']
        block_start = start_idx
        
        blocks = []
        for i in range(start_idx, end_idx):
            if Y[i]['now'] != current_label:
                blocks.append((current_label, block_start, i))
                current_label = Y[i]['now']
                block_start = i
        blocks.append((current_label, block_start, end_idx))
        
        # Process each block
        for label, b_start, b_end in blocks:
            N = b_end - b_start
            if label not in allocs:
                allocs[label] = {'train': 0, 'val': 0, 'test': 0}
                
            if N >= 25:
                # Split block into 3 parts, dropping 11 sequences at each of the 2 boundaries
                avail = N - (2 * GAP)
                
                train_len = max(1, int(avail * 0.70))
                val_len = max(1, int(avail * 0.15))
                test_len = avail - train_len - val_len
                
                t_end = b_start + train_len
                train_indices.extend(range(b_start, t_end))
                allocs[label]['train'] += train_len
                
                v_start = t_end + GAP
                v_end = v_start + val_len
                val_indices.extend(range(v_start, v_end))
                allocs[label]['val'] += val_len
                
                te_start = v_end + GAP
                te_end = b_end
                test_indices.extend(range(te_start, te_end))
                allocs[label]['test'] += (te_end - te_start)
                
            else:
                # Block too small to safely split and drop overlap.
                # Assign to the split that needs it most.
                target = get_target_split(label)
                if target == 'train':
                    train_indices.extend(range(b_start, b_end))
                    allocs[label]['train'] += N
                elif target == 'val':
                    val_indices.extend(range(b_start, b_end))
                    allocs[label]['val'] += N
                else:
                    test_indices.extend(range(b_start, b_end))
                    allocs[label]['test'] += N
                    
    print("\n--- Split Allocation Statistics ---")
    for label, counts in allocs.items():
        total = sum(counts.values())
        print(f"[{label}] Total: {total} -> Train: {counts['train']} ({counts['train']/total:.1%}), Val: {counts['val']} ({counts['val']/total:.1%}), Test: {counts['test']} ({counts['test']/total:.1%})")
        
    print(f"\nTotal Train: {len(train_indices)}")
    print(f"Total Val: {len(val_indices)}")
    print(f"Total Test: {len(test_indices)}")
    
    # Save the arrays
    print("\nSaving split files...")
    np.save(os.path.join(tensors_dir, "train_split_X.npy"), X[train_indices])
    np.save(os.path.join(tensors_dir, "val_split_X.npy"), X[val_indices])
    np.save(os.path.join(tensors_dir, "test_split_X.npy"), X[test_indices])
    
    Y_train = [Y[i] for i in train_indices]
    Y_val = [Y[i] for i in val_indices]
    Y_test = [Y[i] for i in test_indices]
    
    with open(os.path.join(labels_dir, "train_split_Y.json"), "w") as f:
        json.dump(Y_train, f)
    with open(os.path.join(labels_dir, "val_split_Y.json"), "w") as f:
        json.dump(Y_val, f)
    with open(os.path.join(labels_dir, "test_split_Y.json"), "w") as f:
        json.dump(Y_test, f)
        
    print("Done!")

if __name__ == "__main__":
    perform_stratified_split()
