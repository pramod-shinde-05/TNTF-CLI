import os
import numpy as np
import json
import glob
from collections import Counter
from sklearn.model_selection import train_test_split

def balance_and_split(sequences_dir, output_dir, target_count=50000):
    os.makedirs(output_dir, exist_ok=True)
    tensors_dir = os.path.join(sequences_dir, 'tensors')
    labels_dir = os.path.join(sequences_dir, 'labels')
    
    all_x = []
    all_y = []
    
    file_paths = glob.glob(os.path.join(tensors_dir, "*_X.npy"))
    
    print("Loading all sequences into memory...")
    for x_path in file_paths:
        basename = os.path.basename(x_path).replace("_X.npy", "")
        if basename in ["train_split", "val_split", "test_split", "balanced"]:
            continue
            
        y_path = os.path.join(labels_dir, f"{basename}_Y.json")
        
        if os.path.exists(y_path):
            x = np.load(x_path)
            with open(y_path, "r") as f:
                y = json.load(f)
                
            all_x.append(x)
            all_y.extend(y)
            
    if not all_x:
        print("No sequence files found!")
        return
        
    all_x = np.vstack(all_x)
    
    # Extract the 'now' label for balancing
    labels = np.array([item['now'] for item in all_y])
    unique_labels = np.unique(labels)
    
    print(f"Original class distribution: {Counter(labels)}")
    
    balanced_x = []
    balanced_y = []
    
    # Identify Benign vs Attack indices
    benign_idx = np.where(labels == "Benign")[0]
    attack_idx = np.where(labels != "Benign")[0]
    
    # Cap Benign to exactly the number of attacks to achieve perfect 50/50 balance
    np.random.seed(42)
    attack_count = len(attack_idx)
    if len(benign_idx) > attack_count:
        chosen_benign = np.random.choice(benign_idx, attack_count, replace=False)
    else:
        chosen_benign = benign_idx
        
    chosen_attack = attack_idx
        
    chosen_indices_flat = np.concatenate([chosen_benign, chosen_attack])
    # Randomly shuffle to ensure all splits get a fair distribution of classes
    np.random.shuffle(chosen_indices_flat)
    
    balanced_x = all_x[chosen_indices_flat]
    balanced_y = [all_y[i] for i in chosen_indices_flat]
        
    # (Already sorted and extracted above)
    
    print(f"Balanced class distribution: {Counter([item['now'] for item in balanced_y])}")
    
    # 70/15/15 split
    total_len = len(balanced_x)
    print(f"Total balanced sequences: {total_len}. Splitting 70/15/15...")
    
    train_end = int(total_len * 0.70)
    val_end = int(total_len * 0.85)
    
    x_train = balanced_x[:train_end]
    y_train = balanced_y[:train_end]
    
    x_val = balanced_x[train_end:val_end]
    y_val = balanced_y[train_end:val_end]
    
    x_test = balanced_x[val_end:]
    y_test = balanced_y[val_end:]
    
    # Save the unified splits
    np.save(os.path.join(tensors_dir, "train_split_X.npy"), x_train)
    with open(os.path.join(labels_dir, "train_split_Y.json"), "w") as f:
        json.dump(y_train, f)
        
    np.save(os.path.join(tensors_dir, "val_split_X.npy"), x_val)
    with open(os.path.join(labels_dir, "val_split_Y.json"), "w") as f:
        json.dump(y_val, f)
        
    np.save(os.path.join(tensors_dir, "test_split_X.npy"), x_test)
    with open(os.path.join(labels_dir, "test_split_Y.json"), "w") as f:
        json.dump(y_test, f)
        
    splits = {
        "train": ["train_split"],
        "validation": ["val_split"],
        "test": ["test_split"]
    }
    
    with open(os.path.join(output_dir, "split_manifest.json"), "w") as f:
        json.dump(splits, f, indent=4)
        
    print(f"Splits generated successfully at {output_dir}/split_manifest.json")

if __name__ == "__main__":
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(SCRIPT_DIR, "splits")
    sequences_dir = os.path.join(SCRIPT_DIR, "sequences")
    balance_and_split(sequences_dir, output_dir, target_count=50000)
