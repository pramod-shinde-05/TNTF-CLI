#!/bin/bash
set -e

echo "1. Cleaning dataset..."
python3 dataset_v2/dataset_cleaning.py

echo "2. Building state windows..."
python3 dataset_v2/state_builder/state_compiler.py

echo "3. Compiling sequences..."
rm -rf dataset_v2/sequences/tensors/* dataset_v2/sequences/labels/*
python3 dataset_v2/state_builder/sequence_compiler.py

echo "4. Balancing and Splitting sequences..."
python3 dataset_v2/dataset_builder.py

echo "Dataset Generation Pipeline Complete!"
