#!/bin/bash
set -e

echo "Training Temporal Transformer..."
PYTHONPATH=. python3 models/temporal_transformer/train_v6.py

echo "Evaluating Temporal Transformer..."
PYTHONPATH=. python3 models/temporal_transformer/evaluate_model.py

echo "Pipeline Finished!"
