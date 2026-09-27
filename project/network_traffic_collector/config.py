import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

# Default network interface to sniff on. 
# Set to None to use Scapy's default or provide a string like 'eth0' or 'wlan0'
# DEFAULT_INTERFACE = None
DEFAULT_INTERFACE = "eth0"

# How often to print flow updates to the terminal (in seconds)
DISPLAY_UPDATE_INTERVAL = 2.0

# Whether to save payload data
SAVE_PAYLOAD = False

# ML Pipeline Configuration
MIN_PACKETS_FOR_ML = 10
MIN_FLOW_DURATION = 0.5
MODEL_PATH = BASE_DIR.parent / "models" / "temporal_transformer" / "artifacts_v6" / "model.pt"
FEATURE_SCHEMA_PATH = BASE_DIR.parent / "configs" / "feature_schema.json"
