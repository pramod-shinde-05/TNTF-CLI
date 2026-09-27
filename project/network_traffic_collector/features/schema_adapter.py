import json
import os
import numpy as np
from typing import Dict, Any, List, Optional

class FeatureSchemaAdapter:
    def __init__(self, schema_path: str):
        self.schema_path = schema_path
        self.features_list = self._load_schema()
        
        # Protocol mapping
        self.proto_map = {
            'TCP': 6,
            'UDP': 17,
            'ICMP': 1,
            'ICMPv6': 58,
            'IPv4': 4,
            'IPv6': 41,
        }
        
    def _load_schema(self) -> List[str]:
        if not os.path.exists(self.schema_path):
            raise FileNotFoundError(f"Feature schema not found at {self.schema_path}")
            
        with open(self.schema_path, 'r') as f:
            schema = json.load(f)
            
        return [f['name'] for f in schema.get('features', [])]
        
    def validate_schema(self):
        """Validates that we can map features to the schema."""
        if not self.features_list:
            raise ValueError("Feature schema is empty.")
        print(f"Loaded schema with {len(self.features_list)} features.")
        
    def adapt(self, flow: Dict[str, Any]) -> dict:
        """
        Maps a live FlowTracker dictionary to the CIC-IDS2018 feature schema.
        Returns a dictionary mapping exactly to the schema feature names.
        """
        adapted = {}
        
        # Protocol mapping
        proto_str = flow.get('protocol', '')
        proto_num = self.proto_map.get(proto_str, 0)
        
        # Helper for stats
        def get_stat(key, default=0.0):
            return float(flow.get(key, default))
            
        # Build the dictionary mapping internal names to exact 15 CIC-IDS names
        mapping = {
            'protocol': proto_num,
            'dst_port': int(flow.get('dst_port', 0)),
            'flow_duration': get_stat('duration') * 1_000_000, # CIC-IDS2018 uses microseconds
            'tot_fwd_pkts': int(flow.get('forward_packet_count', 0)),
            'tot_bwd_pkts': int(flow.get('backward_packet_count', 0)),
            'totlen_fwd_pkts': int(flow.get('forward_byte_count', 0)),
            'totlen_bwd_pkts': int(flow.get('backward_byte_count', 0)),
            
            # Length stats
            'pkt_len_mean': get_stat('byte_count') / max(1.0, get_stat('packet_count')),
            'pkt_len_std': 0.0, # Approximate or leave 0 if not tracking
            'pkt_len_max': 0.0, # Approximate or leave 0 if not tracking
            
            'flow_pkts_s': get_stat('packets_per_second'),
            'flow_bytes_s': get_stat('bytes_per_second'),
            'flow_iat_mean': get_stat('iat_mean') * 1_000_000,
            'syn_flag_cnt': int(flow.get('syn_count', 0)),
            'rst_flag_cnt': int(flow.get('rst_count', 0)),
        }
        
        # We need pkt_len_max and pkt_len_std from fwd_lengths and bwd_lengths
        lengths = flow.get('fwd_lengths', []) + flow.get('bwd_lengths', [])
        if lengths:
            mapping['pkt_len_max'] = float(max(lengths))
            mean = sum(lengths) / len(lengths)
            variance = sum((x - mean) ** 2 for x in lengths) / max(1, len(lengths) - 1)
            mapping['pkt_len_std'] = float(variance ** 0.5)
        
        # Construct the final feature vector based strictly on the schema order
        for feat in self.features_list:
            adapted[feat] = mapping.get(feat, 0.0)
            
        return adapted
