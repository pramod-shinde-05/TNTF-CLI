import os
import csv
import json
from datetime import datetime
from typing import Dict, Any

class CSVWriter:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.session_dir = None
        self.packets_file = None
        self.flows_file = None
        self.packets_writer = None
        self.flows_writer = None
        self._initialize_session()

    def _initialize_session(self):
        # Create session directory like data/2026-08-22_07-30-15
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.session_dir = os.path.join(self.data_dir, timestamp)
        os.makedirs(self.session_dir, exist_ok=True)
        
        # Write basic metadata
        metadata = {
            'session_start': timestamp,
            'description': 'Network traffic capture session (SIH26153)'
        }
        with open(os.path.join(self.session_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=4)
            
        # Initialize CSVs
        self.packets_file = open(os.path.join(self.session_dir, 'packets.csv'), 'w', newline='')
        self.flows_file = open(os.path.join(self.session_dir, 'flows.csv'), 'w', newline='')
        
        packet_fieldnames = [
            'timestamp', 'packet_number', 'protocol', 'packet_length',
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 
            'ttl', 'ip_id', 'fragment_offset', 'more_fragments', 
            'tcp_flags', 'tcp_flag_syn', 'tcp_flag_ack', 'tcp_flag_fin', 
            'tcp_flag_rst', 'tcp_flag_psh', 'tcp_flag_urg', 'tcp_flag_ece', 'tcp_flag_cwr',
            'tcp_window', 'sequence_number', 'acknowledgment_number', 
            'payload_size', 'iat', 'is_retransmission'
        ]
        
        flow_fieldnames = [
            'flow_id', 'start_time', 'end_time', 
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
            'duration', 'packet_count', 'byte_count', 
            'forward_packet_count', 'backward_packet_count',
            'forward_byte_count', 'backward_byte_count', 'bidirectional_ratio',
            'packets_per_second', 'bytes_per_second', 
            'syn_count', 'ack_count', 'fin_count', 'rst_count', 
            'syn_ratio', 'ack_ratio', 'fin_ratio', 'rst_ratio',
            'retransmission_count', 'port_scan_indicator',
            'iat_mean', 'iat_variance', 'iat_max',
            'init_fwd_win_bytes', 'init_bwd_win_bytes',
            'psh_count', 'urg_count', 'ece_count', 'cwr_count'
        ]
        
        self.packets_writer = csv.DictWriter(self.packets_file, fieldnames=packet_fieldnames)
        self.packets_writer.writeheader()
        
        self.flows_writer = csv.DictWriter(self.flows_file, fieldnames=flow_fieldnames)
        self.flows_writer.writeheader()

    def _sanitize_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """Convert None values to empty strings to represent NULL in CSV."""
        return {k: ("" if v is None else v) for k, v in d.items()}

    def write_packet(self, features: Dict[str, Any]):
        clean_features = self._sanitize_dict(features)
        self.packets_writer.writerow(clean_features)
        
    def write_flow(self, flow: Dict[str, Any]):
        # Filter out internal/intermediate tracking fields that shouldn't go to CSV
        internal_keys = ['iats', '_fwd_max_seq', '_bwd_max_seq', 'fwd_lengths', 'bwd_lengths']
        flow_copy = {k: v for k, v in flow.items() if k not in internal_keys}
        clean_flow = self._sanitize_dict(flow_copy)
        self.flows_writer.writerow(clean_flow)

    def close(self):
        if self.packets_file:
            self.packets_file.close()
        if self.flows_file:
            self.flows_file.close()
