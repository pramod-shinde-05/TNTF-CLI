from typing import Dict, Any, Optional, List, Tuple
import time
from collections import defaultdict

class FlowTracker:
    def __init__(self, flow_timeout: float = 60.0, port_scan_window: float = 10.0, port_scan_threshold: int = 5):
        self.flows: Dict[str, Dict[str, Any]] = {}
        self.flow_timeout = flow_timeout
        self.next_flow_id = 1
        
        # Port scan detection settings
        self.port_scan_window = port_scan_window
        self.port_scan_threshold = port_scan_threshold
        # Tracks src_ip -> list of (timestamp, dst_ip, dst_port)
        self.source_tracker: Dict[str, List[Tuple[float, str, int]]] = defaultdict(list)
        
    def _generate_flow_key(self, features: Dict[str, Any]) -> str:
        """
        Generate a unique flow key from the 5-tuple. 
        Bidirectional flow considers A->B and B->A as the same flow.
        """
        src = features.get('src_ip') or ''
        dst = features.get('dst_ip') or ''
        sport = features.get('src_port') or 0
        dport = features.get('dst_port') or 0
        proto = features.get('protocol', '')
        
        # Sort IP and ports to make it bidirectional
        if src < dst:
            endpoint1 = f"{src}:{sport}"
            endpoint2 = f"{dst}:{dport}"
        elif src > dst:
            endpoint1 = f"{dst}:{dport}"
            endpoint2 = f"{src}:{sport}"
        else:
            if sport < dport:
                endpoint1 = f"{src}:{sport}"
                endpoint2 = f"{dst}:{dport}"
            else:
                endpoint1 = f"{dst}:{dport}"
                endpoint2 = f"{src}:{sport}"
                
        return f"{endpoint1}-{endpoint2}-{proto}"

    def _update_source_tracker(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float) -> bool:
        """
        Update the tracker for a given source IP and return True if it indicates a port scan.
        A port scan is detected if the source contacts more than threshold unique (dst_ip, dst_port) 
        within the sliding time window.
        """
        history = self.source_tracker[src_ip]
        
        # Add new entry
        history.append((timestamp, dst_ip, dst_port))
        
        # Clean up entries older than the window
        cutoff = timestamp - self.port_scan_window
        history = [entry for entry in history if entry[0] > cutoff]
        self.source_tracker[src_ip] = history
        
        # Count unique (dst_ip, dst_port) pairs
        unique_targets = set((entry[1], entry[2]) for entry in history)
        
        return len(unique_targets) >= self.port_scan_threshold

    def update_flow(self, packet_features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # We only track IP flows that have source/dest
        if not packet_features.get('src_ip') or not packet_features.get('dst_ip'):
            return None
            
        key = self._generate_flow_key(packet_features)
        timestamp = packet_features['timestamp']
        length = packet_features['packet_length']
        
        # Check port scan using source tracking
        is_port_scan = self._update_source_tracker(
            packet_features['src_ip'], 
            packet_features['dst_ip'], 
            packet_features['dst_port'], 
            timestamp
        )
        
        # New flow initialization
        if key not in self.flows:
            self.flows[key] = {
                'flow_id': f"{self.next_flow_id:06d}",
                'start_time': timestamp,
                'end_time': timestamp,
                
                # Flow initiator properties
                'src_ip': packet_features['src_ip'],
                'dst_ip': packet_features['dst_ip'],
                'src_port': packet_features['src_port'],
                'dst_port': packet_features['dst_port'],
                'protocol': packet_features['protocol'],
                
                # Aggregated stats
                'duration': 0.0,
                'packet_count': 0,
                'byte_count': 0,
                'forward_packet_count': 0,
                'backward_packet_count': 0,
                'forward_byte_count': 0,
                'backward_byte_count': 0,
                
                # Length stats
                'fwd_lengths': [],
                'bwd_lengths': [],
                
                'bidirectional_ratio': 0.0,
                'packets_per_second': 0.0,
                'bytes_per_second': 0.0,
                
                # TCP specific
                'syn_count': 0,
                'ack_count': 0,
                'fin_count': 0,
                'rst_count': 0,
                'psh_count': 0,
                'urg_count': 0,
                'ece_count': 0,
                'cwr_count': 0,
                'syn_ratio': 0.0,
                'ack_ratio': 0.0,
                'fin_ratio': 0.0,
                'rst_ratio': 0.0,
                'retransmission_count': 0,
                'init_fwd_win_bytes': -1,
                'init_bwd_win_bytes': -1,
                
                # IAT tracking
                'iats': [],
                'iat_mean': 0.0,
                'iat_variance': 0.0,
                'iat_max': 0.0,
                
                # Indicators
                'port_scan_indicator': is_port_scan,
                
                # Internal state for tracking retransmissions
                '_fwd_max_seq': -1,
                '_bwd_max_seq': -1
            }
            self.next_flow_id += 1
            
        flow = self.flows[key]
        
        # Determine direction
        is_forward = (packet_features['src_ip'] == flow['src_ip'] and 
                      packet_features['src_port'] == flow['src_port'])
        
        if is_forward:
            flow['forward_packet_count'] += 1
            flow['forward_byte_count'] += length
            flow['fwd_lengths'].append(length)
        else:
            flow['backward_packet_count'] += 1
            flow['backward_byte_count'] += length
            flow['bwd_lengths'].append(length)
            
        flow['packet_count'] += 1
            
        # Detect Retransmissions (TCP only)
        # Extremely basic heuristic: if seq <= max seen seq in this direction, and payload > 0
        is_retrans = False
        seq = packet_features.get('sequence_number')
        payload = packet_features.get('payload_size') or 0
        
        if seq is not None and packet_features.get('protocol') == 'TCP' and payload > 0:
            if is_forward:
                if seq <= flow['_fwd_max_seq']:
                    is_retrans = True
                else:
                    flow['_fwd_max_seq'] = seq
            else:
                if seq <= flow['_bwd_max_seq']:
                    is_retrans = True
                else:
                    flow['_bwd_max_seq'] = seq
                    
        # Annotate the packet_features BEFORE we return
        packet_features['is_retransmission'] = is_retrans
        if is_retrans:
            flow['retransmission_count'] += 1

        # Calculate IAT
        if flow['packet_count'] > 0:
            flow_iat = max(0.0, timestamp - flow['end_time'])
            flow['iats'].append(flow_iat)
            
        # Update basic stats
        flow['end_time'] = timestamp
        flow['duration'] = max(0.0, flow['end_time'] - flow['start_time'])
        flow['packet_count'] += 1
        flow['byte_count'] += length
        
        # Bidir ratio
        flow['bidirectional_ratio'] = flow['forward_packet_count'] / max(1, flow['packet_count'])
        
        # Rates
        duration = max(0.0001, flow['duration'])
        flow['packets_per_second'] = flow['packet_count'] / duration
        flow['bytes_per_second'] = flow['byte_count'] / duration
        
        # TCP Flags
        if packet_features.get('tcp_flag_syn'): flow['syn_count'] += 1
        if packet_features.get('tcp_flag_ack'): flow['ack_count'] += 1
        if packet_features.get('tcp_flag_fin'): flow['fin_count'] += 1
        if packet_features.get('tcp_flag_rst'): flow['rst_count'] += 1
        if packet_features.get('tcp_flag_psh'): flow['psh_count'] += 1
        if packet_features.get('tcp_flag_urg'): flow['urg_count'] += 1
        if packet_features.get('tcp_flag_ece'): flow['ece_count'] += 1
        if packet_features.get('tcp_flag_cwr'): flow['cwr_count'] += 1
        
        # TCP Initial Window
        if packet_features.get('protocol') == 'TCP':
            win = packet_features.get('tcp_window')
            if win is not None:
                if is_forward and flow['init_fwd_win_bytes'] == -1:
                    flow['init_fwd_win_bytes'] = win
                elif not is_forward and flow['init_bwd_win_bytes'] == -1:
                    flow['init_bwd_win_bytes'] = win
        
        pc = flow['packet_count']
        flow['syn_ratio'] = flow['syn_count'] / pc
        flow['ack_ratio'] = flow['ack_count'] / pc
        flow['fin_ratio'] = flow['fin_count'] / pc
        flow['rst_ratio'] = flow['rst_count'] / pc
        
        # If it wasn't a port scan before, update it if it is now
        if not flow['port_scan_indicator'] and is_port_scan:
            flow['port_scan_indicator'] = True

        # IAT stats
        if flow['iats']:
            flow['iat_mean'] = sum(flow['iats']) / len(flow['iats'])
            flow['iat_max'] = max(flow['iats'])
            if len(flow['iats']) > 1:
                mean = flow['iat_mean']
                variance = sum((x - mean) ** 2 for x in flow['iats']) / (len(flow['iats']) - 1)
                flow['iat_variance'] = variance
                
        return flow
        
    def clean_old_flows(self, current_time: float) -> List[Dict[str, Any]]:
        """Remove flows that haven't seen traffic in a while, return them."""
        expired_keys = []
        for key, flow in self.flows.items():
            if current_time - flow['end_time'] > self.flow_timeout:
                expired_keys.append(key)
                
        expired_flows = [self.flows.pop(k) for k in expired_keys]
        
        # Clean up old source trackers
        cleanup_cutoff = current_time - self.port_scan_window
        stale_srcs = []
        for src, history in self.source_tracker.items():
            # keep only recent
            fresh = [entry for entry in history if entry[0] > cleanup_cutoff]
            if not fresh:
                stale_srcs.append(src)
            else:
                self.source_tracker[src] = fresh
                
        for src in stale_srcs:
            del self.source_tracker[src]
            
        return expired_flows
        
    def get_all_flows(self) -> List[Dict[str, Any]]:
        """Return all active flows"""
        return list(self.flows.values())
