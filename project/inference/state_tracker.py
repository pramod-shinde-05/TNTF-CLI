import numpy as np
from scipy.stats import entropy

class StateTracker:
    def __init__(self):
        # Per-flow state for delta tracking.
        # Maps flow_id -> {'syn', 'rst', 'fwd_pkts', 'bwd_pkts', 'fwd_bytes', 'bwd_bytes'}
        self._prev = {}
        
    def compute_state(self, active_flows, current_time):
        """
        active_flows: list of flow dictionaries from flow_tracker
        Returns a dictionary containing the 15 features representing the overall network state.
        This matches exactly with dataset_v2/state_builder/state_compiler.py
        """
        # Feature initialization
        feature_names = [
            "active_flows", "forward_packets", "backward_packets", "forward_bytes",
            "backward_bytes", "packet_size_mean", "packets_per_second", "bytes_per_second",
            "tcp_ratio", "udp_ratio", "iat_mean", "syn_count", "rst_count",
            "destination_port_entropy", "flow_duration_mean"
        ]
        
        if not active_flows:
            return {feat: 0.0 for feat in feature_names}
            
        state = {}
        
        state['active_flows'] = len(active_flows)
        
        fin_count = sum(f.get('fin_count', 0) for f in active_flows)
        rst_count = sum(f.get('rst_count', 0) for f in active_flows)
        state['closed_flows'] = fin_count + rst_count
        
        durations = [f.get('duration', 0.0) * 1e6 for f in active_flows]
        state['flow_duration_mean'] = float(np.mean(durations)) if durations else 0.0
        state['flow_duration_std'] = float(np.std(durations, ddof=1)) if len(durations) > 1 else 0.0
        
        dst_ports = [int(f.get('dst_port')) if f.get('dst_port') is not None else 0 for f in active_flows]
        unique_ports = set(dst_ports)
        state['unique_destination_ports'] = len(unique_ports)
        
        # --- Delta tracking for packets, bytes, SYN, RST ---
        delta_fwd_pkts = 0
        delta_bwd_pkts = 0
        delta_fwd_bytes = 0
        delta_bwd_bytes = 0
        delta_syn = 0
        delta_rst = 0
        current_flow_ids = set()
        
        for f in active_flows:
            fid = f.get('flow_id')
            current_flow_ids.add(fid)
            
            cur_fwd_pkts  = f.get('forward_packet_count', 0)
            cur_bwd_pkts  = f.get('backward_packet_count', 0)
            cur_fwd_bytes = f.get('forward_byte_count', 0)
            cur_bwd_bytes = f.get('backward_byte_count', 0)
            cur_syn       = f.get('syn_count', 0)
            cur_rst       = f.get('rst_count', 0)
            
            prev = self._prev.get(fid, {
                'fwd_pkts': 0, 'bwd_pkts': 0,
                'fwd_bytes': 0, 'bwd_bytes': 0,
                'syn': 0, 'rst': 0
            })
            
            delta_fwd_pkts  += max(0, cur_fwd_pkts  - prev['fwd_pkts'])
            delta_bwd_pkts  += max(0, cur_bwd_pkts  - prev['bwd_pkts'])
            delta_fwd_bytes += max(0, cur_fwd_bytes - prev['fwd_bytes'])
            delta_bwd_bytes += max(0, cur_bwd_bytes - prev['bwd_bytes'])
            delta_syn       += max(0, cur_syn       - prev['syn'])
            delta_rst       += max(0, cur_rst       - prev['rst'])
            
            self._prev[fid] = {
                'fwd_pkts': cur_fwd_pkts, 'bwd_pkts': cur_bwd_pkts,
                'fwd_bytes': cur_fwd_bytes, 'bwd_bytes': cur_bwd_bytes,
                'syn': cur_syn, 'rst': cur_rst
            }
        
        # Clean up expired flows
        for fid in list(self._prev.keys()):
            if fid not in current_flow_ids:
                del self._prev[fid]
        
        state['forward_packets']  = delta_fwd_pkts
        state['backward_packets'] = delta_bwd_pkts
        state['forward_bytes']    = delta_fwd_bytes
        state['backward_bytes']   = delta_bwd_bytes
        
        state['tcp_flows'] = sum(1 for f in active_flows if f.get('protocol') in ['TCP', 6])
        state['udp_flows'] = sum(1 for f in active_flows if f.get('protocol') in ['UDP', 17])
        state['icmp_flows'] = sum(1 for f in active_flows if f.get('protocol') in ['ICMP', 1])
        
        state['is_http_flows'] = sum(1 for p in dst_ports if p in [80, 8080])
        state['is_https_flows'] = sum(1 for p in dst_ports if p == 443)
        
        state['syn_count'] = delta_syn
        state['ack_count'] = sum(f.get('ack_count', 0) for f in active_flows)
        state['fin_count'] = fin_count
        state['rst_count'] = delta_rst
        
        iats_mean = [f.get('iat_mean', 0.0) * 1e6 for f in active_flows]
        state['iat_mean'] = float(np.mean(iats_mean)) if iats_mean else 0.0
        
        iats_stds = [np.sqrt(f.get('iat_variance', 0.0)) for f in active_flows]
        state['iat_std'] = float(np.mean(iats_stds)) if iats_stds else 0.0
        
        iats_max = [f.get('iat_max', 0.0) for f in active_flows]
        state['iat_max'] = float(np.max(iats_max)) if iats_max else 0.0
        
        pkt_sizes = [f.get('byte_count', 0) / max(f.get('packet_count', 1), 1) for f in active_flows]
        state['packet_size_mean'] = float(np.mean(pkt_sizes)) if pkt_sizes else 0.0
        
        total_delta_packets = delta_fwd_pkts + delta_bwd_pkts
        total_delta_bytes   = delta_fwd_bytes + delta_bwd_bytes
        state['packets_per_second'] = total_delta_packets / 1.0
        state['bytes_per_second']   = total_delta_bytes / 1.0
        state['forward_ratio'] = delta_fwd_pkts / (total_delta_packets + 1e-6)
        state['tcp_ratio'] = state['tcp_flows'] / (state['active_flows'] + 1e-6)
        state['udp_ratio'] = state['udp_flows'] / (state['active_flows'] + 1e-6)
        
        # New TCP Flags
        state['psh_count'] = sum(f.get('psh_count', 0) for f in active_flows)
        state['urg_count'] = sum(f.get('urg_count', 0) for f in active_flows)
        state['ece_count'] = sum(f.get('ece_count', 0) for f in active_flows)
        state['cwe_count'] = sum(f.get('cwr_count', 0) for f in active_flows)
        
        # Win bytes (mean of init win bytes)
        fwd_wins = [f.get('init_fwd_win_bytes', 0) for f in active_flows if f.get('init_fwd_win_bytes', -1) != -1]
        bwd_wins = [f.get('init_bwd_win_bytes', 0) for f in active_flows if f.get('init_bwd_win_bytes', -1) != -1]
        state['init_fwd_win_bytes'] = float(np.mean(fwd_wins)) if fwd_wins else 0.0
        state['init_bwd_win_bytes'] = float(np.mean(bwd_wins)) if bwd_wins else 0.0
        
        # Packet sizes for exact parity with offline Pkt Len statistics
        # Offline takes average of the flows' Pkt Len Mean
        flow_pkt_means = [np.mean(f.get('fwd_lengths', []) + f.get('bwd_lengths', [])) for f in active_flows if (f.get('fwd_lengths', []) + f.get('bwd_lengths', []))]
        state['pkt_len_mean'] = float(np.mean(flow_pkt_means)) if flow_pkt_means else 0.0
        
        flow_pkt_stds = [np.std(f.get('fwd_lengths', []) + f.get('bwd_lengths', []), ddof=1) for f in active_flows if len(f.get('fwd_lengths', []) + f.get('bwd_lengths', [])) > 1]
        state['pkt_len_std'] = float(np.mean(flow_pkt_stds)) if flow_pkt_stds else 0.0
        
        flow_pkt_maxs = [np.max(f.get('fwd_lengths', []) + f.get('bwd_lengths', [])) for f in active_flows if (f.get('fwd_lengths', []) + f.get('bwd_lengths', []))]
        state['pkt_len_max'] = float(np.max(flow_pkt_maxs)) if flow_pkt_maxs else 0.0
        
        # Entropy
        if not dst_ports:
            state['destination_port_entropy'] = 0.0
        else:
            unique, counts = np.unique(dst_ports, return_counts=True)
            state['destination_port_entropy'] = float(entropy(counts, base=2))
            
        # New flows approximation
        state['new_flows'] = state['active_flows']
        
        state['new_destination_ports'] = state['unique_destination_ports']
        
        return state
