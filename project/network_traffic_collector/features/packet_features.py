from typing import Dict, Any, Optional
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet, Raw

def _extract_transport_features(packet: Packet, features: Dict[str, Any]) -> None:
    """Extract TCP/UDP transport-layer features from a packet (shared by IPv4 and IPv6)."""
    if TCP in packet:
        tcp_layer = packet[TCP]
        features['protocol'] = 'TCP'
        features['src_port'] = tcp_layer.sport
        features['dst_port'] = tcp_layer.dport
        
        flags_str = str(tcp_layer.flags)
        features['tcp_flags'] = flags_str
        features['tcp_flag_syn'] = 1 if 'S' in flags_str else 0
        features['tcp_flag_ack'] = 1 if 'A' in flags_str else 0
        features['tcp_flag_fin'] = 1 if 'F' in flags_str else 0
        features['tcp_flag_rst'] = 1 if 'R' in flags_str else 0
        features['tcp_flag_psh'] = 1 if 'P' in flags_str else 0
        features['tcp_flag_urg'] = 1 if 'U' in flags_str else 0
        features['tcp_flag_ece'] = 1 if 'E' in flags_str else 0
        features['tcp_flag_cwr'] = 1 if 'C' in flags_str else 0
        
        features['tcp_window'] = tcp_layer.window
        features['sequence_number'] = tcp_layer.seq
        features['acknowledgment_number'] = tcp_layer.ack
        
        if Raw in packet:
            features['payload_size'] = len(packet[Raw].load)
        else:
            features['payload_size'] = 0
            
    elif UDP in packet:
        udp_layer = packet[UDP]
        features['protocol'] = 'UDP'
        features['src_port'] = udp_layer.sport
        features['dst_port'] = udp_layer.dport
        
        if Raw in packet:
            features['payload_size'] = len(packet[Raw].load)
        else:
            features['payload_size'] = 0
    elif ICMP in packet:
        features['protocol'] = 'ICMP'
        if Raw in packet:
            features['payload_size'] = len(packet[Raw].load)
        else:
            features['payload_size'] = 0
    else:
        # Other IP protocols
        if IP in packet:
            features['protocol'] = f"IP_PROTO_{packet[IP].proto}"
        elif IPv6 in packet:
            features['protocol'] = f"IPv6_PROTO_{packet[IPv6].nh}"
        if Raw in packet:
            features['payload_size'] = len(packet[Raw].load)
        else:
            features['payload_size'] = 0

def extract_packet_features(packet: Packet, packet_number: int, last_timestamp: Optional[float] = None) -> Dict[str, Any]:
    """
    Extracts packet-level features for SIH26153 without saving raw payload content.
    Returns a dictionary of features. Uses None for unsupported/unavailable fields.
    """
    timestamp = float(packet.time)
    
    features = {
        'timestamp': timestamp,
        'packet_number': packet_number,
        'protocol': 'OTHER',
        'packet_length': len(packet),
        
        # IP
        'src_ip': None,
        'dst_ip': None,
        'ttl': None,
        'ip_id': None,
        'fragment_offset': None,
        'more_fragments': None,
        
        # TCP/UDP
        'src_port': None,
        'dst_port': None,
        
        # TCP specific
        'tcp_flags': None,
        'tcp_flag_syn': None,
        'tcp_flag_ack': None,
        'tcp_flag_fin': None,
        'tcp_flag_rst': None,
        'tcp_flag_psh': None,
        'tcp_flag_urg': None,
        'tcp_flag_ece': None,
        'tcp_flag_cwr': None,
        'tcp_window': None,
        'sequence_number': None,
        'acknowledgment_number': None,
        
        # Payload
        'payload_size': None,
        
        # Timing
        'iat': None,
        
        # Populated later by flow tracker
        'is_retransmission': None
    }
    
    if last_timestamp is not None:
        features['iat'] = max(0.0, timestamp - last_timestamp)
        
    if IP in packet:
        ip_layer = packet[IP]
        features['src_ip'] = ip_layer.src
        features['dst_ip'] = ip_layer.dst
        features['ttl'] = ip_layer.ttl
        features['ip_id'] = ip_layer.id
        features['fragment_offset'] = ip_layer.frag
        features['more_fragments'] = 1 if ip_layer.flags == 'MF' else 0
        _extract_transport_features(packet, features)
        
    elif IPv6 in packet:
        ip6_layer = packet[IPv6]
        features['src_ip'] = ip6_layer.src
        features['dst_ip'] = ip6_layer.dst
        features['ttl'] = ip6_layer.hlim  # Hop limit is the IPv6 equivalent of TTL
        _extract_transport_features(packet, features)
        
    elif ARP in packet:
        arp_layer = packet[ARP]
        features['protocol'] = 'ARP'
        features['src_ip'] = arp_layer.psrc
        features['dst_ip'] = arp_layer.pdst
    
    return features
