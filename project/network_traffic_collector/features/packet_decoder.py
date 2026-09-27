from typing import Dict, Any, List
import time
import os

# Scapy layers
from scapy.packet import Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, IPv6ExtHdrFragment
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dhcp import DHCP, BOOTP

DEBUG_MISSING_ADDRESSES = False

def decode_packet(packet: Packet, packet_number: int) -> Dict[str, Any]:
    """
    Decodes a Scapy packet into a hierarchical structure for the UI.
    Extracts L2-L7 information and generates a Wireshark-style Info summary.
    """
    decoded = {
        'protocol': 'OTHER',
        'info': '',
        'source': 'None',
        'destination': 'None',
        'tree': [],
        'raw_summary': packet.summary()
    }
    
    # Base Frame info
    frame_details = {
        'Frame number': packet_number,
        'Timestamp': f"{packet.time:.6f}",
        'Captured length': len(packet),
    }
    decoded['tree'].append({'name': 'Frame', 'details': frame_details})
    
    highest_layer = "Frame"
    info_summary = ""
    
    # ---------------------------------------------------------
    # Layer 2: Ethernet / ARP
    # ---------------------------------------------------------
    if packet.haslayer(Ether):
        eth = packet[Ether]
        highest_layer = "Ethernet"
        eth_details = {
            'Source MAC': eth.src,
            'Destination MAC': eth.dst,
            'EtherType': hex(eth.type) if isinstance(eth.type, int) else eth.type
        }
        decoded['tree'].append({'name': 'Ethernet II', 'details': eth_details})
        
    if packet.haslayer(ARP):
        arp = packet[ARP]
        highest_layer = "ARP"
        decoded['protocol'] = "ARP"
        
        op_map = {1: 'Request', 2: 'Reply'}
        op_str = op_map.get(arp.op, str(arp.op))
        
        arp_details = {
            'Operation': op_str,
            'Sender MAC': arp.hwsrc,
            'Sender IP': arp.psrc,
            'Target MAC': arp.hwdst,
            'Target IP': arp.pdst
        }
        decoded['tree'].append({'name': 'ARP', 'details': arp_details})
        
        if arp.op == 1:
            info_summary = f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif arp.op == 2:
            info_summary = f"{arp.psrc} is at {arp.hwsrc}"
            
    # ---------------------------------------------------------
    # Layer 3: IPv4 / IPv6
    # ---------------------------------------------------------
    if packet.haslayer(IP):
        ip = packet[IP]
        highest_layer = "IPv4"
        decoded['protocol'] = "IPv4"
        
        ip_details = {
            'Version': ip.version,
            'Source IP': ip.src,
            'Destination IP': ip.dst,
            'Header length': ip.ihl * 4 if ip.ihl else "N/A",
            'TTL': ip.ttl,
            'Protocol': ip.proto,
            'Identification': hex(ip.id) if isinstance(ip.id, int) else ip.id,
            'Flags': str(ip.flags),
            'Fragment offset': ip.frag,
            'Total length': ip.len,
            'Checksum': hex(ip.chksum) if isinstance(ip.chksum, int) else ip.chksum
        }
        decoded['tree'].append({'name': 'IPv4', 'details': ip_details})
        
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        highest_layer = "IPv6"
        decoded['protocol'] = "IPv6"
        
        ip6_details = {
            'Version': ip6.version,
            'Source': ip6.src,
            'Destination': ip6.dst,
            'Traffic class': ip6.tc,
            'Flow label': hex(ip6.fl) if isinstance(ip6.fl, int) else ip6.fl,
            'Hop limit': ip6.hlim,
            'Next header': ip6.nh
        }
        decoded['tree'].append({'name': 'IPv6', 'details': ip6_details})

    # ---------------------------------------------------------
    # Layer 4: TCP / UDP / ICMP
    # ---------------------------------------------------------
    src_port = ""
    dst_port = ""
    
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        highest_layer = "TCP"
        decoded['protocol'] = "TCP"
        src_port = str(tcp.sport)
        dst_port = str(tcp.dport)
        
        flags_str = str(tcp.flags)
        
        tcp_details = {
            'Source port': tcp.sport,
            'Destination port': tcp.dport,
            'Sequence number': tcp.seq,
            'Acknowledgment number': tcp.ack,
            'Header length': tcp.dataofs * 4 if tcp.dataofs else "N/A",
            'Flags': flags_str,
            'Window size': tcp.window,
            'Checksum': hex(tcp.chksum) if isinstance(tcp.chksum, int) else tcp.chksum,
            'Urgent pointer': tcp.urgptr
        }
        decoded['tree'].append({'name': 'TCP', 'details': tcp_details})
        
        info_summary = f"{src_port} → {dst_port} [{flags_str}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
        
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        highest_layer = "UDP"
        decoded['protocol'] = "UDP"
        src_port = str(udp.sport)
        dst_port = str(udp.dport)
        
        udp_details = {
            'Source port': udp.sport,
            'Destination port': udp.dport,
            'Length': udp.len,
            'Checksum': hex(udp.chksum) if isinstance(udp.chksum, int) else udp.chksum
        }
        decoded['tree'].append({'name': 'UDP', 'details': udp_details})
        info_summary = f"{src_port} → {dst_port} Len={udp.len}"

    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        highest_layer = "ICMP"
        decoded['protocol'] = "ICMP"
        
        icmp_details = {
            'Type': icmp.type,
            'Code': icmp.code,
            'Checksum': hex(icmp.chksum) if isinstance(icmp.chksum, int) else icmp.chksum
        }
        
        _id = getattr(icmp, 'id', None)
        if _id is not None:
            icmp_details['Identifier'] = _id
            
        _seq = getattr(icmp, 'seq', None)
        if _seq is not None:
            icmp_details['Sequence number'] = _seq
            
        decoded['tree'].append({'name': 'ICMP', 'details': icmp_details})
        
        type_map = {8: 'Echo (ping) request', 0: 'Echo (ping) reply', 3: 'Destination unreachable'}
        info_summary = type_map.get(icmp.type, f"Type {icmp.type} Code {icmp.code}")
        
    elif packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply):
        highest_layer = "ICMPv6"
        decoded['protocol'] = "ICMPv6"
        if packet.haslayer(ICMPv6EchoRequest):
            info_summary = "Echo (ping) request"
        else:
            info_summary = "Echo (ping) reply"
            
        decoded['tree'].append({'name': 'ICMPv6', 'details': {'Info': info_summary}})

    # ---------------------------------------------------------
    # Layer 7: DNS, DHCP, HTTP, TLS
    # ---------------------------------------------------------
    if packet.haslayer(DNS):
        dns = packet[DNS]
        highest_layer = "DNS"
        decoded['protocol'] = "DNS"
        
        dns_details = {
            'Transaction ID': hex(dns.id) if isinstance(dns.id, int) else dns.id,
            'Response': 'Message is a response' if dns.qr else 'Message is a query',
            'Opcode': dns.opcode,
            'Questions': dns.qdcount,
            'Answer RRs': dns.ancount,
            'Authority RRs': dns.nscount,
            'Additional RRs': dns.arcount
        }
        
        if (dns.qdcount or 0) > 0 and dns.qd is not None:
            # dns.qd may be a DNSQR directly or a list-like wrapper
            qd = dns.qd
            if hasattr(qd, 'qname'):
                qname_raw = qd.qname
            elif hasattr(qd, '__getitem__') and len(qd) > 0:
                qname_raw = qd[0].qname
            else:
                qname_raw = None
                
            if qname_raw is not None:
                dns_details['Query Name'] = qname_raw.decode('utf-8', errors='ignore') if isinstance(qname_raw, bytes) else str(qname_raw)
                if hasattr(qd, 'qtype'):
                    dns_details['Query Type'] = qd.qtype
                elif hasattr(qd, '__getitem__') and len(qd) > 0:
                    dns_details['Query Type'] = qd[0].qtype
            
        decoded['tree'].append({'name': 'DNS', 'details': dns_details})
        
        if dns.qr == 0:
            info_summary = f"Standard query {dns_details.get('Query Name', '')}"
        else:
            info_summary = f"Standard query response {dns_details.get('Query Name', '')}"
            
    elif packet.haslayer(DHCP) or packet.haslayer(BOOTP):
        highest_layer = "DHCP"
        decoded['protocol'] = "DHCP"
        msg_type = "DHCP Message"
        if packet.haslayer(DHCP):
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 'message-type':
                    type_map = {1: 'Discover', 2: 'Offer', 3: 'Request', 5: 'Ack'}
                    msg_type = f"DHCP {type_map.get(opt[1], opt[1])}"
                    break
        info_summary = msg_type
        decoded['tree'].append({'name': 'DHCP/BOOTP', 'details': {'Message': msg_type}})
        
    elif src_port in ['80', '8080'] or dst_port in ['80', '8080']:
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            if payload.startswith(b'GET ') or payload.startswith(b'POST ') or payload.startswith(b'HTTP/'):
                highest_layer = "HTTP"
                decoded['protocol'] = "HTTP"
                try:
                    lines = payload.split(b'\r\n')
                    req_line = lines[0].decode('utf-8', errors='ignore')
                    info_summary = req_line
                    decoded['tree'].append({'name': 'HTTP', 'details': {'Request/Response Line': req_line}})
                except:
                    info_summary = "HTTP Data"

    elif src_port == '443' or dst_port == '443':
        if packet.haslayer('Raw'):
            highest_layer = "TLS"
            decoded['protocol'] = "TLS"
            info_summary = "Application Data"
            payload = packet['Raw'].load
            if len(payload) > 5 and payload[0] == 22 and payload[5] == 1:
                info_summary = "Client Hello"
            elif len(payload) > 5 and payload[0] == 22 and payload[5] == 2:
                info_summary = "Server Hello"
                
            decoded['tree'].append({'name': 'TLS', 'details': {'Info': info_summary}})
            
    # Normalize Source and Destination
    norm_src = None
    norm_dst = None
    
    if packet.haslayer(IPv6):
        norm_src = f"[{packet[IPv6].src}]:{src_port}" if src_port else packet[IPv6].src
        norm_dst = f"[{packet[IPv6].dst}]:{dst_port}" if dst_port else packet[IPv6].dst
    elif packet.haslayer(IP):
        norm_src = f"{packet[IP].src}:{src_port}" if src_port else packet[IP].src
        norm_dst = f"{packet[IP].dst}:{dst_port}" if dst_port else packet[IP].dst
    elif packet.haslayer(ARP):
        norm_src = packet[ARP].psrc
        norm_dst = packet[ARP].pdst
    elif packet.haslayer(Ether):
        norm_src = packet[Ether].src
        norm_dst = packet[Ether].dst
        
    decoded['source'] = norm_src if norm_src else "None"
    decoded['destination'] = norm_dst if norm_dst else "None"

    # Fallback info summary
    if not info_summary:
        if decoded['protocol'] != 'OTHER':
            info_summary = f"{decoded['protocol']} Packet"
        else:
            info_summary = decoded['raw_summary']

    decoded['info'] = info_summary
    
    if DEBUG_MISSING_ADDRESSES and (norm_src is None or norm_dst is None):
        with open("/tmp/missing_addr_debug.log", "a") as f:
            f.write("="*40 + "\n")
            f.write(packet.summary() + "\n")
            f.write(packet.show(dump=True) + "\n")
            f.write("="*40 + "\n\n")

    return decoded
