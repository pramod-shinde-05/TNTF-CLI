"""
Unit tests for packet_decoder.py
Tests that decode_packet() returns correct normalized source, destination,
protocol, and info fields for various packet types.
"""
import unittest
import sys
import os

# Add project root to path so we can import features
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

from features.packet_decoder import decode_packet


class TestEthernetIPv4TCP(unittest.TestCase):
    def test_basic_syn(self):
        pkt = Ether(src="aa:bb:cc:dd:ee:f1", dst="aa:bb:cc:dd:ee:f2") / \
              IP(src="10.0.0.1", dst="10.0.0.2") / \
              TCP(sport=52341, dport=443, flags="S")
        d = decode_packet(pkt, 1)
        self.assertEqual(d['source'], "10.0.0.1:52341")
        self.assertEqual(d['destination'], "10.0.0.2:443")
        self.assertEqual(d['protocol'], "TCP")
        self.assertIn("[S]", d['info'])  # scapy flag char is 'S'

    def test_syn_ack(self):
        pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=52341, flags="SA")
        d = decode_packet(pkt, 2)
        self.assertEqual(d['source'], "10.0.0.2:443")
        self.assertEqual(d['destination'], "10.0.0.1:52341")
        self.assertEqual(d['protocol'], "TCP")


class TestEthernetIPv4UDP(unittest.TestCase):
    def test_basic_udp(self):
        pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=33473, dport=53)
        d = decode_packet(pkt, 3)
        self.assertEqual(d['source'], "192.168.1.10:33473")
        self.assertEqual(d['destination'], "8.8.8.8:53")
        self.assertEqual(d['protocol'], "UDP")


class TestEthernetIPv6TCP(unittest.TestCase):
    def test_ipv6_tcp(self):
        pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=12345, dport=80, flags="S")
        d = decode_packet(pkt, 4)
        self.assertEqual(d['source'], "[2001:db8::1]:12345")
        self.assertEqual(d['destination'], "[2001:db8::2]:80")
        self.assertEqual(d['protocol'], "TCP")


class TestEthernetIPv6UDP(unittest.TestCase):
    def test_ipv6_udp(self):
        pkt = Ether() / IPv6(src="2405:200::1", dst="2404:6800::1") / UDP(sport=33473, dport=443)
        d = decode_packet(pkt, 5)
        self.assertEqual(d['source'], "[2405:200::1]:33473")
        self.assertEqual(d['destination'], "[2404:6800::1]:443")
        self.assertEqual(d['protocol'], "UDP")


class TestEthernetARP(unittest.TestCase):
    def test_arp_request(self):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.2")
        d = decode_packet(pkt, 6)
        self.assertEqual(d['source'], "10.0.0.1")
        self.assertEqual(d['destination'], "10.0.0.2")
        self.assertEqual(d['protocol'], "ARP")
        self.assertIn("Who has", d['info'])

    def test_arp_reply(self):
        pkt = Ether() / ARP(op=2, psrc="10.0.0.2", pdst="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:ff")
        d = decode_packet(pkt, 7)
        self.assertEqual(d['source'], "10.0.0.2")
        self.assertEqual(d['destination'], "10.0.0.1")
        self.assertEqual(d['protocol'], "ARP")
        self.assertIn("is at", d['info'])


class TestIPv4ICMP(unittest.TestCase):
    def test_echo_request(self):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8)
        d = decode_packet(pkt, 8)
        self.assertEqual(d['source'], "10.0.0.1")
        self.assertEqual(d['destination'], "10.0.0.2")
        self.assertEqual(d['protocol'], "ICMP")
        self.assertIn("request", d['info'].lower())

    def test_echo_reply(self):
        pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=0)
        d = decode_packet(pkt, 9)
        self.assertEqual(d['source'], "10.0.0.2")
        self.assertEqual(d['destination'], "10.0.0.1")
        self.assertEqual(d['protocol'], "ICMP")
        self.assertIn("reply", d['info'].lower())


class TestIPv6ICMPv6(unittest.TestCase):
    def test_icmpv6_echo_request(self):
        pkt = Ether() / IPv6(src="::1", dst="::2") / ICMPv6EchoRequest()
        d = decode_packet(pkt, 10)
        self.assertEqual(d['source'], "::1")
        self.assertEqual(d['destination'], "::2")
        self.assertEqual(d['protocol'], "ICMPv6")
        self.assertIn("request", d['info'].lower())


class TestDNSOverUDP(unittest.TestCase):
    def test_dns_query(self):
        pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / \
              UDP(sport=33473, dport=53) / DNS(rd=1, qdcount=1, qd=DNSQR(qname="example.com"))
        d = decode_packet(pkt, 11)
        self.assertEqual(d['source'], "192.168.1.10:33473")
        self.assertEqual(d['destination'], "8.8.8.8:53")
        self.assertEqual(d['protocol'], "DNS")
        self.assertIn("example.com", d['info'])


class TestTLSOverTCP(unittest.TestCase):
    def test_tls_client_hello(self):
        # ContentType=22 (Handshake), HandshakeType=1 (ClientHello)
        tls_payload = bytes([22, 3, 1, 0, 5, 1, 0, 0, 1, 0])
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / \
              TCP(sport=55555, dport=443) / Raw(load=tls_payload)
        d = decode_packet(pkt, 12)
        self.assertEqual(d['source'], "10.0.0.1:55555")
        self.assertEqual(d['destination'], "10.0.0.2:443")
        self.assertEqual(d['protocol'], "TLS")
        self.assertIn("Client Hello", d['info'])


class TestTLSQUICOverUDP(unittest.TestCase):
    def test_quic_port_443(self):
        # QUIC goes over UDP port 443
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / \
              UDP(sport=44444, dport=443) / Raw(load=b'\x00' * 20)
        d = decode_packet(pkt, 13)
        self.assertEqual(d['source'], "10.0.0.1:44444")
        self.assertEqual(d['destination'], "10.0.0.2:443")
        # Protocol should still resolve since port 443 is detected
        self.assertNotEqual(d['source'], "None")
        self.assertNotEqual(d['destination'], "None")


class TestEthernetOnlyFallback(unittest.TestCase):
    def test_l2_only(self):
        """When there's no IP/ARP layer, fall back to MAC addresses."""
        pkt = Ether(src="aa:bb:cc:dd:ee:f1", dst="aa:bb:cc:dd:ee:f2")
        d = decode_packet(pkt, 14)
        self.assertEqual(d['source'], "aa:bb:cc:dd:ee:f1")
        self.assertEqual(d['destination'], "aa:bb:cc:dd:ee:f2")


class TestLocalhostTraffic(unittest.TestCase):
    def test_localhost_tcp(self):
        pkt = Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=54321, dport=5000, flags="S")
        d = decode_packet(pkt, 15)
        self.assertEqual(d['source'], "127.0.0.1:54321")
        self.assertEqual(d['destination'], "127.0.0.1:5000")
        self.assertEqual(d['protocol'], "TCP")


class TestNoNoneWhenAddressExists(unittest.TestCase):
    """Ensure we never return 'None' as a string when a valid address exists."""
    
    def test_ipv4_no_none(self):
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1000, dport=2000)
        d = decode_packet(pkt, 100)
        self.assertNotIn("None", d['source'])
        self.assertNotIn("None", d['destination'])
        
    def test_ipv6_no_none(self):
        pkt = Ether() / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=100, dport=200)
        d = decode_packet(pkt, 101)
        self.assertNotIn("None", d['source'])
        self.assertNotIn("None", d['destination'])
        
    def test_arp_no_none(self):
        pkt = Ether() / ARP(psrc="10.0.0.1", pdst="10.0.0.2")
        d = decode_packet(pkt, 102)
        self.assertNotIn("None", d['source'])
        self.assertNotIn("None", d['destination'])


if __name__ == '__main__':
    unittest.main()
