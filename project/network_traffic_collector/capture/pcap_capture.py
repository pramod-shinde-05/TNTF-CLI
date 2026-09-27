import threading
import time
from scapy.all import sniff

class PcapCapture:
    def __init__(self, pcap_path, packet_callback=None):
        self.pcap_path = pcap_path
        self.packet_callback = packet_callback
        self.is_capturing = False
        self.capture_thread = None

    def start(self):
        self.is_capturing = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()

    def stop(self):
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)

    def _capture_loop(self):
        sniff(
            offline=self.pcap_path,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda p: not self.is_capturing
        )
        self.is_capturing = False

    def _process_packet(self, packet):
        if self.packet_callback and self.is_capturing:
            self.packet_callback(packet)
