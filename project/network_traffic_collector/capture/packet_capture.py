import threading
import time
import os
import traceback
from scapy.all import sniff, get_if_list

class PacketCapture:
    def __init__(self, interface=None, packet_callback=None):
        self.interface = interface
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

    def _log_error(self, msg):
        try:
            log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "collector_error.log")
            with open(log_path, "a") as f:
                f.write(f"[PacketCapture] {msg}\n")
        except Exception:
            pass

    def _capture_loop(self):
        # Try the configured interface first, then fall back to alternatives
        interfaces_to_try = []
        
        if self.interface and self.interface != "any":
            interfaces_to_try.append(self.interface)
        
        # Always add None (Scapy default) as a reliable fallback
        interfaces_to_try.append(None)
        
        for iface in interfaces_to_try:
            if not self.is_capturing:
                return
            try:
                iface_name = iface if iface else "default"
                self._log_error(f"Attempting to sniff on interface: {iface_name}")
                sniff(
                    iface=iface,
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda p: not self.is_capturing
                )
                return  # Normal exit (stop_filter triggered)
            except Exception as e:
                self._log_error(f"Sniff failed on '{iface}': {e}\n{traceback.format_exc()}")
                continue
        
        self._log_error("All interfaces failed. No packets will be captured.")

    def _process_packet(self, packet):
        if self.packet_callback and self.is_capturing:
            self.packet_callback(packet)
