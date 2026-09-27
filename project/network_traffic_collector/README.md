# SIH26153 — Network Traffic Feature Collector

A modular, real-time network traffic capture and feature extraction tool built for **Smart India Hackathon 2026 (Problem Statement 26153)**. It provides a **Wireshark-style terminal UI** powered by [Textual](https://github.com/Textualize/textual), deep packet decoding via [Scapy](https://scapy.net/), and automated CSV export of packet-level and flow-level features for future ML/temporal model training.

> **Note:** This module is the **data-ingestion layer only**. No ML/AI models are included yet.

---

## Features

| Category | Details |
|---|---|
| **Live TUI** | Scrollable packet table with `No. / Time / Source / Destination / Protocol / Length / Info` columns |
| **Packet Detail Panel** | Wireshark-style expandable protocol tree (Ethernet → IPv4/IPv6 → TCP/UDP → DNS/TLS/HTTP) |
| **Deep Decoding** | Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, DHCP, HTTP (plaintext), TLS metadata |
| **Filtering** | Live display filters: `tcp`, `udp`, `icmp`, `arp`, `dns`, `port 443`, `host 10.0.0.1` |
| **Flow Tracking** | Bidirectional 5-tuple flows with forward/backward counts, IAT stats, retransmission detection |
| **Port Scan Detection** | Sliding time-window heuristic (configurable threshold and window) |
| **CSV Export** | Timestamped session directories with `packets.csv` and `flows.csv` |
| **Graceful Shutdown** | All active flows are flushed to disk on `q` or `Ctrl+C` |

---

## Project Structure

```
network_traffic_collector/
├── main.py                  # Entry point — wires capture, features, UI, and storage
├── config.py                # Interface, paths, timing constants
├── requirements.txt
│
├── capture/
│   └── packet_capture.py    # Scapy sniff thread
│
├── features/
│   ├── packet_features.py   # SIH26153 CSV feature extraction (IPv4/IPv6/ARP)
│   ├── packet_decoder.py    # Deep L2–L7 decoding for the UI
│   └── flow_features.py     # Bidirectional flow tracker with port-scan detection
│
├── display/
│   └── terminal.py          # Textual TUI (DataTable + Tree detail panel)
│
├── storage/
│   └── csv_writer.py        # Timestamped CSV persistence
│
├── tests/
│   └── test_packet_decoder.py  # 18 unit tests for packet decoding
│
├── models/                  # Placeholder for future ML artifacts
└── data/                    # Auto-generated capture sessions (gitignored)
```

---

## Prerequisites

- **Python 3.10+**
- **Linux** (packet capture requires raw sockets)
- `libpcap-dev` (for Scapy):
  ```bash
  sudo apt install libpcap-dev
  ```

---

## Installation

```bash
cd network_traffic_collector
pip install -r requirements.txt
```

Dependencies: `scapy`, `pandas`, `textual`

---

## Usage

Packet capture requires root privileges:

```bash
cd network_traffic_collector
sudo $(which python3) main.py
```

> **Why `$(which python3)`?** This ensures `sudo` uses your user-installed Python (with the correct packages) rather than the system Python.

### Keyboard Controls

| Key | Action |
|-----|--------|
| `↑` / `↓` | Select packet in table |
| `Enter` | View detailed protocol tree for selected packet |
| `Space` | Pause / resume live display |
| `f` | Open filter bar |
| `c` | Clear active filter |
| `q` | Quit gracefully (flushes all flows to CSV) |

### Filter Syntax

Press `f`, type a filter, and press `Enter`:

| Filter | Example |
|--------|---------|
| Protocol | `tcp`, `udp`, `icmp`, `arp`, `dns` |
| Port | `port 443` |
| Host | `host 192.168.1.1` |

Filters affect **display only** — all packets continue to be saved to disk.

---

## Output

Each run creates a timestamped directory under `data/`:

```
data/
└── session_2026-08-22_10-15-30/
    ├── packets.csv    # Per-packet features
    └── flows.csv      # Aggregated flow statistics
```

### Packet CSV Fields
`timestamp`, `packet_number`, `protocol`, `packet_length`, `src_ip`, `dst_ip`, `ttl`, `ip_id`, `fragment_offset`, `more_fragments`, `src_port`, `dst_port`, `tcp_flags`, `tcp_flag_syn/ack/fin/rst/psh/urg/ece/cwr`, `tcp_window`, `sequence_number`, `acknowledgment_number`, `payload_size`, `iat`, `is_retransmission`

### Flow CSV Fields
`flow_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `start_time`, `end_time`, `duration`, `packet_count`, `byte_count`, `forward_packet_count`, `backward_packet_count`, `bidirectional_ratio`, `packets_per_second`, `bytes_per_second`, `syn/ack/fin/rst_count`, `syn/ack/fin/rst_ratio`, `retransmission_count`, `iat_mean`, `iat_variance`, `iat_max`, `port_scan_indicator`

---

## Running Tests

```bash
cd network_traffic_collector
python3 -m unittest tests.test_packet_decoder -v
```

---

## Testing with the Local Dataset-Based Simulator

To test the system against real CIC-IDS2018 attack traffic geometry, you can use the standalone `attack_simulator.py` script. This script reads the original CSV dataset and replays the exact temporal characteristics and flow volumes against a local test application (`127.0.0.1:5000`).

**Key Point**: This script does *not* fake ML predictions. It generates raw local traffic that is independently captured and evaluated by the ML pipeline.

### Step 1: Start the Collector & AI Pipeline
```bash
sudo $(which python3) network_traffic_collector/main.py --ml
```

### Step 2: Start the Target App
```bash
python3 Test_App/app.py
```

### Step 3: Run the Attack Simulator
In a third terminal window:
```bash
python3 attack_simulator.py --attack "DoS attacks-Hulk" --duration 120
```

Available arguments:
- `--attack`: The exact name of the attack in the dataset (e.g., `DoS attacks-Hulk`, `Bot`, `Infilteration`)
- `--duration`: Stop simulating after X seconds.
- `--dry-run`: Parse the dataset and show the expected timing without sending any HTTP requests.

---

## License

This project is developed for SIH 2026 (Problem Statement 26153).
