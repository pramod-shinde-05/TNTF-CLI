import time
import sys
import threading
from datetime import datetime
import traceback
import argparse
import os
import json

from config import DATA_DIR, DEFAULT_INTERFACE, DISPLAY_UPDATE_INTERVAL, MIN_PACKETS_FOR_ML, MIN_FLOW_DURATION, FEATURE_SCHEMA_PATH
from capture.packet_capture import PacketCapture
from features.packet_features import extract_packet_features
from features.flow_features import FlowTracker
from features.packet_decoder import decode_packet
from storage.csv_writer import CSVWriter
from display.terminal import TrafficMonitorApp, PacketMessage, StatsMessage, ForecastMessage

def main():
    parser = argparse.ArgumentParser(description="Live Network Traffic Collector with ML")
    parser.add_argument('--ml', action='store_true', help="Enable live ML prediction")
    args = parser.parse_args()
    
    # ML Initialization
    adapter = None
    temporal_predictor = None
    state_tracker = None
    
    if args.ml:
        print("Initializing ML subsystem...")
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from inference.live_predictor import LivePredictor
        from inference.state_tracker import StateTracker

        
        # Initialize Temporal AI (Transformer)
        try:
            temporal_predictor = LivePredictor(
                artifact_dir=os.path.abspath(os.path.join(os.path.dirname(__file__), '../models/temporal_transformer/artifacts_v6'))
            )
            state_tracker = StateTracker()
            print("Temporal Predictor successfully loaded.")
        except Exception as e:
            print(f"Warning: Temporal Predictor not loaded (missing models/configs). Error: {e}")
            temporal_predictor = None
            
    # Elevated privileges check
    if sys.platform != "win32" and not hasattr(sys, 'getwindowsversion'):
        if os.geteuid() != 0:
            print("WARNING: Packet capture typically requires root privileges.")
            print("You may need to run this script with 'sudo'.")
            print("Continuing anyway (starting in 2 seconds)...")
            time.sleep(2)

    # Initialize components
    csv_writer = CSVWriter(data_dir=DATA_DIR)
    flow_tracker = FlowTracker()
    
    start_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # State tracking
    state = {
        'packet_count': 0,
        'byte_count': 0,
        'last_packet_count': 0,
        'last_byte_count': 0,
        'last_stats_time': time.time(),
        'total_flows_count': 0,
        'completed_flows_count': 0,
        'last_packet_time': None,
        'is_running': True,
        'last_temporal_state_time': time.time()
    }
    
    # Initialize Textual App
    def reset_ai_state():
        if temporal_predictor:
            if hasattr(temporal_predictor, 'reset'):
                temporal_predictor.reset()
            elif hasattr(temporal_predictor, 'state_buffer'):
                temporal_predictor.state_buffer.clear()
        flow_tracker.flows.clear()
        
        t_now = time.time()
        state.update({
            'packet_count': 0, 'byte_count': 0,
            'last_packet_count': 0, 'last_byte_count': 0,
            'total_flows_count': 0, 'completed_flows_count': 0,
            'last_packet_time': None,
            'simulated_time': None,
            'last_temporal_state_time': t_now,
            'last_stats_time': t_now
        })
        
    class AppController:
        def __init__(self, temporal_predictor):
            self.app = None
            self.temporal_predictor = temporal_predictor
            
        def run_offline_analysis(self, filepath):
            from capture.offline_processor import OfflineProcessor
            from display.terminal import FileAnalysisProgressMessage, FileAnalysisCompleteMessage
            
            def update_cb(msg, pct):
                try:
                    self.app.call_from_thread(self.app.post_message, FileAnalysisProgressMessage(msg, pct))
                except RuntimeError:
                    pass
                    
            processor = OfflineProcessor(predictor=self.temporal_predictor)
            
            try:
                if filepath.endswith('.csv'):
                    res = processor.process_csv(filepath, update_callback=update_cb)
                else:
                    res = {"error": "PCAP offline analysis requires full pipeline stubbing. Use CSV offline analysis."}
            except Exception as e:
                res = {"error": str(e)}
                
            try:
                self.app.call_from_thread(self.app.post_message, FileAnalysisCompleteMessage(res))
            except RuntimeError:
                pass
                
        def run_pcap_replay(self, filepath):
            from capture.pcap_capture import PcapCapture
            
            state['offline_mode'] = True
            
            # Stop live capture
            if state.get('live_capture'):
                state['live_capture'].stop()
                
            # Reset tracking state for fresh PCAP
            flow_tracker.flows.clear()
            if self.temporal_predictor:
                self.temporal_predictor.reset()
            if self.app:
                self.app.action_reset_state()
                
            state.update({
                'packet_count': 0, 'byte_count': 0,
                'last_packet_count': 0, 'last_byte_count': 0,
                'total_flows_count': 0, 'completed_flows_count': 0,
                'last_packet_time': None,
                'simulated_time': None,
                'last_temporal_state_time': None,
                'last_stats_time': None
            })
            
            pcap = PcapCapture(filepath, packet_callback=packet_callback)
            state['live_capture'] = pcap
            pcap.start()
            
        def resume_live_capture(self):
            state['offline_mode'] = False
            
            if state.get('live_capture'):
                state['live_capture'].stop()
                
            flow_tracker.flows.clear()
            if self.temporal_predictor:
                self.temporal_predictor.reset()
            if self.app:
                self.app.action_reset_state()
                
            t_now = time.time()
            state.update({
                'packet_count': 0, 'byte_count': 0,
                'last_packet_count': 0, 'last_byte_count': 0,
                'total_flows_count': 0, 'completed_flows_count': 0,
                'last_packet_time': None,
                'simulated_time': None,
                'last_temporal_state_time': t_now,
                'last_stats_time': t_now
            })
            
            pcap = PacketCapture(interface=DEFAULT_INTERFACE, packet_callback=packet_callback)
            state['live_capture'] = pcap
            pcap.start()
                
    controller = AppController(temporal_predictor)
    app = TrafficMonitorApp(interface=DEFAULT_INTERFACE, start_time=start_time_str, reset_callback=reset_ai_state, app_context=controller)
    controller.app = app
    
    # State tracking is now defined above reset_ai_state
    
    ml_predictions_cache = {}
    
    def packet_callback(raw_packet):
        try:
            state['packet_count'] += 1
            state['byte_count'] += len(raw_packet)
            features = extract_packet_features(
                packet=raw_packet, 
                packet_number=state['packet_count'],
                last_timestamp=state['last_packet_time']
            )
            state['last_packet_time'] = features['timestamp']
            decoded_info = decode_packet(raw_packet, state['packet_count'])
            
            flow = flow_tracker.update_flow(features)
            if flow and flow['packet_count'] == 1:
                state['total_flows_count'] += 1
                    
            # Send UI message FIRST so CSV errors can never block the display
            if state['is_running']:
                try:
                    msg = PacketMessage(
                        packet_features=features.copy(), 
                        flow_features=flow.copy() if flow else None,
                        decoded_info=decoded_info,
                        ml_prediction=None
                    )
                    app.call_from_thread(app.post_message, msg)
                except RuntimeError:
                    pass
                    
            if state.get('offline_mode'):
                packet_time = float(raw_packet.time)
                if state.get('simulated_time') is None:
                    state['simulated_time'] = packet_time
                    state['last_temporal_state_time'] = packet_time
                    state['last_stats_time'] = packet_time
                    
                if packet_time - state['simulated_time'] >= DISPLAY_UPDATE_INTERVAL:
                    state['simulated_time'] = packet_time
                    trigger_stats_update(packet_time)
                    # Accelerated pacing: 1 simulated second = 0.1 real seconds (10x speed)
                    time.sleep(0.1)
            
            # CSV writes are best-effort; failures must not block the pipeline
            try:
                csv_writer.write_packet(features)
                if flow:
                    csv_writer.write_flow(flow)
            except Exception:
                pass
        except Exception as e:
            with open(os.path.join(os.path.dirname(__file__), "collector_error.log"), "a") as f:
                f.write(f"Packet callback error: {e}\n{traceback.format_exc()}\n")

    def trigger_stats_update(current_time):
        from display.terminal import FlowUpdateMessage
        try:
            expired_flows = flow_tracker.clean_old_flows(current_time)
            state['completed_flows_count'] += len(expired_flows)
            
            expired_keys = [f.get('flow_id') for f in expired_flows if 'flow_id' in f]
            for key in expired_keys:
                ml_predictions_cache.pop(key, None)
            
            flow_updates = []
            active_flows = flow_tracker.get_all_flows()
            
            # 1. Temporal State Generation (every 1 second)
            if temporal_predictor and state_tracker:
                if current_time - state['last_temporal_state_time'] >= 1.0:
                    state['last_temporal_state_time'] = current_time
                    
                    network_state = state_tracker.compute_state(active_flows, current_time)
                    if network_state is not None:  # Even an empty {} state is valid for silence padding
                        with open(os.path.join(os.path.dirname(__file__), "sih_forecast.log"), "a") as log_f:
                            log_f.write(f"[{datetime.now().strftime('%H:%M:%S')}] state generated\n")
                            
                        temporal_predictor.add_state(network_state)
                        forecast_results = temporal_predictor.predict(int(current_time * 1000))
                        
                        if forecast_results:
                            with open(os.path.join(os.path.dirname(__file__), "sih_forecast.log"), "a") as log_f:
                                log_f.write(f"[{datetime.now().strftime('%H:%M:%S')}] prediction generated\n")
                            
                            # Inject micro-level attack if present
                            if state.get('last_micro_attack'):
                                atk = state['last_micro_attack']
                                forecast_results['threat_level'] = f"Micro-Attack: {atk}"
                                forecast_results['current_prediction'] = f"Attack ({atk})"
                            
                            try:
                                app.call_from_thread(app.post_message, ForecastMessage(forecast=forecast_results))
                            except RuntimeError:
                                pass
            
            # Update UI flows without legacy Micro-Level ML
            for f in active_flows:
                pred = {'predicted_class': 'Benign', 'confidence': 1.0}
                flow_updates.append({'flow': f.copy(), 'ml_prediction': pred})
                
            if state['is_running']:
                try:
                    app.call_from_thread(app.post_message, FlowUpdateMessage(flows=flow_updates))
                    
                    now = current_time
                    dt = float(now - state['last_stats_time'])
                    if dt <= 0.0: 
                        dt = 1.0
                    
                    pkts = int(state.get('packet_count', 0))
                    bytes_cnt = int(state.get('byte_count', 0))
                    
                    last_pkts = int(state.get('last_packet_count', 0))
                    last_bytes = int(state.get('last_byte_count', 0))
                    
                    pps = float(pkts - last_pkts) / dt
                    bps = float(bytes_cnt - last_bytes) / dt
                    
                    state['last_packet_count'] = pkts
                    state['last_byte_count'] = bytes_cnt
                    state['last_stats_time'] = now
                    
                    protocols = {}
                    for f in active_flows:
                        p = f.get('protocol', 'OTHER')
                        if isinstance(p, int):
                            if p == 6: p = 'TCP'
                            elif p == 17: p = 'UDP'
                            elif p == 1: p = 'ICMP'
                            else: p = str(p)
                        protocols[p] = protocols.get(p, 0) + 1

                    stats = {
                        'packet_count': pkts,
                        'packets_per_sec': pps,
                        'bytes_per_sec': bps,
                        'protocols': protocols,
                        'active_flows_count': len(active_flows),
                        'completed_flows_count': state['completed_flows_count'],
                        'total_flows_count': state['total_flows_count']
                    }
                    app.call_from_thread(app.post_message, StatsMessage(stats=stats))
                except RuntimeError:
                    pass
        except Exception as e:
            with open(os.path.join(os.path.dirname(__file__), "collector_error.log"), "a") as f_err:
                f_err.write(f"Stats update error: {e}\n{traceback.format_exc()}\n")

    def stats_loop():
        while state['is_running']:
            if not state.get('offline_mode'):
                trigger_stats_update(time.time())
            time.sleep(DISPLAY_UPDATE_INTERVAL)

    capture = PacketCapture(interface=DEFAULT_INTERFACE, packet_callback=packet_callback)
    stats_thread = threading.Thread(target=stats_loop, daemon=True)
    
    # Store references so AppController can swap them
    state['live_capture'] = capture
    
    try:
        capture.start()
        stats_thread.start()
        app.run()
    except KeyboardInterrupt:
        pass
    finally:
        state['is_running'] = False
        print("Stopping capture and UI...")
        capture.stop()
        stats_thread.join(timeout=2.0)
        
        print("Flushing active flows to disk...")
        active_flows = flow_tracker.get_all_flows()
        for flow in active_flows:
            csv_writer.write_flow(flow)
            
        csv_writer.close()
        print(f"Capture stopped. Data saved in {csv_writer.session_dir}")

if __name__ == "__main__":
    main()
