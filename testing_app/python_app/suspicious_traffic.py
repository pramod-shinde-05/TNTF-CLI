import socket
import time
import random
import threading

TARGET_IP = "10.86.181.236"
TOTAL_CONNECTIONS = 2000
CONCURRENCY = 50

def suspicious_connect():
    """Attempt a connection to a random port and drop it immediately to trigger behavioral anomaly."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        random_port = random.randint(1024, 65535)
        # Attempt connection (sends SYN)
        s.connect((TARGET_IP, random_port))
    except Exception:
        pass
    finally:
        s.close()

def main():
    print(f"Starting Suspicious Traffic Generator (Behavioral Anomaly Test) against {TARGET_IP}")
    print(f"This will generate rapid connections to highly random ports, simulating reconnaissance or anomalous behavior.")
    print("Expected Result: Transformer -> Benign, Anomaly Score -> >75%, Threat Level -> Suspicious")
    
    time.sleep(2)
    
    start_time = time.time()
    
    threads = []
    
    # We run this rapidly in a tight loop
    for i in range(TOTAL_CONNECTIONS):
        t = threading.Thread(target=suspicious_connect)
        threads.append(t)
        t.start()
        
        # Keep concurrency limited
        if len(threads) >= CONCURRENCY:
            for t in threads:
                t.join()
            threads = []
            
    for t in threads:
        t.join()
        
    duration = time.time() - start_time
    print(f"\nCompleted {TOTAL_CONNECTIONS} anomalous connection attempts in {duration:.2f} seconds.")

if __name__ == "__main__":
    main()
