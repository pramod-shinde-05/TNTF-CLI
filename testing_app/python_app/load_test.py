import requests
import time
from concurrent.futures import ThreadPoolExecutor

TARGET_URL = "http://10.86.181.236:5000/search?q=test"

DURATION = 180
CONCURRENCY = 100


def send_request():
    try:
        requests.get(TARGET_URL, timeout=2)
    except requests.RequestException:
        pass


def main():
    print("Starting sustained traffic test...")
    print(f"Target: {TARGET_URL}")
    print(f"Concurrency: {CONCURRENCY}")
    print(f"Duration: {DURATION} seconds")

    end_time = time.time() + DURATION

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        while time.time() < end_time:
            for _ in range(CONCURRENCY):
                executor.submit(send_request)

    print("Traffic test completed.")


if __name__ == "__main__":
    main()