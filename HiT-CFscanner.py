#!/usr/bin/env python3
"""
Cloudflare Scanner - Save ALL Online IPs
Scans and saves every IP that responds to ping
"""

import subprocess
import ipaddress
import sys
import threading
import time
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os
import platform
import random
import json

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

if platform.system() == 'Windows':
    os.system('color')

ALL_RANGES = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17"
]

# Test more ports including non-standard ones
PORTS_TO_TEST = [
    80, 443, 8080, 8443,           # Standard HTTP/HTTPS
    2052, 2053, 2082, 2083,        # Cloudflare HTTP
    2086, 2087, 2095, 2096,        # Cloudflare HTTPS
    8880, 9443,                    # Alternative
    3000, 5000, 8000, 9000,        # Development ports
    22, 3389, 5900,                # SSH/RDP/VNC (unlikely but worth checking)
]

# Optimized settings for i7 12th Gen
WORKERS = 200
BATCH_SIZE = 500
TIMEOUT = 0.2
DELAY = 0.001

TOTAL = 0
SCANNED = 0
ONLINE = 0
FOUND = 0
START = None
OUTPUT_FILE = None
ONLINE_FILE = None
JSON_FILE = None
STOP = False
lock = threading.Lock()
online_ips = []  # Store ALL online IPs
working_ips = []  # Store IPs with open ports

def p(msg, status="info"):
    t = datetime.now().strftime("%H:%M:%S")
    c = {
        "ok": Colors.GREEN, "err": Colors.RED, "info": Colors.CYAN,
        "warn": Colors.YELLOW, "prog": Colors.BLUE
    }
    print(f"{c.get(status, Colors.WHITE)}[{t}] {msg}{Colors.RESET}")

def ping(ip):
    try:
        if platform.system() == 'Windows':
            cmd = ['ping', '-n', '1', '-w', '200', str(ip)]
        else:
            cmd = ['ping', '-c', '1', '-W', '0.2', str(ip)]
        
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL, timeout=0.4)
        return result.returncode == 0
    except:
        return False

def tcp(ip, port):
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        r = s.connect_ex((str(ip), port))
        s.close()
        return r == 0
    except:
        return False

def save_online(ip):
    """Save online IP immediately"""
    try:
        with open(ONLINE_FILE, "a", encoding='utf-8') as f:
            f.write(f"{ip}\n")
            f.flush()
    except:
        pass

def save_working(ip, ports):
    """Save working IP with ports"""
    try:
        with open(OUTPUT_FILE, "a", encoding='utf-8') as f:
            f.write(f"{ip}|{','.join(map(str, ports))}\n")
            f.flush()
    except:
        pass

def save_json():
    """Save all results as JSON"""
    try:
        data = {
            "scan_time": datetime.now().isoformat(),
            "total_scanned": SCANNED,
            "online_count": ONLINE,
            "working_count": FOUND,
            "online_ips": online_ips,
            "working_ips": [{"ip": ip, "ports": ports} for ip, ports in working_ips]
        }
        with open(JSON_FILE, "w", encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except:
        pass

def scan(ip):
    global SCANNED, ONLINE, FOUND
    if STOP: return
    
    if ping(ip):
        # Test all ports
        open_ports = []
        for port in PORTS_TO_TEST:
            if tcp(ip, port):
                open_ports.append(port)
        
        with lock:
            SCANNED += 1
            ONLINE += 1
            online_ips.append(str(ip))
        
        # Save online IP immediately
        save_online(str(ip))
        
        if open_ports:
            with lock:
                FOUND += 1
                working_ips.append((str(ip), open_ports))
            save_working(str(ip), open_ports)
            print(f"\n{Colors.GREEN}★ FOUND: {ip} → [{', '.join(map(str, open_ports))}]{Colors.RESET}")
        else:
            # Still show as online
            if ONLINE % 20 == 0:
                print(f"\n{Colors.GREEN}✓ ONLINE: {ip}{Colors.RESET}", end="")
        
        return True
    else:
        with lock:
            SCANNED += 1
        
        if SCANNED % 500 == 0:
            elapsed = time.time() - START if START else 1
            speed = SCANNED / elapsed if elapsed > 0 else 0
            progress = (SCANNED / TOTAL) * 100
            remaining = TOTAL - SCANNED
            eta = remaining / speed if speed > 0 else 0
            
            print(f"\r{Colors.CYAN}📊 {SCANNED:,}/{TOTAL:,} ({progress:.1f}%) | "
                  f"Online: {ONLINE} | Found: {FOUND} | "
                  f"{speed:.0f} IP/s | ETA: {eta/3600:.1f}h{Colors.RESET}", 
                  end="", flush=True)
        
        return False

def get_all_ips():
    p("Collecting all Cloudflare IPs...", "info")
    ips = []
    for r in ALL_RANGES:
        try:
            net = ipaddress.ip_network(r, strict=False)
            count = 0
            for ip in net.hosts():
                ips.append(str(ip))
                count += 1
            p(f"  {r}: {count:,} IPs", "info")
        except Exception as e:
            p(f"  Error with {r}: {e}", "err")
    return ips

def signal_handler(sig, frame):
    global STOP
    print(f"\n\n{Colors.YELLOW}⚠ Stopping... Please wait...{Colors.RESET}")
    STOP = True

def main():
    global WORKERS, TOTAL, OUTPUT_FILE, ONLINE_FILE, JSON_FILE, START, STOP
    global SCANNED, ONLINE, FOUND
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("╔══════════════════════════════════════════════════╗")
    print("║     CLOUDFLARE SCANNER - SAVE ALL ONLINE        ║")
    print(f"║     Testing {len(PORTS_TO_TEST)} ports on each IP                ║")
    print("╚══════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    OUTPUT_FILE = f"cloudflare_working_{timestamp}.txt"
    ONLINE_FILE = f"cloudflare_online_{timestamp}.txt"
    JSON_FILE = f"cloudflare_results_{timestamp}.json"
    
    # Create output files
    for file, header in [
        (OUTPUT_FILE, "# Cloudflare Working IPs (with open ports)\n# IP|PORT1,PORT2,...\n"),
        (ONLINE_FILE, "# Cloudflare Online IPs (ping successful)\n# One IP per line\n"),
    ]:
        with open(file, "w", encoding='utf-8') as f:
            f.write(header + "#" + "="*50 + "\n")
    
    # Collect IPs
    p("\n📦 Phase 1: Collecting IPs...", "prog")
    all_ips = get_all_ips()
    TOTAL = len(all_ips)
    random.shuffle(all_ips)
    
    p(f"\n🚀 Phase 2: Starting scan", "prog")
    p(f"Total IPs: {TOTAL:,}", "info")
    p(f"Testing ports: {PORTS_TO_TEST}", "info")
    p(f"Output files:", "info")
    p(f"  Online IPs: {ONLINE_FILE}", "ok")
    p(f"  Working IPs: {OUTPUT_FILE}", "ok")
    p(f"  JSON Report: {JSON_FILE}", "ok")
    print("-" * 60)
    
    START = time.time()
    
    try:
        for i in range(0, len(all_ips), BATCH_SIZE):
            if STOP:
                break
            
            batch = all_ips[i:i+BATCH_SIZE]
            
            with ThreadPoolExecutor(max_workers=WORKERS) as executor:
                futures = [executor.submit(scan, ip) for ip in batch]
                
                for future in futures:
                    try:
                        future.result(timeout=1)
                    except:
                        pass
            
            time.sleep(DELAY)
            
            # Save JSON every 100 batches
            if i % (BATCH_SIZE * 100) == 0 and i > 0:
                save_json()
    
    except KeyboardInterrupt:
        STOP = True
    
    # Final save
    save_json()
    
    elapsed = time.time() - START if START else 0
    speed = SCANNED / elapsed if elapsed > 0 else 0
    
    print(f"\n\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}📊 FINAL REPORT{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"Total scanned: {SCANNED:,}/{TOTAL:,}")
    print(f"{Colors.GREEN}Online IPs: {ONLINE}{Colors.RESET}")
    print(f"{Colors.GREEN}Working IPs (open ports): {FOUND}{Colors.RESET}")
    print(f"Duration: {elapsed/60:.0f} minutes")
    print(f"Speed: {speed:.0f} IP/sec")
    print(f"\n📁 Output files:")
    print(f"  {Colors.GREEN}Online IPs:{Colors.RESET} {ONLINE_FILE}")
    print(f"  {Colors.GREEN}Working IPs:{Colors.RESET} {OUTPUT_FILE}")
    print(f"  {Colors.GREEN}JSON Report:{Colors.RESET} {JSON_FILE}")
    
    # Show sample online IPs
    if online_ips:
        print(f"\n{Colors.GREEN}Sample Online IPs (for manual testing):{Colors.RESET}")
        for ip in online_ips[-20:]:
            print(f"  {Colors.GREEN}{ip}{Colors.RESET}")
    
    # Quick manual test suggestions
    if online_ips and FOUND == 0:
        print(f"\n{Colors.YELLOW}💡 Manual Testing Suggestions:{Colors.RESET}")
        print(f"  Test with curl: curl -v http://{online_ips[-1]}/")
        print(f"  Test HTTPS: curl -v https://{online_ips[-1]}/")
        print(f"  Test with nmap: nmap -p- {online_ips[-1]}")
        print(f"  Check all online IPs in: {ONLINE_FILE}")
    
    if platform.system() == 'Windows':
        print(f"\n{Colors.YELLOW}Press Enter to exit...{Colors.RESET}")
        input()

if __name__ == "__main__":
    main()
