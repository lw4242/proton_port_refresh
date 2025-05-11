# This script kills Deluge, ProtonVPN and all its associated components, then restarts everything and copies the port number into Deluge's config file
# Tested working as of ProtonVPN client 4.1.12 and Deluge client 2.2.0
# Be sure to run this script as admin (some kill commands require elevation) and configure your ProtonVPN client to connect to a random server on startup
# Also change your directories in the CONFIG section of this script to match the correct paths for your system

import os
import re
import time
import psutil
import glob
import subprocess

# ------------------- CONFIG -------------------
VPN_EXE = r"C:\Program Files\Proton\VPN\ProtonVPN.Launcher.exe"
DELUGE_EXE = r"C:\Program Files\Deluge\deluge.exe"
DELUGE_CONFIG = r"C:\Users\<YourUsername>\AppData\Roaming\deluge\core.conf"
LOG_DIR = r"C:\Users\<YourUsername>\AppData\Local\Proton\Proton VPN\Logs"

PROCESS_ACTIONS = {
    "openvpn.exe": "kill",
    "deluge.exe": "terminate",
    "ProtonVPN.Client.exe": "kill",
    "ProtonVPNService.exe": "kill",
    "ProtonVPN.WireGuardService.exe": "kill"
}

PORT_PATTERN = r"Port pair (\d{1,5})"
DELUGE_PORT_PATTERN = r'"listen_ports":\s*\[\s*(\d{1,5})\s*\]'

# ------------------- FUNCTIONS -------------------

def terminate_conflicting_processes():
    print("Checking and terminating conflicting programs...")
    found = False
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name']
            if name in PROCESS_ACTIONS:
                getattr(proc, PROCESS_ACTIONS[name])()
                found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if found:
        print("Processes terminated. Waiting for clean exit...")
        time.sleep(3)
    else:
        print("No conflicting processes found.")
        time.sleep(1)
    print(".")

def start_protonvpn():
    print("Starting ProtonVPN...")
    os.startfile(VPN_EXE)
    print(".")

def is_vpn_connected():
    for name, _ in psutil.net_if_addrs().items():
        if 'ProtonVPN' in name or 'tun' in name.lower() or 'tap' in name.lower():
            stats = psutil.net_if_stats().get(name)
            if stats and stats.isup:
                return True
    return False

def wait_for_vpn_connection():
    print("Waiting for ProtonVPN to connect...")
    while not is_vpn_connected():
        print("Still waiting...")
        time.sleep(5)
    print("VPN connected.")
    print(".")

def get_latest_log_file():
    logs = glob.glob(os.path.join(LOG_DIR, "client-logs*"))
    return max(logs, key=os.path.getmtime) if logs else None

def wait_for_port_in_log(log_file):
    print(f"Watching log file: {log_file}")
    last_size = os.path.getsize(log_file)
    print("Waiting for Port pair to appear in the log...")
    while True:
        time.sleep(2)
        new_size = os.path.getsize(log_file)
        if new_size > last_size:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(last_size)
                new_data = f.read()
                match = re.search(PORT_PATTERN, new_data)
                if match:
                    port = match.group(1)
                    print(f"Found port number: {port}")
                    print(".")
                    return port
            last_size = new_size

def update_deluge_port(port):
    print("Updating Deluge config...")

    with open(DELUGE_CONFIG, "r", encoding="utf-8") as f:
        config = f.read()

    # Regex: match optional whitespace before the key
    pattern = r'\s*"listen_ports"\s*:\s*\[\s*\d{1,5}\s*,\s*\d{1,5}\s*\]'
    new_block = f'    "listen_ports": [\n        {port},\n        {port}\n    ]'

    new_config, count = re.subn(pattern, new_block, config, flags=re.DOTALL)

    if count:
        with open(DELUGE_CONFIG, "w", encoding="utf-8") as f:
            f.write(new_config)
        print(f"Port updated to {port}.")
    else:
        print("Failed to find or update listen_ports in Deluge config.")

def launch_deluge():
    print("Starting Deluge...")
    os.startfile(DELUGE_EXE)
    print(".")
    print("Done.")
    time.sleep(5)

# ------------------- MAIN -------------------

def main():
    terminate_conflicting_processes()
    start_protonvpn()
    wait_for_vpn_connection()

    log_file = get_latest_log_file()
    if not log_file:
        print("No log file found. Exiting.")
        return

    port = wait_for_port_in_log(log_file)
    if port:
        update_deluge_port(port)
        launch_deluge()

if __name__ == "__main__":
    main()
