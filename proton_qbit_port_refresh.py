# This script kills qBittorrent, ProtonVPN and all their associated components, then restarts everything and copies the port number into qBittorrent's config file
# Tested working as of ProtonVPN client 4.1.12 and qBittorrent 5.1.0
# It must be run as an administrator
# Configure your ProtonVPN client to connect to a random server on startup
# Also change your directories in the CONFIG section of this script to match the correct paths for your system
# If enabling debug logging then set LOGGING_ENABLED = True and provide a valid file path

import os
import re
import time
import psutil
import glob
import logging
import sys
import ctypes

# ------------------- CONFIG -------------------
VPN_EXE = r"C:\Program Files\Proton\VPN\ProtonVPN.Launcher.exe"
QBIT_EXE = r"C:\Program Files\qBittorrent\qbittorrent.exe"
QBIT_CONFIG = r"C:\Users\<YourUsername>\AppData\Roaming\qBittorrent\qBittorrent.ini"
LOG_DIR = r"C:\Users\<YourUsername>\AppData\Local\Proton\Proton VPN\Logs"

PROCESS_ACTIONS = {
    "openvpn.exe": "kill",
    "qbittorrent.exe": "terminate",
    "ProtonVPN.Client.exe": "kill",
    "ProtonVPNService.exe": "kill",
    "ProtonVPN.WireGuardService.exe": "kill"
}

PORT_PATTERN = r"Port pair (\d{1,5})"

# ------------------- LOGGING -------------------
ENABLE_LOGGING = False
DEBUG_LOG_PATH = r"C:\Users\<YourUsername>\Documents\vpn_port_debug.log"  # Change path if needed

if ENABLE_LOGGING:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(DEBUG_LOG_PATH),
            logging.StreamHandler(sys.stdout)
        ]
    )

def log(message):
    if ENABLE_LOGGING:
        logging.debug(message)
    else:
        print(message)

# ------------------- FUNCTIONS -------------------

def check_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    if not is_admin:
        print("This script requires administrative privileges. Please run as administrator.")
        time.sleep(10)
        sys.exit(1)

def terminate_conflicting_processes():
    log("Checking and terminating conflicting programs...")
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
        log("Processes terminated. Waiting for clean exit...")
        time.sleep(3)
    else:
        log("No conflicting processes found.")
    log(".")

def start_protonvpn():
    log("Starting ProtonVPN...")
    os.startfile(VPN_EXE)
    log(".")

def is_vpn_connected():
    for name, _ in psutil.net_if_addrs().items():
        if 'ProtonVPN' in name or 'tun' in name.lower() or 'tap' in name.lower():
            stats = psutil.net_if_stats().get(name)
            if stats and stats.isup:
                return True
    return False

def wait_for_vpn_connection():
    log("Waiting for ProtonVPN to connect...")
    while not is_vpn_connected():
        log("Still waiting...")
        time.sleep(2)
    log("VPN connected.")
    log(".")

def get_latest_log_file():
    logs = glob.glob(os.path.join(LOG_DIR, "client-logs*"))
    return max(logs, key=os.path.getmtime) if logs else None

def wait_for_port_in_log(log_file):
    log(f"Watching log file: {log_file}")
    last_size = os.path.getsize(log_file)
    log("Waiting for *new* Port pair to appear in the log...")

    while True:
        current_size = os.path.getsize(log_file)
        if current_size > last_size:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(last_size)
                new_data = f.read()
                matches = re.findall(PORT_PATTERN, new_data)
                if matches:
                    port = matches[-1]
                    log(f"Found new port number: {port}")
                    return port
            last_size = current_size
        time.sleep(2)

def update_qbittorrent_port(port):
    log("Updating qBittorrent config...")

    updated = False
    lines = []

    try:
        with open(QBIT_CONFIG, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip().startswith("Session\\Port="):
                    line = f"Session\\Port={port}\n"
                    updated = True
                lines.append(line)

        if updated:
            with open(QBIT_CONFIG, "w", encoding="utf-8") as f:
                f.writelines(lines)
            log(f"Port updated to {port}.")
        else:
            log("No Session\\Port line found to update.")
    except Exception as e:
        log(f"Error updating config: {e}")

def launch_qbittorrent():
    log("Starting qBittorrent...")
    os.startfile(QBIT_EXE)
    log(".")

# ------------------- MAIN -------------------

def main():
    check_admin()

    try:
        terminate_conflicting_processes()
        start_protonvpn()
        time.sleep(5)
        wait_for_vpn_connection()

        log_file = get_latest_log_file()
        if not log_file:
            log("No log file found. Exiting.")
            return

        port = wait_for_port_in_log(log_file)
        if port:
            update_qbittorrent_port(port)
            launch_qbittorrent()

    except KeyboardInterrupt:
        log("Script interrupted by user.")
    except Exception as e:
        log(f"Fatal error: {e}")

if __name__ == "__main__":
    main()
    print("This window will close in 10 seconds...")
    time.sleep(10)
