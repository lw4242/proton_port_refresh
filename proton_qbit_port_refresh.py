# This script kills qBittorrent, ProtonVPN and all their associated components
# Then restarts everything, copies the port number into qBittorrent's config file, and updates network adapter token name if necessary
# Tested working as of ProtonVPN client 4.2.1 and qBittorrent 5.1.2, on a Windows 11 Pro 24H2 install (build 26100.4652)
# It must be run as an administrator. If adding to Task Scheduler then make sure 'run with the highest privileges' is ticked
# Configure your ProtonVPN client to connect to a random server on startup
# Also change your directories and paths in the CONFIG section of this script to match the correct paths for your system

import os
import re
import time
import psutil
import glob
import logging
import sys
import ctypes
import subprocess
from ctypes import wintypes

# ------------------- CONFIG -------------------

# Executable locations
VPN_EXE = r"C:\Program Files\Proton\VPN\ProtonVPN.Launcher.exe"
QBIT_EXE = r"C:\Program Files\qBittorrent\qbittorrent.exe"

# ProtonVPN client log path (used to scrape 'Port pair NNNNN')
LOG_DIR = r"C:\Users\Plex\AppData\Local\Proton\Proton VPN\Logs"

# qBittorrent configuration file location (used to update port, and the network adapter token if TOKEN_ENFORCEMENT = 1) 
QBIT_CONFIG = r"C:\Users\Plex\AppData\Roaming\qBittorrent\qBittorrent.ini"

# Force renewal of network adapter token name
# When enabled, gets the current network adapter token name from Windows enumeration and updates qBittorrent.ini with the correct value
# Enable if you are having issues with no connections after restarting qB (https://github.com/qbittorrent/qBittorrent/issues/23103)
TOKEN_ENFORCEMENT = 1

# Maximum length of time between Proton client launch and detection of port pair in log
# If times out (eg client freezes on start up) then kill client and start process again
CLIENT_TIMEOUT = 30

# Maximum number of restarts after time out occurs
# Stops your network connection being battered if the client is stuck in a fault state
MAX_RESTARTS = 3

# Logging for debug purposes
ENABLE_LOGGING = True
DEBUG_LOG_PATH = r"C:\Users\Plex\Documents\vpn_port_debug.log"


# ------------------- ASSORTED FLAGS -------------------

# regex for extracting port pair from log
PORT_PATTERN = r"Port pair (\d{1,5})"

# name of interface as it appears in qBittorrent GUI
VPN_INTERFACE_FRIENDLY_NAME = "ProtonVPN"

# Processes to terminate prior to reconnection (action: terminate or kill)
PROCESS_ACTIONS = {
    "openvpn.exe": "kill",
    "qbittorrent.exe": "terminate",
    "ProtonVPN.Client.exe": "kill",
    "ProtonVPNService.exe": "kill",
    "ProtonVPN.WireGuardService.exe": "kill"
}

# ------------------- LOGGING SETUP -------------------

if ENABLE_LOGGING:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(DEBUG_LOG_PATH, encoding="utf-8"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def log(message):
    if ENABLE_LOGGING:
        logging.debug(message)
    else:
        print(message)

# ------------------- ADMIN CHECK -------------------

def check_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False
    if not is_admin:
        print("This script requires administrative privileges. Please run as administrator.")
        time.sleep(10)
        sys.exit(1)

# ------------------- PROCESS CONTROL -------------------

# Regex to extract forwarded port from ProtonVPN logs


def terminate_conflicting_processes():
    log("Terminating conflicting processes...")
    found = False
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name']
            if name in PROCESS_ACTIONS:
                action = getattr(proc, PROCESS_ACTIONS[name], None)
                if callable(action):
                    action()
                    found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if found:
        log("Processes terminated. Waiting for clean exit...")
        time.sleep(3)
    else:
        log("No conflicting processes found.")

def start_protonvpn():
    log("Starting ProtonVPN...")
    os.startfile(VPN_EXE)

def is_vpn_connected():
    # Heuristic: any up interface with Proton/TUN/TAP/WG in name
    for name, _ in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        if not stats or not stats.isup:
            continue
        lname = name.lower()
        if "proton" in lname or "tun" in lname or "tap" in lname or "wg" in lname:
            return True
    return False

def wait_for_vpn_connection(timeout=CLIENT_TIMEOUT):
    log("Waiting for VPN connection...")
    t0 = time.time()
    while time.time() - t0 < timeout:
        if is_vpn_connected():
            log("VPN connected.")
            # Reset restart counter on success
            os.environ.pop("REFRESH_RESTARTS", None)
            return
        time.sleep(2)
    raise TimeoutError("VPN did not connect within timeout")

# ------------------- PROTONVPN LOG SCRAPE -------------------

def get_latest_log_file():
    paths = glob.glob(os.path.join(LOG_DIR, "client-logs*"))
    if not paths:
        return None
    return max(paths, key=os.path.getmtime)

def wait_for_port_in_log(log_file, timeout=60):
    log(f"Watching log file for new port: {log_file}")
    try:
        last_size = os.path.getsize(log_file)
    except OSError:
        last_size = 0

    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            current_size = os.path.getsize(log_file)
            if current_size > last_size:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(last_size)
                    new_data = f.read()
                m = re.findall(PORT_PATTERN, new_data)
                if m:
                    port = m[-1]
                    log(f"Detected forwarded port: {port}")
                    return port
                last_size = current_size
        except Exception as e:
            log(f"Log read error: {e}")
        time.sleep(2)
    raise TimeoutError("Timed out waiting for forwarded port in log")

# ------------------- QBITTORRENT CONFIG EDITS -------------------

def update_qbittorrent_port(port: str):
    log("Updating qBittorrent port in configuration...")
    try:
        with open(QBIT_CONFIG, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        log(f"Unable to read qBittorrent config: {e}")
        return

    updated = False
    out = []
    for line in lines:
        if line.strip().startswith("Session\\Port="):
            out.append(f"Session\\Port={port}\n")
            updated = True
        else:
            out.append(line)

    if updated:
        try:
            with open(QBIT_CONFIG, "w", encoding="utf-8") as f:
                f.writelines(out)
            log(f"qBittorrent port updated to {port}.")
        except Exception as e:
            log(f"Unable to write qBittorrent config: {e}")
    else:
        log("No 'Session\\Port=' line found; nothing updated.")

# ------------------- ADAPTER TOKEN HELPERS -------------------

class NET_LUID_LH(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_ulonglong)]

iphlpapi = ctypes.WinDLL("iphlpapi")
ConvertInterfaceIndexToLuid = iphlpapi.ConvertInterfaceIndexToLuid
ConvertInterfaceIndexToLuid.argtypes = [wintypes.ULONG, ctypes.POINTER(NET_LUID_LH)]
ConvertInterfaceIndexToLuid.restype = wintypes.ULONG

def _luid_token_from_index(idx: int):
    luid = NET_LUID_LH(0)
    ret = ConvertInterfaceIndexToLuid(idx, ctypes.byref(luid))
    if ret != 0:
        return None
    val = int(luid.Value)
    iftype = (val >> 48) & 0xFFFF
    netluid_index = (val >> 24) & 0xFFFFFF
    return f"iftype{iftype}_{netluid_index}"

def _get_adapter_token_by_name(name_substring):
    try:
        proc = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "interfaces"],
            capture_output=True, text=True, check=True
        )
    except Exception:
        return None
    rx = re.compile(r"^\s*(\d+)\s+\d+\s+\d+\s+\S+\s+(.*\S)\s*$")
    for line in proc.stdout.splitlines():
        m = rx.match(line)
        if m:
            idx = int(m.group(1))
            name = m.group(2)
            if name_substring.lower() in name.lower():
                return _luid_token_from_index(idx)
    return None

def enforce_vpn_binding():
    """
    Ensure both:
        Session\\InterfaceName=<friendly>
        Session\\Interface=<current token>
    Remove:
        Session\\InterfaceId=...
        Session\\InterfaceAddress=...
    """
    if TOKEN_ENFORCEMENT != 1:
        log("Token enforcement disabled.")
        return

    token = _get_adapter_token_by_name(VPN_INTERFACE_FRIENDLY_NAME)
    if not token:
        log("VPN adapter token not found; skipping binding enforcement.")
        return
    log(f"Current adapter token: {token}")

    keep_key_name = "Session\\InterfaceName"
    keep_key_token = "Session\\Interface"
    drop_prefixes = ("Session\\InterfaceId=", "Session\\InterfaceAddress=")

    desired_name_line = f"{keep_key_name}={VPN_INTERFACE_FRIENDLY_NAME}\n"
    desired_token_line = f"{keep_key_token}={token}\n"

    try:
        with open(QBIT_CONFIG, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        log(f"Unable to read qBittorrent config for binding enforcement: {e}")
        return

    out = []
    have_bt = False
    have_name = False
    have_token = False

    for line in lines:
        s = line.strip()
        if s.lower() == "[bittorrent]":
            have_bt = True
            out.append(line)
            continue
        if s.startswith(keep_key_name + "="):
            out.append(desired_name_line)  # normalize
            have_name = True
            continue
        if s.startswith(keep_key_token + "="):
            out.append(desired_token_line)  # normalize
            have_token = True
            continue
        if any(s.startswith(p) for p in drop_prefixes):
            continue  # drop volatile keys
        out.append(line)

    if not have_name or not have_token:
        if not have_bt:
            out.append("[BitTorrent]\n")
        if not have_name:
            out.append(desired_name_line)
        if not have_token:
            out.append(desired_token_line)

    try:
        with open(QBIT_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(out)
        log("Enforced VPN binding: InterfaceName and Interface updated; volatile keys removed.")
    except Exception as e:
        log(f"Unable to write qBittorrent config for binding enforcement: {e}")

# ------------------- LAUNCH -------------------

def launch_qbittorrent():
    log("Starting qBittorrent...")
    os.startfile(QBIT_EXE)

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
            log("No ProtonVPN log file found; skipping port update.")
        else:
            port = wait_for_port_in_log(log_file, timeout=60)
            if port:
                update_qbittorrent_port(port)

        # Run binding enforcement AFTER port update but BEFORE launching qBittorrent
        enforce_vpn_binding()

        launch_qbittorrent()

    except TimeoutError as te:
        count = int(os.environ.get("REFRESH_RESTARTS", "0"))
        if count < MAX_RESTARTS:
            count += 1
            os.environ["REFRESH_RESTARTS"] = str(count)
            log(f"{te}. Restarting script (attempt {count}/{MAX_RESTARTS})...")
            python = sys.executable
            os.execl(python, python, *sys.argv)
        else:
            msg = f"Maximum restarts reached ({MAX_RESTARTS}). ProtonVPN unresponsive. Halted."
            log(msg)
            input("Press enter key to exit...")
            sys.exit(1)
    except KeyboardInterrupt:
        msg = f"Interrupted by user. Exiting..."
        log(msg)
        time.sleep(10)
        sys.exit(1)
    except Exception as e:
        msg = f"Fatal error: {e}. Exiting..."
        log(msg)
        time.sleep(10)
        sys.exit(1)

if __name__ == "__main__":
    main()
    print("This window will close in 10 seconds...")
    time.sleep(10)
