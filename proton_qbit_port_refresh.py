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

VPN_EXE = r"C:\Program Files\Proton\VPN\ProtonVPN.Launcher.exe" #Path to ProtonVPN.Launcher.exe
QBIT_EXE = r"C:\Program Files\qBittorrent\qbittorrent.exe" #Path to qBittorrent.exe

LOG_DIR = r"C:\Users\Plex\AppData\Local\Proton\Proton VPN\Logs" #Path to ProtonVPN Logs dir
QBIT_CONFIG = r"C:\Users\Plex\AppData\Roaming\qBittorrent\qBittorrent.ini" #Path to qBittorrrent.ini

#When TOKEN_ENFORCEMENT = 1, ensures qBittorrent binds the correct ProtonVPN adapter (usually iftype53_32768 or iftype53_32769)
#This prevents leaks and prevents connection failures when the adapter token assigned by Windows has changed (resulting in ProtonVPN appearing twice in the dropdown)
TOKEN_ENFORCEMENT = 1

CLIENT_TIMEOUT = 60 #Maximum number of seconds to wait for VPN interface to come up after restart
MAX_RESTARTS = 3 #How many times the script will re-exec if VPN fails to connect or no port is found

#When PORT_CHANGE_ENFORCEMENT = 1, consider success only if most recent port before launching ProtonVPN =/= most recent port after launching ProtonVPN
#This is to ensure that (a) randomise server is working and (b) the app itself is working
#Turn this off if you anticipate the port remaining the same between launches as expected behaviour
PORT_CHANGE_ENFORCEMENT = 1
PORT_CHANGE_RETRIES = 2      # additional full restart cycles if port did not change
PORT_CHANGE_WAIT = 60        # seconds to wait for a post-restart port
PORT_STABILIZE_SLEEP = 30    # seconds to allow Proton services to settle after start
PORT_POLL_INTERVAL = 5       # seconds between log scans for forwarded port

#Logging debug output of THIS SCRIPT
#Recommended for troubleshooting purposes
ENABLE_LOGGING = True
DEBUG_LOG_PATH = r"C:\Users\Plex\Documents\vpn_port_debug.log"

# ------------------- FLAGS -------------------

# Matches "Port pair 52070->52070", "Forwarded port: 52070", "Assigned port 52070"
PORT_PATTERN = r"(?:Port\s*pair|Forwarded\s*port|Assigned\s*port)\D+(\d{2,5})"
VPN_INTERFACE_FRIENDLY_NAME = "ProtonVPN"

PROCESS_ACTIONS = {
    "openvpn.exe": "kill",
    "qbittorrent.exe": "terminate",
    "ProtonVPN.Client.exe": "kill",
    "ProtonVPNService.exe": "kill",
    "ProtonVPN.WireGuardService.exe": "kill",
}

# ------------------- LOGGING -------------------

if ENABLE_LOGGING:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(DEBUG_LOG_PATH, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def log(message: str) -> None:
    if ENABLE_LOGGING:
        logging.debug(message)
    else:
        print(message)


# ------------------- ADMIN CHECK -------------------

def check_admin() -> None:
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False
    if not is_admin:
        print("This script requires administrative privileges. Please run as administrator.")
        time.sleep(10)
        sys.exit(1)


# ------------------- PROCESS CONTROL -------------------

def terminate_conflicting_processes() -> None:
    log("Terminating conflicting processes...")
    found = False
    for proc in psutil.process_iter(['name']):
        try:
            name = (proc.info['name'] or "").lower()
            for target, action_name in PROCESS_ACTIONS.items():
                if name == target.lower():
                    action = getattr(proc, action_name, None)
                    if callable(action):
                        action()
                    found = True
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if found:
        log("Processes terminated. Waiting for clean exit...")
        time.sleep(3)
    else:
        log("No conflicting processes found.")


def start_protonvpn() -> None:
    log("Starting ProtonVPN...")
    os.startfile(VPN_EXE)


def is_vpn_connected() -> bool:
    for name, _ in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        if not stats or not stats.isup:
            continue
        lname = name.lower()
        if "proton" in lname or "tun" in lname or "tap" in lname or "wg" in lname:
            return True
    return False


def wait_for_vpn_connection(timeout: int = CLIENT_TIMEOUT) -> None:
    log("Waiting for VPN connection...")
    t0 = time.time()
    while time.time() - t0 < timeout:
        if is_vpn_connected():
            log("VPN connected.")
            os.environ.pop("REFRESH_RESTARTS", None)
            return
        time.sleep(2)
    raise TimeoutError("VPN did not connect within timeout")


# ------------------- PROTONVPN LOG SCRAPE -------------------

def _candidate_logs():
    # Include all .log and files starting with client-logs (covers rotations without .log)
    patterns = [os.path.join(LOG_DIR, "*.log"),
                os.path.join(LOG_DIR, "client-logs*")]
    seen = set()
    for pat in patterns:
        for p in glob.glob(pat):
            if os.path.isfile(p) and p not in seen:
                seen.add(p)
                yield p


def get_latest_log_file() -> str | None:
    paths = list(_candidate_logs())
    if not paths:
        return None
    return max(paths, key=os.path.getmtime)


def get_last_forwarded_port_from_file(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
        m = re.findall(PORT_PATTERN, data, flags=re.IGNORECASE)
        return m[-1] if m else None
    except Exception as e:
        log(f"Failed reading {path}: {e}")
        return None


def get_last_forwarded_port_from_logs() -> str | None:
    # Search all candidate logs and take the most recent match by file mtime
    best = None
    best_ts = -1
    for p in _candidate_logs():
        port = get_last_forwarded_port_from_file(p)
        if port:
            ts = os.path.getmtime(p)
            if ts > best_ts:
                best = port
                best_ts = ts
    if best:
        log(f"Most recent forwarded port found in logs: {best}")
    else:
        log("No forwarded port found in any log.")
    return best


def wait_for_port_in_log(log_file: str, timeout: int = 60, poll_interval: int = PORT_POLL_INTERVAL) -> str | None:
    """
    Poll the given log file every poll_interval seconds for a forwarded port line.
    Returns the most recent port found, or None if no port appears within timeout.
    """
    log(f"Watching log file for forwarded port: {log_file}")
    t0 = time.time()

    while time.time() - t0 < timeout:
        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
            m = re.findall(PORT_PATTERN, data, flags=re.IGNORECASE)
            if m:
                port = m[-1]
                log(f"Detected forwarded port: {port}")
                return port
        except Exception as e:
            log(f"Log read error: {e}")
        time.sleep(poll_interval)

    return None


# ------------------- QBIT CONFIG -------------------

def update_qbittorrent_port(port: str) -> None:
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


# ------------------- ADAPTER TOKEN -------------------

class NET_LUID_LH(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_ulonglong)]


iphlpapi = ctypes.WinDLL("iphlpapi")
ConvertInterfaceIndexToLuid = iphlpapi.ConvertInterfaceIndexToLuid
ConvertInterfaceIndexToLuid.argtypes = [wintypes.ULONG, ctypes.POINTER(NET_LUID_LH)]
ConvertInterfaceIndexToLuid.restype = wintypes.ULONG


def _luid_token_from_index(idx: int) -> str | None:
    luid = NET_LUID_LH(0)
    ret = ConvertInterfaceIndexToLuid(idx, ctypes.byref(luid))
    if ret != 0:
        return None
    val = int(luid.Value)
    iftype = (val >> 48) & 0xFFFF
    netluid_index = (val >> 24) & 0xFFFFFF
    return f"iftype{iftype}_{netluid_index}"


def _get_adapter_token_by_name(name_substring: str) -> str | None:
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
                log(f"Matched adapter: {name}")
                return _luid_token_from_index(idx)
    return None


def enforce_vpn_binding() -> None:
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
            out.append(desired_name_line)
            have_name = True
            continue
        if s.startswith(keep_key_token + "="):
            out.append(desired_token_line)
            have_token = True
            continue
        if any(s.startswith(p) for p in drop_prefixes):
            continue
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
        log("Enforced VPN binding updated.")
    except Exception as e:
        log(f"Unable to write qBittorrent config for binding enforcement: {e}")


# ------------------- LAUNCH -------------------

def launch_qbittorrent() -> None:
    log("Starting qBittorrent...")
    os.startfile(QBIT_EXE)


# ------------------- ORCHESTRATION -------------------

def vpn_restart_cycle() -> str | None:
    terminate_conflicting_processes()
    start_protonvpn()
    time.sleep(PORT_STABILIZE_SLEEP)
    wait_for_vpn_connection(timeout=CLIENT_TIMEOUT)
    log_file = get_latest_log_file()
    post_port = None
    if log_file:
        post_port = wait_for_port_in_log(log_file, timeout=PORT_CHANGE_WAIT, poll_interval=PORT_POLL_INTERVAL)
    else:
        log("No ProtonVPN log file found after restart.")
    return post_port


# ------------------- MAIN -------------------

def main() -> None:
    check_admin()

    # Read the most recent port before killing anything
    previous_port = get_last_forwarded_port_from_logs()
    if previous_port:
        log(f"Pre-restart forwarded port: {previous_port}")
    else:
        log("No pre-restart forwarded port detected.")

    try:
        # First restart cycle
        post_port = vpn_restart_cycle()

        # Optional enforcement that the port must change
        if PORT_CHANGE_ENFORCEMENT and previous_port and post_port and post_port == previous_port:
            log(f"Post-restart port {post_port} equals pre-restart port {previous_port}. Enforcing change.")
            retries = 0
            while retries < PORT_CHANGE_RETRIES:
                retries += 1
                log(f"Port change retry {retries}/{PORT_CHANGE_RETRIES}")
                post_port = vpn_restart_cycle()
                if post_port and post_port != previous_port:
                    log(f"Observed new port after retry: {post_port}")
                    break
            if post_port == previous_port:
                log("Port did not change after retries. Proceeding to avoid excessive restarts.")

        # If no port found but VPN is connected, proceed without updating qBittorrent port
        if post_port:
            update_qbittorrent_port(post_port)
        else:
            if is_vpn_connected():
                log("VPN connected but no forwarded port observed. Proceeding without port update.")
            else:
                raise TimeoutError("VPN not connected and no forwarded port observed.")

        enforce_vpn_binding()
        launch_qbittorrent()

    except TimeoutError as te:
        if not is_vpn_connected():
            count = int(os.environ.get("REFRESH_RESTARTS", "0"))
            if count < MAX_RESTARTS:
                count += 1
                os.environ["REFRESH_RESTARTS"] = str(count)
                log(f"{te}. Restarting script (attempt {count}/{MAX_RESTARTS})...")
                python = sys.executable
                os.execl(python, python, *sys.argv)
        log("Maximum restarts reached or VPN appears connected. Halting.")
        input("Press enter key to exit...")
        sys.exit(1)
    except KeyboardInterrupt:
        log("Interrupted by user. Exiting...")
        time.sleep(10)
        sys.exit(1)
    except Exception as e:
        log(f"Fatal error: {e}. Exiting...")
        time.sleep(10)
        sys.exit(1)


if __name__ == "__main__":
    main()
    print("This window will close in 10 seconds...")
    time.sleep(10)
