# This script kills qBittorrent, ProtonVPN and all their associated components
# Then restarts everything, copies the port number into qBittorrent's config file, and updates ProtonVPN IP entry in config file if necessary
# Tested working as of ProtonVPN client 4.3.5 and qBittorrent 5.1.2, on a Windows 11 Pro 24H2 install (build 26100.6899)
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
import socket
from datetime import datetime, timezone
from ctypes import wintypes

# ------------------- CONFIG -------------------

VPN_EXE = r"C:\Program Files\Proton\VPN\ProtonVPN.Launcher.exe"
QBIT_EXE = r"C:\Program Files\qBittorrent\qbittorrent.exe"

LOG_DIR = r"C:\Users\Plex\AppData\Local\Proton\Proton VPN\Logs"
QBIT_CONFIG = r"C:\Users\Plex\AppData\Roaming\qBittorrent\qBittorrent.ini"

# Name ProtonVPN's interface appears as in your taskbar
# Used in script to check whether interface is up
# Also used as a name match for token enforcement if enabled (see below)
VPN_INTERFACE_FRIENDLY_NAME = "ProtonVPN"

# Maximum number of script restarts before aborting
# Prevents network thrashing if there's a problem that is preventing the script completing
MAX_RESTARTS = 3

# Enforce that the forwarded port after restart differs from the last seen port
PORT_CHANGE_ENFORCEMENT = 1    # disable if the port remaining the same is an expected behaviour in your use case
PORT_CHANGE_RETRIES = 2      # additional full restart cycles if port did not change
PORT_CHANGE_WAIT = 60        # seconds to wait for a post-restart port
CLIENT_TIMEOUT = 120    # seconds to allow Proton services to settle after start
PORT_POLL_INTERVAL = 5       # seconds between log scans for forwarded port

# Script debug output
ENABLE_LOGGING = True
DEBUG_LOG_PATH = r"C:\Users\Plex\Documents\vpn_port_debug.log"

# Keep script alive and re-poll logs every X minutes for port changes (0 disables)
PORT_REPOLL_MINUTES = 0

# ------------------- FLAGS -------------------

# Matches "Port pair XXXXX->XXXXX", "Forwarded port: XXXXX", "Assigned port: XXXXX"
PORT_PATTERN = r"(?:Port\s*pair|Forwarded\s*port|Assigned\s*port)\D+(\d{2,5})"
TIMESTAMP_PATTERN = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)"

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

def wait_for_adapter_up(adapter_name: str, timeout: int = CLIENT_TIMEOUT, poll_interval: int = 2) -> bool:
    """
    Wait until the given network adapter reports as 'up'.
    Returns True if the adapter is up within the timeout, False otherwise.
    """
    log(f"Waiting for adapter '{adapter_name}' to come up...")
    t0 = time.time()
    while time.time() - t0 < timeout:
        stats = psutil.net_if_stats().get(adapter_name)
        if stats and stats.isup:
            log(f"Adapter '{adapter_name}' is up.")
            return True
        time.sleep(poll_interval)
    log(f"Adapter '{adapter_name}' did not come up within {timeout} seconds.")
    return False

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


def terminate_qbittorrent_only() -> None:
    """Terminate only qBittorrent without touching VPN processes."""
    log("Terminating qBittorrent...")
    procs = []
    for proc in psutil.process_iter(['name']):
        try:
            if (proc.info['name'] or "").lower() == "qbittorrent.exe":
                proc.terminate()
                procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if procs:
        psutil.wait_procs(procs, timeout=5)
        time.sleep(1)  # allow handles to release
        log("qBittorrent terminated.")
    else:
        log("qBittorrent not running.")


# ------------------- PROTONVPN LOG SCRAPE -------------------

TIMESTAMP_PATTERN = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)"
def _parse_timestamp(line: str) -> datetime | None:
    m = re.match(TIMESTAMP_PATTERN, line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")
        return ts.replace(tzinfo=timezone.utc).astimezone()
    except Exception:
        return None

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
    """
    Scan all ProtonVPN client logs for the most recent valid forwarded port.
    Only considers 'PortMappingCommunication' or 'Assigned port' lines,
    ignoring repeated 'SleepingUntilRefresh' entries. Returns the port
    with the newest timestamp overall.
    """
    port_times: dict[str, datetime] = {}

    for path in _candidate_logs():
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "PortMappingCommunication" not in line and "Assigned port" not in line:
                        continue
                    port_match = re.search(PORT_PATTERN, line, flags=re.IGNORECASE)
                    if port_match:
                        ts = _parse_timestamp(line)
                        if ts:
                            port = port_match.group(1)
                            if port not in port_times or ts > port_times[port]:
                                port_times[port] = ts
        except Exception as e:
            log(f"Error reading {path}: {e}")

    if not port_times:
        log("No forwarded port found in any log.")
        return None

    newest_port = max(port_times, key=lambda p: port_times[p])
    log(f"Newest forwarded port found: {newest_port} at {port_times[newest_port]}")
    return newest_port


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


def _get_adapter_ipv4_by_name(name_substring: str) -> str | None:
    for name, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        if not stats or not stats.isup:
            continue
        if name_substring.lower() not in name.lower():
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address and addr.address != "127.0.0.1":
                return addr.address
    return None

def wait_for_vpn_ip(name_substring: str, timeout: int = 20) -> str | None:
    """Wait until the specified adapter has a valid IPv4 address."""
    for _ in range(timeout):
        ipaddr = _get_adapter_ipv4_by_name(name_substring)
        if ipaddr:
            return ipaddr
        time.sleep(1)
    return None

def enforce_vpn_binding() -> None:
    import socket, time

    ipaddr = wait_for_vpn_ip(VPN_INTERFACE_FRIENDLY_NAME)
    if not ipaddr:
        log("Timed out waiting for ProtonVPN IPv4 address.")
        return

    try:
        with open(QBIT_CONFIG, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        log(f"Unable to read qBittorrent config: {e}")
        return

    out = []
    in_bt_section = False
    wrote_name = wrote_ip = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("["):
            # when a new section begins, close BitTorrent section if we were in it
            if in_bt_section and not (wrote_name and wrote_ip):
                if not wrote_name:
                    out.append(f"Session\\InterfaceName={VPN_INTERFACE_FRIENDLY_NAME}\n")
                if not wrote_ip:
                    out.append(f"Session\\InterfaceAddress={ipaddr}\n")
            in_bt_section = stripped.lower() == "[bittorrent]"
            out.append(line)
            continue

        if in_bt_section:
            if stripped.startswith("Session\\InterfaceName="):
                out.append(f"Session\\InterfaceName={VPN_INTERFACE_FRIENDLY_NAME}\n")
                wrote_name = True
                continue
            if stripped.startswith("Session\\InterfaceAddress="):
                out.append(f"Session\\InterfaceAddress={ipaddr}\n")
                wrote_ip = True
                continue
            if stripped.startswith("Session\\Interface=") or stripped.startswith("Session\\InterfaceId="):
                # drop any obsolete token entries
                continue

        out.append(line)

    # if [BitTorrent] section was never found, create it
    if not any("[BitTorrent]" in l for l in out):
        out.append("[BitTorrent]\n")
        out.append(f"Session\\InterfaceName={VPN_INTERFACE_FRIENDLY_NAME}\n")
        out.append(f"Session\\InterfaceAddress={ipaddr}\n")
    else:
        # if BitTorrent section existed but lines missing, append now
        if in_bt_section and (not wrote_name or not wrote_ip):
            if not wrote_name:
                out.append(f"Session\\InterfaceName={VPN_INTERFACE_FRIENDLY_NAME}\n")
            if not wrote_ip:
                out.append(f"Session\\InterfaceAddress={ipaddr}\n")

    try:
        with open(QBIT_CONFIG, "w", encoding="utf-8") as f:
            f.writelines(out)
        log(f"Updated [BitTorrent] binding to ProtonVPN ({ipaddr}).")
    except Exception as e:
        log(f"Unable to write qBittorrent config: {e}")

# ------------------- LAUNCH -------------------

def launch_qbittorrent() -> None:
    log("Starting qBittorrent...")
    os.startfile(QBIT_EXE)


# ------------------- ORCHESTRATION -------------------

def vpn_restart_cycle(prev_port: str | None = None) -> str | None:
    terminate_conflicting_processes()
    start_protonvpn()

    restart_time = datetime.now().astimezone()

    if not wait_for_adapter_up(VPN_INTERFACE_FRIENDLY_NAME, timeout=CLIENT_TIMEOUT):
        raise TimeoutError("ProtonVPN adapter did not come up in time.")
    wait_for_vpn_connection(timeout=CLIENT_TIMEOUT)

    log("Waiting for a new forwarded port entry in logs...")
    t0 = time.time()
    while time.time() - t0 < PORT_CHANGE_WAIT:
        port_times: dict[str, datetime] = {}
        for path in _candidate_logs():
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if "PortMappingCommunication" not in line and "Assigned port" not in line:
                            continue
                        m = re.search(PORT_PATTERN, line, flags=re.IGNORECASE)
                        if m:
                            ts = _parse_timestamp(line)
                            if ts and ts > restart_time:  # only accept lines newer than restart
                                port_times[m.group(1)] = ts
            except Exception:
                continue

        if port_times:
            newest_port = max(port_times, key=lambda p: port_times[p])
            newest_time = port_times[newest_port]
            log(f"New forwarded port {newest_port} detected at {newest_time}")
            return newest_port

        time.sleep(PORT_POLL_INTERVAL)

    log("Timeout: no new forwarded port appeared after restart.")
    return None





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
        # Optional keep-alive re-poll loop
        if PORT_REPOLL_MINUTES and PORT_REPOLL_MINUTES > 0:
            log(f"Re-polling every {PORT_REPOLL_MINUTES} minutes for port changes.")
            last_port = post_port or previous_port or get_last_forwarded_port_from_logs()
            while True:
                time.sleep(PORT_REPOLL_MINUTES * 60)
                current_port = get_last_forwarded_port_from_logs()
                if current_port and current_port != last_port:
                    log(f"Detected port change {last_port} to {current_port}")
                    # Ensure qBittorrent restarts on the new port
                    terminate_qbittorrent_only()
                    update_qbittorrent_port(current_port)
                    enforce_vpn_binding()
                    launch_qbittorrent()
                    last_port = current_port
                else:
                    log("No port change detected in this interval.")

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
