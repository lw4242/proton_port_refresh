# This script kills qBittorrent, ProtonVPN and all their associated components
# Then restarts everything, copies the port number into qBittorrent's config file, and updates network adapter token name if necessary
# Tested working as of ProtonVPN client 4.3.1 and qBittorrent 5.1.2, on a Windows 11 Pro 24H2 install (build 26100.6584)
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

# Enforce checking of current adapter token and writing into qBittorrent.ini
# Ideally enable as it will prevent the issue of ProtonVPN appearing twice in the qBittorrent dropdown when Windows refreshes its token
# But can be disabled if this causes problems
TOKEN_ENFORCEMENT = 1

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
