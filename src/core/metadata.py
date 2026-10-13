"""Analyst metadata and OPSEC assessment for forensic sessions."""

import getpass
import ipaddress
import platform
import re
import socket
import subprocess
from pathlib import Path
from typing import Optional

import requests

# Central helpers keep action decisions and persisted metadata consistent.
from src.core.guarded_http import guarded_request

from src.core.scope_guard import check_and_trace, set_source_ip

# Interface names used by common VPN clients and WireGuard setups.
_TUNNEL_NAME_PREFIXES = (
    "wg", "tun", "tap", "ppp", "utun", "ipsec",
    "proton", "pvpn", "nordlynx", "mullvad", "tailscale",
)
# /sys/class/net/<iface>/type: ARPHRD_NONE (WireGuard, tun) and ARPHRD_PPP.
_TUNNEL_LINK_TYPES = {"65534", "512"}


def get_external_ip() -> str:
    """Get our external IP address for forensic documentation"""
    try:
        services = [
            "https://api.ipify.org",
            "https://checkip.amazonaws.com",
            "https://ipinfo.io/ip",
        ]
        for service in services:
            try:
                response = guarded_request(requests.get, service, timeout=5, tool="external_ip", source_probe=True)
                if response.status_code == 200:
                    # Validate discovery data before using it as trace context.
                    value = str(ipaddress.ip_address(response.text.strip()))
                    set_source_ip(value)
                    return value
            except Exception:
                continue
        return "Unknown"
    except Exception:
        return "Unknown"


def get_local_ip() -> str:
    """Get our local IP address"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # UDP connect only selects a local route; trace it nevertheless.
            if not check_and_trace("local_route", "UDP route 8.8.8.8:80", "8.8.8.8", tool="metadata"):
                return "Unknown"
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "Unknown"


def get_system_metadata() -> dict:
    """Collect system metadata for forensic documentation"""
    try:
        return {
            "hostname": socket.gethostname(),
            "username": getpass.getuser(),
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
        }
    except Exception:
        return {
            "hostname": "Unknown",
            "username": "Unknown",
            "platform": "Unknown",
            "platform_version": "Unknown",
            "architecture": "Unknown",
        }


def detect_tunnel_interface(probe_ip: str = "8.8.8.8") -> Optional[str]:
    """Return the VPN tunnel interface that carries internet traffic (Linux only).

    Asks the kernel which interface it would use for ``probe_ip``
    (``ip route get`` sends no packet). That also covers policy routing as
    set up by wg-quick, which /proc/net/route does not show. The interface
    counts as a tunnel if it is a layer-3 tunnel or PPP device, or carries a
    typical VPN interface name. Returns None on other platforms or on error.
    """
    if platform.system() != "Linux":
        return None
    try:
        # The command queries local routing state without sending a packet.
        if not check_and_trace("subprocess", f"ip -o route get {probe_ip}", probe_ip, tool="ip", method="route"):
            return None
        output = subprocess.run(
            ["ip", "-o", "route", "get", probe_ip],
            capture_output=True, text=True, timeout=3, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None

    match = re.search(r"\bdev\s+(\S+)", output)
    if not match:
        return None
    iface = match.group(1)
    try:
        link_type = Path(f"/sys/class/net/{iface}/type").read_text(encoding="ascii").strip()
    except OSError:
        link_type = ""
    if link_type in _TUNNEL_LINK_TYPES or iface.lower().startswith(_TUNNEL_NAME_PREFIXES):
        return iface
    return None


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def assess_opsec_risk(external_ip: str, local_ip: str) -> dict:
    """Assess OPSEC risks for forensic analysis.

    Attribution risk is LOW only when a VPN signal is present. NAT alone does
    not lower it: the target still sees the public IP of the NAT router.
    """
    behind_nat = external_ip != local_ip and _is_private_ip(local_ip)

    tunnel_interface = detect_tunnel_interface()
    vpn_signal = "tunnel_interface" if tunnel_interface else None

    potential_vpn = bool(tunnel_interface)
    try:
        if not check_and_trace("dns", f"PTR {external_ip}", external_ip, tool="metadata", method="dns"):
            raise OSError("blocked_by_scope")
        rdns = socket.getfqdn(external_ip).lower()
        if any(
            k in rdns
            for k in (
                "mullvad",
                "nordvpn",
                "expressvpn",
                "protonvpn",
                "privateinternetaccess",
                "torguard",
                "hidemyass",
                "vyprvpn",
                "ipvanish",
                "surfshark",
            )
        ):
            potential_vpn = True
            vpn_signal = vpn_signal or "rdns"
    except Exception:
        pass

    attribution_risk = "LOW" if potential_vpn else "MEDIUM"
    stealth_level = "HIGH" if potential_vpn else "MEDIUM"

    return {
        "attribution_risk": attribution_risk,
        "stealth_level": stealth_level,
        "analysis_type": "MIXED - Passive APIs + Active Probes",
        "behind_nat": behind_nat,
        "potential_vpn": potential_vpn,
        "vpn_signal": vpn_signal,
        "tunnel_interface": tunnel_interface,
    }
