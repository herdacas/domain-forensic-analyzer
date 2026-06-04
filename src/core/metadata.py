"""Analyst metadata and OPSEC assessment for forensic sessions."""

import getpass
import platform
import socket

import requests


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
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    return response.text.strip()
            except Exception:
                continue
        return "Unknown"
    except Exception:
        return "Unknown"


def get_local_ip() -> str:
    """Get our local IP address"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
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


def assess_opsec_risk(external_ip: str, local_ip: str) -> dict:
    """Assess OPSEC risks for forensic analysis"""
    behind_nat = external_ip != local_ip and local_ip.startswith(
        ("192.168.", "10.", "172.")
    )

    potential_vpn = False
    try:
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
    except Exception:
        pass

    attribution_risk = "LOW" if behind_nat else "MEDIUM"
    stealth_level = "HIGH" if potential_vpn else "MEDIUM"

    return {
        "attribution_risk": attribution_risk,
        "stealth_level": stealth_level,
        "analysis_type": "MIXED - Passive APIs + Active Probes",
        "behind_nat": behind_nat,
        "potential_vpn": potential_vpn,
    }
