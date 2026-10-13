"""Validated engagement rules with a non-overridable exclusion baseline."""

import ipaddress
import json
import math
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from src.core.time_utils import utc_now

PROJECT_ROOT = Path(__file__).resolve().parents[2]
# Retain a minimum baseline even if an engagement or local file removes entries.
DEFAULT_HARD_DOMAINS = (
    "ns1.dns-parking.com", "ns2.dns-parking.com", "mail.protonmail.ch",
    "protonmail.ch", "proton.ch", "stripe.com", "api.openai.com",
    "api.anthropic.com", "api.mistral.ai", "openai.azure.com",
    "cognitiveservices.azure.com", "nexmo.com", "vonage.com", "twilio.com",
    "graph.microsoft.com", "login.microsoftonline.com",
)
DEFAULT_HARD_IPS = ("142.132.194.129",)
DEFAULT_FORBIDDEN = ("dos", "ddos", "brute_force", "fuzzing", "axfr", "persistent_access")


def extract_host(target: str) -> str:
    """Normalize URLs, IDNA hosts and bracketed IPv6 without suffix confusion."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Empty target")
    value = target.strip()
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid target URL")
        value = parsed.hostname
    value = value.rstrip(".").lower()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        # Some HTTP/system transports accept integer, octal or hex IPv4 literals.
        try:
            return socket.inet_ntoa(socket.inet_aton(value))
        except OSError:
            pass
        if any(c in value for c in "/:@?#\\ \t\r\n"):
            raise ValueError("Invalid target host")
        return value.encode("idna").decode("ascii")


def _domain_match(host: str, rule: str) -> bool:
    rule = extract_host(rule.removeprefix("*."))
    return host == rule or host.endswith("." + rule)


def _instant(value: str):
    if not value:
        return None
    if not isinstance(value, str):
        raise ValueError("Timewindow values must be ISO 8601 strings")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timewindow requires a timezone")
    return parsed.astimezone(timezone.utc)


def _read(path: Path):
    with path.open(encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError(f"Scope configuration must be an object: {path}")
    return data


class ScopeConfig:
    def __init__(self, path: Path | None = None, defaults_path: Path | None = None):
        self._data = _read(Path(path)) if path is not None else {}
        baseline = Path(defaults_path) if defaults_path else PROJECT_ROOT / "config/hard_exclusions_default.json"
        # Always load the basis file; embedded minimum is retained if it is absent.
        defaults = _read(baseline) if baseline.exists() else {}
        self._hard = {"domains": list(DEFAULT_HARD_DOMAINS), "ips": list(DEFAULT_HARD_IPS), "cidrs": []}
        for source in (defaults, self._data.get("hard_exclusions", {})):
            self._validate_targets(source, hard=True)
            for key in self._hard:
                self._hard[key].extend(source.get(key, []))
        for key in ("targets_allowed", "targets_denied"):
            self._validate_targets(self._data.get(key, {}))
        for key in ("methods_allowed", "methods_forbidden", "source_ips_allowed"):
            self._string_list(self._data.get(key, []), key)
        for value in self._data.get("source_ips_allowed", []):
            ipaddress.ip_network(value, strict=False)
        allowed = self._data.get("targets_allowed", {})
        ports = allowed.get("ports", [])
        if not isinstance(ports, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
            raise ValueError("Ports must be integers between 1 and 65535")
        self._string_list(allowed.get("paths", []), "paths")
        if any(not p.startswith("/") for p in allowed.get("paths", [])):
            raise ValueError("Allowed paths must start with /")
        self._start = _instant(self._data.get("valid_from_utc", ""))
        self._end = _instant(self._data.get("valid_until_utc", ""))
        if self._start and self._end and self._start > self._end:
            raise ValueError("Timewindow start is after end")
        rate = self._data.get("rate_limit_req_per_sec", 20)
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate <= 0:
            raise ValueError("Rate limit must be positive and finite")

    @staticmethod
    def _string_list(value, name):
        if not isinstance(value, list) or any(not isinstance(v, str) or not v.strip() for v in value):
            raise ValueError(f"{name} must be a list of nonempty strings")

    @classmethod
    def _validate_targets(cls, value, hard=False):
        if not isinstance(value, dict):
            raise ValueError("Target rules must be objects")
        for key in ("domains", "ips", "cidrs"):
            cls._string_list(value.get(key, []), key)
        for domain in value.get("domains", []):
            extract_host(domain.removeprefix("*."))
        for ip in value.get("ips", []) + value.get("cidrs", []):
            ipaddress.ip_network(ip, strict=False)

    def is_within_timewindow(self) -> bool:
        now = utc_now()
        return (self._start is None or now >= self._start) and (self._end is None or now <= self._end)

    @staticmethod
    def _match(host, rules):
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return any(_domain_match(host, rule) for rule in rules.get("domains", []))
        # IPv4-mapped IPv6 must not bypass a denied IPv4 address or CIDR.
        addresses = [address]
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            addresses.append(address.ipv4_mapped)
        return any(candidate in ipaddress.ip_network(rule, strict=False)
                   for candidate in addresses
                   for rule in rules.get("ips", []) + rules.get("cidrs", []))

    def is_target_allowed(self, target: str, port: int | None = None, path: str = "") -> tuple[bool, str]:
        try:
            host = extract_host(target)
        except (ValueError, UnicodeError):
            return False, "invalid_target"
        if self._match(host, self._hard):
            return False, "hard_exclusion: " + host
        if self._match(host, self._data.get("targets_denied", {})):
            return False, "denied: " + host
        allowed = self._data.get("targets_allowed", {})
        if (allowed.get("domains") or allowed.get("ips") or allowed.get("cidrs")) and not self._match(host, allowed):
            return False, "not_in_allowlist"
        if port is not None and allowed.get("ports") and port not in allowed["ports"]:
            return False, "port_not_allowed"
        if path and allowed.get("paths"):
            from posixpath import normpath
            normalized = normpath(unquote(path))
            if not any(normalized == p.rstrip("/") or normalized.startswith(p.rstrip("/") + "/")
                       for p in allowed["paths"]):
                return False, "path_not_allowed"
        return True, "allowed"

    def is_method_allowed(self, method: str) -> tuple[bool, str]:
        method = method.lower()
        forbidden = self._data.get("methods_forbidden", list(DEFAULT_FORBIDDEN))
        if method in [m.lower() for m in forbidden]:
            return False, "method_forbidden: " + method
        allowed = [m.lower() for m in self._data.get("methods_allowed", [])]
        # AXFR always requires explicit opt-in, including when no scope is loaded.
        if method == "axfr" and method not in allowed:
            return False, "axfr_not_in_methods_allowed"
        if allowed and method not in allowed:
            return False, "method_not_in_allowlist: " + method
        return True, "allowed"

    def is_source_allowed(self, source_ip: str) -> tuple[bool, str]:
        rules = self._data.get("source_ips_allowed", [])
        if not rules:
            return True, "allowed"
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return False, "source_ip_unknown"
        if not any(address in ipaddress.ip_network(rule, strict=False) for rule in rules):
            return False, "source_ip_not_allowed"
        return True, "allowed"

    @property
    def rate_limit(self) -> float:
        return self._data.get("rate_limit_req_per_sec", 20)
