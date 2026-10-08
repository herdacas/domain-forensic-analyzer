"""
AlienVault OTX client for Domain Forensic Analyzer.

Passive domain intelligence from the Open Threat Exchange: passive DNS observations,
hostnames seen below the domain and threat pulses that reference it. Replaces SecurityTrails
as the passive domain-intelligence source (free account, API key in OTX_API_KEY).

Only OTX is queried; the target domain itself is never contacted.
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.config.api_config import SecureAPIManager
from src.utils.api_helpers import api_error_response

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
REQUEST_TIMEOUT = 30
MAX_RECORDS = 2000  # passive DNS entries evaluated per domain (popular domains return far more)
MAX_SUBDOMAINS = 50  # names returned in the result; all names are counted
MAX_PULSE_NAMES = 5
USER_AGENT = "Domain-Forensic-Analyzer/1.0"

# One passive DNS download per process and domain: the otx module and the DNS history share it.
_PASSIVE_DNS_CACHE: Dict[Tuple[str, str], Dict[str, Any]] = {}


def _status_error(status_code: int) -> Dict[str, Any]:
    if status_code == 429:
        return {"status": "quota_exceeded", "error": "AlienVault OTX API quota exceeded"}
    if status_code in (401, 403):
        return {"status": "failed", "error": f"AlienVault OTX rejected the API key (HTTP {status_code})"}
    return {"status": "failed", "error": f"AlienVault OTX HTTP {status_code}"}


def fetch_passive_dns(
    domain: str, api_key: str, session: Optional[requests.Session] = None
) -> Dict[str, Any]:
    """Return {"status": "success", "records": [...]} or a status/error dict.

    Records are OTX passive DNS entries (hostname, address, record_type, first, last, asn),
    capped at MAX_RECORDS. Successful downloads are cached for the lifetime of the process.
    """
    clean = domain.strip().lower().rstrip(".")
    cache_key = (clean, api_key)
    if cache_key in _PASSIVE_DNS_CACHE:
        return _PASSIVE_DNS_CACHE[cache_key]

    http = session or requests.Session()
    try:
        response = http.get(
            f"{OTX_BASE_URL}/indicators/domain/{clean}/passive_dns",
            headers={"X-OTX-API-KEY": api_key, "Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as error:
        return {"status": "failed", "error": f"AlienVault OTX request failed: {type(error).__name__}"}

    if response.status_code == 404:
        result = {"status": "success", "records": [], "total": 0}
    elif response.status_code != 200:
        return _status_error(response.status_code)
    else:
        try:
            payload = response.json()
        except ValueError:
            return {"status": "failed", "error": "AlienVault OTX returned invalid JSON"}
        entries = payload.get("passive_dns") if isinstance(payload, dict) else None
        entries = entries if isinstance(entries, list) else []
        records = [e for e in entries[:MAX_RECORDS] if isinstance(e, dict)]
        total = payload.get("count") if isinstance(payload.get("count"), int) else len(entries)
        result = {"status": "success", "records": records, "total": total}

    _PASSIVE_DNS_CACHE[cache_key] = result
    return result


def _clean_name(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


class OTXClient:
    """AlienVault OTX API client for passive domain intelligence."""

    def __init__(self):
        self.api_manager = SecureAPIManager()
        self.config = self.api_manager.get_api_config("otx")
        self.session = requests.Session()

        if self.config:
            self.session.headers.update(
                {
                    "X-OTX-API-KEY": self.config.api_key,
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                }
            )

    def analyze_domain_intelligence(self, domain: str) -> Dict[str, Any]:
        """
        Main OTX domain intelligence analysis.

        Args:
            domain: Domain to analyze

        Returns:
            Structured intelligence data (same top-level layout as the former SecurityTrails module)
        """
        if not self.config:
            return self._get_demo_result(domain)

        clean = _clean_name(domain)
        try:
            general = self._get_general(clean)
            pdns = fetch_passive_dns(clean, self.config.api_key, self.session)
            parts = (general, pdns)
            any_succeeded = any(p.get("status") == "success" for p in parts)

            if not any_succeeded:
                quota = any(p.get("status") == "quota_exceeded" for p in parts)
                return {
                    "analysis_status": "quota_exceeded" if quota else "failed",
                    "domain": domain,
                    "api_status": "quota_exceeded" if quota else "api_error",
                    "error": next((p.get("error") for p in parts if p.get("error")), "AlienVault OTX unavailable"),
                    "domain_details": {"subdomain_count": 0},
                }

            records = pdns.get("records", []) if pdns.get("status") == "success" else []
            subdomains = self._extract_subdomains(clean, records)
            categorized = self._categorize_subdomains(subdomains)
            historical = self._get_historical_dns_summary(clean, records, pdns)
            subdomain_data = {
                "total_found": len(subdomains),
                "top_subdomains": subdomains[:MAX_SUBDOMAINS],
                "categorized_assets": {k: v[:MAX_SUBDOMAINS] for k, v in categorized.items()},
                "sensitive_count": len(categorized["admin"]) + len(categorized["api"]),
                "records_evaluated": len(records),
                "records_total": pdns.get("total"),
                "status": pdns.get("status", "failed"),
            }
            domain_info = {
                "hostname": clean,
                "subdomain_count": len(subdomains),
                "pulse_count": general.get("pulse_count"),
                "first_seen": historical.get("first_seen"),
                "status": "success",
            }

            return {
                "analysis_status": "abgeschlossen",
                "domain": domain,
                "api_status": "live_data",
                "source": "AlienVault OTX",
                "partial": not all(p.get("status") == "success" for p in parts),
                "domain_details": domain_info,
                "historical_dns": historical,
                "subdomain_intelligence": subdomain_data,
                "threat_intelligence": general,
                "intelligence_summary": self._create_intelligence_summary(
                    domain_info, historical, subdomain_data, general
                ),
            }

        except Exception as error:
            return api_error_response(error, {"domain": domain})

    def _get_general(self, domain: str) -> Dict[str, Any]:
        """Threat pulses and validation entries that reference the domain."""
        try:
            response = self.session.get(
                f"{self.config.base_url}/indicators/domain/{domain}/general",
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as error:
            return {"status": "failed", "error": f"AlienVault OTX request failed: {type(error).__name__}"}
        if response.status_code == 404:
            return {"status": "success", "pulse_count": 0, "pulse_names": [], "validation": []}
        if response.status_code != 200:
            return _status_error(response.status_code)
        try:
            data = response.json()
        except ValueError:
            return {"status": "failed", "error": "AlienVault OTX returned invalid JSON"}

        pulse_info = data.get("pulse_info") if isinstance(data.get("pulse_info"), dict) else {}
        pulses = pulse_info.get("pulses") if isinstance(pulse_info.get("pulses"), list) else []
        count = pulse_info.get("count")
        names = [
            str(p.get("name"))[:120]
            for p in pulses
            if isinstance(p, dict) and p.get("name")
        ][:MAX_PULSE_NAMES]
        validation = [
            str(v.get("source"))[:40]
            for v in (data.get("validation") or [])
            if isinstance(v, dict) and v.get("source")
        ][:5]
        return {
            "status": "success",
            "pulse_count": count if isinstance(count, int) else len(pulses),
            "pulse_names": names,
            "validation": validation,
        }

    def _extract_subdomains(self, domain: str, records: List[Dict[str, Any]]) -> List[str]:
        """Labels below the domain (e.g. 'www', 'mail.eu'), most recently seen first."""
        suffix = "." + domain
        last_seen: Dict[str, str] = {}
        for record in records:
            name = _clean_name(record.get("hostname"))
            if name.startswith("*."):
                name = name[2:]
            if not name.endswith(suffix) or name == domain:
                continue
            label = name[: -len(suffix)]
            if not label:
                continue
            seen = str(record.get("last") or "")
            if seen > last_seen.get(label, ""):
                last_seen[label] = seen
            else:
                last_seen.setdefault(label, seen)
        return sorted(last_seen, key=lambda name: (last_seen[name], name), reverse=True)

    def _get_historical_dns_summary(
        self, domain: str, records: List[Dict[str, Any]], pdns: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Address and mail server history of the domain itself (not of its subdomains)."""
        status = pdns.get("status", "failed")
        historical: Dict[str, Any] = {
            "a_records": [],
            "mx_records": [],
            "record_type_counts": {},
            "unique_ips": 0,
            "first_seen": None,
            "last_seen": None,
            "status": status,
        }
        if status != "success":
            return historical

        addresses: Dict[str, Dict[str, Any]] = {}
        mail_servers: Dict[str, Dict[str, Any]] = {}
        counts: Dict[str, int] = {}
        firsts, lasts = [], []
        for record in records:
            if _clean_name(record.get("hostname")) != domain:
                continue
            rtype = str(record.get("record_type") or "").upper()
            value = _clean_name(record.get("address"))
            if not rtype or not value:
                continue
            first, last = record.get("first"), record.get("last")
            counts[rtype] = counts.get(rtype, 0) + 1
            if first:
                firsts.append(str(first))
            if last:
                lasts.append(str(last))
            target = addresses if rtype in ("A", "AAAA") else mail_servers if rtype == "MX" else None
            if target is None:
                continue
            entry = target.setdefault(value, {"first_seen": first, "last_seen": last, "asn": record.get("asn")})
            if first and (not entry["first_seen"] or str(first) < str(entry["first_seen"])):
                entry["first_seen"] = first
            if last and (not entry["last_seen"] or str(last) > str(entry["last_seen"])):
                entry["last_seen"] = last

        def newest(items: Dict[str, Dict[str, Any]]):
            return sorted(items.items(), key=lambda kv: str(kv[1].get("last_seen") or ""), reverse=True)

        historical["a_records"] = [
            {
                "first_seen": info["first_seen"],
                "last_seen": info["last_seen"],
                "ip_addresses": [address],
                "organizations": [str(info["asn"])[:80]] if info.get("asn") else [],
            }
            for address, info in newest(addresses)[:5]
        ]
        historical["mx_records"] = [
            {"first_seen": info["first_seen"], "last_seen": info["last_seen"], "mail_servers": [server]}
            for server, info in newest(mail_servers)[:3]
        ]
        historical["record_type_counts"] = counts
        historical["unique_ips"] = len(addresses)
        historical["first_seen"] = min(firsts) if firsts else None
        historical["last_seen"] = max(lasts) if lasts else None
        return historical

    def _categorize_subdomains(self, subdomains: list) -> Dict[str, list]:
        """Categorize subdomains for security analysis"""
        categories: Dict[str, List[str]] = {"admin": [], "api": [], "dev": [], "mail": [], "other": []}

        for subdomain in subdomains:
            sub_lower = subdomain.lower()

            if any(pattern in sub_lower for pattern in ["admin", "panel", "manage", "control"]):
                categories["admin"].append(subdomain)
            elif any(pattern in sub_lower for pattern in ["api", "rest", "graphql", "webhook"]):
                categories["api"].append(subdomain)
            elif any(pattern in sub_lower for pattern in ["dev", "test", "stage", "debug"]):
                categories["dev"].append(subdomain)
            elif any(pattern in sub_lower for pattern in ["mail", "smtp", "imap", "pop"]):
                categories["mail"].append(subdomain)
            else:
                categories["other"].append(subdomain)

        return categories

    def _create_intelligence_summary(
        self, domain_info: Dict, historical: Dict, subdomains: Dict, general: Dict
    ) -> Dict[str, Any]:
        """Create intelligence summary for risk assessment"""
        summary = {
            "total_subdomains": domain_info.get("subdomain_count", 0),
            "historical_changes": len(historical.get("a_records", [])),
            "sensitive_assets": subdomains.get("sensitive_count", 0),
            "pulse_count": general.get("pulse_count") or 0,
            "risk_indicators": [],
        }

        if summary["sensitive_assets"] > 5:
            summary["risk_indicators"].append("High number of sensitive subdomains")

        if historical.get("unique_ips", 0) > 5:
            summary["risk_indicators"].append("Multiple IP address changes detected")

        if summary["pulse_count"] > 0:
            summary["risk_indicators"].append(
                f"Referenced in {summary['pulse_count']} OTX threat pulse(s)"
            )

        return summary

    def _get_demo_result(self, domain: str) -> Dict[str, Any]:
        """Demo result for testing without API key"""
        return {
            "analysis_status": "demo_abgeschlossen",
            "domain": domain,
            "api_status": "demo_mode",
            "source": "AlienVault OTX",
            "domain_details": {
                "hostname": domain,
                "subdomain_count": 6,
                "pulse_count": 0,
                "first_seen": "2020-01-15",
                "status": "demo",
            },
            "historical_dns": {
                "a_records": [
                    {
                        "first_seen": "2022-01-01",
                        "last_seen": "2023-01-01",
                        "ip_addresses": ["192.168.1.100"],
                        "organizations": ["Demo Hosting Inc"],
                    }
                ],
                "mx_records": [],
                "record_type_counts": {"A": 1},
                "unique_ips": 1,
                "first_seen": "2022-01-01",
                "last_seen": "2023-01-01",
                "status": "demo",
            },
            "subdomain_intelligence": {
                "total_found": 6,
                "top_subdomains": ["www", "api", "admin", "dev", "mail", "cdn"],
                "categorized_assets": {
                    "admin": ["admin"],
                    "api": ["api"],
                    "dev": ["dev"],
                    "mail": ["mail"],
                    "other": ["www", "cdn"],
                },
                "sensitive_count": 2,
                "status": "demo",
            },
            "threat_intelligence": {"status": "demo", "pulse_count": 0, "pulse_names": [], "validation": []},
            "intelligence_summary": {
                "total_subdomains": 6,
                "historical_changes": 1,
                "sensitive_assets": 2,
                "pulse_count": 0,
                "risk_indicators": ["Demo Mode - configure OTX_API_KEY for real analysis"],
            },
        }
