"""
IP History Analyzer for Domain Forensic Analyzer.

Answers two forensic questions:
  1. Which IPs did the domain historically resolve to? (from dns_history timeline)
  2. Which other domains share / shared the current IP? (reverse IP lookup)

Reverse-IP sources:
  - VirusTotal /ip_addresses/{ip}/resolutions  (API key required)
  - RobTex     /ipquery/{ip}                   (free, no key)
  - HackerTarget /reverseiplookup/?q={ip}      (free, rate-limited)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from ..utils.api_key_reader import APIKeyReader

logger = logging.getLogger("ip_history_analyzer")
logger.addHandler(logging.NullHandler())
logger.propagate = False


class IPHistoryAnalyzer:
    """Collect co-hosted domain intelligence via reverse-IP lookup from multiple sources."""

    def __init__(self):
        self.virustotal_api_key = APIKeyReader("VIRUSTOTAL_API_KEY", "virustotal").get()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Domain-Forensic-Analyzer/1.0"})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_reverse_ip(self, ip: str, domain: str) -> Dict[str, Any]:
        """
        Collect domains co-hosted on *ip* from three passive sources.

        Returns a structured dict with per-source results, a merged
        deduplicated domain list (top 20), and the raw total count.
        """
        sources: Dict[str, Dict[str, Any]] = {
            "virustotal": self._query_virustotal_reverse(ip),
            "robtex": self._query_robtex_reverse(ip),
            "hackertarget": self._query_hackertarget_reverse(ip),
        }

        seen: set = set()
        merged: List[Dict[str, Any]] = []
        clean_domain = domain.lower().strip().rstrip(".")

        source_labels = {
            "virustotal": "VirusTotal",
            "robtex": "RobTex",
            "hackertarget": "HackerTarget",
        }
        for source_key, source_data in sources.items():
            for entry in source_data.get("domains", []):
                name = entry.get("domain", "").lower().strip().rstrip(".")
                if not name or name == clean_domain:
                    continue
                if name not in seen:
                    seen.add(name)
                    merged.append({**entry, "source": source_labels.get(source_key, source_key)})

        total_found = len(seen)
        merged.sort(
            key=lambda e: (e.get("last_seen") or "", e.get("domain", "")),
            reverse=True,
        )

        return {
            "analysis_status": "abgeschlossen",
            "ip_address": ip,
            "domain": domain,
            "sources": sources,
            "total_co_hosted": total_found,
            "top_co_hosted": merged[:20],
        }

    # ------------------------------------------------------------------
    # Source collectors
    # ------------------------------------------------------------------

    def _query_virustotal_reverse(self, ip: str) -> Dict[str, Any]:
        """GET /ip_addresses/{ip}/resolutions — domains that resolved to this IP."""
        if not self.virustotal_api_key:
            return {"status": "skipped", "reason": "no API key", "domains": []}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
        try:
            response = self.session.get(
                url,
                headers={"x-apikey": self.virustotal_api_key},
                timeout=25,
            )
            if response.status_code == 429:
                return {"status": "quota_exceeded", "domains": []}
            if response.status_code == 404:
                return {"status": "not_found", "domains": []}
            response.raise_for_status()

            domains: List[Dict[str, Any]] = []
            for item in response.json().get("data", []) or []:
                attrs = item.get("attributes", {}) or {}
                name = attrs.get("host_name") or attrs.get("hostname") or ""
                name = name.lower().strip().rstrip(".")
                date_val = attrs.get("date") or attrs.get("last_resolved")
                if name:
                    domains.append({"domain": name, "last_seen": self._fmt_date(date_val)})

            return {"status": "success", "domains": domains, "count": len(domains)}

        except Exception as error:
            return {"status": "error", "error": str(error), "domains": []}

    def _query_robtex_reverse(self, ip: str) -> Dict[str, Any]:
        """GET /ipquery/{ip} — passive reverse-IP from RobTex (no key required)."""
        url = f"https://freeapi.robtex.com/ipquery/{ip}"
        try:
            response = self.session.get(url, timeout=20)
            if response.status_code == 404:
                return {"status": "not_found", "domains": []}
            response.raise_for_status()

            data = response.json()
            domains: List[Dict[str, Any]] = []

            # 'pas' = passive A records (historically pointed here)
            # 'act' = currently active records
            for field in ("pas", "act"):
                for entry in data.get(field, []) or []:
                    if isinstance(entry, dict):
                        name = str(entry.get("o", "")).lower().strip().rstrip(".")
                        ts = entry.get("t")
                        last_seen = self._fmt_timestamp(ts)
                    elif isinstance(entry, str):
                        name = entry.lower().strip().rstrip(".")
                        last_seen = None
                    else:
                        continue
                    if name:
                        domains.append({"domain": name, "last_seen": last_seen})

            return {
                "status": "success" if domains else "no_data",
                "domains": domains,
                "count": len(domains),
            }

        except Exception as error:
            return {"status": "error", "error": str(error), "domains": []}

    def _query_hackertarget_reverse(self, ip: str) -> Dict[str, Any]:
        """GET /reverseiplookup/?q={ip} — plain-text reverse-IP from HackerTarget."""
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        try:
            response = self.session.get(url, timeout=20)
            text = response.text.strip()

            # HackerTarget signals rate-limit or errors inside the body
            lowered = text.lower()
            if "api count exceeded" in lowered or (
                text.startswith("error") and len(text) < 120
            ):
                return {"status": "rate_limited", "domains": []}

            domains: List[Dict[str, Any]] = []
            for line in text.splitlines():
                name = line.strip().lower().rstrip(".")
                if not name or self._looks_like_ip(name):
                    continue
                domains.append({"domain": name, "last_seen": None})

            return {
                "status": "success" if domains else "no_data",
                "domains": domains,
                "count": len(domains),
            }

        except Exception as error:
            return {"status": "error", "error": str(error), "domains": []}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        parts = value.split(".")
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    @staticmethod
    def _fmt_date(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d")
            except Exception:
                return None
        text = str(value).strip()
        return text[:10] if len(text) >= 10 else text or None

    @staticmethod
    def _fmt_timestamp(value: Any) -> Optional[str]:
        if value is None:
            return None
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d")
        except Exception:
            return None
