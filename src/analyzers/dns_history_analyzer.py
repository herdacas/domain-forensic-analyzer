"""
DNS History Timeline Analyzer for Domain Forensic Analyzer.

Audit note:
Existing historical DNS support was found in securitytrails_client.py, but it is
limited to a compact A/MX summary and is not suitable for a forensic timeline.
This module keeps that legacy summary intact and implements a separate normalized
DNS history timeline from scratch.

SecurityTrails and VirusTotal clients were audited for historical endpoints.
AbuseIPDB was audited too, but its current integration exposes IP reputation
reports rather than DNS record timeline data, so it is not used as a DNS history
source here.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from ..utils.api_key_reader import APIKeyReader

logger = logging.getLogger("dns_history_analyzer")
logger.addHandler(logging.NullHandler())
logger.propagate = False


class DNSHistoryAnalyzer:
    """Collect and analyze historical DNS changes from multiple passive sources."""

    RECORD_TYPES = ("a", "aaaa", "mx", "ns", "txt", "cname")

    def __init__(self):
        self.securitytrails_api_key = APIKeyReader("SECURITYTRAILS_API_KEY", "securitytrails").get()
        self.virustotal_api_key = APIKeyReader("VIRUSTOTAL_API_KEY", "virustotal").get()
        self.securitytrails_base_url = "https://api.securitytrails.com/v1"
        self.virustotal_base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()

    def analyze_dns_history(self, domain: str) -> Dict[str, Any]:
        """Build a unified historical DNS timeline for a domain."""
        clean_domain = domain.strip().lower()

        # RobTex is the primary free passive DNS source (no API key required).
        # Mnemonic (Norwegian CERT) is a free passive DNS API with timestamps; no key needed.
        # VirusTotal provides IP resolution history when an API key is present.
        # SecurityTrails adds record-level history when quota is available.
        # crt.sh certificate transparency is kept as opportunistic supplement.
        source_results = {
            "robtex": self._collect_robtex_history(clean_domain),
            "mnemonic": self._collect_mnemonic_history(clean_domain),
            "virustotal": self._collect_virustotal_history(clean_domain),
            "securitytrails": self._collect_securitytrails_history(clean_domain),
            "certificate_transparency": self._collect_certificate_transparency(clean_domain),
        }

        events = []
        errors = []
        data_sources = []
        for source_name, source_result in source_results.items():
            status = source_result.get("status")
            if status == "success":
                if source_result.get("events"):
                    data_sources.append(source_result.get("label", source_name))
                events.extend(source_result.get("events", []))
            elif status == "quota_exceeded":
                errors.append(f"{source_name}: API quota exceeded")
            elif source_result.get("error"):
                errors.append(f"{source_name}: {source_result['error']}")

        if not events:
            fallback = self._build_native_fallback(clean_domain)
            events.extend(fallback["events"])
            data_sources.append(fallback["label"])

        ct_metadata = source_results["certificate_transparency"].get("ct_metadata")

        all_unique = self._deduplicate_events(events)
        # Span and per-type buckets come from ALL events — not affected by display limit.
        span = self._calculate_timeline_span(all_unique)
        a_events = sorted(
            [e for e in all_unique if e.get("record_type") in ("A", "AAAA")],
            key=lambda e: self._sort_key(e.get("date")),
            reverse=True,
        )[:50]
        ns_events = sorted(
            [e for e in all_unique if e.get("record_type") == "NS"],
            key=lambda e: self._sort_key(e.get("date")),
        )[:30]
        mx_events = sorted(
            [e for e in all_unique if e.get("record_type") == "MX"],
            key=lambda e: self._sort_key(e.get("date")),
        )[:30]
        # Display timeline capped at 60; excludes CT to avoid crowding out DNS events.
        timeline = sorted(
            [e for e in all_unique if e.get("record_type") != "CT"],
            key=lambda e: self._sort_key(e.get("date")),
            reverse=True,
        )[:60]
        # CT events counted separately for the certificate history block.
        ct_events = sorted(
            [e for e in all_unique if e.get("record_type") == "CT"],
            key=lambda e: self._sort_key(e.get("date")),
            reverse=True,
        )[:60]
        pattern_analysis = self._analyze_patterns(timeline)

        return {
            "analysis_status": "abgeschlossen",
            "domain": clean_domain,
            "api_status": "live_data" if data_sources else "fallback",
            "data_sources": data_sources,
            "timeline_span": span,
            "major_changes": len([event for event in timeline if event.get("severity") in ["medium", "high"]]),
            "timeline": timeline,
            "a_history": a_events,
            "ns_history": ns_events,
            "mx_history": mx_events,
            "ct_history": ct_events,
            "ct_metadata": ct_metadata,
            "pattern_analysis": pattern_analysis,
            "historical_risk_events": pattern_analysis.get("historical_risk_events", []),
            "source_errors": errors,
        }

    def _collect_robtex_history(self, domain: str) -> Dict[str, Any]:
        """Collect passive DNS history from RobTex (free, no API key required).

        Returns one event per unique (rrtype, rrdata) pair with first/last-seen
        timestamps derived from Unix epoch values in the response.
        """
        endpoint = f"https://freeapi.robtex.com/pdns/forward/{domain}"
        try:
            response = self.session.get(endpoint, timeout=20)
            if response.status_code == 404:
                return {"status": "failed", "label": "RobTex", "events": [], "error": "domain not found"}
            response.raise_for_status()
        except Exception as error:
            return {"status": "failed", "label": "RobTex", "events": [], "error": str(error)}

        events = []
        for raw_line in response.text.strip().splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                entry = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            if not isinstance(entry, dict):
                continue

            rrtype = str(entry.get("rrtype", "")).upper()
            rrdata = str(entry.get("rrdata", "")).strip().rstrip(".")
            if not rrtype or not rrdata:
                continue

            time_first = entry.get("time_first")
            time_last = entry.get("time_last")
            first_seen = self._normalize_timestamp(time_first)
            last_seen = self._normalize_timestamp(time_last)

            events.append(self._make_event(
                event_date=first_seen,
                change_type=f"{rrtype} record observed",
                record_type=rrtype,
                source="RobTex",
                previous_value=None,
                new_value=[rrdata],
                classification=self._classify_change(rrtype.lower(), [rrdata]),
                severity="low",
                last_seen=last_seen,
            ))

        return {
            "status": "success" if events else "failed",
            "label": "RobTex",
            "events": events,
            "error": None if events else "no records returned",
        }

    def _collect_securitytrails_history(self, domain: str) -> Dict[str, Any]:
        if not self.securitytrails_api_key:
            return {"status": "skipped", "error": "SecurityTrails API key not configured", "events": []}

        headers = {"APIKEY": self.securitytrails_api_key, "Accept": "application/json"}
        events = []
        errors = []

        for record_type in self.RECORD_TYPES:
            endpoint = f"{self.securitytrails_base_url}/history/{domain}/dns/{record_type}"
            try:
                response = self.session.get(endpoint, headers=headers, timeout=25)
                if response.status_code == 404:
                    continue
                if response.status_code == 429:
                    return {"status": "quota_exceeded", "label": "SecurityTrails", "events": []}
                response.raise_for_status()
                payload = response.json()
                events.extend(self._parse_securitytrails_records(record_type, payload))
                time.sleep(0.2)
            except Exception as error:
                errors.append(f"{record_type}: {error}")

        return {
            "status": "success" if events else "failed",
            "label": "SecurityTrails",
            "events": events,
            "error": "; ".join(errors[:3]) if errors and not events else None,
        }

    def _parse_securitytrails_records(self, record_type: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        events = []
        for record in payload.get("records", []) or []:
            values = self._extract_record_values(record_type, record.get("values", []))
            if not values:
                continue
            first_seen = self._normalize_timestamp(record.get("first_seen") or record.get("firstSeen"))
            last_seen = self._normalize_timestamp(record.get("last_seen") or record.get("lastSeen"))
            events.append(self._make_event(
                event_date=first_seen or last_seen,
                change_type=f"{record_type.upper()} record observed",
                record_type=record_type.upper(),
                source="SecurityTrails",
                previous_value=None,
                new_value=values,
                classification=self._classify_change(record_type, values),
                last_seen=last_seen,
            ))
        return events

    def _collect_virustotal_history(self, domain: str) -> Dict[str, Any]:
        if not self.virustotal_api_key:
            return {"status": "skipped", "error": "VirusTotal API key not configured", "events": []}

        headers = {"x-apikey": self.virustotal_api_key}
        endpoint = f"{self.virustotal_base_url}/domains/{domain}/resolutions"

        try:
            response = self.session.get(endpoint, headers=headers, timeout=25)
            response.raise_for_status()
            payload = response.json()
        except Exception as error:
            return {"status": "failed", "label": "VirusTotal", "events": [], "error": str(error)}

        grouped_by_date: Dict[str, Set[str]] = {}
        for item in payload.get("data", []) or []:
            attributes = item.get("attributes", {}) or {}
            ip_address = attributes.get("ip_address") or attributes.get("host_name")
            date_value = attributes.get("date") or attributes.get("last_resolved")
            if not ip_address:
                continue
            normalized_date = self._normalize_timestamp(date_value) or "unknown"
            date_key = normalized_date[:10] if normalized_date != "unknown" else "unknown"
            grouped_by_date.setdefault(date_key, set()).add(str(ip_address).strip())

        events = []
        for date_key, ip_addresses in grouped_by_date.items():
            sorted_ips = sorted(ip_addresses)
            severity = "low" if len(sorted_ips) > 3 else "medium"
            events.append(self._make_event(
                event_date=date_key,
                change_type="Historical IP resolution",
                record_type="A",
                source="VirusTotal",
                previous_value=None,
                new_value=sorted_ips,
                classification=(
                    "Load-balanced resolution set"
                    if len(sorted_ips) > 3
                    else self._classify_change("a", sorted_ips)
                ),
                severity=severity,
            ))

        return {"status": "success" if events else "failed", "label": "VirusTotal", "events": events}

    def _collect_mnemonic_history(self, domain: str) -> Dict[str, Any]:
        """Collect passive DNS history from Mnemonic (Norwegian CERT).

        Free, no API key required. Unauthenticated limit: 1 000 req/day, 10 req/min.
        Single request fetches all record types; timestamps are milliseconds.
        """
        endpoint = f"https://api.mnemonic.no/pdns/v3/{domain}"
        try:
            response = self.session.get(
                endpoint,
                params={"limit": 1000},
                headers={"User-Agent": "Domain-Forensic-Analyzer/1.0"},
                timeout=20,
            )
            if response.status_code == 404:
                return {"status": "failed", "label": "Mnemonic", "events": [], "error": "domain not found"}
            if response.status_code == 429:
                return {"status": "quota_exceeded", "label": "Mnemonic", "events": []}
            response.raise_for_status()
            payload = response.json()
        except Exception as error:
            return {"status": "failed", "label": "Mnemonic", "events": [], "error": str(error)}

        events = []
        for entry in payload.get("data", []) or []:
            rrtype = str(entry.get("rrtype", "")).upper()
            answer = str(entry.get("answer", "")).strip().rstrip(".")
            if not rrtype or not answer:
                continue

            ts_first = entry.get("firstSeenTimestamp")
            ts_last = entry.get("lastSeenTimestamp")
            first_seen = self._normalize_timestamp(ts_first / 1000) if ts_first else None
            last_seen = self._normalize_timestamp(ts_last / 1000) if ts_last else None

            events.append(self._make_event(
                event_date=first_seen,
                change_type=f"{rrtype} record observed",
                record_type=rrtype,
                source="Mnemonic",
                previous_value=None,
                new_value=[answer],
                classification=self._classify_change(rrtype.lower(), [answer]),
                severity="low",
                last_seen=last_seen,
            ))

        return {
            "status": "success" if events else "failed",
            "label": "Mnemonic",
            "events": events,
            "error": None if events else "no records returned",
        }

    def _collect_crtsh(self, domain: str) -> Dict[str, Any]:
        """Fetch certificate transparency data from crt.sh (primary source)."""
        endpoint = "https://crt.sh/"
        params = {"q": f"%.{domain}", "output": "json"}
        max_retries = 2
        last_error: Exception = None
        for attempt in range(1, max_retries + 2):
            try:
                response = self.session.get(endpoint, params=params, timeout=25)
                response.raise_for_status()
                payload = response.json()
                break
            except Exception as error:
                last_error = error
                if attempt <= max_retries:
                    time.sleep(1)
        else:
            return {"status": "failed", "label": "crt.sh", "events": [],
                    "error": str(last_error)}

        seen_names: Set[Tuple[str, str]] = set()
        events = []
        for certificate in payload[:250]:
            not_before = self._normalize_timestamp(certificate.get("not_before"))
            raw_names = str(certificate.get("name_value") or "")
            names = sorted({name.strip().lower().lstrip("*.") for name in raw_names.splitlines() if name.strip()})
            subdomains = [name for name in names if name == domain or name.endswith(f".{domain}")]
            if not subdomains:
                continue
            key = (not_before or "unknown", "|".join(subdomains))
            if key in seen_names:
                continue
            seen_names.add(key)
            events.append(self._make_event(
                event_date=not_before,
                change_type="Certificate names observed",
                record_type="CT",
                source="crt.sh",
                previous_value=None,
                new_value=subdomains[:10],
                classification="Certificate / subdomain expansion",
                severity="low" if len(subdomains) < 5 else "medium",
            ))

        return {
            "status": "success" if events else "failed",
            "label": "crt.sh",
            "events": events,
        }

    def _collect_certspotter(self, domain: str) -> Dict[str, Any]:
        """Fetch certificate transparency data from CertSpotter (fallback source)."""
        endpoint = "https://api.certspotter.com/v1/issuances"
        params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        max_retries = 2
        last_error: Exception = None
        for attempt in range(1, max_retries + 2):
            try:
                response = self.session.get(endpoint, params=params, timeout=25)
                response.raise_for_status()
                payload = response.json()
                break
            except Exception as error:
                last_error = error
                if attempt <= max_retries:
                    time.sleep(1)
        else:
            return {"status": "failed", "label": "CertSpotter", "events": [],
                    "error": str(last_error)}

        if not isinstance(payload, list):
            return {"status": "failed", "label": "CertSpotter", "events": [],
                    "error": "unexpected response format"}

        seen_names: Set[Tuple[str, str]] = set()
        events = []
        for issuance in payload[:250]:
            not_before = self._normalize_timestamp(issuance.get("not_before"))
            dns_names = issuance.get("dns_names") or []
            names = sorted({name.strip().lower().lstrip("*.") for name in dns_names if name.strip()})
            subdomains = [name for name in names if name == domain or name.endswith(f".{domain}")]
            if not subdomains:
                continue
            key = (not_before or "unknown", "|".join(subdomains))
            if key in seen_names:
                continue
            seen_names.add(key)
            events.append(self._make_event(
                event_date=not_before,
                change_type="Certificate names observed",
                record_type="CT",
                source="CertSpotter",
                previous_value=None,
                new_value=subdomains[:10],
                classification="Certificate / subdomain expansion",
                severity="low" if len(subdomains) < 5 else "medium",
            ))

        return {
            "status": "success" if events else "failed",
            "label": "CertSpotter",
            "events": events,
        }

    def _collect_certificate_transparency(self, domain: str) -> Dict[str, Any]:
        """Collect CT data with fallback chain: crt.sh → CertSpotter."""
        crtsh = self._collect_crtsh(domain)
        if crtsh["status"] == "success":
            active = crtsh
        else:
            certspotter = self._collect_certspotter(domain)
            if certspotter["status"] == "success":
                active = certspotter
            else:
                return {
                    "status": "failed",
                    "label": "Certificate Transparency",
                    "events": [],
                    "ct_metadata": None,
                    "error": (
                        f"crt.sh: {crtsh.get('error', 'no data')}; "
                        f"CertSpotter: {certspotter.get('error', 'no data')}"
                    ),
                }

        events = active["events"]
        source_label = active["label"]

        # Build structured metadata for the report block
        dates = [e["date"] for e in events if e.get("date") and e["date"] != "unknown"]
        earliest = min(dates)[:10] if dates else None
        latest = max(dates)[:10] if dates else None

        all_subdomains: Set[str] = set()
        for event in events:
            for name in event.get("new_value", []):
                if name == domain:
                    continue
                if name.endswith(f".{domain}"):
                    prefix = name[: -(len(domain) + 1)]
                    if prefix:
                        all_subdomains.add(prefix)

        ct_metadata = {
            "count": len(events),
            "source_label": source_label,
            "earliest": earliest,
            "latest": latest,
            "subdomains": sorted(all_subdomains)[:10],
        }

        return {
            "status": "success",
            "label": source_label,
            "events": events,
            "ct_metadata": ct_metadata,
        }

    def _build_native_fallback(self, domain: str) -> Dict[str, Any]:
        return {
            "label": "Native Fallback",
            "events": [self._make_event(
                event_date=datetime.now(timezone.utc).isoformat(),
                change_type="Current DNS baseline",
                record_type="BASELINE",
                source="Native Fallback",
                previous_value=None,
                new_value=[domain],
                classification="No historical data available",
                severity="low",
            )],
        }

    def _extract_record_values(self, record_type: str, values: List[Dict[str, Any]]) -> List[str]:
        extracted = []
        keys_by_type = {
            "a": ("ip", "ipv4", "value"),
            "aaaa": ("ipv6", "ip", "value"),
            "mx": ("hostname", "value"),
            "ns": ("nameserver", "hostname", "value"),
            "txt": ("value", "text"),
            "cname": ("hostname", "value"),
        }
        for value in values or []:
            if not isinstance(value, dict):
                text = str(value).strip()
            else:
                text = ""
                for key in keys_by_type.get(record_type, ("value",)):
                    if value.get(key):
                        text = str(value[key]).strip()
                        break
            if text:
                extracted.append(text.rstrip("."))
        return sorted(set(extracted))

    def _make_event(
        self,
        event_date: Optional[str],
        change_type: str,
        record_type: str,
        source: str,
        previous_value: Optional[List[str]],
        new_value: List[str],
        classification: str,
        severity: str = "medium",
        last_seen: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "date": event_date or "unknown",
            "last_seen": last_seen,
            "change_type": change_type,
            "record_type": record_type,
            "source": source,
            "previous": previous_value or [],
            "new": new_value,
            "classification": classification,
            "severity": severity,
        }

    def _deduplicate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate events without applying a display limit."""
        seen: set = set()
        unique_events = []
        for event in events:
            key = (
                event.get("date"),
                event.get("record_type"),
                event.get("source"),
                tuple(event.get("new", [])),
            )
            if key in seen:
                continue
            seen.add(key)
            unique_events.append(event)
        return unique_events

    def _calculate_timeline_span(self, timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
        dates = [self._parse_datetime(event.get("date")) for event in timeline]
        dates = [date for date in dates if date]
        if not dates:
            return {"start_date": None, "end_date": None, "days": 0}
        start_date = min(dates)
        end_date = max(dates)
        return {
            "start_date": start_date.date().isoformat(),
            "end_date": end_date.date().isoformat(),
            "days": max((end_date - start_date).days, 0),
        }

    def _analyze_patterns(self, timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
        change_events = [
            event for event in timeline
            if event.get("classification") != "Load-balanced resolution set"
            and event.get("record_type") != "CT"
        ]
        total_events = len(change_events)
        span = self._calculate_timeline_span(timeline)
        days = max(span.get("days") or 0, 1)
        monthly_rate = total_events / max(days / 30, 1)

        if monthly_rate >= 10:
            frequency = "high change velocity"
        elif monthly_rate >= 3:
            frequency = "moderate change velocity"
        else:
            frequency = "low change velocity"

        record_types = {event.get("record_type") for event in timeline}
        ip_values = {
            value
            for event in change_events
            if event.get("record_type") in {"A", "AAAA"}
            for value in event.get("new", [])
        }
        load_balanced_sets = [
            event for event in timeline
            if event.get("classification") == "Load-balanced resolution set"
        ]

        suspicious = []
        if monthly_rate >= 10:
            suspicious.append("rapid DNS change pattern")
        if len(ip_values) >= 12:
            suspicious.append("many historical IP resolutions")
        ns_events_in_timeline = [e for e in timeline if e.get("record_type") == "NS"]
        distinct_ns_dates = {str(e.get("date", ""))[:10] for e in ns_events_in_timeline if e.get("date", "unknown") != "unknown"}
        if "NS" in record_types and len(distinct_ns_dates) > 2:
            suspicious.append("multiple nameserver changes")

        if suspicious:
            risk_level = "MEDIUM" if len(suspicious) < 3 else "HIGH"
            # "volatile" only when change rate is actually high; historical patterns on
            # established domains (many IPs, NS migrations over years) are "moderately dynamic"
            if monthly_rate >= 5 or len(suspicious) >= 3:
                stability = "volatile"
            else:
                stability = "moderately dynamic"
        elif load_balanced_sets and not suspicious:
            risk_level = "LOW"
            stability = "load-balanced / distributed"
        elif total_events >= 10:
            risk_level = "LOW"
            stability = "moderately stable"
        else:
            risk_level = "LOW"
            stability = "stable or limited history"

        return {
            "change_frequency": frequency,
            "infrastructure_stability": stability,
            "suspicious_patterns": suspicious or ["none detected"],
            "risk_level": risk_level,
            "historical_risk_events": suspicious,
        }

    def _classify_change(self, record_type: str, values: List[str]) -> str:
        normalized_type = record_type.lower()
        if normalized_type in {"a", "aaaa"}:
            return "Infrastructure resolution change"
        if normalized_type == "mx":
            return "Mail routing change"
        if normalized_type == "ns":
            return "Authority / nameserver change"
        if normalized_type == "txt":
            return "Policy or verification change"
        if normalized_type == "cname":
            return "Service routing change"
        return "Historical observation"

    def _normalize_timestamp(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
        text = str(value).strip()
        if not text:
            return None
        parsed = self._parse_datetime(text)
        return parsed.isoformat() if parsed else text

    def _parse_datetime(self, value: Any) -> Optional[datetime]:
        if not value:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        text = str(value).strip().replace("Z", "+00:00")
        for candidate in (text, f"{text}+00:00"):
            try:
                parsed = datetime.fromisoformat(candidate)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    def _sort_key(self, value: Any) -> datetime:
        return self._parse_datetime(value) or datetime.min.replace(tzinfo=timezone.utc)
