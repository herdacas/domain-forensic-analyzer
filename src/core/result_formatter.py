"""Terminal result formatting for Domain Forensic Analyzer."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.core.result_aggregator import UnifiedResult
from src.utils.colors import Colors


def _compute_risk_summary(result: UnifiedResult) -> Tuple[str, List[str], str]:
    """Compute a concise overall risk summary for display."""
    vt_result = result.results.get("virustotal", {})
    abuse_result = result.results.get("abuseipdb", {})
    subdomain_result = result.results.get("subdomain", {})
    whois_result = result.results.get("whois", {})
    ssl_result = result.results.get("ssl", {})
    network_result = result.results.get("network", {})
    http_behavior = network_result.get("http_behavior", {})
    risk_factors = []
    overall_risk = "LOW"

    # Domain age check
    creation_raw = whois_result.get("creation_date") or whois_result.get("createdDate")
    if creation_raw:
        try:
            date_str = str(creation_raw)[:10]
            created_dt = datetime.strptime(date_str, "%Y-%m-%d")
            age_days = (
                datetime.now(timezone.utc).replace(tzinfo=None) - created_dt
            ).days
            if age_days < 30:
                risk_factors.append(f"Newly registered domain ({age_days} days old)")
                overall_risk = "HIGH"
            elif age_days < 90:
                risk_factors.append(f"Recently registered domain ({age_days} days old)")
                if overall_risk == "LOW":
                    overall_risk = "MEDIUM"
        except (ValueError, TypeError):
            pass

    wildcard_detected = bool(
        subdomain_result.get("wildcard_detected")
        or subdomain_result.get("dns_configuration", {}).get("wildcard_detected", False)
    )

    if not wildcard_detected:
        if result.sensitive_assets_found >= 20:
            risk_factors.append(
                f"Excessive attack surface ({result.sensitive_assets_found} sensitive assets)"
            )
            overall_risk = "HIGH"
        elif result.sensitive_assets_found >= 10:
            risk_factors.append(
                f"Large attack surface ({result.sensitive_assets_found} sensitive assets)"
            )
            overall_risk = "MEDIUM"

    malicious_detections = vt_result.get("threat_analysis", {}).get(
        "malicious_detections", 0
    )
    if malicious_detections >= 3:
        risk_factors.append(
            f"Domain flagged as malicious by {malicious_detections} security vendors"
        )
        overall_risk = "HIGH"
    elif malicious_detections > 0:
        risk_factors.append(
            f"Limited malicious detections at VirusTotal ({malicious_detections} vendors)"
        )
        if overall_risk == "LOW":
            overall_risk = "MEDIUM"

    abuse_confidence = abuse_result.get("abuse_confidence", 0)
    if abuse_confidence > 50:
        risk_factors.append(f"High IP abuse confidence ({abuse_confidence}%)")
        if overall_risk != "CRITICAL":
            overall_risk = "HIGH"
    elif abuse_confidence > 25:
        risk_factors.append(f"Moderate IP abuse reports ({abuse_confidence}%)")
        if overall_risk == "LOW":
            overall_risk = "MEDIUM"

    # SSL/TLS certificate risk checks
    if ssl_result.get("available"):
        days_to_expiry = ssl_result.get("days_to_expiry")
        if days_to_expiry is not None:
            if days_to_expiry < 0:
                risk_factors.append(
                    f"Certificate expired {abs(days_to_expiry)} days ago"
                )
                if overall_risk not in ("CRITICAL", "HIGH"):
                    overall_risk = "HIGH"
            elif days_to_expiry < 14:
                risk_factors.append(f"Certificate expiring in {days_to_expiry} days")
                if overall_risk not in ("CRITICAL", "HIGH"):
                    overall_risk = "HIGH"
            elif days_to_expiry < 30:
                risk_factors.append("Certificate expiring soon")
                if overall_risk == "LOW":
                    overall_risk = "MEDIUM"
        if ssl_result.get("self_signed"):
            risk_factors.append("Self-signed certificate detected")
            if overall_risk == "LOW":
                overall_risk = "MEDIUM"
        tls_ver = ssl_result.get("tls_version", "")
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            risk_factors.append(f"TLS 1.3 not supported ({tls_ver} in use)")

    # HTTP/S behavior risk checks
    if http_behavior:
        https_reachable = http_behavior.get("https_status") is not None
        if (
            https_reachable
            and not http_behavior.get("has_redirect")
            and http_behavior.get("http_status") is not None
        ):
            risk_factors.append("HTTP served without redirect to HTTPS")
        if https_reachable and not http_behavior.get("hsts"):
            risk_factors.append("HSTS not configured")

    if overall_risk == "CRITICAL":
        recommendation = "LIKELY MALICIOUS - Multiple high-confidence indicators"
    elif overall_risk == "HIGH":
        recommendation = "ELEVATED RISK - Further validation recommended"
    elif overall_risk == "MEDIUM":
        recommendation = "REVIEW REQUIRED - Mixed or limited risk signals"
    else:
        recommendation = "NO MALICIOUS INDICATORS - Low risk profile"

    return overall_risk, risk_factors, recommendation


def _display_traceroute_details(
    traceroute_data: Dict[str, Any], enhanced_path: List[Dict[str, Any]]
) -> None:
    """Render the full traceroute without truncating hops."""
    traceroute_status = traceroute_data.get("status", "unknown")
    command_timeout = traceroute_data.get("command_timeout_seconds")
    probe_timeout_ms = traceroute_data.get("probe_timeout_ms")
    max_hops = traceroute_data.get("max_hops")
    hops = traceroute_data.get("hops", []) or []
    last_responsive_hop = traceroute_data.get("last_responsive_hop")
    first_unresponsive_hop = traceroute_data.get("first_unresponsive_hop")

    if traceroute_status not in ["success", "partial"]:
        if traceroute_status == "timeout":
            print(f"├── Status: {Colors.warning('TIMEOUT')}")
            print(f"├── Traceroute: {Colors.dim('incomplete')}")
        else:
            print(f"├── Status: {Colors.error('FAILED')}")
            print(f"├── Traceroute: {Colors.error('UNAVAILABLE')}")
        if command_timeout:
            print(f"├── Command Timeout: {Colors.info(f'{command_timeout}s')}")
        if probe_timeout_ms:
            print(f"├── Probe Timeout: {Colors.info(f'{probe_timeout_ms}ms')} per hop")
        if max_hops:
            print(f"├── Max Hops: {Colors.info(str(max_hops))}")
        error_text = traceroute_data.get("error")
        if error_text:
            print(f"└── Detail: {Colors.dim(error_text)}")
        return

    if traceroute_status == "partial":
        print(f"├── Status: {Colors.warning('PARTIAL')}")
        print(
            f"├── Traceroute: {Colors.info(f'{len(hops)} hops observed before stop')}"
        )
        print(f"├── Last Responsive Hop: {Colors.info(str(last_responsive_hop))}")
        print(
            f"├── Timeout Observed From Hop: {Colors.warning(str(first_unresponsive_hop))}"
        )
        print(f"├── Command Timeout: {Colors.info(f'{command_timeout}s')}")
        print(f"├── Probe Timeout: {Colors.info(f'{probe_timeout_ms}ms')} per hop")
        print(f"├── Max Hops: {Colors.info(str(max_hops))}")
        error_text = traceroute_data.get("error")
        if error_text:
            print(f"├── Detail: {Colors.dim(error_text)}")
    else:
        print(f"├── Traceroute: {Colors.info(f'{len(hops)} hops')}")

    if not hops:
        print(f"└── No hop data returned")
        return

    enhanced_by_hop = {
        hop.get("hop_number"): hop for hop in enhanced_path if isinstance(hop, dict)
    }

    for index, hop in enumerate(hops):
        branch = "└──" if index == len(hops) - 1 else "├──"
        hop_number = hop.get("hop", index + 1)
        ip_address = hop.get("ip") or "*"
        hostname = hop.get("hostname") or ""
        status = hop.get("status", "unknown").upper()
        latencies = hop.get("latencies", []) or []

        hop_details = enhanced_by_hop.get(hop_number, {})
        classification = hop_details.get("hop_classification")
        type_label = (
            classification.replace("_", " ").upper() if classification else "UNKNOWN"
        )
        if index == len(hops) - 1 and status == "RESPONSIVE":
            type_label = "TARGET"

        print(f"{branch} Hop {hop_number}: {ip_address}")

        child_prefix = "    " if index == len(hops) - 1 else "│   "
        detail_lines = []

        if hostname:
            detail_lines.append(f"Hostname: {hostname}")
        elif ip_address == "*":
            detail_lines.append("Hostname: not resolved")

        if latencies:
            detail_lines.append(f"RTT: {' | '.join(latencies)}")
        elif ip_address == "*" or status != "RESPONSIVE":
            detail_lines.append("RTT: not available")

        type_value = (
            type_label if status == "RESPONSIVE" else f"{type_label} | {status}"
        )
        detail_lines.append(f"Type: {type_value}")

        for detail_index, detail_line in enumerate(detail_lines):
            detail_branch = "└──" if detail_index == len(detail_lines) - 1 else "├──"
            print(f"{child_prefix}{detail_branch} {detail_line}")


def _get_subdomain_categories(
    subdomain_result: Dict[str, Any],
) -> Dict[str, List[Dict[str, Any]]]:
    """Return asset categories across old and new result keys."""
    return (
        subdomain_result.get("asset_categories")
        or subdomain_result.get("categorized_assets")
        or {}
    )


def _extract_nameserver_entries(dns_result: Dict[str, Any]) -> List[str]:
    """Normalize nameserver entries for display."""
    raw_nameservers = (
        dns_result.get("nameservers")
        or dns_result.get("ns_records")
        or dns_result.get("name_servers")
        or []
    )
    entries = []
    for nameserver in raw_nameservers:
        if isinstance(nameserver, dict):
            value = (
                nameserver.get("server")
                or nameserver.get("hostname")
                or nameserver.get("name")
            )
        else:
            value = str(nameserver)
        if value:
            entries.append(value.strip().rstrip(",."))
    return entries


def _extract_mail_server_entries(dns_result: Dict[str, Any]) -> List[str]:
    """Normalize MX entries for display."""
    raw_mail_servers = (
        dns_result.get("mail_servers") or dns_result.get("mx_records") or []
    )
    domain = str(dns_result.get("domain", "")).strip().rstrip(".")
    entries = []
    for mail_server in raw_mail_servers:
        if isinstance(mail_server, dict):
            server = (
                mail_server.get("server")
                or mail_server.get("hostname")
                or mail_server.get("mail_server")
            )
            priority = mail_server.get("priority")
            if server and priority is not None:
                clean_server = str(server).strip().rstrip(",.")
                if clean_server and "." not in clean_server and domain:
                    clean_server = f"{clean_server}.{domain}"
                clean_priority = str(priority).strip().rstrip(",.")
                entries.append(f"{clean_server} (priority {clean_priority})")
            elif server:
                clean_server = str(server).strip().rstrip(",.")
                if clean_server and "." not in clean_server and domain:
                    clean_server = f"{clean_server}.{domain}"
                entries.append(clean_server)
        else:
            value = str(mail_server)
            if value:
                clean_value = value.strip().rstrip(",.")
                if clean_value and "." not in clean_value and domain:
                    clean_value = f"{clean_value}.{domain}"
                entries.append(clean_value)
    return entries


def _format_policy_record(value: Any, max_length: int = 90) -> str:
    """Render long policy-style DNS records in a compact single-line form."""
    text = str(value or "").strip()
    if not text:
        return "not configured"
    return text if len(text) <= max_length else f"{text[:max_length - 3]}..."


def _format_spf_analysis(spf_analysis: Dict[str, Any]) -> str:
    """Render a short SPF assessment summary for the report."""
    if not spf_analysis or spf_analysis.get("status") != "configured":
        return "not configured"
    return str(spf_analysis.get("summary") or "configured")


def _format_dmarc_analysis(dmarc_analysis: Dict[str, Any]) -> str:
    """Render a compact DMARC configuration summary."""
    if not dmarc_analysis or dmarc_analysis.get("status") != "configured":
        return "not configured"
    return str(dmarc_analysis.get("summary") or "configured")


def _format_dkim_discovery(dkim_result: Dict[str, Any]) -> str:
    """Summarize heuristic DKIM selector discovery in one line."""
    selectors = dkim_result.get("selectors", []) or []
    if not selectors:
        return "no common selectors detected (heuristic discovery only)"
    selector_names = [
        str(entry.get("selector")).strip()
        for entry in selectors[:3]
        if isinstance(entry, dict) and entry.get("selector")
    ]
    if not selector_names:
        return "selectors discovered via heuristic lookup"
    return f"{len(selectors)} discovered via heuristic lookup ({', '.join(selector_names)})"


def _format_dns_config_assessment(assessment: Dict[str, Any]) -> str:
    """Render the overall DNS configuration assessment summary."""
    if not assessment:
        return "not assessed"
    return str(assessment.get("summary") or "not assessed")


def _format_dns_assessment_findings(
    assessment: Dict[str, Any], max_items: int = 2
) -> str:
    """Render the most relevant DNS hardening findings as a compact list."""
    findings = assessment.get("findings", []) if isinstance(assessment, dict) else []
    if not findings:
        return "no material hardening gaps observed"
    return "; ".join(str(item) for item in findings[:max_items])


def _format_history_value(values: Any, max_items: int = 3, max_length: int = 86) -> str:
    """Render DNS history values compactly for the forensic summary."""
    if not values:
        return "none"
    if isinstance(values, str):
        items = [values]
    elif isinstance(values, (list, tuple, set)):
        items = [str(item) for item in values if str(item).strip()]
    else:
        items = [str(values)]
    if not items:
        return "none"
    rendered = ", ".join(items[:max_items])
    if len(items) > max_items:
        rendered += f", +{len(items) - max_items} more"
    return (
        rendered if len(rendered) <= max_length else f"{rendered[:max_length - 3]}..."
    )


def _format_history_date(value: Any) -> str:
    """Render ISO-like history timestamps as dates when possible."""
    if not value or value == "unknown":
        return "unknown date"
    text = str(value)
    return text[:10] if len(text) >= 10 else text


def _format_whois_value(value: Any, default: str = "Unknown") -> str:
    """Render WHOIS values that may be scalar, list-like, or missing."""
    if value is None:
        return default
    if isinstance(value, (list, tuple, set)):
        cleaned = [str(item).strip() for item in value if str(item).strip()]
        return ", ".join(cleaned) if cleaned else default
    text = str(value).strip()
    return text if text else default


def _format_whois_nameservers(value: Any) -> List[str]:
    """Normalize WHOIS nameserver data for display."""
    if not value:
        return []
    if isinstance(value, str):
        nameservers = [value]
    elif isinstance(value, (list, tuple, set)):
        nameservers = list(value)
    else:
        nameservers = [str(value)]
    normalized = []
    seen = set()
    for nameserver in nameservers:
        text = str(nameserver).strip().rstrip(".")
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(text)
    return normalized


def _build_sensitive_asset_lookup(
    subdomain_result: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    """Map discovered subdomains to their sensitive-asset metadata."""
    sensitive_lookup = {}
    for sensitive in subdomain_result.get("sensitive_assets", []) or []:
        asset = sensitive.get("asset", {}) if isinstance(sensitive, dict) else {}
        full_domain = asset.get("full_domain")
        if full_domain:
            sensitive_lookup[full_domain] = sensitive
    return sensitive_lookup


def _get_edge_protection_summary(cdn_result: Dict[str, Any]) -> Tuple[str, str]:
    """Summarize CDN/WAF presence explicitly, including negative findings."""
    provider = cdn_result.get("provider_name", "Unknown")
    features = cdn_result.get("features", []) or []
    protection_level = str(cdn_result.get("protection_level", "unknown")).lower()
    provider_type = str(cdn_result.get("infrastructure_type", "direct")).lower()

    if provider in ["Unknown", "Unknown/Direct"] or provider_type == "direct":
        return "No CDN/WAF detected", "Origin appears directly exposed"

    waf_present = (
        any("waf" in str(feature).lower() for feature in features)
        or protection_level == "high"
    )
    if waf_present:
        return f"{provider} detected", "WAF / edge protection available"
    return f"{provider} detected", "No explicit WAF capability identified"


def _format_provider_type(provider_type: Any) -> str:
    """Render provider types with stable casing."""
    value = str(provider_type or "Unknown").strip().lower()
    if value == "cdn":
        return "CDN"
    if value == "direct":
        return "Direct"
    if value == "cloud":
        return "Cloud"
    if value == "gov-cloud":
        return "Government Cloud"
    if value == "hosting":
        return "Hosting"
    if value == "transit":
        return "Transit / ISP"
    if value == "platform":
        return "Platform"
    if value == "unknown":
        return "Unknown"
    return str(provider_type).strip().title()


def _classify_hosting_type(cdn_result: Dict[str, Any], domain: str = "") -> str:
    """Derive hosting type from CDN provider classification, domain TLD, and ISP/org strings."""
    provider_type = str(cdn_result.get("infrastructure_type", "")).lower()

    if provider_type == "cdn":
        return "CDN"
    if provider_type == "gov-cloud":
        return "Government"
    if provider_type in ("cloud", "hosting"):
        return "Cloud"
    if provider_type == "transit":
        return "Transit / ISP"

    d = domain.lower()

    # TLD-based government check (.gov, .gv.at, .gouv.fr, .bund.de, etc.)
    gov_tld_patterns = (
        ".gov",
        ".gv.at",
        ".gouv.",
        ".bund.de",
        ".mil",
        ".gc.ca",
        ".gov.uk",
    )
    if any(p in d for p in gov_tld_patterns):
        return "Government"

    # Domain name keyword check — countries that use ccTLD for government (e.g. .de)
    gov_domain_prefixes = (
        "bundesregierung.",
        "bundestag.",
        "bundesrat.",
        "bundeswehr.",
        "bundesamt",
        "bundeskanzler",
        "bundesministerium",
        "bundespolizei.",
        "bundesnetzagentur.",
    )
    if any(p in d for p in gov_domain_prefixes):
        return "Government"

    geo = cdn_result.get("geolocation", {}) or {}
    asn_info = cdn_result.get("asn_info", {}) or {}
    combined = " ".join(
        [
            str(asn_info.get("organization", "")),
            str(asn_info.get("isp", "")),
            str(geo.get("org", "")),
            str(geo.get("isp", "")),
        ]
    ).lower()

    # Known government-exclusive IT providers (DACH region)
    gov_org_keywords = (
        "conet deutschland",
        "babiel",
        "bundesrechenzentrum",
        "dataport",
        "brz gmbh",
        "govix",
    )
    if any(k in combined for k in gov_org_keywords):
        return "Government"

    edu_keywords = (
        "universit",
        "hochschule",
        "college",
        "education",
        "research",
        "akademie",
        "institut",
    )
    if any(k in combined for k in edu_keywords):
        return "Education"

    cloud_keywords = (
        "amazon",
        "microsoft",
        "google",
        "hetzner",
        "ovh",
        "digitalocean",
        "linode",
        "vultr",
        "cloudflare",
        "akamai",
        "fastly",
        "outscale",
        "ionos",
        "1&1",
        "contabo",
        "leaseweb",
        "choopa",
        "data center",
        "datacenter",
        "hosting",
        "server",
        "cloud",
    )
    if any(k in combined for k in cloud_keywords):
        return "Cloud"

    return "Commercial"


def _get_geographic_risk(country_code: str) -> str:
    """Return HIGH / MEDIUM / LOW risk label based on ISO country code."""
    high_risk = {"CN", "RU", "KP", "IR"}
    medium_risk = {"BY", "SY", "VE", "CU", "MM", "SD", "AF", "IQ", "LY", "SO", "YE"}
    if country_code in high_risk:
        return "HIGH"
    if country_code in medium_risk:
        return "MEDIUM"
    return "LOW"


def _format_category_name(category: str) -> str:
    """Render category names with stable casing."""
    category_lower = str(category).lower()
    if category_lower == "api":
        return "API"
    if category_lower == "dev":
        return "Dev"
    return str(category).title()


def _count_execution_outcomes(result: UnifiedResult) -> Tuple[int, int, int]:
    """Count successful, failed, and timeout module outcomes."""
    successful = len(result.modules_successful)
    failed = 0
    timeout = 0

    _non_failure = {"abgeschlossen", "demo_abgeschlossen", "quota_exceeded", "skipped"}
    for module_result in result.results.values():
        if not isinstance(module_result, dict):
            continue
        if module_result.get("analysis_status") in _non_failure:
            continue
        if module_result.get("failure_type") == "timeout":
            timeout += 1
        else:
            failed += 1

    return successful, failed, timeout


def _extract_vt_category_signals(vt_result: Dict[str, Any]) -> List[str]:
    """Normalize VirusTotal category hints for display."""
    categories = vt_result.get("categories", {}) or {}
    if not isinstance(categories, dict):
        return []

    def format_category_label(value: Any) -> str:
        text = str(value).strip()
        if not text:
            return ""
        if text.islower():
            if "/" in text:
                return "/".join(part.strip().title() for part in text.split("/"))
            return text.title()
        return text

    signals = []
    seen = set()
    for source_name, category_value in categories.items():
        source_text = str(source_name).strip()
        category_text = format_category_label(category_value)

        if not category_text:
            continue

        if source_text and source_text.lower() not in category_text.lower():
            signal = f"{category_text} ({source_text})"
        else:
            signal = category_text

        normalized = signal.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        signals.append(signal)

    return signals


def _render_dns_history_block(
    dns_history_result: dict,
    whois_result: dict,
    dns_result: dict,
    cdn_result: dict,
) -> None:
    print(f"\n{Colors.section_header('DNS HISTORY TIMELINE', 50)}")
    if dns_history_result.get("analysis_status") == "abgeschlossen":
        data_sources = dns_history_result.get("data_sources", []) or []
        timeline_span = dns_history_result.get("timeline_span", {}) or {}
        timeline = dns_history_result.get("timeline", []) or []
        pattern_analysis = dns_history_result.get("pattern_analysis", {}) or {}
        historical_risk_events = (
            dns_history_result.get("historical_risk_events", []) or []
        )

        start_date = timeline_span.get("start_date") or "unknown"
        end_date = timeline_span.get("end_date") or "unknown"
        span_days = timeline_span.get("days", 0)

        print(
            f"├── Data Sources: {Colors.info(', '.join(data_sources) if data_sources else 'none')}"
        )

        whois_creation_raw = whois_result.get("creation_date") or whois_result.get(
            "createdDate"
        )
        whois_created_str = (
            _format_history_date(whois_creation_raw) if whois_creation_raw else None
        )
        first_seen_candidates = [
            d
            for d in [start_date, whois_created_str]
            if d and d not in ("unknown", "unknown date") and len(d) >= 10
        ]
        first_seen = min(first_seen_candidates) if first_seen_candidates else "unknown"
        if first_seen != "unknown":
            if (
                whois_created_str
                and first_seen == whois_created_str
                and first_seen != start_date
            ):
                fs_source = " (WHOIS)"
            else:
                fs_source = f" ({data_sources[0]})" if data_sources else ""
        else:
            fs_source = ""
        print(f"├── First Seen: {Colors.info(first_seen)}{fs_source}")

        current_ip = dns_result.get("ipv4") or (
            dns_result.get("fallback_data") or {}
        ).get("ipv4")
        if current_ip:
            a_history = dns_history_result.get("a_history") or []
            ip_a_events = [e for e in a_history if current_ip in e.get("new", [])]
            ip_dates = [
                e["date"]
                for e in ip_a_events
                if e.get("date") and e["date"] not in ("unknown",)
            ]
            if ip_dates:
                ip_first_str = min(ip_dates)[:10]
                try:
                    ip_dt = datetime.strptime(ip_first_str, "%Y-%m-%d")
                    days_ago = (datetime.now() - ip_dt).days
                    if days_ago < 365:
                        age_label = "relatively recent"
                    elif days_ago < 3 * 365:
                        age_label = "established"
                    else:
                        age_label = "long-standing"
                except Exception:
                    age_label = ""
                age_suffix = f" – {age_label}" if age_label else ""
                print(
                    f"├── Current IP {current_ip} first seen: {Colors.info(ip_first_str)}{age_suffix}"
                )
            elif ip_a_events:
                print(
                    f"├── Current IP {current_ip} first seen: {Colors.dim('no date in history')}"
                )
            else:
                cdn_provider = cdn_result.get("provider_detected")
                cdn_note = (
                    " (CDN anycast – not tracked in passive DNS)"
                    if cdn_provider
                    else ""
                )
                print(
                    f"├── Current IP {current_ip} first seen: {Colors.dim('not found in history')}{cdn_note}"
                )

        print(
            f"├── Timeline Span: {Colors.info(f'{start_date} to {end_date} ({span_days} days)')}"
        )

        ns_history = dns_history_result.get("ns_history") or []
        ns_grouped: Dict[str, List[str]] = {}
        for e in ns_history:
            d = _format_history_date(e.get("date"))
            for v in e.get("new", []):
                ns_grouped.setdefault(d, [])
                if v not in ns_grouped[d]:
                    ns_grouped[d].append(v)
        if ns_grouped:
            print(
                f"├── NS Record Changes: {Colors.info(str(len(ns_grouped)))} change events"
            )
            visible_ns = list(ns_grouped.items())[:4]
            for idx, (d, vals) in enumerate(visible_ns):
                connector = "└──" if idx == len(visible_ns) - 1 else "├──"
                print(
                    f"│   {connector} {d}: {Colors.dim(_format_history_value(vals, max_items=4, max_length=68))}"
                )
        else:
            print(f"├── NS Record Changes: {Colors.dim('no NS changes in history')}")

        mx_history = dns_history_result.get("mx_history") or []
        mx_grouped: Dict[str, List[str]] = {}
        for e in mx_history:
            d = _format_history_date(e.get("date"))
            for v in e.get("new", []):
                mx_grouped.setdefault(d, [])
                if v not in mx_grouped[d]:
                    mx_grouped[d].append(v)
        if mx_grouped:
            print(
                f"├── MX Record Changes: {Colors.info(str(len(mx_grouped)))} change events"
            )
            visible_mx = list(mx_grouped.items())[:4]
            for idx, (d, vals) in enumerate(visible_mx):
                connector = "└──" if idx == len(visible_mx) - 1 else "├──"
                print(
                    f"│   {connector} {d}: {Colors.dim(_format_history_value(vals, max_items=4, max_length=68))}"
                )
        else:
            print(f"├── MX Record Changes: {Colors.dim('no MX changes in history')}")

        ct_metadata = dns_history_result.get("ct_metadata")
        ct_history = dns_history_result.get("ct_history") or []
        if ct_metadata:
            src_lbl = ct_metadata.get("source_label", "crt.sh")
            cert_count = ct_metadata.get("count", len(ct_history))
            ct_earliest = ct_metadata.get("earliest") or "unknown"
            ct_latest = ct_metadata.get("latest") or "unknown"
            ct_subs = ct_metadata.get("subdomains", [])
            print(
                f"├── Certificate History ({src_lbl}): {Colors.info(str(cert_count))} certificates"
            )
            if ct_subs:
                print(f"│   ├── Earliest: {ct_earliest}, Latest: {ct_latest}")
                sub_str = ", ".join(ct_subs[:8])
                if len(ct_subs) > 8:
                    sub_str += f", +{len(ct_subs) - 8} more"
                print(f"│   └── Subdomains via CT: {Colors.dim(sub_str)}")
            else:
                print(f"│   └── Earliest: {ct_earliest}, Latest: {ct_latest}")
        elif ct_history:
            ct_dates = [
                e["date"]
                for e in ct_history
                if e.get("date") and e["date"] not in ("unknown",)
            ]
            ct_earliest = min(ct_dates)[:10] if ct_dates else "unknown"
            ct_latest = max(ct_dates)[:10] if ct_dates else "unknown"
            print(
                f"├── Certificate History (crt.sh): {Colors.info(str(len(ct_history)))} certificates"
            )
            print(f"│   └── Earliest: {ct_earliest}, Latest: {ct_latest}")
        else:
            print(
                f"├── Certificate History: {Colors.dim('not available (all sources failed)')}"
            )

        print(
            f"├── Major Changes: {Colors.info(str(dns_history_result.get('major_changes', 0)))} detected"
        )

        recent_events = [e for e in timeline if e.get("record_type") != "CT"][:3]
        if recent_events:
            print(f"├── Recent Events:")
            for idx, event in enumerate(recent_events):
                connector = "└──" if idx == len(recent_events) - 1 else "├──"
                rec_vals = _format_history_value(
                    event.get("new"), max_items=2, max_length=58
                )
                rtype = event.get("record_type", "?")
                print(
                    f"│   {connector} {_format_history_date(event.get('date'))}: [{rtype}] {Colors.dim(rec_vals)}"
                )

        suspicious_patterns = pattern_analysis.get(
            "suspicious_patterns", ["not assessed"]
        )
        suspicious_text = (
            "; ".join(str(p) for p in suspicious_patterns[:3])
            if isinstance(suspicious_patterns, list)
            else str(suspicious_patterns)
        )
        print(f"├── Pattern Analysis:")
        print(
            f"│   ├── Change Frequency: {Colors.info(str(pattern_analysis.get('change_frequency', 'not assessed')))}"
        )
        print(
            f"│   ├── Infrastructure Stability: {Colors.info(str(pattern_analysis.get('infrastructure_stability', 'unknown')))}"
        )
        print(f"│   ├── Suspicious Patterns: {Colors.info(suspicious_text)}")
        print(
            f"│   └── Risk Assessment: {Colors.warning(str(pattern_analysis.get('risk_level', 'UNKNOWN')))}"
        )
        if historical_risk_events:
            print(
                f"└── Historical Risk Events: {Colors.warning('; '.join(str(i) for i in historical_risk_events[:3]))}"
            )
        else:
            print(f"└── Historical Risk Events: {Colors.success('none detected')}")
    elif dns_history_result:
        print(f"├── DNS History: {Colors.warning('UNAVAILABLE')}")
        print(
            f"└── Detail: {Colors.dim(str(dns_history_result.get('error') or 'No timeline data available'))}"
        )
    else:
        print(f"└── DNS History: {Colors.error('NOT RUN')}")


def _render_virustotal_status(
    vt_result: dict,
    unavailable_color=Colors.error,
    unavailable_text: str = "ANALYSIS FAILED",
) -> None:
    """Render VirusTotal domain reputation status."""
    if vt_result.get("analysis_status") in ["abgeschlossen", "demo_abgeschlossen"]:
        api_status = vt_result.get("api_status", "unknown")
        threat_analysis = vt_result.get("threat_analysis", {})
        threat_intel = vt_result.get("threat_intelligence", {})
        malicious = threat_analysis.get("malicious_detections", 0)
        suspicious = threat_analysis.get("suspicious_detections", 0)
        total_vendors = threat_analysis.get("total_security_vendors", 0)
        reputation_score = threat_intel.get(
            "reputation_score", vt_result.get("reputation", 0)
        )
        category_signals = _extract_vt_category_signals(vt_result)
        status_text = "Demo Mode" if api_status == "demo_mode" else "Live Data"

        if malicious >= 3:
            threat_color = Colors.error
            threat_text = f"MALICIOUS ({malicious}/{total_vendors} vendors)"
        elif malicious > 0:
            threat_color = Colors.warning
            threat_text = f"REVIEW ({malicious}/{total_vendors} malicious vendors)"
        elif suspicious >= 3:
            threat_color = Colors.warning
            threat_text = f"SUSPICIOUS ({suspicious}/{total_vendors} vendors)"
        else:
            threat_color = Colors.success
            threat_text = f"CLEAN ({malicious + suspicious}/{total_vendors} vendors)"

        print(f"├── Domain Reputation: {threat_color(threat_text)} [{status_text}]")
        print(f"├── VT Reputation Score: {Colors.info(str(reputation_score))}")
        if category_signals:
            print(
                f"├── VT Category Signals: {Colors.info(', '.join(category_signals[:5]))}"
            )
    else:
        print(f"├── Domain Reputation: {unavailable_color(unavailable_text)}")


def _render_securitytrails_status(st_result: dict, unavailable_branch: str) -> None:
    """Render SecurityTrails historical/domain intelligence status."""
    if st_result.get("analysis_status") in ["abgeschlossen", "demo_abgeschlossen"]:
        api_status = st_result.get("api_status", "unknown")
        domain_details = st_result.get("domain_details", {})
        subdomain_count = (
            domain_details.get("subdomain_count", 0)
            if isinstance(domain_details, dict)
            else 0
        )
        status_text = "Demo Mode" if api_status == "demo_mode" else "Live Data"

        if subdomain_count > 0:
            print(
                f"├── SecurityTrails History: {Colors.info(f'{subdomain_count} subdomains in historical dataset')} [{status_text}]"
            )
        else:
            print(
                f"├── SecurityTrails History: {Colors.dim('No historical data')} [{status_text}]"
            )
    else:
        st_api_status = st_result.get("api_status", "")
        if st_api_status in ("quota_exceeded", "demo_mode"):
            print(
                f"{unavailable_branch} SecurityTrails: {Colors.dim('not available - quota exceeded or no API key')}"
            )
        else:
            print(f"{unavailable_branch} SecurityTrails: {Colors.dim('not available')}")


def _render_abuseipdb_status(abuse_result: dict) -> None:
    """Render AbuseIPDB IP reputation status."""
    if abuse_result.get("analysis_status") in ["abgeschlossen", "demo_abgeschlossen"]:
        api_status = abuse_result.get("api_status", "unknown")
        abuse_confidence = abuse_result.get("abuse_confidence", 0)
        country_code = abuse_result.get("country_code", "Unknown")
        status_text = "Demo Mode" if api_status == "demo_mode" else "Live Data"

        if abuse_confidence > 50:
            abuse_color = Colors.error
            abuse_text = f"HIGH ABUSE ({abuse_confidence}%)"
        elif abuse_confidence > 25:
            abuse_color = Colors.warning
            abuse_text = f"MODERATE ABUSE ({abuse_confidence}%)"
        else:
            abuse_color = Colors.success
            abuse_text = f"CLEAN ({abuse_confidence}%)"

        print(f"├── IP Reputation: {abuse_color(abuse_text)} [{status_text}]")
        if country_code != "Unknown":
            print(f"├── Geographic Risk: {Colors.info(country_code)}")
    else:
        print(f"├── IP Reputation: {Colors.error('ANALYSIS FAILED')}")


def _collect_live_api_statuses(
    vt_result: dict,
    whois_result: dict,
    dns_history_result: dict,
    st_result: Optional[dict] = None,
    abuse_result: Optional[dict] = None,
    ip_history_result: Optional[dict] = None,
) -> List[str]:
    """Return display labels for live APIs used in the report."""
    api_statuses = []
    if st_result and st_result.get("api_status") == "live_data":
        api_statuses.append("SecurityTrails")
    if abuse_result and abuse_result.get("api_status") == "live_data":
        api_statuses.append("AbuseIPDB")
    if vt_result.get("api_status") == "live_data":
        api_statuses.append("VirusTotal")
    if whois_result.get("source") == "WhoisXML API":
        api_statuses.append("WhoisXML")

    dns_history_sources = [
        source
        for source in dns_history_result.get("data_sources", [])
        if source != "Native Fallback"
    ]
    if dns_history_sources:
        api_statuses.append(f"DNS History ({', '.join(dns_history_sources[:3])})")

    if ip_history_result:
        ip_history_sources = [
            k
            for k, v in (ip_history_result.get("sources") or {}).items()
            if v.get("status") == "success"
        ]
        if ip_history_sources:
            api_statuses.append(f"Reverse IP ({', '.join(ip_history_sources)})")

    return api_statuses


def _render_risk_assessment_values(
    overall_risk: str,
    risk_factors: List[str],
    recommendation: str,
    risk_color,
) -> None:
    """Render shared risk assessment rows."""
    print(f"├── Overall Risk: {risk_color(overall_risk)}")
    if risk_factors:
        print(f"├── Risk Factors:")
        for factor in risk_factors:
            print(f"│   ├── {factor}")
    print(f"└── Recommendation: {risk_color(recommendation)}")


def _render_execution_values(
    result: UnifiedResult,
    successful_modules: int,
    failed_modules: int,
    timeout_modules: int,
    api_statuses: List[str],
    mode_line: Optional[str] = None,
) -> None:
    """Render shared execution rows."""
    print(
        f"├── Execution Time: {Colors.info(f'{result.total_execution_time:.1f} seconds')}"
    )
    print(
        f"├── Modules Executed: {Colors.success(str(successful_modules))} successful, {Colors.error(str(failed_modules))} failed, {Colors.warning(str(timeout_modules))} timeout"
    )
    if mode_line:
        print(mode_line)
    if api_statuses:
        print(f"├── Live APIs Used: {Colors.success(', '.join(api_statuses))}")
    else:
        print(f"├── Live APIs Used: {Colors.warning('Demo Mode - Configure API keys')}")
    print(f"└── Detailed Logs: {Colors.dim('logs/domain_analyzer_*.log')}")


def _display_historical_blocks(
    result: UnifiedResult,
    dns_history_result: dict,
    vt_result: dict,
    st_result: dict,
    dns_result: dict,
    whois_result: dict,
    cdn_result: dict,
    hist_ip: str,
    hist_date: str,
    overall_risk: str,
    risk_factors: list,
    recommendation: str,
    risk_color,
    successful_modules: int,
    failed_modules: int,
    timeout_modules: int,
) -> None:
    """Compact report for inactive/expired domains: DNS history + VT reputation + risk only."""
    _render_dns_history_block(dns_history_result, whois_result, dns_result, cdn_result)

    # --- IP & DOMAIN HISTORY (historical IPs only — no active reverse-IP data) ---
    print(f"\n{Colors.section_header('IP & DOMAIN HISTORY', 50)}")
    print(f"├── Current IP: {Colors.dim('not resolving (domain inactive)')}")
    print(
        f"├── Last Known IP: {Colors.format_ip(hist_ip)} {Colors.dim(f'(last seen {hist_date})')}"
    )

    a_history = dns_history_result.get("a_history") or []
    ip_dates_hist: Dict[str, str] = {}
    for event in a_history:
        date_val = event.get("date") or "unknown"
        for ip_val in event.get("new", []):
            ip_str = str(ip_val).strip()
            if (
                ip_str
                and ":" not in ip_str
                and (ip_str not in ip_dates_hist or date_val > ip_dates_hist[ip_str])
            ):
                ip_dates_hist[ip_str] = date_val
    if ip_dates_hist:
        sorted_ips = sorted(ip_dates_hist.items(), key=lambda x: x[1], reverse=True)
        print(f"├── Historical IPs ({len(sorted_ips)} unique observed):")
        for ip_val, date_str in sorted_ips[:8]:
            date_short = date_str[:10] if date_str != "unknown" else "unknown"
            print(f"│   ├── {date_short}: {Colors.format_ip(ip_val)}")
        if len(sorted_ips) > 8:
            print(f"│   └── {Colors.dim(f'... and {len(sorted_ips) - 8} more')}")
    else:
        print(f"├── Historical IPs: {Colors.dim('no A-record history')}")
    print(f"└── Reverse IP: {Colors.dim('not available (domain inactive)')}")

    # --- THREAT INTELLIGENCE (VT domain reputation only) ---
    print(f"\n{Colors.section_header('THREAT INTELLIGENCE', 50)}")
    _render_virustotal_status(
        vt_result, unavailable_color=Colors.dim, unavailable_text="not available"
    )
    _render_securitytrails_status(st_result, unavailable_branch="├──")
    print(
        f"└── IP Reputation: {Colors.dim('not available (domain inactive — no current IP)')}"
    )

    # --- RISK ASSESSMENT ---
    print(f"\n{Colors.section_header('RISK ASSESSMENT', 50)}")
    _render_risk_assessment_values(
        overall_risk, risk_factors, recommendation, risk_color
    )

    # --- EXECUTION ---
    print(f"\n{Colors.section_header('EXECUTION', 50)}")
    api_statuses = _collect_live_api_statuses(
        vt_result, whois_result, dns_history_result
    )
    mode_line = (
        f"├── Mode: {Colors.warning('HISTORICAL ANALYSIS')} "
        f"{Colors.dim('(domain inactive — current DNS resolution failed)')}"
    )
    _render_execution_values(
        result,
        successful_modules,
        failed_modules,
        timeout_modules,
        api_statuses,
        mode_line=mode_line,
    )

    _render_report_footer()

def _build_summary_context(result: UnifiedResult) -> Dict[str, Any]:
    """Collect shared values used by the terminal summary renderers."""
    overall_risk, risk_factors, recommendation = _compute_risk_summary(result)
    risk_color = (
        Colors.error
        if overall_risk == "CRITICAL"
        else Colors.warning if overall_risk in ["HIGH", "MEDIUM"] else Colors.success
    )

    vt_result = result.results.get("virustotal", {})
    abuse_result = result.results.get("abuseipdb", {})
    st_result = result.results.get("securitytrails", {})
    dns_result = result.results.get("dns", {})
    whois_result = result.results.get("whois", {})
    dns_history_result = result.results.get("dns_history", {})
    cdn_result = result.results.get("cdn", {})
    ip_history_result = result.results.get("ip_history", {})
    # REQ-003: detect inactive domain — extract last known IP from dns_history a_history
    hist_ip = None
    hist_date = "unknown"
    for _ev in dns_history_result.get("a_history") or []:
        _vals = _ev.get("new", [])
        if _vals and isinstance(_vals, list):
            _ip = _vals[0]
            if isinstance(_ip, str) and _ip and ":" not in _ip:
                hist_ip = _ip
                hist_date = str(_ev.get("date", "unknown"))
                break
    is_historical = bool(hist_ip and not dns_result.get("ipv4"))
    network_result = result.results.get("network", {})
    http_behavior = network_result.get("http_behavior", {})
    ssl_result = result.results.get("ssl", {})
    subdomain_result = result.results.get("subdomain", {})
    wildcard_detected = bool(
        subdomain_result.get("wildcard_detected")
        or subdomain_result.get("dns_configuration", {}).get("wildcard_detected", False)
    )
    successful_modules, failed_modules, timeout_modules = _count_execution_outcomes(
        result
    )
    return {
        "result": result,
        "overall_risk": overall_risk,
        "risk_factors": risk_factors,
        "recommendation": recommendation,
        "risk_color": risk_color,
        "vt_result": vt_result,
        "abuse_result": abuse_result,
        "st_result": st_result,
        "dns_result": dns_result,
        "whois_result": whois_result,
        "dns_history_result": dns_history_result,
        "cdn_result": cdn_result,
        "ip_history_result": ip_history_result,
        "hist_ip": hist_ip,
        "hist_date": hist_date,
        "is_historical": is_historical,
        "network_result": network_result,
        "http_behavior": http_behavior,
        "ssl_result": ssl_result,
        "subdomain_result": subdomain_result,
        "wildcard_detected": wildcard_detected,
        "successful_modules": successful_modules,
        "failed_modules": failed_modules,
        "timeout_modules": timeout_modules,
    }

def _render_report_header(ctx: Dict[str, Any]) -> None:
    """Render the report header report section."""
    result = ctx["result"]
    overall_risk = ctx["overall_risk"]
    risk_color = ctx["risk_color"]
    wildcard_detected = ctx["wildcard_detected"]
    asset_summary_label = "Candidates" if wildcard_detected else "Assets"
    sensitive_summary_label = (
        "Sensitive Candidates" if wildcard_detected else "Sensitive"
    )

    print(f"\n{Colors.investigation_separator(80)}")
    print(Colors.header(f"DOMAIN FORENSIC ANALYSIS: {result.domain.upper()}"))
    print(
        f"Summary: Risk {risk_color(overall_risk)} | {asset_summary_label} {Colors.highlight(str(result.total_assets_found))} | "
        f"{sensitive_summary_label} {Colors.warning(str(result.sensitive_assets_found))} | "
        f"Modules {Colors.info(f'{len(result.modules_successful)}/{len(result.modules_executed)}')} | "
        f"Time {Colors.info(f'{result.total_execution_time:.1f}s')}"
    )
    print(Colors.investigation_separator(80))


def _render_summary_section(ctx: Dict[str, Any]) -> None:
    """Render the summary section report section."""
    result = ctx["result"]
    overall_risk = ctx["overall_risk"]
    risk_factors = ctx["risk_factors"]
    recommendation = ctx["recommendation"]
    risk_color = ctx["risk_color"]

    print(f"\n{Colors.section_header('SUMMARY', 50)}")
    print(f"├── Domain: {Colors.warning(result.domain.upper())}")
    print(f"├── Overall Risk: {risk_color(overall_risk)}")
    print(f"├── Recommendation: {risk_color(recommendation)}")
    if risk_factors:
        print(f"├── Key Risk Factors:")
        for factor in risk_factors[:3]:
            print(f"│   ├── {factor}")
    print(
        f"└── Execution: {Colors.info(f'{result.total_execution_time:.1f}s')} | "
        f"{Colors.info(f'{len(result.modules_successful)}/{len(result.modules_executed)} modules successful')}"
    )


def _render_target_section(ctx: Dict[str, Any]) -> None:
    """Render the target section report section."""
    dns_result = ctx["dns_result"]
    hist_ip = ctx["hist_ip"]
    hist_date = ctx["hist_date"]
    is_historical = ctx["is_historical"]

    print(f"\n{Colors.section_header('TARGET', 50)}")
    if dns_result.get("analysis_status") == "abgeschlossen":
        ip = dns_result.get("ipv4", "Unknown")
        ipv6 = dns_result.get("ipv6", "Not configured")
        reverse_dns = dns_result.get("reverse_dns", "Not available")
        nameservers = _extract_nameserver_entries(dns_result)
        mail_servers = _extract_mail_server_entries(dns_result)

        if ip and ip != "None":
            print(f"├── IPv4: {Colors.format_ip(ip)}")
        elif is_historical:
            print(f"├── IPv4: {Colors.dim('not currently resolving')}")
            print(
                f"├── Status: {Colors.warning('HISTORICAL ANALYSIS')} {Colors.dim('(domain inactive)')}"
            )
            print(
                f"├── Last Known IP: {Colors.format_ip(hist_ip)} {Colors.dim(f'(last seen {hist_date})')}"
            )
        else:
            print(f"├── IPv4: {Colors.dim('None')}")
        if ipv6 and ipv6 != "Not configured":
            print(f"├── IPv6: {Colors.info(ipv6)}")
        print(f"├── Nameservers: {Colors.info(str(len(nameservers)))} configured")
        if nameservers:
            for nameserver in nameservers:
                print(f"│   ├── {nameserver}")
        reverse_dns_text = (
            reverse_dns
            if reverse_dns and reverse_dns != "Not available"
            else "not available"
        )
        print(f"├── Reverse DNS: {Colors.dim(reverse_dns_text)}")
        print(f"└── Mail Servers: {Colors.info(str(len(mail_servers)))} configured")
        if mail_servers:
            for mail_server in mail_servers:
                print(f"    ├── {mail_server}")
    else:
        print(f"├── DNS: {Colors.error('FAILED')}")
        print(f"└── Unable to resolve domain")


def _render_geo_asn_section(ctx: Dict[str, Any]) -> None:
    """Render the geo asn section report section."""
    result = ctx["result"]
    dns_result = ctx["dns_result"]
    cdn_result = ctx["cdn_result"]

    print(f"\n{Colors.section_header('GEO & ASN', 50)}")
    geo = cdn_result.get("geolocation") or {}
    asn_info = cdn_result.get("asn_info") or {}
    if geo.get("status") == "success":
        country = geo.get("country", "Unknown")
        country_code = geo.get("countryCode", "")
        region = geo.get("region", "Unknown")
        city = geo.get("city", "Unknown")
        asn_raw = str(asn_info.get("asn") or geo.get("as") or "")
        asn_parts = asn_raw.split(" ", 1)
        asn_number = asn_parts[0] if asn_raw else "Unknown"
        asn_org = (
            asn_parts[1]
            if len(asn_parts) > 1
            else (asn_info.get("organization") or "Unknown")
        )
        isp = str(asn_info.get("isp") or geo.get("isp") or "Unknown")
        country_display = f"{country_code} – {country}" if country_code else country
        hosting_type = _classify_hosting_type(cdn_result, result.domain)
        geo_risk = _get_geographic_risk(country_code)
        geo_risk_color = (
            Colors.error
            if geo_risk == "HIGH"
            else Colors.warning if geo_risk == "MEDIUM" else Colors.success
        )
        print(f"├── IP: {Colors.format_ip(dns_result.get('ipv4', 'Unknown'))}")
        print(f"├── Country: {Colors.info(country_display)}")
        print(f"├── Region: {Colors.info(region)}")
        print(f"├── City: {Colors.info(city)}")
        print(f"├── ASN: {Colors.info(asn_number)}")
        print(f"├── ASN Organisation: {Colors.info(asn_org)}")
        print(f"├── ISP: {Colors.info(isp)}")
        print(f"├── Hosting Type: {Colors.info(hosting_type)}")
        print(f"└── Geographic Risk: {geo_risk_color(geo_risk)}")
    else:
        print(
            f"└── GeoIP: {Colors.dim('not available (CDN module not run or geo lookup failed)')}"
        )


def _render_whois_section(ctx: Dict[str, Any]) -> None:
    """Render the whois section report section."""
    dns_result = ctx["dns_result"]
    whois_result = ctx["whois_result"]

    print(f"\n{Colors.section_header('WHOIS REGISTRATION', 50)}")
    if whois_result.get("analysis_status") == "abgeschlossen":
        registry_policy = whois_result.get("registry_policy")  # e.g. 'DENIC'
        domain_tld = "." + (whois_result.get("domain") or "").rsplit(".", 1)[-1].lower()
        redacted_note = (
            f"Not disclosed by registry ({registry_policy} policy)"
            if registry_policy
            else None
        )

        def _whois_field(raw_value: Any, field_default: str = "Unknown") -> tuple:
            """Return (display_value, is_redacted)."""
            val = _format_whois_value(raw_value, field_default)
            if val == "Unknown" and redacted_note:
                return redacted_note, True
            return val, False

        registrar, reg_redacted = _whois_field(
            whois_result.get("registrar") or whois_result.get("registrarName")
        )
        creation_date, cd_redacted = _whois_field(
            whois_result.get("creation_date") or whois_result.get("createdDate")
        )
        expiration_date, ed_redacted = _whois_field(
            whois_result.get("expiration_date") or whois_result.get("expiresDate")
        )
        updated_date, _ = _whois_field(
            whois_result.get("updated_date") or whois_result.get("updatedDate")
        )
        registrant_name = _format_whois_value(
            whois_result.get("registrant_name")
            or (whois_result.get("registrant") or {}).get("name"),
            "Not disclosed",
        )
        registrant_org = _format_whois_value(
            whois_result.get("registrant_organization")
            or (whois_result.get("registrant") or {}).get("organization"),
            "Not disclosed",
        )
        registrant_country = _format_whois_value(
            whois_result.get("registrant_country")
            or (whois_result.get("registrant") or {}).get("country")
        )
        nameservers = _format_whois_nameservers(
            whois_result.get("name_servers") or whois_result.get("nameServers")
        )
        nameserver_source = "WHOIS"
        if not nameservers and dns_result.get("analysis_status") == "abgeschlossen":
            nameservers = _extract_nameserver_entries(dns_result)
            nameserver_source = "DNS fallback"
        source = _format_whois_value(whois_result.get("source"))

        if registry_policy:
            print(
                f"├── Registry Note: {Colors.dim(f'{registry_policy} ({domain_tld}) redacts registrar and date fields by policy')}"
            )

        print(
            f"├── Registrar: {Colors.dim(registrar) if reg_redacted else Colors.info(registrar)}"
        )
        print(
            f"├── Created: {Colors.dim(creation_date) if cd_redacted else Colors.info(creation_date)}"
        )
        print(
            f"├── Expires: {Colors.dim(expiration_date) if ed_redacted else Colors.info(expiration_date)}"
        )
        print(f"├── Updated: {Colors.info(updated_date)}")
        print(f"├── Registrant: {Colors.dim(registrant_name)}")
        if registrant_org != "Not disclosed":
            print(f"├── Organization: {Colors.dim(registrant_org)}")
        print(f"├── Country: {Colors.dim(registrant_country)}")
        privacy_proxy = whois_result.get("privacy_proxy")
        if privacy_proxy:
            print(f"├── Privacy Proxy: {Colors.warning(privacy_proxy + ' detected')}")
        nameserver_label = f"{len(nameservers)} listed"
        if nameserver_source != "WHOIS":
            nameserver_label += f" ({nameserver_source})"
        print(f"├── Nameservers: {Colors.info(nameserver_label)}")
        for nameserver in nameservers[:5]:
            print(f"│   ├── {nameserver}")
        print(f"└── Source: {Colors.dim(source)}")
    elif whois_result:
        error_text = (
            whois_result.get("error")
            or whois_result.get("failure_type")
            or "Data unavailable"
        )
        print(f"├── WHOIS: {Colors.warning('UNAVAILABLE')}")
        print(f"└── Detail: {Colors.dim(str(error_text))}")
    else:
        print(f"└── WHOIS: {Colors.error('NOT RUN')}")


def _render_dns_forensics_section(ctx: Dict[str, Any]) -> None:
    """Render the dns forensics section report section."""
    result = ctx["result"]
    dns_result = ctx["dns_result"]
    whois_result = ctx["whois_result"]
    dns_history_result = ctx["dns_history_result"]
    cdn_result = ctx["cdn_result"]

    print(f"\n{Colors.section_header('DNS FORENSICS', 50)}")
    if dns_result.get("analysis_status") == "abgeschlossen":
        soa_record = dns_result.get("soa_record", {}) or {}
        txt_records = dns_result.get("txt_records", []) or []
        spf_record = dns_result.get("spf_record")
        spf_analysis = dns_result.get("spf_analysis", {}) or {}
        spf_includes = dns_result.get("spf_includes", []) or []
        dmarc_record = dns_result.get("dmarc_record")
        dmarc_analysis = dns_result.get("dmarc_analysis", {}) or {}
        dkim = dns_result.get("dkim", {}) or {}
        caa_records_raw = dns_result.get("caa_records", []) or []
        dnssec = dns_result.get("dnssec", {}) or {}
        zone_transfer = dns_result.get("zone_transfer", {}) or {}
        dns_config_assessment = dns_result.get("dns_configuration_assessment", {}) or {}
        ns_records = dns_result.get("ns_records", []) or []
        mx_records = dns_result.get("mx_records", []) or []
        a_ttl = dns_result.get("a_record_ttl")
        mx_ttl = dns_result.get("mx_record_ttl")
        ns_ttl = dns_result.get("ns_record_ttl")
        cname_target = dns_result.get("cname_target")

        soa_primary = soa_record.get("primary_nameserver", "not available")
        soa_serial = soa_record.get("serial", "not available")
        print(f"├── SOA Primary NS: {Colors.info(str(soa_primary))}")
        print(f"├── SOA Serial: {Colors.info(str(soa_serial))}")

        # NS Records
        if ns_records:
            ns_ttl_str = f"  [TTL {ns_ttl}s]" if ns_ttl is not None else ""
            print(
                f"├── NS Records: {Colors.info(str(len(ns_records)))} nameservers{Colors.dim(ns_ttl_str)}"
            )
            for ns in ns_records:
                print(f"│   ├── {ns}")
        else:
            print(f"├── NS Records: {Colors.dim('none')}")

        # MX Records
        if mx_records:
            mx_ttl_str = f"  [TTL {mx_ttl}s]" if mx_ttl is not None else ""
            sorted_mx = sorted(
                mx_records,
                key=lambda x: (
                    int(x.get("priority", 99))
                    if str(x.get("priority", 99)).isdigit()
                    else 99
                ),
            )
            print(
                f"├── MX Records: {Colors.info(str(len(mx_records)))} mail servers{Colors.dim(mx_ttl_str)}"
            )
            for mx in sorted_mx:
                print(f"│   ├── {mx.get('priority', '?'):>3}  {mx.get('server', '?')}")
        else:
            print(f"├── MX Records: {Colors.dim('none configured')}")

        # A Record TTL
        if a_ttl is not None:
            print(f"├── A Record TTL: {Colors.info(str(a_ttl) + 's')}")

        # CNAME (only shown when present — root apex rarely has one)
        if cname_target:
            print(
                f"├── CNAME: {Colors.info(result.domain)} → {Colors.info(cname_target)}"
            )

        print(f"├── TXT Records: {Colors.info(str(len(txt_records)))} observed")

        # SPF
        print(f"├── SPF Policy: {Colors.info(_format_policy_record(spf_record))}")
        print(f"├── SPF Analysis: {Colors.info(_format_spf_analysis(spf_analysis))}")
        if spf_includes:
            print(f"├── SPF Include Chain (depth <= 2):")
            for entry in spf_includes:
                depth = entry.get("depth", 1)
                indent = "│   " + "    " * (depth - 1)
                label = entry.get("domain", "?")
                record = entry.get("record")
                if entry.get("error"):
                    print(f"{indent}├── {label}: {Colors.dim('lookup failed')}")
                elif record:
                    short = record[:72] + "..." if len(record) > 72 else record
                    print(f"{indent}├── {label}: {Colors.dim(short)}")
                else:
                    print(f"{indent}├── {label}: {Colors.dim('no SPF')}")

        # DMARC
        print(f"├── DMARC Policy: {Colors.info(_format_policy_record(dmarc_record))}")
        print(
            f"├── DMARC Status: {Colors.info(_format_dmarc_analysis(dmarc_analysis))}"
        )
        sp = dmarc_analysis.get("subdomain_policy")
        if sp and sp != "not_set":
            print(f"├── DMARC Subdomain (sp=): {Colors.info(str(sp))}")
        rua = dmarc_analysis.get("rua")
        ruf = dmarc_analysis.get("ruf")
        if rua or ruf:
            parts = []
            if rua:
                parts.append(f"rua: {rua}")
            if ruf:
                parts.append(f"ruf: {ruf}")
            print(f"├── DMARC Reporting: {Colors.dim(', '.join(parts))}")

        # DKIM
        print(f"├── DKIM Selectors: {Colors.info(_format_dkim_discovery(dkim))}")

        # CAA — issuewild explicitly separated
        if caa_records_raw:
            issuewild_tags = [r for r in caa_records_raw if r.get("tag") == "issuewild"]
            all_labels = [f"{r.get('tag')} {r.get('value')}" for r in caa_records_raw]
            print(f"├── CAA Policy: {Colors.info(', '.join(all_labels[:4]))}")
            if issuewild_tags:
                wild_vals = ", ".join(r.get("value", "") for r in issuewild_tags)
                print(f"│   ├── issuewild: {Colors.info(wild_vals)}")
            else:
                print(
                    f"│   └── {Colors.dim('no issuewild restriction (wildcard certs unrestricted)')}"
                )
        else:
            print(f"├── CAA Policy: {Colors.dim('not configured')}")

        dnssec_status = (
            "enabled" if dnssec.get("status") == "enabled" else "not detected"
        )
        print(f"├── DNSSEC: {Colors.info(dnssec_status)}")
        print(
            f"├── DNS Config Assessment: {Colors.info(_format_dns_config_assessment(dns_config_assessment))}"
        )
        zone_status = zone_transfer.get("status", "unknown")
        if zone_status == "allowed":
            zone_label = (
                f"allowed via {zone_transfer.get('successful_nameserver', 'unknown')}"
            )
            print(f"├── Zone Transfer: {Colors.error(zone_label)}")
        elif zone_status == "not_allowed":
            print(f"├── Zone Transfer: {Colors.success('not allowed or filtered')}")
        else:
            print(f"├── Zone Transfer: {Colors.dim('not tested')}")
        print(
            f"└── Assessment Findings: {Colors.info(_format_dns_assessment_findings(dns_config_assessment))}"
        )
    else:
        print(f"└── DNS Forensics: {Colors.error('UNAVAILABLE')}")

    _render_dns_history_block(dns_history_result, whois_result, dns_result, cdn_result)


def _render_network_path_section(ctx: Dict[str, Any]) -> None:
    """Render the network path section report section."""
    network_result = ctx["network_result"]

    print(f"\n{Colors.section_header('NETWORK PATH', 50)}")
    if network_result.get("analysis_status") == "abgeschlossen":
        connectivity = network_result.get("connectivity_test", {})
        traceroute = network_result.get("traceroute_data", {})
        enhanced_path = network_result.get("enhanced_network_path", [])
        response_times = (
            connectivity.get("response_times", {})
            if isinstance(connectivity, dict)
            else {}
        )
        ping_time = (
            response_times.get("ping", "Unknown")
            if isinstance(response_times, dict)
            else "Unknown"
        )
        ping_reachable = (
            bool(connectivity.get("ping_reachable"))
            if isinstance(connectivity, dict)
            else False
        )

        if ping_reachable and ping_time != "Unknown":
            print(
                f"├── Connectivity: {Colors.info(f'Ping reachable ({ping_time} latency)')}"
            )
        elif ping_reachable:
            print(f"├── Connectivity: {Colors.info('Ping reachable')}")
        else:
            print(f"├── Connectivity: {Colors.warning('Ping unavailable or filtered')}")
        _display_traceroute_details(traceroute, enhanced_path)
    else:
        failure_type = network_result.get("failure_type")
        if failure_type == "timeout":
            print(f"├── Status: {Colors.warning('TIMEOUT')}")
            print(f"├── Traceroute: {Colors.dim('incomplete')}")
            print(
                f"└── Detail: {Colors.dim('Network analysis exceeded configured timeout')}"
            )
        else:
            print(f"└── Network Path: {Colors.error('UNAVAILABLE')}")


def _render_http_behavior_section(ctx: Dict[str, Any]) -> None:
    """Render the http behavior section report section."""
    http_behavior = ctx["http_behavior"]

    print(f"\n{Colors.section_header('HTTP/S BEHAVIOR', 50)}")
    if (
        http_behavior.get("assessment", "unavailable") == "unavailable"
        and not http_behavior.get("http_status")
        and not http_behavior.get("https_status")
    ):
        print(
            f"└── HTTP/S Behavior: {Colors.dim('not available (connection refused or timeout)')}"
        )
    else:
        # HTTP Status
        http_st = http_behavior.get("http_status")
        if http_st is not None:
            if http_behavior.get("has_redirect"):
                print(
                    f"├── HTTP Status: {Colors.info(str(http_st))} {Colors.dim('HTTPS redirect')}"
                )
            else:
                print(
                    f"├── HTTP Status: {Colors.warning(f'{http_st} OK (no redirect)')}"
                )
        else:
            print(f"├── HTTP Status: {Colors.dim('not reachable')}")

        # HTTPS Status
        https_st = http_behavior.get("https_status")
        if https_st is not None:
            https_color = Colors.success if 200 <= https_st < 300 else Colors.warning
            print(f"├── HTTPS Status: {https_color(f'{https_st} OK')}")
        else:
            print(f"├── HTTPS Status: {Colors.warning('not reachable')}")

        # Server
        server = http_behavior.get("server")
        if server:
            print(f"├── Server: {Colors.info(server)}")

        # X-Frame-Options
        xfo = http_behavior.get("x_frame_options")
        if xfo:
            print(f"├── X-Frame-Options: {Colors.success(xfo)}")
        else:
            print(f"├── X-Frame-Options: {Colors.warning('not set')}")

        # Content-Security-Policy
        csp = http_behavior.get("csp")
        if csp:
            print(f"├── Content-Security-Policy: {Colors.success('present')}")
        else:
            print(f"├── Content-Security-Policy: {Colors.warning('not configured')}")

        # HSTS
        if http_behavior.get("hsts"):
            max_age = http_behavior.get("hsts_max_age")
            inc_sub = http_behavior.get("hsts_include_subdomains", False)
            hsts_parts = []
            if max_age is not None:
                hsts_parts.append(f"max-age={max_age}")
            if inc_sub:
                hsts_parts.append("includeSubDomains")
            hsts_str = "; ".join(hsts_parts) if hsts_parts else "present"
            print(f"├── HSTS: {Colors.success(hsts_str)}")
        else:
            print(f"├── HSTS: {Colors.warning('not configured')}")

        # Redirect Chain
        chain = http_behavior.get("redirect_chain", [])
        if chain:

            def _strip_default_port(url: str) -> str:
                try:
                    from urllib.parse import urlparse, urlunparse

                    p = urlparse(url)
                    if (p.scheme == "https" and p.port == 443) or (
                        p.scheme == "http" and p.port == 80
                    ):
                        return urlunparse(p._replace(netloc=p.hostname))
                except Exception:
                    pass
                return url

            chain_urls = [_strip_default_port(e["url"]) for e in chain if e.get("url")]
            hop_count = len(chain) - 1
            if hop_count < 0:
                hop_count = 0
            chain_str = " -> ".join(chain_urls)
            hop_label = (
                f"({hop_count} hop)" if hop_count == 1 else f"({hop_count} hops)"
            )
            print(
                f"├── Redirect Chain: {Colors.dim(chain_str)} {Colors.dim(hop_label)}"
            )

        # Assessment
        assessment = http_behavior.get("assessment", "unavailable")
        if assessment == "strong":
            print(
                f"└── Assessment: {Colors.success('Strong - HTTPS enforced, HSTS active')}"
            )
        elif assessment == "moderate":
            if not http_behavior.get("hsts"):
                print(
                    f"└── Assessment: {Colors.info('Moderate - HTTPS available, HSTS missing')}"
                )
            else:
                print(
                    f"└── Assessment: {Colors.info('Moderate - HTTPS available, no HTTP redirect')}"
                )
        elif assessment == "weak":
            print(
                f"└── Assessment: {Colors.warning('Weak - HTTP served without redirect to HTTPS')}"
            )
        else:
            print(f"└── Assessment: {Colors.dim('unavailable')}")


def _render_ssl_section(ctx: Dict[str, Any]) -> None:
    """Render the ssl section report section."""
    ssl_result = ctx["ssl_result"]

    print(f"\n{Colors.section_header('SSL / TLS', 50)}")
    if ssl_result.get("analysis_status") == "abgeschlossen":
        if not ssl_result.get("available"):
            err = ssl_result.get("error", "unknown error")
            print(f"└── SSL/TLS: {Colors.dim(f'not available ({err})')}")
        elif ssl_result.get("parse_error"):
            _parse_err = ssl_result.get("parse_error", "")[:80]
            print(
                f"├── TLS Version: {Colors.info(ssl_result.get('tls_version', 'Unknown'))}"
            )
            print(f"└── Certificate: {Colors.warning(f'parse error: {_parse_err}')}")
        else:
            issuer_org = ssl_result.get("issuer_org") or ""
            issuer_cn = ssl_result.get("issuer_cn") or ""
            if issuer_org and issuer_cn and issuer_org != issuer_cn:
                issuer_str = f"{issuer_org} ({issuer_cn})"
            else:
                issuer_str = issuer_org or issuer_cn or "Unknown"

            days = ssl_result.get("days_to_expiry", 0)
            if days < 0:
                expiry_color = Colors.error
            elif days < 14:
                expiry_color = Colors.warning
            elif days < 30:
                expiry_color = Colors.warning
            else:
                expiry_color = Colors.success

            assessment = ssl_result.get("assessment", "")
            if assessment.startswith("INVALID") or assessment.startswith("WARNING"):
                assessment_color = (
                    Colors.error if assessment.startswith("INVALID") else Colors.warning
                )
            else:
                assessment_color = Colors.success

            sans = ssl_result.get("sans", []) or []
            print(f"├── Issuer: {Colors.info(issuer_str)}")
            print(
                f"├── Valid From: {Colors.info(ssl_result.get('valid_from', 'Unknown'))}"
            )
            print(
                f"├── Valid Until: {Colors.info(ssl_result.get('valid_until', 'Unknown'))}"
            )
            print(f"├── Days to Expiry: {expiry_color(f'{days} days')}")
            print(
                f"├── Certificate Type: {Colors.info(ssl_result.get('cert_type', 'Unknown'))}"
            )
            print(
                f"├── TLS Version: {Colors.info(ssl_result.get('tls_version', 'Unknown'))}"
            )
            if sans:
                san_limit = 10
                print(f"├── Subject Alternative Names ({len(sans)} total):")
                for san in sans[:san_limit]:
                    print(f"│   ├── {san}")
                if len(sans) > san_limit:
                    print(f"│   └── {Colors.dim(f'... +{len(sans) - san_limit} more')}")
            print(f"└── Assessment: {assessment_color(assessment)}")
    else:
        print(f"└── SSL/TLS: {Colors.dim('not analyzed')}")


def _render_infrastructure_section(ctx: Dict[str, Any]) -> None:
    """Render the infrastructure section report section."""
    cdn_result = ctx["cdn_result"]

    print(f"\n{Colors.section_header('INFRASTRUCTURE', 50)}")
    if cdn_result.get("analysis_status") == "abgeschlossen":
        provider = cdn_result.get("provider_name", "Unknown")
        provider_type = cdn_result.get("provider_type") or cdn_result.get(
            "infrastructure_type", "Unknown"
        )
        protection = str(cdn_result.get("protection_level", "Unknown")).title()
        location = (
            cdn_result.get("location")
            or cdn_result.get("geolocation")
            or cdn_result.get("geo_data")
            or {}
        )

        if location and isinstance(location, dict):
            country = location.get("country", "Unknown")
            city = location.get("city", "Unknown")
        else:
            country = cdn_result.get("country", "Unknown")
            city = cdn_result.get("city", "Unknown")

        edge_summary, waf_summary = _get_edge_protection_summary(cdn_result)
        print(
            f"├── Infrastructure: {Colors.info(provider)} ({_format_provider_type(provider_type)})"
        )
        print(f"├── Protection Level: {Colors.info(protection)}")
        print(f"├── Edge Protection: {Colors.info(edge_summary)}")
        print(f"├── WAF Assessment: {Colors.info(waf_summary)}")
        print(f"└── Location: {Colors.info(f'{city}, {country}')}")
    else:
        print(f"└── CDN / Hosting: {Colors.error('UNAVAILABLE')}")


def _render_attack_surface_section(ctx: Dict[str, Any]) -> None:
    """Render the attack surface section report section."""
    result = ctx["result"]
    risk_color = ctx["risk_color"]
    subdomain_result = ctx["subdomain_result"]
    wildcard_detected = ctx["wildcard_detected"]

    print(f"\n{Colors.section_header('ATTACK SURFACE', 50)}")
    if subdomain_result.get("analysis_status") == "abgeschlossen":
        total_assets = result.total_assets_found
        sensitive_assets_count = result.sensitive_assets_found
        asset_categories = _get_subdomain_categories(subdomain_result)
        discovered_assets = subdomain_result.get("discovered_assets", [])
        sensitive_lookup = _build_sensitive_asset_lookup(subdomain_result)

        total_label = (
            "DNS-resolved Candidates" if wildcard_detected else "Total Subdomains"
        )
        total_suffix = (
            "identified via DNS wildcard" if wildcard_detected else "discovered"
        )
        print(
            f"├── {total_label}: {Colors.highlight(str(total_assets))} {total_suffix}"
        )
        sensitive_label = (
            "Sensitive Candidates" if wildcard_detected else "Sensitive Assets"
        )
        sensitive_suffix = (
            "matched sensitive patterns" if wildcard_detected else "identified"
        )
        print(
            f"├── {sensitive_label}: {Colors.warning(str(sensitive_assets_count))} {sensitive_suffix}"
        )

        if asset_categories:
            for category, assets in asset_categories.items():
                if assets and len(assets) > 0:
                    if category.lower() in ["admin", "api", "dev"]:
                        if wildcard_detected:
                            print(
                                f"├── {_format_category_name(category)}: {Colors.dim(str(len(assets)))} (candidates)"
                            )
                        else:
                            print(
                                f"├── {_format_category_name(category)}: {Colors.error(str(len(assets)))} (SENSITIVE)"
                            )
                    else:
                        print(
                            f"├── {_format_category_name(category)}: {Colors.info(str(len(assets)))}"
                        )

        sensitive_assets = subdomain_result.get("sensitive_assets", []) or []
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sensitive_assets = sorted(
            sensitive_assets,
            key=lambda item: (
                risk_order.get(str(item.get("risk_level", "")).upper(), 99),
                str((item.get("asset") or {}).get("full_domain", "")),
            ),
        )

        if wildcard_detected:
            if discovered_assets:
                print(f"├── Example Candidates:")
                for asset in sorted(
                    discovered_assets,
                    key=lambda item: item.get("full_domain", item.get("subdomain", "")),
                )[:5]:
                    full_domain = asset.get("full_domain") or asset.get(
                        "subdomain", "unknown"
                    )
                    sensitive_meta = sensitive_lookup.get(full_domain, {})
                    risk_level = str(sensitive_meta.get("risk_level", "")).upper()
                    risk_reason = sensitive_meta.get("risk_reason")
                    line = full_domain
                    if risk_level:
                        line += f" [{risk_level}]"
                    if risk_reason:
                        line += f" - {risk_reason}"
                    print(f"│   ├── {line}")
            print(
                f"├── Validation Note: {Colors.warning('Wildcard DNS is enabled; DNS resolution alone does not prove host existence')}"
            )
            print(
                f"└── DNS Config: {Colors.info('WILDCARD ENABLED')} (Enumeration resistance)"
            )
        else:
            if sensitive_assets:
                print(f"├── Findings:")
                for asset in sensitive_assets[:3]:
                    asset_data = (
                        asset.get("asset", {}) if isinstance(asset, dict) else {}
                    )
                    subdomain = asset_data.get("full_domain") or asset_data.get(
                        "subdomain", "unknown"
                    )
                    risk = str(asset.get("risk_level", "unknown")).upper()
                    reason = asset.get("risk_reason", "unknown")
                    risk_color = Colors.error if risk == "CRITICAL" else Colors.warning
                    print(f"│   ├── {risk_color(subdomain)} [{risk}] - {reason}")

            if discovered_assets:
                print(f"├── Discovered Subdomains:")
                for asset in sorted(
                    discovered_assets,
                    key=lambda item: item.get("full_domain", item.get("subdomain", "")),
                ):
                    full_domain = asset.get("full_domain") or asset.get(
                        "subdomain", "unknown"
                    )
                    sensitive_meta = sensitive_lookup.get(full_domain, {})
                    risk_level = str(sensitive_meta.get("risk_level", "")).upper()
                    risk_reason = sensitive_meta.get("risk_reason")
                    line = full_domain
                    if risk_level:
                        line += f" [{risk_level}]"
                    if risk_reason:
                        line += f" - {risk_reason}"
                    print(f"│   ├── {line}")

            print(f"└── DNS Config: {Colors.success('Standard Resolution')}")
    else:
        print(f"├── Subdomain Analysis: {Colors.error('FAILED')}")
        print(f"└── Unable to assess attack surface")


def _render_threat_intelligence_section(ctx: Dict[str, Any]) -> None:
    """Render the threat intelligence section report section."""
    vt_result = ctx["vt_result"]
    abuse_result = ctx["abuse_result"]
    st_result = ctx["st_result"]

    print(f"\n{Colors.section_header('THREAT INTELLIGENCE', 50)}")
    _render_virustotal_status(vt_result)
    _render_abuseipdb_status(abuse_result)
    _render_securitytrails_status(st_result, unavailable_branch="└──")


def _render_ip_domain_history_section(ctx: Dict[str, Any]) -> None:
    """Render the ip domain history section report section."""
    dns_result = ctx["dns_result"]
    dns_history_result = ctx["dns_history_result"]
    cdn_result = ctx["cdn_result"]
    ip_history_result = ctx["ip_history_result"]

    print(f"\n{Colors.section_header('IP & DOMAIN HISTORY', 50)}")
    current_ip = dns_result.get("ipv4")
    is_cdn = cdn_result.get("infrastructure_type") == "cdn"
    cdn_name = cdn_result.get("provider_name", "CDN")

    if current_ip:
        print(f"├── Current IP: {Colors.format_ip(current_ip)}")

    # --- Domain IP History (from dedicated a_history bucket, all A events) ---
    a_events = dns_history_result.get("a_history", []) or []
    ip_dates: Dict[str, str] = {}
    for event in a_events:
        date_val = event.get("date") or "unknown"
        for ip_val in event.get("new", []):
            ip_str = str(ip_val).strip()
            if ip_str and (ip_str not in ip_dates or date_val > ip_dates[ip_str]):
                ip_dates[ip_str] = date_val
    if ip_dates:
        sorted_ips = sorted(ip_dates.items(), key=lambda x: x[1], reverse=True)
        print(f"├── Domain IP History ({len(sorted_ips)} unique IPs observed):")
        for ip_val, date_str in sorted_ips[:5]:
            date_short = date_str[:10] if date_str != "unknown" else "unknown"
            marker = " (current)" if ip_val == current_ip else ""
            print(
                f"│   ├── {date_short}: {Colors.format_ip(ip_val)}{Colors.dim(marker)}"
            )
        if len(sorted_ips) > 5:
            print(f"│   └── {Colors.dim(f'... and {len(sorted_ips) - 5} more')}")
    else:
        print(f"├── Domain IP History: {Colors.dim('no historical data')}")

    # --- Reverse IP Lookup ---
    if ip_history_result.get("analysis_status") == "abgeschlossen" and current_ip:
        total_co_hosted = ip_history_result.get("total_co_hosted", 0)
        top_co_hosted = ip_history_result.get("top_co_hosted", []) or []
        display_limit = 5 if is_cdn else 20
        if total_co_hosted > display_limit:
            print(
                f"├── Reverse IP ({Colors.format_ip(current_ip)}, showing top {display_limit} of {total_co_hosted} total):"
            )
        elif total_co_hosted > 0:
            print(
                f"├── Reverse IP ({Colors.format_ip(current_ip)}, {total_co_hosted} total):"
            )
        else:
            print(f"├── Reverse IP ({Colors.format_ip(current_ip)}):")

        if is_cdn:
            print(
                f"│   ├── {Colors.warning(f'CDN infrastructure ({cdn_name}) — shared IPs serve many domains')}"
            )

        if total_co_hosted > 0:
            for entry in top_co_hosted[:display_limit]:
                name = entry.get("domain", "")
                ls = entry.get("last_seen", "")
                src = entry.get("source", "")
                parts = []
                if src:
                    parts.append(src)
                if ls:
                    parts.append(ls)
                suffix = f" ({', '.join(parts)})" if parts else ""
                print(f"│   ├── {name}{Colors.dim(suffix)}")
            if total_co_hosted > display_limit:
                print(
                    f"│   ├── {Colors.dim(f'... +{total_co_hosted - display_limit} more')}"
                )
            print(
                f"│   └── Total unique co-hosted: {Colors.info(str(total_co_hosted))}"
            )
        else:
            print(f"│   └── {Colors.dim('No co-hosted domains found')}")

        # Infrastructure classification
        if is_cdn:
            infra_label, infra_color = "CDN shared infrastructure", Colors.info
        elif total_co_hosted <= 2:
            infra_label, infra_color = "dedicated / private", Colors.success
        elif total_co_hosted > 50:
            infra_label, infra_color = "shared hosting (high density)", Colors.warning
        elif total_co_hosted > 10:
            infra_label, infra_color = "shared hosting", Colors.info
        else:
            infra_label, infra_color = "small shared / VPS", Colors.success
        print(f"└── Assessment: {infra_color(infra_label)}")
    else:
        print(f"├── Reverse IP: {Colors.dim('not analyzed')}")
        print(f"└── Assessment: {Colors.dim('unavailable')}")


def _render_risk_assessment_section(ctx: Dict[str, Any]) -> None:
    """Render the risk assessment section report section."""
    overall_risk = ctx["overall_risk"]
    risk_factors = ctx["risk_factors"]
    recommendation = ctx["recommendation"]
    risk_color = ctx["risk_color"]

    print(f"\n{Colors.section_header('RISK ASSESSMENT', 50)}")
    _render_risk_assessment_values(
        overall_risk, risk_factors, recommendation, risk_color
    )


def _render_execution_section(ctx: Dict[str, Any]) -> None:
    """Render the execution section report section."""
    result = ctx["result"]
    vt_result = ctx["vt_result"]
    abuse_result = ctx["abuse_result"]
    st_result = ctx["st_result"]
    whois_result = ctx["whois_result"]
    dns_history_result = ctx["dns_history_result"]
    ip_history_result = ctx["ip_history_result"]
    successful_modules = ctx["successful_modules"]
    failed_modules = ctx["failed_modules"]
    timeout_modules = ctx["timeout_modules"]

    print(f"\n{Colors.section_header('EXECUTION', 50)}")
    api_statuses = _collect_live_api_statuses(
        vt_result,
        whois_result,
        dns_history_result,
        st_result=st_result,
        abuse_result=abuse_result,
        ip_history_result=ip_history_result,
    )
    _render_execution_values(
        result,
        successful_modules,
        failed_modules,
        timeout_modules,
        api_statuses,
    )


def _render_historical_report(ctx: Dict[str, Any]) -> None:
    """Render the compact historical-analysis path."""
    _display_historical_blocks(
        ctx["result"],
        ctx["dns_history_result"],
        ctx["vt_result"],
        ctx["st_result"],
        ctx["dns_result"],
        ctx["whois_result"],
        ctx["cdn_result"],
        ctx["hist_ip"],
        ctx["hist_date"],
        ctx["overall_risk"],
        ctx["risk_factors"],
        ctx["recommendation"],
        ctx["risk_color"],
        ctx["successful_modules"],
        ctx["failed_modules"],
        ctx["timeout_modules"],
    )

def _render_report_footer() -> None:
    """Render the final report footer."""
    print(f"\n{Colors.investigation_separator(80)}")
    print(f"FORENSIC ANALYSIS COMPLETE")
    print(Colors.investigation_separator(80))



def display_forensic_summary(result: UnifiedResult) -> None:
    """
    Display forensic analysis results with a concise summary first and full details after.
    """
    ctx = _build_summary_context(result)

    _render_report_header(ctx)
    _render_summary_section(ctx)
    _render_target_section(ctx)

    if ctx["is_historical"]:
        _render_historical_report(ctx)
        return

    _render_geo_asn_section(ctx)
    _render_whois_section(ctx)
    _render_dns_forensics_section(ctx)
    _render_network_path_section(ctx)
    _render_http_behavior_section(ctx)
    _render_ssl_section(ctx)
    _render_infrastructure_section(ctx)
    _render_attack_surface_section(ctx)
    _render_threat_intelligence_section(ctx)
    _render_ip_domain_history_section(ctx)
    _render_risk_assessment_section(ctx)
    _render_execution_section(ctx)
    _render_report_footer()
