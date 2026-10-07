"""Shared heuristic domain risk assessment for JSON and terminal reports."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Tuple

if TYPE_CHECKING:
    from src.core.result_aggregator import UnifiedResult


def assess_domain_risk(result: "UnifiedResult") -> Tuple[str, List[str], str]:
    """Compute a concise overall risk summary for display."""
    live_results = {name: data for name, data in result.results.items()
                    if data.get("analysis_status") == "abgeschlossen"}
    vt_result = live_results.get("virustotal", {})
    abuse_result = live_results.get("abuseipdb", {})
    subdomain_result = live_results.get("subdomain", {})
    whois_result = live_results.get("whois", {})
    ssl_result = live_results.get("ssl", {})
    network_result = live_results.get("network", {})
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
                risk_factors.append(f"whois: Newly registered domain ({age_days} days old)")
                overall_risk = "HIGH"
            elif age_days < 90:
                risk_factors.append(f"whois: Recently registered domain ({age_days} days old)")
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
                f"subdomain: Excessive attack surface ({result.sensitive_assets_found} sensitive assets)"
            )
            overall_risk = "HIGH"
        elif result.sensitive_assets_found >= 10:
            risk_factors.append(
                f"subdomain: Large attack surface ({result.sensitive_assets_found} sensitive assets)"
            )
            if overall_risk == "LOW":
                overall_risk = "MEDIUM"

    malicious_detections = vt_result.get("threat_analysis", {}).get(
        "malicious_detections", 0
    )
    if malicious_detections >= 3:
        risk_factors.append(
            f"virustotal: Domain flagged as malicious by {malicious_detections} security vendors"
        )
        overall_risk = "HIGH"
    elif malicious_detections > 0:
        risk_factors.append(
            f"virustotal: Limited malicious detections at VirusTotal ({malicious_detections} vendors)"
        )
        if overall_risk == "LOW":
            overall_risk = "MEDIUM"

    abuse_confidence = abuse_result.get("abuse_confidence", 0)
    if abuse_confidence > 50:
        risk_factors.append(f"abuseipdb: High IP abuse confidence ({abuse_confidence}%)")
        if overall_risk != "CRITICAL":
            overall_risk = "HIGH"
    elif abuse_confidence > 25:
        risk_factors.append(f"abuseipdb: Moderate IP abuse reports ({abuse_confidence}%)")
        if overall_risk == "LOW":
            overall_risk = "MEDIUM"

    # SSL/TLS certificate risk checks
    if ssl_result.get("available"):
        days_to_expiry = ssl_result.get("days_to_expiry")
        if days_to_expiry is not None:
            if days_to_expiry < 0:
                risk_factors.append(
                    f"ssl: Certificate expired {abs(days_to_expiry)} days ago"
                )
                if overall_risk not in ("CRITICAL", "HIGH"):
                    overall_risk = "HIGH"
            elif days_to_expiry < 14:
                risk_factors.append(f"ssl: Certificate expiring in {days_to_expiry} days")
                if overall_risk not in ("CRITICAL", "HIGH"):
                    overall_risk = "HIGH"
            elif days_to_expiry < 30:
                risk_factors.append("ssl: Certificate expiring soon")
                if overall_risk == "LOW":
                    overall_risk = "MEDIUM"
        if ssl_result.get("self_signed"):
            risk_factors.append("ssl: Self-signed certificate detected")
            if overall_risk == "LOW":
                overall_risk = "MEDIUM"
        tls_ver = ssl_result.get("tls_version", "")
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            risk_factors.append(f"ssl: TLS 1.3 not supported ({tls_ver} in use)")

    # HTTP/S behavior risk checks
    if http_behavior:
        https_reachable = http_behavior.get("https_status") is not None
        if (
            https_reachable
            and not http_behavior.get("has_redirect")
            and http_behavior.get("http_status") is not None
        ):
            risk_factors.append("network: HTTP served without redirect to HTTPS")
        if https_reachable and not http_behavior.get("hsts"):
            risk_factors.append("network: HSTS not configured")

    if result.critical_assets_count:
        risk_factors.append(f"subdomain: {result.critical_assets_count} critical asset candidates")
        overall_risk = "HIGH"
    if result.infrastructure and result.infrastructure.protection_level == "minimal":
        risk_factors.append("cdn: Minimal infrastructure protection")
    if not live_results:
        return "UNKNOWN", [], "INSUFFICIENT DATA - No completed live modules"

    if overall_risk == "CRITICAL":
        recommendation = "LIKELY MALICIOUS - Multiple high-confidence indicators"
    elif overall_risk == "HIGH":
        recommendation = "ELEVATED RISK - Further validation recommended"
    elif overall_risk == "MEDIUM":
        recommendation = "REVIEW REQUIRED - Mixed or limited risk signals"
    else:
        recommendation = "NO MALICIOUS INDICATORS IN AVAILABLE DATA - Review source coverage"

    return overall_risk, risk_factors, recommendation

