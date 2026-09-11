# whois.py — WHOIS integration for Domain Forensic Analyzer
# MIT License – Copyright (c) 2025 herdacas
"""WHOIS integration for Domain Forensic Analyzer."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
import whois  # python-whois
from dotenv import load_dotenv

from ..utils.api_key_reader import APIKeyReader

logger = logging.getLogger("whois_module")
logger.addHandler(logging.NullHandler())
logger.propagate = False

load_dotenv()

WHOISXML_API_KEY = APIKeyReader("WHOISXML_API_KEY", "whoisxml").get()

# Registries known to redact WHOIS fields by policy
REDACTING_REGISTRIES: Dict[str, str] = {
    ".de": "DENIC",
    ".at": "nic.at",
    ".ch": "SWITCH",
    ".nl": "SIDN",
    ".fi": "Traficom",
    ".no": "Norid",
    ".se": "IIS",
    ".dk": "DK Hostmaster",
}


def _detect_registry_policy(domain: str) -> Optional[str]:
    """Return registry name if TLD is known to redact WHOIS data by policy."""
    tld = "." + domain.strip().lower().rsplit(".", 1)[-1]
    return REDACTING_REGISTRIES.get(tld)


# --------------------------------------------------------------------------- #
# Privacy proxy / WHOIS shield detection
# --------------------------------------------------------------------------- #
_PRIVACY_PROXY_SIGNALS: list = [
    ("WhoisGuard", ["whoisguard"]),
    ("Domains By Proxy", ["domainsbyproxy"]),
    ("PrivacyProtect", ["privacyprotect"]),
    ("Withheld for Privacy", ["withheld for privacy", "withheldforprivacy"]),
    ("Perfect Privacy", ["perfect privacy", "perfectprivacy"]),
    ("Identity Protection Service", ["identity protect"]),
    ("Contact Privacy", ["contact privacy"]),
    ("Data Protected", ["data protected"]),
    ("Redacted for Privacy", ["redacted for privacy"]),
    ("Privacy Guardian", ["privacyguardian"]),
    ("Anonymize.com", ["anonymize.com"]),
    ("Whois Privacy Protection", ["whois privacy protection", "whois privacy"]),
]


def _detect_privacy_proxy(
    registrar: Optional[str],
    registrant_email: Optional[str],
    registrant_name: Optional[str] = None,
) -> Optional[str]:
    """Return proxy service name if a known privacy proxy / WHOIS shield is detected."""
    haystack = " ".join(
        filter(
            None,
            [
                str(registrar or "").lower(),
                str(registrant_email or "").lower(),
                str(registrant_name or "").lower(),
            ],
        )
    )
    for proxy_name, keywords in _PRIVACY_PROXY_SIGNALS:
        if any(kw in haystack for kw in keywords):
            return proxy_name
    return None


def _normalize_date(date_obj: Any) -> Optional[str]:
    if not date_obj:
        return None
    if isinstance(date_obj, list):
        date_obj = date_obj[0]
    if isinstance(date_obj, datetime):
        return date_obj.isoformat()
    if isinstance(date_obj, str):
        return date_obj
    return str(date_obj)


def _extract_whoisxml_nameservers(
    record: Dict[str, Any], registry_data: Dict[str, Any]
) -> list:
    """Extract nameservers from all WhoisXML locations seen in API responses."""
    nameservers: List[str] = []

    for source in (record.get("nameServers"), registry_data.get("nameServers")):
        if not source:
            continue
        if isinstance(source, dict):
            candidates = (
                source.get("hostNames")
                or source.get("hostnames")
                or source.get("hosts")
            )
        else:
            candidates = source

        if isinstance(candidates, str):
            candidates = [candidates]
        if not isinstance(candidates, list):
            continue

        for candidate in candidates:
            text = str(candidate).strip().rstrip(".")
            if text and text.lower() not in {item.lower() for item in nameservers}:
                nameservers.append(text)

    return nameservers


def get_whois_local(domain: str) -> Dict[str, Any]:
    """Query WHOIS via python-whois (no API key required). Used as fallback."""
    logger.info("WHOIS (lokal) - Abfrage fuer %s", domain)
    try:
        w = whois.whois(domain)

        result = {
            "source": "python-whois (lokal)",
            "domain": domain.lower(),
            "registrar": w.registrar,
            "creation_date": _normalize_date(w.creation_date),
            "expiration_date": _normalize_date(w.expiration_date),
            "updated_date": _normalize_date(w.updated_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "registrant_name": w.get("name"),
            "registrant_organization": w.get("org"),
            "registrant_country": w.get("country"),
            "registrant_email": w.get("email"),
            "registry_policy": _detect_registry_policy(domain),
            "privacy_proxy": _detect_privacy_proxy(
                w.registrar, w.get("email"), w.get("name")
            ),
            "raw_text": str(w),
        }
        logger.debug("WHOIS lokal erfolgreich fuer %s", domain)
        return result

    except Exception as e:
        logger.warning("WHOIS lokal fehlgeschlagen fuer %s: %s", domain, e)
        return {
            "source": "python-whois (lokal)",
            "domain": domain.lower(),
            "error": str(e),
        }


def get_whois_xmlapi(domain: str) -> Dict[str, Any]:
    """Query WHOIS via WhoisXML API (500 req/month free). Preferred over local fallback."""
    if (
        not WHOISXML_API_KEY
        or WHOISXML_API_KEY.strip() == ""
        or "your_key" in WHOISXML_API_KEY
    ):
        logger.warning("WHOISXML_API_KEY fehlt oder ungültig → wird übersprungen")
        return {"error": "WHOISXML_API_KEY nicht konfiguriert"}

    url = "https://whoisxmlapi.com/whoisserver/WhoisService"
    params = {
        "apiKey": WHOISXML_API_KEY,
        "domainName": domain,
        "outputFormat": "JSON",
        "da": "1",  # include registrant data where available
    }

    logger.info("WHOIS (WhoisXML API) - Abfrage fuer %s", domain)
    try:
        response = requests.get(url, params=params, timeout=20)
        response.raise_for_status()
        data = response.json()

        if "ErrorMessage" in data:
            err = data["ErrorMessage"]["msg"]
            logger.warning("WhoisXML API Fehler fuer %s: %s", domain, err)
            return {"source": "WhoisXML API", "error": err}

        record = data.get("WhoisRecord", {})

        registrant = record.get("registrant", {}) or {}
        registry_data = record.get("registryData", {})

        result = {
            "source": "WhoisXML API",
            "domain": domain.lower(),
            "registrar": record.get("registrarName"),
            "creation_date": record.get("createdDate")
            or registry_data.get("createdDate"),
            "expiration_date": record.get("expiresDate")
            or registry_data.get("expiresDate"),
            "updated_date": record.get("updatedDate")
            or registry_data.get("updatedDate"),
            "name_servers": _extract_whoisxml_nameservers(record, registry_data),
            "status": record.get("status") or registry_data.get("status"),
            "registrant_name": registrant.get("name"),
            "registrant_organization": registrant.get("organization"),
            "registrant_country": registrant.get("country"),
            "registrant_email": registrant.get("email") or record.get("contactEmail"),
            "administrative_contact": record.get("administrativeContact"),
            "technical_contact": record.get("technicalContact"),
            "audit_created_date": record.get("audit", {}).get("createdDate"),
            "audit_updated_date": record.get("audit", {}).get("updatedDate"),
            "historical_available": bool(record.get("dataHistory")),
            "registry_policy": _detect_registry_policy(domain),
            "privacy_proxy": _detect_privacy_proxy(
                record.get("registrarName"),
                registrant.get("email") or record.get("contactEmail"),
                registrant.get("name"),
            ),
            "raw_json": data,
        }
        logger.debug("WHOIS WhoisXML API erfolgreich fuer %s", domain)
        return result

    except requests.exceptions.RequestException as e:
        logger.warning("WHOIS WhoisXML API Request-Fehler fuer %s: %s", domain, e)
        return {"source": "WhoisXML API", "error": str(e)}
    except Exception as e:
        logger.error("Unerwarteter Fehler bei WhoisXML API fuer %s: %s", domain, e)
        return {"source": "WhoisXML API", "error": str(e)}


def get_whois(domain: str) -> Dict[str, Any]:
    """Public entry point — returns best available WHOIS result (API first, local fallback)."""
    domain = domain.strip().lower()

    if WHOISXML_API_KEY and WHOISXML_API_KEY.strip():
        result = get_whois_xmlapi(domain)
        if "error" not in result or "rate limit" in str(result.get("error", "")).lower():
            logger.info("WHOIS via WhoisXML API for %s", domain)
            return result

    logger.info("WHOIS fallback to python-whois for %s", domain)
    return get_whois_local(domain)
