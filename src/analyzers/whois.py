# whois.py
# Vollständige, produktionsreife WHOIS-Integration für den Domain Forensic Analyzer
# MIT License – Copyright (c) 2025 herdacas

import logging
from datetime import datetime
from typing import Any, Dict, Optional

import requests
import whois  # python-whois
from dotenv import load_dotenv

from ..utils.api_key_reader import APIKeyReader

logger = logging.getLogger("whois_module")
logger.addHandler(logging.NullHandler())
logger.propagate = False

# --------------------------------------------------------------------------- #
# Laden der Umgebungsvariablen (.env)
# --------------------------------------------------------------------------- #
load_dotenv()


WHOISXML_API_KEY = APIKeyReader("WHOISXML_API_KEY", "whoisxml").get()

# --------------------------------------------------------------------------- #
# Registries known to redact WHOIS fields by policy
# --------------------------------------------------------------------------- #
REDACTING_REGISTRIES: Dict[str, str] = {
    '.de': 'DENIC',
    '.at': 'nic.at',
    '.ch': 'SWITCH',
    '.nl': 'SIDN',
    '.fi': 'Traficom',
    '.no': 'Norid',
    '.se': 'IIS',
    '.dk': 'DK Hostmaster',
}


def _detect_registry_policy(domain: str) -> Optional[str]:
    """Return registry name if TLD is known to redact WHOIS data by policy."""
    tld = '.' + domain.strip().lower().rsplit('.', 1)[-1]
    return REDACTING_REGISTRIES.get(tld)


# --------------------------------------------------------------------------- #
# Privacy proxy / WHOIS shield detection
# --------------------------------------------------------------------------- #
_PRIVACY_PROXY_SIGNALS: list = [
    ('WhoisGuard',                  ['whoisguard']),
    ('Domains By Proxy',            ['domainsbyproxy']),
    ('PrivacyProtect',              ['privacyprotect']),
    ('Withheld for Privacy',        ['withheld for privacy', 'withheldforprivacy']),
    ('Perfect Privacy',             ['perfect privacy', 'perfectprivacy']),
    ('Identity Protection Service', ['identity protect']),
    ('Contact Privacy',             ['contact privacy']),
    ('Data Protected',              ['data protected']),
    ('Redacted for Privacy',        ['redacted for privacy']),
    ('Privacy Guardian',            ['privacyguardian']),
    ('Anonymize.com',               ['anonymize.com']),
    ('Whois Privacy Protection',    ['whois privacy protection', 'whois privacy']),
]


def _detect_privacy_proxy(registrar: Optional[str], registrant_email: Optional[str],
                           registrant_name: Optional[str] = None) -> Optional[str]:
    """Return proxy service name if a known privacy proxy / WHOIS shield is detected."""
    haystack = ' '.join(filter(None, [
        str(registrar or '').lower(),
        str(registrant_email or '').lower(),
        str(registrant_name or '').lower(),
    ]))
    for proxy_name, keywords in _PRIVACY_PROXY_SIGNALS:
        if any(kw in haystack for kw in keywords):
            return proxy_name
    return None


# --------------------------------------------------------------------------- #
# Hilfsfunktion: Datums-Normalisierung (python-whois liefert unterschiedliche Typen)
# --------------------------------------------------------------------------- #
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


def _extract_whoisxml_nameservers(record: Dict[str, Any], registry_data: Dict[str, Any]) -> list:
    """Extract nameservers from all WhoisXML locations seen in API responses."""
    nameservers = []

    for source in (record.get("nameServers"), registry_data.get("nameServers")):
        if not source:
            continue
        if isinstance(source, dict):
            candidates = source.get("hostNames") or source.get("hostnames") or source.get("hosts")
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

# --------------------------------------------------------------------------- #
# 1. Kostenlose lokale WHOIS-Abfrage (Fallback)
# --------------------------------------------------------------------------- #
def get_whois_local(domain: str) -> Dict[str, Any]:
    """
    WHOIS-Abfrage mit python-whois (keine API-Key nötig).
    Sehr zuverlässig für gängige TLDs.
    """
    logger.info(f"WHOIS (lokal) – Abfrage für {domain}")
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
            "privacy_proxy": _detect_privacy_proxy(w.registrar, w.get("email"), w.get("name")),
            "raw_text": str(w)
        }
        logger.debug(f"WHOIS lokal erfolgreich für {domain}")
        return result

    except Exception as e:
        logger.warning(f"WHOIS lokal fehlgeschlagen für {domain}: {str(e)}")
        return {
            "source": "python-whois (lokal)",
            "domain": domain.lower(),
            "error": str(e)
        }

# --------------------------------------------------------------------------- #
# 2. Professionelle API-Abfrage via WhoisXML API (empfohlen)
# --------------------------------------------------------------------------- #
def get_whois_xmlapi(domain: str) -> Dict[str, Any]:
    """
    Hochwertige WHOIS-Abfrage inkl. historischer Daten über WhoisXML API.
    Kostenloser Plan: 500 Abfragen/Monat.
    """
    if not WHOISXML_API_KEY or WHOISXML_API_KEY.strip() == "" or "your_key" in WHOISXML_API_KEY:
        logger.warning("WHOISXML_API_KEY fehlt oder ungültig → wird übersprungen")
        return {"error": "WHOISXML_API_KEY nicht konfiguriert"}

    url = "https://whoisxmlapi.com/whoisserver/WhoisService"
    params = {
        "apiKey": WHOISXML_API_KEY,
        "domainName": domain,
        "outputFormat": "JSON",
        "da": "1"  # inkl. Registrant-Daten, wo verfügbar
    }

    logger.info(f"WHOIS (WhoisXML API) – Abfrage für {domain}")
    try:
        response = requests.get(url, params=params, timeout=20)
        response.raise_for_status()
        data = response.json()

        if "ErrorMessage" in data:
            err = data["ErrorMessage"]["msg"]
            logger.warning(f"WhoisXML API Fehler für {domain}: {err}")
            return {"source": "WhoisXML API", "error": err}

        record = data.get("WhoisRecord", {})

        registrant = record.get("registrant", {}) or {}
        registry_data = record.get("registryData", {})

        result = {
            "source": "WhoisXML API",
            "domain": domain.lower(),
            "registrar": record.get("registrarName"),
            "creation_date": record.get("createdDate") or registry_data.get("createdDate"),
            "expiration_date": record.get("expiresDate") or registry_data.get("expiresDate"),
            "updated_date": record.get("updatedDate") or registry_data.get("updatedDate"),
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
            "raw_json": data
        }
        logger.debug(f"WHOIS WhoisXML API erfolgreich für {domain}")
        return result

    except requests.exceptions.RequestException as e:
        logger.warning(f"WHOIS WhoisXML API Request-Fehler für {domain}: {str(e)}")
        return {"source": "WhoisXML API", "error": str(e)}
    except Exception as e:
        logger.error(f"Unerwarteter Fehler bei WhoisXML API für {domain}: {str(e)}")
        return {"source": "WhoisXML API", "error": str(e)}

# --------------------------------------------------------------------------- #
# 3. Kombinierte Hauptfunktion mit intelligentem Fallback
# --------------------------------------------------------------------------- #
def get_whois(domain: str) -> Dict[str, Any]:
    """
    Öffentliche Hauptfunktion – liefert immer das beste verfügbare Ergebnis.
    Reihenfolge:
      1. WhoisXML API (wenn Key vorhanden)
      2. python-whois als Fallback
    """
    domain = domain.strip().lower()

    # 1. Versuch: WhoisXML API (besser, aktueller, mehr Details)
    if WHOISXML_API_KEY and WHOISXML_API_KEY.strip():
        result = get_whois_xmlapi(domain)
        if "error" not in result or "rate limit" in str(result.get("error", "")).lower():
            logger.info(f"WHOIS erfolgreich via WhoisXML API für {domain}")
            return result

    # 2. Fallback: Lokale python-whois-Abfrage
    logger.info(f"WHOIS Fallback auf python-whois für {domain}")
    fallback = get_whois_local(domain)
    return fallback
