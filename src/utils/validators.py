"""
Domain Validation Utilities
Eingabe-Validierung und Domain-Parsing fuer forensische Domain-Analyse
"""

import re
from typing import Dict, List, Optional


class DomainValidator:
    """
    Professionelle Domain-Validierung fuer forensische Analysen

    Implementiert RFC-konforme Domain-Validierung und bietet erweiterte
    Parsing-Funktionen fuer forensische Domain-Untersuchungen.
    """

    # RFC-konforme Domain-Regex (vereinfacht aber robust)
    DOMAIN_PATTERN = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"

    # Top-Level-Domains fuer erweiterte Validierung
    COMMON_TLDS = {
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "int",
        "de",
        "uk",
        "fr",
        "jp",
        "au",
        "ca",
        "ru",
        "cn",
        "in",
        "br",
        "mx",
        "it",
        "es",
        "nl",
    }

    # RFC 2606 / RFC 6761 reserved TLDs — guaranteed non-operational in public DNS
    RESERVED_TLDS = {"invalid", "local", "test", "localhost", "example"}

    # Known file extensions that are NOT valid ccTLDs.
    # .sh (Saint Helena) and .md (Moldova) are omitted — they are real TLDs.
    _FILE_EXTENSIONS = frozenset(
        {
            "txt",
            "pdf",
            "csv",
            "json",
            "log",
            "py",
            "xlsx",
            "docx",
            "xml",
            "yaml",
            "yml",
            "ini",
            "cfg",
            "bat",
            "exe",
        }
    )

    # Compound second-level ccTLDs where apex is SLD.2ndLevel.ccTLD (3 labels).
    # Includes generic commercial namespaces (co.uk, com.au) and government /
    # institutional registry namespaces (gouv.fr, gob.es, gov.au, ac.jp …).
    # For namespace TLDs the organization is one label deeper than the namespace,
    # so ssi.gouv.fr, anssi.gouv.fr etc. must NOT be stripped to gouv.fr.
    COMPOUND_TLDS = {
        # Generic commercial / organisational
        "co.uk",
        "co.jp",
        "co.kr",
        "co.in",
        "co.nz",
        "co.za",
        "co.id",
        "co.il",
        "com.au",
        "com.br",
        "com.ar",
        "com.mx",
        "com.sg",
        "com.my",
        "com.hk",
        "org.uk",
        "net.au",
        "me.uk",
        "org.au",
        # Government namespaces
        "gov.uk",
        "gouv.fr",
        "gob.es",
        "gob.mx",
        "gob.ar",
        "gob.cl",
        "gob.pe",
        "gov.au",
        "gov.br",
        "gov.in",
        "gov.sg",
        "gov.nz",
        "gov.za",
        "gov.il",
        "gov.it",
        "gov.pl",
        "gov.pt",
        "gov.gr",
        "gov.tr",
        "gov.ph",
        "gov.my",
        # Academic / education namespaces
        "ac.uk",
        "ac.jp",
        "ac.nz",
        "ac.za",
        "ac.in",
        "ac.id",
        "ac.il",
        "edu.au",
        "edu.sg",
        "edu.br",
        "edu.pl",
        # Other institutional
        "ne.jp",
        "or.jp",
        "nhs.uk",
        "police.uk",
    }

    @staticmethod
    def _to_punycode(domain: str) -> Optional[str]:
        """Convert a Unicode domain name to ASCII-compatible Punycode (IDNA 2003)."""
        try:
            return domain.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            try:
                return ".".join(
                    label.encode("idna").decode("ascii") for label in domain.split(".")
                )
            except Exception:
                return None

    @staticmethod
    def preprocess_domain(raw: str):
        """
        Normalizes a domain input before scanning.

        Returns (domain, message):
          - domain is None  -> skip; message explains why
          - domain != raw   -> was normalized; message describes the change
          - message is None -> input accepted unchanged

        Rules (in order):
          0a. REQ-001: backslash in input -> reject (file path)
          0b. REQ-001: no dot after cleaning -> reject (no TLD possible)
          0c. REQ-001: known file extension as last label -> reject
          1.  REQ-002: non-ASCII labels -> convert to Punycode silently
          2.  Reserved TLDs (RFC 2606/6761) -> skip entirely
          3.  Any subdomain -> strip to apex SLD.TLD (subdomain scanning is v2.0)
        """
        cleaned = DomainValidator.clean_domain(raw)
        if not cleaned:
            return None, f"Skipping '{raw}': invalid format"

        raw_display = raw.strip()

        # REQ-001a: backslash -> file path (clean_domain does not strip backslashes)
        if "\\" in cleaned:
            return None, f"Error: '{raw_display}' does not look like a domain name."

        # REQ-001b: no dot -> cannot have a TLD label
        if "." not in cleaned:
            return None, f"Error: '{raw_display}' does not look like a domain name."

        # REQ-001c: known file extension as rightmost label
        ext = cleaned.rsplit(".", 1)[-1]
        if ext in DomainValidator._FILE_EXTENSIONS:
            hint = (
                f"\n  Did you mean: python run.py --list {raw_display}"
                if ext == "txt"
                else ""
            )
            return (
                None,
                f"Error: '{raw_display}' does not look like a domain name.{hint}",
            )

        # REQ-005: IP address — all-numeric labels indicate IPv4, not a domain name
        if all(label.isdigit() for label in cleaned.split(".")):
            return None, f"Error: '{raw_display}' is an IP address, not a domain name."

        # REQ-002: IDN/Punycode — convert non-ASCII labels to ACE form silently
        try:
            cleaned.encode("ascii")
        except UnicodeEncodeError:
            converted = DomainValidator._to_punycode(cleaned)
            if converted is None:
                return (
                    None,
                    f"Skipping '{raw_display}': invalid internationalized domain name",
                )
            cleaned = converted

        parts = cleaned.split(".")
        tld = parts[-1].lower() if parts else ""

        # Rule 1: reserved TLDs — never scannable
        if tld in DomainValidator.RESERVED_TLDS:
            return None, (
                f"Skipping '{cleaned}': .{tld} is a reserved TLD "
                f"(RFC 2606/6761) and does not exist in public DNS"
            )

        # Rule 2: reduce any subdomain to apex domain
        two_part = ".".join(p.lower() for p in parts[-2:]) if len(parts) >= 2 else ""
        apex_depth = 3 if two_part in DomainValidator.COMPOUND_TLDS else 2

        if len(parts) > apex_depth:
            apex = ".".join(parts[-apex_depth:])
            return apex, f"'{cleaned}' -> scanning apex '{apex}'"

        return cleaned, None

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """
        Validiert Domain-Format nach RFC-Standards

        Args:
            domain (str): Zu validierende Domain

        Returns:
            bool: True wenn Domain gueltig ist
        """
        if not domain or not isinstance(domain, str):
            return False

        # Laenge pruefen (RFC-Limit: 253 Zeichen)
        if len(domain) > 253:
            return False

        # Domain bereinigen
        clean_domain = DomainValidator.clean_domain(domain)

        # Leere Domain nach Bereinigung
        if not clean_domain:
            return False

        # Regex-Validierung
        if not re.match(DomainValidator.DOMAIN_PATTERN, clean_domain):
            return False

        # Zusaetzliche Validierungen
        parts = clean_domain.split(".")

        # Mindestens eine TLD erforderlich
        if len(parts) < 2:
            return False

        # Jeder Teil darf maximal 63 Zeichen haben (RFC-Standard)
        for part in parts:
            if len(part) > 63 or len(part) == 0:
                return False

            # Darf nicht mit Bindestrich beginnen oder enden
            if part.startswith("-") or part.endswith("-"):
                return False

        return True

    @staticmethod
    def clean_domain(domain: str) -> str:
        """
        Bereinigt Domain von Protokollen, Pfaden und Ports

        Args:
            domain (str): Rohe Domain-Eingabe

        Returns:
            str: Bereinigte Domain
        """
        if not domain or not isinstance(domain, str):
            return ""

        # Whitespace entfernen
        domain = domain.strip()

        # Protokoll entfernen (http://, https://, ftp://, etc.)
        if "://" in domain:
            domain = domain.split("://", 1)[1]

        # Port entfernen (:8080, :443, etc.)
        if ":" in domain and not domain.count(":") > 1:  # Keine IPv6
            domain = domain.split(":")[0]

        # Pfad entfernen (/path/to/resource)
        if "/" in domain:
            domain = domain.split("/")[0]

        # Query-Parameter entfernen (?param=value)
        if "?" in domain:
            domain = domain.split("?")[0]

        # Fragment entfernen (#section)
        if "#" in domain:
            domain = domain.split("#")[0]

        # Trailing Punkt entfernen (DNS-Notation)
        domain = domain.rstrip(".")

        return domain.lower()

    @staticmethod
    def get_domain_parts(domain: str) -> Optional[Dict]:
        """
        Extrahiert und analysiert Domain-Bestandteile

        Args:
            domain (str): Zu parsende Domain

        Returns:
            dict: Domain-Bestandteile oder None bei ungueltig
        """
        # Domain validieren
        if not DomainValidator.is_valid_domain(domain):
            return None

        # Domain bereinigen
        clean_domain = DomainValidator.clean_domain(domain)
        parts = clean_domain.split(".")

        # Domain-Struktur analysieren
        result = {
            "full_domain": clean_domain,
            "parts": parts,
            "parts_count": len(parts),
            "tld": parts[-1] if len(parts) > 0 else None,
            "domain_name": None,
            "subdomain": None,
            "is_subdomain": len(parts) > 2,
            "depth_level": len(parts) - 2 if len(parts) >= 2 else 0,
        }

        # Domain-Name extrahieren (Second-Level-Domain)
        if len(parts) >= 2:
            result["domain_name"] = parts[-2]
            result["base_domain"] = f"{parts[-2]}.{parts[-1]}"
        else:
            result["base_domain"] = clean_domain

        # Subdomain extrahieren
        if len(parts) > 2:
            subdomain_parts = parts[:-2]
            result["subdomain"] = ".".join(subdomain_parts)
            result["subdomain_levels"] = len(subdomain_parts)
        else:
            result["subdomain_levels"] = 0

        # TLD-Analyse
        tld = result["tld"]
        if tld:
            result["tld_info"] = {
                "is_common": tld in DomainValidator.COMMON_TLDS,
                "length": len(tld),
                "is_country_code": len(tld) == 2 and tld.isalpha(),
            }

        return result

    @staticmethod
    def is_suspicious_domain(domain: str) -> Dict[str, any]:
        """
        Analysiert Domain auf verdaechtige Eigenschaften

        Args:
            domain (str): Zu analysierende Domain

        Returns:
            dict: Verdacht-Analyse mit Details
        """
        if not DomainValidator.is_valid_domain(domain):
            return {"is_suspicious": True, "reason": "Invalid domain format"}

        clean_domain = DomainValidator.clean_domain(domain)
        parts = DomainValidator.get_domain_parts(clean_domain)

        suspicion_factors = []
        suspicion_score = 0

        # Lange Domain-Namen (potenzielle Typosquatting)
        if len(clean_domain) > 30:
            suspicion_factors.append("Unusually long domain name")
            suspicion_score += 2

        # Viele Subdomains (potenzielle Subdomain-Abuse)
        if parts and parts["subdomain_levels"] > 3:
            suspicion_factors.append("Deep subdomain nesting")
            suspicion_score += 3

        # Viele Bindestriche (potenzielle Obfuscation)
        hyphen_count = clean_domain.count("-")
        if hyphen_count > 3:
            suspicion_factors.append("Excessive use of hyphens")
            suspicion_score += 2

        # Zahlen im Domain-Namen (potenzielle Variation)
        if re.search(r"\d", clean_domain):
            suspicion_factors.append("Contains numbers")
            suspicion_score += 1

        # Ungewoehnliche TLD
        if parts and parts["tld_info"] and not parts["tld_info"]["is_common"]:
            suspicion_factors.append("Uncommon TLD")
            suspicion_score += 1

        # Verdacht-Level bestimmen
        if suspicion_score >= 5:
            suspicion_level = "HIGH"
        elif suspicion_score >= 3:
            suspicion_level = "MEDIUM"
        elif suspicion_score >= 1:
            suspicion_level = "LOW"
        else:
            suspicion_level = "NONE"

        return {
            "is_suspicious": suspicion_score > 0,
            "suspicion_level": suspicion_level,
            "suspicion_score": suspicion_score,
            "factors": suspicion_factors,
            "domain_analysis": parts,
        }

    @staticmethod
    def suggest_typo_domains(domain: str, max_suggestions: int = 5) -> List[str]:
        """
        Generiert moegliche Typosquatting-Varianten einer Domain

        Args:
            domain (str): Basis-Domain
            max_suggestions (int): Maximale Anzahl Vorschlaege

        Returns:
            list: Liste moeglicher Typo-Domains
        """
        if not DomainValidator.is_valid_domain(domain):
            return []

        clean_domain = DomainValidator.clean_domain(domain)
        parts = DomainValidator.get_domain_parts(clean_domain)

        if not parts or not parts["domain_name"]:
            return []

        domain_name = parts["domain_name"]
        tld = parts["tld"]
        suggestions = []

        # Zeichen-Vertauschungen (Character swapping)
        for i in range(len(domain_name) - 1):
            chars = list(domain_name)
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
            suggestion = f"{''.join(chars)}.{tld}"
            suggestions.append(suggestion)

        # Zeichen-Ersetzungen (Similar looking characters)
        replacements = {
            "o": "0",
            "0": "o",
            "i": "1",
            "1": "i",
            "l": "1",
            "e": "3",
            "a": "@",
            "s": "$",
            "g": "9",
        }

        for char, replacement in replacements.items():
            if char in domain_name:
                suggestion = f"{domain_name.replace(char, replacement, 1)}.{tld}"
                suggestions.append(suggestion)

        # Zeichen-Hinzufuegungen (Character additions)
        common_additions = ["www", "mail", "secure", "login"]
        for addition in common_additions:
            suggestion = f"{addition}{domain_name}.{tld}"
            suggestions.append(suggestion)
            suggestion = f"{domain_name}{addition}.{tld}"
            suggestions.append(suggestion)

        # Duplikate entfernen und limitieren
        unique_suggestions = list(set(suggestions))
        valid_suggestions = [
            s for s in unique_suggestions if DomainValidator.is_valid_domain(s)
        ]

        return valid_suggestions[:max_suggestions]


# Test-Funktion fuer Domain-Validator
