"""
Domain Validation Utilities
Eingabe-Validierung und Domain-Parsing fuer forensische Domain-Analyse
"""

import re
from typing import Optional, Dict, List

class DomainValidator:
    """
    Professionelle Domain-Validierung fuer forensische Analysen
    
    Implementiert RFC-konforme Domain-Validierung und bietet erweiterte
    Parsing-Funktionen fuer forensische Domain-Untersuchungen.
    """
    
    # RFC-konforme Domain-Regex (vereinfacht aber robust)
    DOMAIN_PATTERN = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    # Top-Level-Domains fuer erweiterte Validierung
    COMMON_TLDS = {
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'de', 'uk', 'fr', 
        'jp', 'au', 'ca', 'ru', 'cn', 'in', 'br', 'mx', 'it', 'es', 'nl'
    }
    
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
        parts = clean_domain.split('.')
        
        # Mindestens eine TLD erforderlich
        if len(parts) < 2:
            return False
        
        # Jeder Teil darf maximal 63 Zeichen haben (RFC-Standard)
        for part in parts:
            if len(part) > 63 or len(part) == 0:
                return False
            
            # Darf nicht mit Bindestrich beginnen oder enden
            if part.startswith('-') or part.endswith('-'):
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
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        
        # Port entfernen (:8080, :443, etc.)
        if ':' in domain and not domain.count(':') > 1:  # Keine IPv6
            domain = domain.split(':')[0]
        
        # Pfad entfernen (/path/to/resource)
        if '/' in domain:
            domain = domain.split('/')[0]
        
        # Query-Parameter entfernen (?param=value)
        if '?' in domain:
            domain = domain.split('?')[0]
        
        # Fragment entfernen (#section)
        if '#' in domain:
            domain = domain.split('#')[0]
        
        # Trailing Punkt entfernen (DNS-Notation)
        domain = domain.rstrip('.')
        
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
        parts = clean_domain.split('.')
        
        # Domain-Struktur analysieren
        result = {
            'full_domain': clean_domain,
            'parts': parts,
            'parts_count': len(parts),
            'tld': parts[-1] if len(parts) > 0 else None,
            'domain_name': None,
            'subdomain': None,
            'is_subdomain': len(parts) > 2,
            'depth_level': len(parts) - 2 if len(parts) >= 2 else 0
        }
        
        # Domain-Name extrahieren (Second-Level-Domain)
        if len(parts) >= 2:
            result['domain_name'] = parts[-2]
            result['base_domain'] = f"{parts[-2]}.{parts[-1]}"
        else:
            result['base_domain'] = clean_domain
        
        # Subdomain extrahieren
        if len(parts) > 2:
            subdomain_parts = parts[:-2]
            result['subdomain'] = '.'.join(subdomain_parts)
            result['subdomain_levels'] = len(subdomain_parts)
        else:
            result['subdomain_levels'] = 0
        
        # TLD-Analyse
        tld = result['tld']
        if tld:
            result['tld_info'] = {
                'is_common': tld in DomainValidator.COMMON_TLDS,
                'length': len(tld),
                'is_country_code': len(tld) == 2 and tld.isalpha()
            }
        
        return result
    
    @staticmethod
    def extract_domains_from_text(text: str) -> List[str]:
        """
        Extrahiert alle Domains aus einem Text
        
        Args:
            text (str): Text zur Domain-Extraktion
            
        Returns:
            list: Liste gefundener Domains
        """
        if not text or not isinstance(text, str):
            return []
        
        # Erweiterte Domain-Regex fuer Text-Extraktion
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+\b'
        
        # Domains finden
        potential_domains = re.findall(domain_pattern, text)
        
        # Validierte Domains filtern
        valid_domains = []
        for match in potential_domains:
            if isinstance(match, tuple):
                # Regex gibt Tupel zurueck, vollstaendige Match nehmen
                domain = match[0] if match[0] else text[text.find(match[1]):text.find(match[1])+len(match[1])+len(match[2])+2]
            else:
                domain = match
            
            # Nochmals durch einfache Regex
            full_match = re.search(domain_pattern, domain)
            if full_match:
                domain = full_match.group(0)
            
            if DomainValidator.is_valid_domain(domain):
                if domain not in valid_domains:  # Duplikate vermeiden
                    valid_domains.append(domain)
        
        return valid_domains
    
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
            return {'is_suspicious': True, 'reason': 'Invalid domain format'}
        
        clean_domain = DomainValidator.clean_domain(domain)
        parts = DomainValidator.get_domain_parts(clean_domain)
        
        suspicion_factors = []
        suspicion_score = 0
        
        # Lange Domain-Namen (potenzielle Typosquatting)
        if len(clean_domain) > 30:
            suspicion_factors.append('Unusually long domain name')
            suspicion_score += 2
        
        # Viele Subdomains (potenzielle Subdomain-Abuse)
        if parts and parts['subdomain_levels'] > 3:
            suspicion_factors.append('Deep subdomain nesting')
            suspicion_score += 3
        
        # Viele Bindestriche (potenzielle Obfuscation)
        hyphen_count = clean_domain.count('-')
        if hyphen_count > 3:
            suspicion_factors.append('Excessive use of hyphens')
            suspicion_score += 2
        
        # Zahlen im Domain-Namen (potenzielle Variation)
        if re.search(r'\d', clean_domain):
            suspicion_factors.append('Contains numbers')
            suspicion_score += 1
        
        # Ungewoehnliche TLD
        if parts and parts['tld_info'] and not parts['tld_info']['is_common']:
            suspicion_factors.append('Uncommon TLD')
            suspicion_score += 1
        
        # Verdacht-Level bestimmen
        if suspicion_score >= 5:
            suspicion_level = 'HIGH'
        elif suspicion_score >= 3:
            suspicion_level = 'MEDIUM'
        elif suspicion_score >= 1:
            suspicion_level = 'LOW'
        else:
            suspicion_level = 'NONE'
        
        return {
            'is_suspicious': suspicion_score > 0,
            'suspicion_level': suspicion_level,
            'suspicion_score': suspicion_score,
            'factors': suspicion_factors,
            'domain_analysis': parts
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
        
        if not parts or not parts['domain_name']:
            return []
        
        domain_name = parts['domain_name']
        tld = parts['tld']
        suggestions = []
        
        # Zeichen-Vertauschungen (Character swapping)
        for i in range(len(domain_name) - 1):
            chars = list(domain_name)
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
            suggestion = f"{''.join(chars)}.{tld}"
            suggestions.append(suggestion)
        
        # Zeichen-Ersetzungen (Similar looking characters)
        replacements = {
            'o': '0', '0': 'o', 'i': '1', '1': 'i', 'l': '1', 
            'e': '3', 'a': '@', 's': '$', 'g': '9'
        }
        
        for char, replacement in replacements.items():
            if char in domain_name:
                suggestion = f"{domain_name.replace(char, replacement, 1)}.{tld}"
                suggestions.append(suggestion)
        
        # Zeichen-Hinzufuegungen (Character additions)
        common_additions = ['www', 'mail', 'secure', 'login']
        for addition in common_additions:
            suggestion = f"{addition}{domain_name}.{tld}"
            suggestions.append(suggestion)
            suggestion = f"{domain_name}{addition}.{tld}"
            suggestions.append(suggestion)
        
        # Duplikate entfernen und limitieren
        unique_suggestions = list(set(suggestions))
        valid_suggestions = [s for s in unique_suggestions if DomainValidator.is_valid_domain(s)]
        
        return valid_suggestions[:max_suggestions]

# Test-Funktion fuer Domain-Validator
def main():
    """
    Umfassende Test-Funktion fuer den Domain-Validator
    Demonstriert alle Funktionen mit verschiedenen Test-Cases
    """
    # Import fuer Test-Ausgabe
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    from src.utils.colors import Colors
    
    print(Colors.header("DOMAIN VALIDATOR COMPREHENSIVE TEST"))
    print(Colors.investigation_separator(60))
    
    # Test-Domains definieren
    test_cases = [
        # Gueltige Domains
        "stackoverflow.com",
        "sub.domain.example.org", 
        "https://github.com/user/repo",
        "mail.google.com:443",
        "www.example.de/path?param=value",
        
        # Grenzfaelle
        "a.co",
        "very-long-subdomain-name.example.com",
        "test123.example.net",
        
        # Ungueltige Domains
        "invalid..domain",
        ".invalid.com",
        "toolong" + "x" * 250 + ".com",
        "spaced domain.com",
        ""
    ]
    
    print(Colors.section_header("BASIC VALIDATION TEST", 60))
    
    for domain in test_cases:
        is_valid = DomainValidator.is_valid_domain(domain)
        cleaned = DomainValidator.clean_domain(domain)
        
        status = Colors.success("VALID") if is_valid else Colors.error("INVALID")
        print(f"{status} '{domain}' -> '{cleaned}'")
        
        if is_valid:
            parts = DomainValidator.get_domain_parts(cleaned)
            if parts:
                print(f"  Base: {Colors.format_domain(parts['base_domain'])}")
                if parts['subdomain']:
                    print(f"  Subdomain: {Colors.info(parts['subdomain'])}")
                print(f"  TLD: {Colors.highlight(parts['tld'])} "
                      f"({'common' if parts['tld_info']['is_common'] else 'uncommon'})")
        print()
    
    print(Colors.section_header("SUSPICION ANALYSIS TEST", 60))
    
    suspicious_domains = [
        "very-long-suspicious-domain-name-with-many-hyphens.tk",
        "deep.sub.domain.level.test.example.com",
        "paypal-security-update123.com",
        "google.com"  # Kontrolle: normale Domain
    ]
    
    for domain in suspicious_domains:
        if DomainValidator.is_valid_domain(domain):
            analysis = DomainValidator.is_suspicious_domain(domain)
            level_color = Colors.risk_level(analysis['suspicion_level'])
            
            print(f"Domain: {Colors.format_domain(domain)}")
            print(f"  Suspicion Level: {level_color}")
            print(f"  Score: {analysis['suspicion_score']}")
            if analysis['factors']:
                print(f"  Factors: {', '.join(analysis['factors'])}")
            print()
    
    print(Colors.section_header("TYPO GENERATION TEST", 60))
    
    base_domain = "github.com"
    if DomainValidator.is_valid_domain(base_domain):
        typos = DomainValidator.suggest_typo_domains(base_domain, 3)
        print(f"Typo suggestions for {Colors.format_domain(base_domain)}:")
        for typo in typos:
            print(f"  {Colors.warning(typo)}")
    
    print(Colors.investigation_separator(60))
    print(Colors.success("Domain Validator Test completed successfully"))

if __name__ == "__main__":
    main()