"""
DNS Analyzer Module for Domain Forensic Analyzer.

This module keeps the DNS result schema intentionally small:
- domain
- ipv4
- ipv6
- reverse_dns
- mx_records
- ns_records
- analysis_status

The returned data is reduced to the values that are currently used by the
main workflow and the final report.
"""

import os
import socket
import subprocess
import sys
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

# Foundation-Module importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.utils.colors import Colors
from src.utils.validators import DomainValidator
from config.settings import get_settings

class DNSAnalyzer:
    """
    DNS-Grundlagen-Analyse fuer forensische Untersuchungen.

    Das Modul liefert bewusst nur die DNS-Werte, die im weiteren Ablauf
    wirklich relevant sind: Aufloesung, Reverse-DNS, NS-Records und MX-Records.
    """
    
    def __init__(self):
        """Initialisiert DNS-Analyzer mit Konfiguration."""
        self.settings = get_settings()
        self.dns_timeout = self.settings.scan_settings.dns_timeout
        
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Fuehrt die DNS-Basisanalyse fuer eine Domain aus.
        
        Args:
            domain: Zu analysierende Domain.
            
        Returns:
            Ein kompaktes Ergebnis-Dictionary fuer den Hauptworkflow.
        """
        print(Colors.header("DNS FOUNDATION ANALYSIS"))
        print(Colors.investigation_separator(60))
        
        if not DomainValidator.is_valid_domain(domain):
            error_msg = f"Ungueltige Domain: {domain}"
            print(Colors.error(error_msg))
            return {'error': error_msg, 'analysis_status': 'fehlgeschlagen'}
        
        clean_domain = DomainValidator.clean_domain(domain)
        print(f"Analysiere Domain: {Colors.format_domain(clean_domain)}")
        
        # Das Basisschema bleibt absichtlich klein und stabil.
        results = {
            'domain': clean_domain,
            'ipv4': None,
            'ipv6': None,
            'reverse_dns': None,
            'mx_records': [],
            'ns_records': [],
        }
        
        print(f"\n{Colors.section_header('DNS RESOLUTION', 50)}")
        results.update(self._resolve_ipv4(clean_domain))
        results.update(self._resolve_ipv6(clean_domain))
        
        if results.get('ipv4'):
            results.update(self._reverse_dns_lookup(results['ipv4']))
        
        print(f"\n{Colors.section_header('DNS RECORDS', 50)}")
        results.update(self._analyze_mx_records(clean_domain))
        results.update(self._analyze_ns_records(clean_domain))
        
        results['analysis_status'] = 'abgeschlossen'
        self._display_summary(results)
        return results

    @contextmanager
    def _socket_timeout(self):
        """
        Kapselt den temporaeren Socket-Timeout.

        Die Standardbibliothek nutzt hier einen globalen Default-Timeout.
        Dieser Helper stellt sicher, dass der vorherige Wert immer wieder
        hergestellt wird, auch wenn eine Ausnahme auftritt.
        """
        previous_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.dns_timeout)
        try:
            yield
        finally:
            socket.setdefaulttimeout(previous_timeout)
    
    def _resolve_ipv4(self, domain: str) -> Dict[str, Optional[str]]:
        """Loest die Domain auf IPv4 auf."""
        try:
            with self._socket_timeout():
                ipv4_address = socket.gethostbyname(domain)
            
            print(f"  {Colors.success('IPv4:')} {Colors.format_ip(ipv4_address)}")
            return {'ipv4': ipv4_address}
            
        except socket.gaierror:
            print(f"  {Colors.error('IPv4:')} Aufloesung fehlgeschlagen")
            return {'ipv4': None}
        except Exception:
            print(f"  {Colors.error('IPv4:')} Unerwarteter Fehler")
            return {'ipv4': None}
    
    def _resolve_ipv6(self, domain: str) -> Dict[str, Optional[str]]:
        """Prueft, ob eine IPv6-Aufloesung vorhanden ist."""
        try:
            with self._socket_timeout():
                addr_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
            
            if addr_info:
                ipv6_address = addr_info[0][4][0]
                print(f"  {Colors.success('IPv6:')} {Colors.format_ip(ipv6_address)}")
                return {'ipv6': ipv6_address}

            print(f"  {Colors.warning('IPv6:')} Nicht konfiguriert")
            return {'ipv6': None}
                
        except (socket.gaierror, OSError):
            print(f"  {Colors.warning('IPv6:')} Nicht verfuegbar")
            return {'ipv6': None}
    
    def _reverse_dns_lookup(self, ip_address: str) -> Dict[str, Optional[str]]:
        """Fuehrt den PTR-Lookup fuer die aufgeloeste IPv4-Adresse durch."""
        try:
            with self._socket_timeout():
                hostname = socket.gethostbyaddr(ip_address)[0]
            
            print(f"  {Colors.success('Reverse DNS:')} {Colors.format_domain(hostname)}")
            return {'reverse_dns': hostname}
            
        except (socket.herror, socket.gaierror, OSError):
            print(f"  {Colors.warning('Reverse DNS:')} Nicht verfuegbar")
            return {'reverse_dns': None}
    
    def _query_nslookup(self, record_type: str, domain: str) -> Optional[str]:
        """
        Fuehrt eine gezielte nslookup-Abfrage aus.

        Die CLI-Abfrage bleibt hier bewusst in einer Funktion gekapselt,
        damit Fehlerbehandlung und Plattformbesonderheiten nicht doppelt
        im MX- und NS-Pfad implementiert werden.
        """
        try:
            result = subprocess.run(
                ['nslookup', f'-type={record_type}', domain],
                capture_output=True,
                text=True,
                timeout=self.dns_timeout,
                encoding='cp850',
                errors='replace'
            )
        except subprocess.TimeoutExpired:
            print(f"    {Colors.error('Timeout nach')} {self.dns_timeout}s")
            return None
        except Exception as error:
            print(f"    {Colors.error('Fehler:')} {error}")
            return None

        if result.returncode != 0:
            return None

        return result.stdout or ""

    def _analyze_mx_records(self, domain: str) -> Dict[str, List[Dict[str, str]]]:
        """Ermittelt MX-Records ueber nslookup und normalisiert das Ergebnis."""
        print(f"  {Colors.info('MX-Records:')} Abfrage...")

        output = self._query_nslookup('MX', domain)
        if output is None:
            return {'mx_records': []}

        mx_records = self._parse_mx_records(output)
        if mx_records:
            print(f"    {Colors.success('Gefunden:')} {len(mx_records)} Mail-Server")
            for index, mx_record in enumerate(mx_records[:3], 1):
                print(
                    f"    {index}. {Colors.format_domain(mx_record['server'])} "
                    f"(Prioritaet: {mx_record['priority']})"
                )
        else:
            print(f"    {Colors.warning('Keine Mail-Server konfiguriert')}")

        return {'mx_records': mx_records}
    
    def _parse_mx_records(self, nslookup_output: str) -> List[Dict[str, str]]:
        """
        Parst MX-Zeilen aus der nslookup-Ausgabe.

        Die Logik ist absichtlich einfach gehalten:
        - nur relevante Zeilen mit "mail exchanger"
        - nur Prioritaet + Zielhost
        - Duplikate werden ueber den Hostnamen entfernt
        """
        mx_records: List[Dict[str, str]] = []

        for line in nslookup_output.splitlines():
            if 'mail exchanger' not in line.lower():
                continue

            priority, server = self._extract_mx_parts(line)
            if priority and server:
                mx_records.append({'priority': priority, 'server': server})

        return self._deduplicate_mx_records(mx_records)

    def _extract_mx_parts(self, line: str) -> tuple[Optional[str], Optional[str]]:
        """Extrahiert Prioritaet und Zielhost aus einer einzelnen MX-Zeile."""
        parts = line.strip().split()
        if not parts:
            return None, None

        if '=' in parts:
            equals_index = parts.index('=')
            if equals_index + 2 < len(parts):
                priority = self._clean_priority(parts[equals_index + 1])
                server = self._normalize_hostname(parts[equals_index + 2])
                if priority and server:
                    return priority, server

        for index, part in enumerate(parts):
            priority = self._clean_priority(part)
            if priority and index + 1 < len(parts):
                server = self._normalize_hostname(parts[index + 1])
                if server and server.lower() != 'exchanger':
                    return priority, server

        return None, None

    def _deduplicate_mx_records(self, mx_records: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Entfernt doppelte MX-Eintraege anhand des Zielhosts."""
        unique_records: List[Dict[str, str]] = []
        seen_servers = set()

        for mx_record in mx_records:
            server = mx_record['server'].lower()
            if server in seen_servers:
                continue
            seen_servers.add(server)
            unique_records.append(mx_record)

        return unique_records
    
    def _analyze_ns_records(self, domain: str) -> Dict[str, List[str]]:
        """Ermittelt NS-Records ueber nslookup und normalisiert das Ergebnis."""
        print(f"  {Colors.info('NS-Records:')} Abfrage...")

        output = self._query_nslookup('NS', domain)
        if output is None:
            return {'ns_records': []}

        ns_records = self._parse_ns_records(output, domain)
        if ns_records:
            print(f"    {Colors.success('Gefunden:')} {len(ns_records)} Nameserver")
            for index, nameserver in enumerate(ns_records[:3], 1):
                print(f"    {index}. {Colors.format_domain(nameserver)}")
        else:
            print(f"    {Colors.warning('Keine Nameserver gefunden')}")

        return {'ns_records': ns_records}
    
    def _parse_ns_records(self, nslookup_output: str, domain: str) -> List[str]:
        """Parst Nameserver aus der nslookup-Ausgabe und entfernt Duplikate."""
        ns_records: List[str] = []
        clean_domain = domain.lower().rstrip('.')

        for line in nslookup_output.splitlines():
            if 'nameserver' not in line.lower():
                continue

            parts = line.strip().split()
            if len(parts) < 2:
                continue

            nameserver = self._normalize_hostname(parts[-1])
            if not nameserver:
                continue
            if nameserver.lower() == clean_domain:
                continue
            if nameserver not in ns_records:
                ns_records.append(nameserver)

        return ns_records

    def _clean_priority(self, value: Any) -> Optional[str]:
        """Normalisiert eine MX-Prioritaet auf eine reine Zahl."""
        text = str(value).strip().rstrip('.,')
        return text if text.isdigit() else None

    def _normalize_hostname(self, value: Any) -> Optional[str]:
        """Bereinigt Hostnamen aus nslookup-Ausgaben fuer die Weiterverarbeitung."""
        hostname = str(value).strip().rstrip('.,')
        if not hostname:
            return None
        if hostname.lower() in {'exchanger', 'unbekannt'}:
            return None
        return hostname
    
    def _display_summary(self, results: Dict[str, Any]) -> None:
        """Zeigt eine kompakte Modul-Zusammenfassung fuer Standalone-Laeufe."""
        print(f"\n{Colors.investigation_separator(60)}")
        print(Colors.header("DNS ANALYSIS SUMMARY"))
        print(Colors.investigation_separator(60))
        
        print(f"Domain: {Colors.format_domain(results['domain'])}")
        
        if results.get('ipv4'):
            print(f"IPv4: {Colors.success('RESOLVED')} -> {Colors.format_ip(results['ipv4'])}")
            
            if results.get('reverse_dns'):
                print(f"Reverse DNS: {Colors.success('AVAILABLE')} -> {Colors.format_domain(results['reverse_dns'])}")
            else:
                print(f"Reverse DNS: {Colors.warning('NOT AVAILABLE')}")
        else:
            print(f"IPv4: {Colors.error('RESOLUTION FAILED')}")
        
        if results.get('ipv6'):
            print(f"IPv6: {Colors.success('CONFIGURED')} -> {Colors.format_ip(results['ipv6'])}")
        else:
            print(f"IPv6: {Colors.warning('NOT CONFIGURED')}")
        
        mx_count = len(results.get('mx_records', []))
        if mx_count > 0:
            print(f"Mail Servers: {Colors.success(f'{mx_count} CONFIGURED')}")
        else:
            print(f"Mail Servers: {Colors.warning('NONE CONFIGURED')}")
        
        ns_count = len(results.get('ns_records', []))
        if ns_count > 0:
            print(f"Name Servers: {Colors.success(f'{ns_count} FOUND')}")
        else:
            print(f"Name Servers: {Colors.warning('NONE FOUND')}")
        
        print(Colors.investigation_separator(60))
        print(f"Analysis Status: {Colors.success('COMPLETE')}")
        print(Colors.investigation_separator(60))

def main():
    """
    Einfache Standalone-Smoke-Tests fuer das DNS-Modul.

    Das ist kein Ersatz fuer echte Tests, hilft aber beim manuellen
    Gegenpruefen von Parsern und Konsolenausgabe.
    """
    print(Colors.header("DNS ANALYZER MODULE TEST"))
    print(Colors.investigation_separator(60))
    
    test_domains = [
        "stackoverflow.com",
        "github.com",
        "futuremultiverse.com"
    ]
    
    analyzer = DNSAnalyzer()
    
    for i, domain in enumerate(test_domains, 1):
        print(f"\n{Colors.section_header(f'TEST {i}: {domain.upper()}', 60)}")
        
        results = analyzer.analyze_domain(domain)
        
        if results.get('error'):
            print(Colors.error(f"Test fehlgeschlagen: {results['error']}"))
        else:
            print(Colors.success(f"Test erfolgreich fuer {domain}"))
        
        if i < len(test_domains):
            import time
            time.sleep(1)
    
    print(f"\n{Colors.investigation_separator(60)}")
    print(Colors.success("DNS ANALYZER TESTING COMPLETE"))
    print(Colors.investigation_separator(60))

if __name__ == "__main__":
    main()

        
