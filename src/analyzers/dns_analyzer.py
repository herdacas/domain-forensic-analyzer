         
"""
DNS Analyzer Module for Domain Forensic Analyzer
DNS-Grundlagen-Analyse fuer forensische Domain-Untersuchungen

Step 2.1 Implementation - Mit MX-Parser Bug-Fix
"""

import socket
import subprocess
import sys
import os
from typing import Dict, List, Optional, Any
from datetime import datetime

# Foundation-Module importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.utils.colors import Colors
from src.utils.validators import DomainValidator
from config.settings import get_settings

class DNSAnalyzer:
    """
    DNS-Grundlagen-Analyse fuer forensische Untersuchungen
    
    Fuehrt IPv4/IPv6-Aufloesung, Reverse-DNS, MX-Records und 
    NS-Records Analyse durch. Basis fuer alle weiteren Module.
    """
    
    def __init__(self):
        """Initialisiert DNS-Analyzer mit Konfiguration"""
        self.results = {}
        self.domain = None
        self.settings = get_settings()
        self.dns_timeout = self.settings.scan_settings.dns_timeout
        
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Hauptanalyse-Funktion fuer DNS-Untersuchung
        
        Args:
            domain (str): Zu analysierende Domain
            
        Returns:
            dict: DNS-Analyseergebnisse
        """
        print(Colors.header("DNS FOUNDATION ANALYSIS"))
        print(Colors.investigation_separator(60))
        
        # Domain-Validierung
        if not DomainValidator.is_valid_domain(domain):
            error_msg = f"Ungueltige Domain: {domain}"
            print(Colors.error(error_msg))
            return {'error': error_msg, 'analysis_status': 'fehlgeschlagen'}
        
        # Domain bereinigen
        clean_domain = DomainValidator.clean_domain(domain)
        self.domain = clean_domain
        print(f"Analysiere Domain: {Colors.format_domain(clean_domain)}")
        
        # Ergebnis-Dictionary initialisieren
        results = {
            'domain': clean_domain,
            'timestamp': datetime.now().isoformat(),
            'ipv4': None,
            'ipv4_status': None,
            'ipv6': None,
            'ipv6_status': None,
            'reverse_dns': None,
            'reverse_dns_status': None,
            'mx_records': [],
            'mx_status': None,
            'ns_records': [],
            'ns_status': None,
            'analysis_status': 'gestartet'
        }
        
        # DNS-Analysen durchfuehren
        print(f"\n{Colors.section_header('DNS RESOLUTION', 50)}")
        results.update(self._resolve_ipv4(clean_domain))
        results.update(self._resolve_ipv6(clean_domain))
        
        # Reverse DNS bei erfolgreicher IPv4-Aufloesung
        if results.get('ipv4'):
            results.update(self._reverse_dns_lookup(results['ipv4']))
        
        print(f"\n{Colors.section_header('DNS RECORDS', 50)}")
        results.update(self._analyze_mx_records(clean_domain))
        results.update(self._analyze_ns_records(clean_domain))
        
        # Analyse abschliessen
        results['analysis_status'] = 'abgeschlossen'
        self.results = results
        
        # Zusammenfassung anzeigen
        self._display_summary(results)
        return results
    
    def _resolve_ipv4(self, domain: str) -> Dict[str, Any]:
        """
        IPv4-Adressaufloesung mit Timeout-Handling
        
        Args:
            domain (str): Domain fuer IPv4-Aufloesung
            
        Returns:
            dict: IPv4-Ergebnisse
        """
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.dns_timeout)
            
            ipv4_address = socket.gethostbyname(domain)
            socket.setdefaulttimeout(old_timeout)
            
            print(f"  {Colors.success('IPv4:')} {Colors.format_ip(ipv4_address)}")
            return {'ipv4': ipv4_address, 'ipv4_status': 'aufgeloest'}
            
        except socket.gaierror as error:
            socket.setdefaulttimeout(old_timeout)
            print(f"  {Colors.error('IPv4:')} Aufloesung fehlgeschlagen")
            return {'ipv4': None, 'ipv4_status': 'fehlgeschlagen', 'ipv4_error': str(error)}
        except Exception as error:
            socket.setdefaulttimeout(old_timeout)
            print(f"  {Colors.error('IPv4:')} Unerwarteter Fehler")
            return {'ipv4': None, 'ipv4_status': 'fehler', 'ipv4_error': str(error)}
    
    def _resolve_ipv6(self, domain: str) -> Dict[str, Any]:
        """
        IPv6-Unterstuetzung pruefen
        
        Args:
            domain (str): Domain fuer IPv6-Pruefung
            
        Returns:
            dict: IPv6-Ergebnisse
        """
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.dns_timeout)
            
            addr_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
            socket.setdefaulttimeout(old_timeout)
            
            if addr_info:
                ipv6_address = addr_info[0][4][0]
                print(f"  {Colors.success('IPv6:')} {Colors.format_ip(ipv6_address)}")
                return {'ipv6': ipv6_address, 'ipv6_status': 'konfiguriert'}
            else:
                print(f"  {Colors.warning('IPv6:')} Nicht konfiguriert")
                return {'ipv6': None, 'ipv6_status': 'nicht_konfiguriert'}
                
        except (socket.gaierror, OSError):
            socket.setdefaulttimeout(old_timeout)
            print(f"  {Colors.warning('IPv6:')} Nicht verfuegbar")
            return {'ipv6': None, 'ipv6_status': 'nicht_verfuegbar'}
    
    def _reverse_dns_lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Reverse-DNS-Aufloesung fuer Infrastructure-Mapping
        
        Args:
            ip_address (str): IP-Adresse fuer Reverse-Lookup
            
        Returns:
            dict: Reverse-DNS Ergebnisse
        """
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.dns_timeout)
            
            hostname = socket.gethostbyaddr(ip_address)[0]
            socket.setdefaulttimeout(old_timeout)
            
            print(f"  {Colors.success('Reverse DNS:')} {Colors.format_domain(hostname)}")
            return {'reverse_dns': hostname, 'reverse_dns_status': 'aufgeloest'}
            
        except (socket.herror, socket.gaierror):
            socket.setdefaulttimeout(old_timeout)
            print(f"  {Colors.warning('Reverse DNS:')} Nicht verfuegbar")
            return {'reverse_dns': None, 'reverse_dns_status': 'nicht_verfuegbar'}
    
    def _analyze_mx_records(self, domain: str) -> Dict[str, Any]:
        """
        MX-Records Analyse fuer Mail-Infrastructure
        
        Args:
            domain (str): Domain fuer MX-Analyse
            
        Returns:
            dict: MX-Records Ergebnisse
        """
        try:
            print(f"  {Colors.info('MX-Records:')} Abfrage...")
            
            result = subprocess.run(
                ['nslookup', '-type=MX', domain], 
                capture_output=True, 
                text=True, 
                timeout=self.dns_timeout,
                encoding='cp850',
                errors='replace'
            )
            
            if result.returncode == 0 and 'mail exchanger' in result.stdout.lower():
                mx_records = self._parse_mx_records(result.stdout)
                
                if mx_records:
                    print(f"    {Colors.success('Gefunden:')} {len(mx_records)} Mail-Server")
                    for i, mx in enumerate(mx_records[:3], 1):
                        print(f"    {i}. {Colors.format_domain(mx['server'])} (Prioritaet: {mx['priority']})")
                    
                    return {'mx_records': mx_records, 'mx_status': 'konfiguriert'}
                else:
                    print(f"    {Colors.warning('Parsing fehlgeschlagen')}")
                    return {'mx_records': [], 'mx_status': 'parsing_fehler'}
            else:
                print(f"    {Colors.warning('Keine Mail-Server konfiguriert')}")
                return {'mx_records': [], 'mx_status': 'keine_gefunden'}
                
        except subprocess.TimeoutExpired:
            print(f"    {Colors.error('Timeout nach')} {self.dns_timeout}s")
            return {'mx_records': [], 'mx_status': 'timeout'}
        except Exception as error:
            print(f"    {Colors.error('Fehler:')} {str(error)}")
            return {'mx_records': [], 'mx_status': 'fehlgeschlagen'}
    
    def _parse_mx_records(self, nslookup_output: str) -> List[Dict[str, str]]:
        """
        Parst MX-Records aus nslookup-Ausgabe - KORRIGIERTE VERSION
        
        Args:
            nslookup_output (str): nslookup Rohdaten
            
        Returns:
            list: Korrekt geparste MX-Records
        """
        mx_records = []
        lines = nslookup_output.split('\n')
        
        for line in lines:
            if 'mail exchanger' in line.lower():
                line_clean = line.strip()
                
                # Format: "domain MX preference = priority mailserver"
                # Beispiel: "stackoverflow.com MX preference = 5 alt1.aspmx.l.google.com"
                
                if 'preference' in line_clean.lower() and '=' in line_clean:
                    try:
                        parts = line_clean.split()
                        equals_index = None
                        
                        # Index von "=" finden
                        for i, part in enumerate(parts):
                            if part == '=':
                                equals_index = i
                                break
                        
                        if equals_index is not None and equals_index + 2 < len(parts):
                            priority = parts[equals_index + 1]
                            server = parts[equals_index + 2].rstrip('.')
                            
                            # Nur gueltige Server hinzufuegen
                            if server and server != 'exchanger' and server != 'unbekannt':
                                mx_records.append({
                                    'priority': priority,
                                    'server': server
                                })
                    except (ValueError, IndexError):
                        # Fallback-Parsing
                        parts = line_clean.split()
                        if len(parts) >= 6:
                            for i in range(len(parts)):
                                if parts[i].isdigit():
                                    priority = parts[i]
                                    if i + 1 < len(parts):
                                        server = parts[i + 1].rstrip('.')
                                        if server and server != 'exchanger':
                                            mx_records.append({
                                                'priority': priority,
                                                'server': server
                                            })
                                    break
                else:
                    # Alternatives Format ohne "preference"
                    parts = line_clean.split()
                    if len(parts) >= 6:
                        server = parts[-1].rstrip('.')
                        priority = parts[-2] if parts[-2].isdigit() else 'unbekannt'
                        
                        if server and server != 'exchanger' and len(server) > 3:
                            mx_records.append({
                                'priority': priority,
                                'server': server
                            })
        
        # Duplikate entfernen
        seen_servers = set()
        unique_mx_records = []
        for mx in mx_records:
            if mx['server'] not in seen_servers:
                seen_servers.add(mx['server'])
                unique_mx_records.append(mx)
        
        return unique_mx_records
    
    def _analyze_ns_records(self, domain: str) -> Dict[str, Any]:
        """
        NS-Records Analyse fuer DNS-Infrastructure
        
        Args:
            domain (str): Domain fuer NS-Analyse
            
        Returns:
            dict: NS-Records Ergebnisse
        """
        try:
            print(f"  {Colors.info('NS-Records:')} Abfrage...")
            
            result = subprocess.run(
                ['nslookup', '-type=NS', domain], 
                capture_output=True, 
                text=True, 
                timeout=self.dns_timeout,
                encoding='cp850',
                errors='replace'
            )
            
            if result.returncode == 0 and 'nameserver' in result.stdout.lower():
                ns_records = self._parse_ns_records(result.stdout, domain)
                
                if ns_records:
                    print(f"    {Colors.success('Gefunden:')} {len(ns_records)} Nameserver")
                    for i, ns in enumerate(ns_records[:3], 1):
                        print(f"    {i}. {Colors.format_domain(ns)}")
                    
                    return {'ns_records': ns_records, 'ns_status': 'gefunden'}
                else:
                    print(f"    {Colors.warning('Parsing fehlgeschlagen')}")
                    return {'ns_records': [], 'ns_status': 'parsing_fehler'}
            else:
                print(f"    {Colors.warning('Abfrage fehlgeschlagen')}")
                return {'ns_records': [], 'ns_status': 'abfrage_fehler'}
                
        except subprocess.TimeoutExpired:
            print(f"    {Colors.error('Timeout nach')} {self.dns_timeout}s")
            return {'ns_records': [], 'ns_status': 'timeout'}
        except Exception as error:
            print(f"    {Colors.error('Fehler:')} {str(error)}")
            return {'ns_records': [], 'ns_status': 'fehlgeschlagen'}
    
    def _parse_ns_records(self, nslookup_output: str, domain: str) -> List[str]:
        """
        Parst NS-Records aus nslookup-Ausgabe
        
        Args:
            nslookup_output (str): nslookup Rohdaten
            domain (str): Original-Domain
            
        Returns:
            list: Nameserver-Liste
        """
        ns_records = []
        lines = nslookup_output.split('\n')
        
        for line in lines:
            if 'nameserver' in line.lower():
                parts = line.strip().split()
                if len(parts) >= 4:
                    nameserver = parts[-1].rstrip('.')
                    if nameserver and nameserver != domain and nameserver not in ns_records:
                        ns_records.append(nameserver)
        
        return ns_records
    
    def _display_summary(self, results: Dict[str, Any]) -> None:
        """
        Zeigt DNS-Analyse Zusammenfassung
        
        Args:
            results (dict): Analyseergebnisse
        """
        print(f"\n{Colors.investigation_separator(60)}")
        print(Colors.header("DNS ANALYSIS SUMMARY"))
        print(Colors.investigation_separator(60))
        
        # Domain-Status
        print(f"Domain: {Colors.format_domain(results['domain'])}")
        
        # IPv4-Status
        if results.get('ipv4'):
            print(f"IPv4: {Colors.success('RESOLVED')} -> {Colors.format_ip(results['ipv4'])}")
            
            if results.get('reverse_dns'):
                print(f"Reverse DNS: {Colors.success('AVAILABLE')} -> {Colors.format_domain(results['reverse_dns'])}")
            else:
                print(f"Reverse DNS: {Colors.warning('NOT AVAILABLE')}")
        else:
            print(f"IPv4: {Colors.error('RESOLUTION FAILED')}")
        
        # IPv6-Status
        if results.get('ipv6'):
            print(f"IPv6: {Colors.success('CONFIGURED')} -> {Colors.format_ip(results['ipv6'])}")
        else:
            print(f"IPv6: {Colors.warning('NOT CONFIGURED')}")
        
        # Mail-Server
        mx_count = len(results.get('mx_records', []))
        if mx_count > 0:
            print(f"Mail Servers: {Colors.success(f'{mx_count} CONFIGURED')}")
        else:
            print(f"Mail Servers: {Colors.warning('NONE CONFIGURED')}")
        
        # Nameserver
        ns_count = len(results.get('ns_records', []))
        if ns_count > 0:
            print(f"Name Servers: {Colors.success(f'{ns_count} FOUND')}")
        else:
            print(f"Name Servers: {Colors.error('ANALYSIS FAILED')}")
        
        print(Colors.investigation_separator(60))
        print(f"Analysis Status: {Colors.success('COMPLETE')}")
        print(Colors.investigation_separator(60))
    
    def get_results(self) -> Dict[str, Any]:
        """
        Gibt letzte Analyseergebnisse zurueck
        
        Returns:
            dict: DNS-Analyseergebnisse
        """
        return self.results
    
    def get_domain(self) -> Optional[str]:
        """
        Gibt analysierte Domain zurueck
        
        Returns:
            str: Domain oder None
        """
        return self.domain

# Test-Funktion fuer DNS-Analyzer
def main():
    """
    Test-Funktion fuer DNS-Analyzer Modul
    Testet mit 3 Benchmark-Domains
    """
    print(Colors.header("DNS ANALYZER MODULE TEST - STEP 2.1 (FIXED)"))
    print(Colors.investigation_separator(60))
    
    # Benchmark-Domains
    test_domains = [
        "stackoverflow.com",    # CDN-Fall (Cloudflare)
        "github.com",          # Platform-Fall
        "futuremultiverse.com" # Wildcard-Fall
    ]
    
    analyzer = DNSAnalyzer()
    
    for i, domain in enumerate(test_domains, 1):
        print(f"\n{Colors.section_header(f'TEST {i}: {domain.upper()}', 60)}")
        
        results = analyzer.analyze_domain(domain)
        
        if results.get('error'):
            print(Colors.error(f"Test fehlgeschlagen: {results['error']}"))
        else:
            print(Colors.success(f"Test erfolgreich fuer {domain}"))
        
        # Pause zwischen Tests
        if i < len(test_domains):
            import time
            time.sleep(1)
    
    print(f"\n{Colors.investigation_separator(60)}")
    print(Colors.success("DNS ANALYZER STEP 2.1 - TESTING COMPLETE (FIXED VERSION)"))
    print(Colors.investigation_separator(60))

if __name__ == "__main__":
    main()

        