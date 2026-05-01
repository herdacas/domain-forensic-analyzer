"""
DNS Analyzer Module for Domain Forensic Analyzer.

The module started as a compact DNS foundation block and now also provides
focused DNS-forensics values that are useful for professional research:
- DNS resolution basics (A, AAAA, PTR, MX, NS)
- zone metadata (SOA, TXT, CAA)
- mail-security indicators (SPF, DMARC, DKIM discovery)
- DNS integrity hints (DNSSEC, AXFR exposure)
- a compact DNS configuration assessment for the final report
"""

import os
import socket
import subprocess
import sys
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

import dns.exception
import dns.query
import dns.resolver
import dns.zone

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
        # Heuristic discovery list for common DKIM selectors. This is not
        # exhaustive, but it catches many real-world deployments without
        # turning the DNS module into a slow brute-force pass.
        self.common_dkim_selectors = [
            'default', 'selector1', 'selector2', 'google',
            'dkim', 'mail', 'k1', 'amazonses'
        ]

    def _create_resolver(self, nameservers: Optional[List[str]] = None) -> dns.resolver.Resolver:
        """
        Erstellt einen Resolver mit konsistenten Timeouts.

        Die DNS-Forensik-Funktionen sollen auf derselben Timeout-Basis laufen wie
        die restliche Analyse, aber ohne weiteren globalen Prozesszustand.
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout
        if nameservers:
            resolver.nameservers = nameservers
        return resolver

    def _resolve_dns_records(self, name: str, record_type: str, nameservers: Optional[List[str]] = None) -> List[Any]:
        """Fuehrt eine Resolver-Abfrage fuer einen konkreten Record-Typ aus."""
        try:
            resolver = self._create_resolver(nameservers)
            answer = resolver.resolve(name, record_type)
            return list(answer)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception:
            return []
        
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
            'soa_record': {},
            'txt_records': [],
            'spf_record': None,
            'spf_analysis': {},
            'dmarc_record': None,
            'dmarc_analysis': {},
            'dkim': {},
            'caa_records': [],
            'dnssec': {},
            'zone_transfer': {},
            'dns_configuration_assessment': {},
        }
        
        print(f"\n{Colors.section_header('DNS RESOLUTION', 50)}")
        results.update(self._resolve_ipv4(clean_domain))
        results.update(self._resolve_ipv6(clean_domain))
        
        if results.get('ipv4'):
            results.update(self._reverse_dns_lookup(results['ipv4']))
        
        print(f"\n{Colors.section_header('DNS RECORDS', 50)}")
        results.update(self._analyze_mx_records(clean_domain))
        results.update(self._analyze_ns_records(clean_domain))

        print(f"\n{Colors.section_header('DNS FORENSICS', 50)}")
        results.update(self._analyze_soa_record(clean_domain))
        results.update(self._analyze_txt_records(clean_domain))
        results.update(self._analyze_spf_record(results.get('txt_records', [])))
        results.update(self._analyze_spf_policy(results.get('spf_record')))
        results.update(self._analyze_dmarc_record(clean_domain))
        results.update(self._analyze_dmarc_configuration(results.get('dmarc_record')))
        results.update(self._analyze_dkim_selectors(clean_domain))
        results.update(self._analyze_caa_records(clean_domain))
        results.update(self._analyze_dnssec(clean_domain))
        results.update(self._analyze_zone_transfer(clean_domain, results.get('ns_records', [])))
        results.update(
            self._assess_dns_configuration(
                results.get('spf_analysis', {}),
                results.get('dmarc_analysis', {}),
                results.get('dkim', {}),
                results.get('dnssec', {}),
                results.get('zone_transfer', {}),
                results.get('caa_records', []),
            )
        )
        
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

    def _analyze_soa_record(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Ermittelt den SOA-Record als Grundlage fuer DNS-Zonenvaliditaet."""
        print(f"  {Colors.info('SOA-Record:')} Abfrage...")
        records = self._resolve_dns_records(domain, 'SOA')
        if not records:
            print(f"    {Colors.warning('Nicht verfuegbar')}")
            return {'soa_record': {}}

        soa = records[0]
        soa_record = {
            'primary_nameserver': str(soa.mname).rstrip('.'),
            'responsible_party': str(soa.rname).rstrip('.'),
            'serial': int(soa.serial),
            'refresh': int(soa.refresh),
            'retry': int(soa.retry),
            'expire': int(soa.expire),
            'minimum_ttl': int(soa.minimum),
        }
        print(f"    {Colors.success('Primary NS:')} {soa_record['primary_nameserver']}")
        print(f"    {Colors.success('Serial:')} {soa_record['serial']}")
        return {'soa_record': soa_record}

    def _analyze_txt_records(self, domain: str) -> Dict[str, List[str]]:
        """Ermittelt TXT-Records fuer SPF- und Policy-bezogene Hinweise."""
        print(f"  {Colors.info('TXT-Records:')} Abfrage...")
        records = self._resolve_dns_records(domain, 'TXT')
        txt_records = [self._normalize_txt_record(record) for record in records]
        txt_records = [record for record in txt_records if record]

        if txt_records:
            print(f"    {Colors.success('Gefunden:')} {len(txt_records)} TXT-Records")
        else:
            print(f"    {Colors.warning('Keine TXT-Records gefunden')}")

        return {'txt_records': txt_records}

    def _analyze_spf_record(self, txt_records: List[str]) -> Dict[str, Optional[str]]:
        """Extrahiert den SPF-Record aus bereits gelesenen TXT-Records."""
        spf_record = next((record for record in txt_records if record.lower().startswith('v=spf1')), None)
        if spf_record:
            print(f"  {Colors.success('SPF:')} Vorhanden")
        else:
            print(f"  {Colors.warning('SPF:')} Nicht gefunden")
        return {'spf_record': spf_record}

    def _analyze_spf_policy(self, spf_record: Optional[str]) -> Dict[str, Dict[str, Any]]:
        """
        Bewertet die SPF-Policy ueber die reine Existenz hinaus.

        Fuer die forensische Einordnung sind vor allem relevant:
        - ob ein `all`-Mechanismus vorhanden ist
        - wie strikt dieser ist (`-all` vs `~all`)
        - wie komplex die Policy ueber include/redirect aufgebaut ist
        """
        analysis = {
            'status': 'missing',
            'all_mechanism': 'not_present',
            'includes_count': 0,
            'redirect_present': False,
            'ip4_count': 0,
            'ip6_count': 0,
            'summary': 'not configured',
            'findings': [],
        }

        if not spf_record:
            analysis['findings'].append('No SPF policy configured')
            return {'spf_analysis': analysis}

        tokens = [token.strip() for token in spf_record.split() if token.strip()]
        analysis['status'] = 'configured'
        analysis['includes_count'] = sum(1 for token in tokens if token.lower().startswith('include:'))
        analysis['redirect_present'] = any(token.lower().startswith('redirect=') for token in tokens)
        analysis['ip4_count'] = sum(1 for token in tokens if token.lower().startswith('ip4:'))
        analysis['ip6_count'] = sum(1 for token in tokens if token.lower().startswith('ip6:'))

        all_token = next((token for token in tokens[1:] if token.lower().endswith('all')), None)
        if all_token:
            qualifier = all_token[0] if all_token[0] in ['+', '-', '~', '?'] else '+'
            mechanism_map = {
                '-': 'hard_fail',
                '~': 'soft_fail',
                '?': 'neutral',
                '+': 'allow_all'
            }
            analysis['all_mechanism'] = mechanism_map.get(qualifier, 'allow_all')
        else:
            analysis['findings'].append('SPF policy has no explicit all-mechanism')

        if analysis['all_mechanism'] == 'hard_fail':
            analysis['summary'] = f"hard fail (-all), includes: {analysis['includes_count']}"
        elif analysis['all_mechanism'] == 'soft_fail':
            analysis['summary'] = f"soft fail (~all), includes: {analysis['includes_count']}"
            analysis['findings'].append('SPF uses soft fail (~all)')
        elif analysis['all_mechanism'] == 'neutral':
            analysis['summary'] = f"neutral (?all), includes: {analysis['includes_count']}"
            analysis['findings'].append('SPF uses neutral all-policy (?all)')
        elif analysis['all_mechanism'] == 'allow_all':
            analysis['summary'] = 'allow-all (+all) - unsafe'
            analysis['findings'].append('SPF allows all senders (+all)')
        else:
            analysis['summary'] = f"configured, includes: {analysis['includes_count']}"

        if analysis['redirect_present']:
            analysis['summary'] += ', redirect present'

        return {'spf_analysis': analysis}

    def _analyze_dmarc_record(self, domain: str) -> Dict[str, Optional[str]]:
        """Ermittelt den DMARC-Record unter _dmarc.<domain>."""
        print(f"  {Colors.info('DMARC:')} Abfrage...")
        records = self._resolve_dns_records(f'_dmarc.{domain}', 'TXT')
        normalized_records = [self._normalize_txt_record(record) for record in records]
        dmarc_record = next((record for record in normalized_records if record.lower().startswith('v=dmarc1')), None)

        if dmarc_record:
            print(f"    {Colors.success('Richtlinie erkannt')}")
        else:
            print(f"    {Colors.warning('Nicht gefunden')}")

        return {'dmarc_record': dmarc_record}

    def _parse_policy_directives(self, record: Optional[str]) -> Dict[str, str]:
        """Parst semikolon-separierte Policy-Direktiven wie bei DMARC sauber aus."""
        directives = {}
        if not record:
            return directives

        for part in str(record).split(';'):
            directive = part.strip()
            if not directive or '=' not in directive:
                continue
            key, value = directive.split('=', 1)
            directives[key.strip().lower()] = value.strip()

        return directives

    def _analyze_dmarc_configuration(self, dmarc_record: Optional[str]) -> Dict[str, Dict[str, Any]]:
        """Bewertet DMARC-Konfiguration inklusive Policy- und Reporting-Status."""
        directives = self._parse_policy_directives(dmarc_record)
        policy = directives.get('p')
        has_reporting = bool(directives.get('rua') or directives.get('ruf'))

        analysis = {
            'status': 'missing' if not dmarc_record else 'configured',
            'policy': policy or 'not_set',
            'subdomain_policy': directives.get('sp') or policy or 'not_set',
            'reporting_enabled': has_reporting,
            'alignment': {
                'adkim': directives.get('adkim', 'r'),
                'aspf': directives.get('aspf', 'r')
            },
            'summary': 'not configured',
            'findings': [],
        }

        if not dmarc_record:
            analysis['findings'].append('DMARC not configured')
            return {'dmarc_analysis': analysis}

        reporting_text = 'reporting enabled' if has_reporting else 'no reporting endpoints'
        analysis['summary'] = f"policy: {analysis['policy']}, {reporting_text}"

        if analysis['policy'] == 'none':
            analysis['findings'].append('DMARC policy is monitor-only (p=none)')
        elif analysis['policy'] not in {'quarantine', 'reject'}:
            analysis['findings'].append('DMARC policy is missing or non-standard')

        if not has_reporting:
            analysis['findings'].append('DMARC has no rua/ruf reporting destination')

        return {'dmarc_analysis': analysis}

    def _analyze_dkim_selectors(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """
        Sucht nach haeufig verwendeten DKIM-Selektoren.

        Die Discovery ist absichtlich heuristisch: Wir testen eine kleine Menge
        verbreiteter Selektoren und melden Funde, ohne den DNS-Teil unnötig zu
        verlangsamen.
        """
        print(f"  {Colors.info('DKIM-Selectors:')} Heuristische Discovery...")
        discovered = []
        tested_selectors = []

        for selector in self.common_dkim_selectors:
            tested_selectors.append(selector)
            query_name = f'{selector}._domainkey.{domain}'
            records = self._resolve_dns_records(query_name, 'TXT')
            normalized_records = [self._normalize_txt_record(record) for record in records]
            dkim_record = next(
                (
                    record for record in normalized_records
                    if 'v=dkim1' in record.lower() or 'p=' in record.lower()
                ),
                None
            )
            if dkim_record:
                discovered.append({
                    'selector': selector,
                    'record': dkim_record
                })
            if len(discovered) >= 3:
                break

        if discovered:
            print(f"    {Colors.success('Gefunden:')} {len(discovered)} DKIM-Selector(en)")
            for entry in discovered:
                print(f"    - {entry['selector']}._domainkey")
            status = 'selectors_found'
        else:
            print(f"    {Colors.warning('Keine gaengigen DKIM-Selectoren erkannt')}")
            status = 'not_detected'

        return {
            'dkim': {
                'status': status,
                'selectors': discovered,
                'tested_selectors': tested_selectors,
                'discovery_mode': 'heuristic_common_selectors'
            }
        }

    def _normalize_caa_field(self, value: Any) -> str:
        """
        Normalisiert CAA-Teilfelder auf lesbaren Text.

        dnspython liefert `tag` und `value` je nach Version teils als Bytes.
        Der Report soll daraus immer klare Labels wie `issue letsencrypt.org`
        statt Python-Bytes-Notation machen.
        """
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='replace').strip().strip('"')
        return str(value).strip().strip('"')

    def _analyze_caa_records(self, domain: str) -> Dict[str, List[Dict[str, Any]]]:
        """Ermittelt CAA-Policies fuer Zertifikatsausstellung."""
        print(f"  {Colors.info('CAA-Records:')} Abfrage...")
        records = self._resolve_dns_records(domain, 'CAA')
        caa_records = []

        for record in records:
            caa_records.append({
                'flags': int(record.flags),
                'tag': self._normalize_caa_field(record.tag),
                'value': self._normalize_caa_field(record.value)
            })

        if caa_records:
            print(f"    {Colors.success('Gefunden:')} {len(caa_records)} CAA-Policies")
        else:
            print(f"    {Colors.warning('Keine CAA-Policies gefunden')}")

        return {'caa_records': caa_records}

    def _analyze_dnssec(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Prueft, ob DNSSEC-Hinweise wie DS oder DNSKEY vorhanden sind."""
        print(f"  {Colors.info('DNSSEC:')} Pruefung...")
        ds_records = self._resolve_dns_records(domain, 'DS')
        dnskey_records = self._resolve_dns_records(domain, 'DNSKEY')

        dnssec = {
            'has_ds': bool(ds_records),
            'has_dnskey': bool(dnskey_records),
            'status': 'enabled' if ds_records or dnskey_records else 'not_detected'
        }

        if dnssec['status'] == 'enabled':
            print(f"    {Colors.success('DNSSEC erkannt')}")
        else:
            print(f"    {Colors.warning('Keine DNSSEC-Indikatoren erkannt')}")

        return {'dnssec': dnssec}

    def _analyze_zone_transfer(self, domain: str, nameservers: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Prueft, ob ein offener AXFR gegen autoritative Nameserver moeglich ist.

        Bereits ein erfolgreicher Transfer waere fuer ein professionelles Tool
        ein sehr relevanter Befund.
        """
        print(f"  {Colors.info('Zone Transfer (AXFR):')} Pruefung...")
        tested_nameservers = []

        for nameserver in nameservers[:3]:
            server_ips = self._resolve_dns_records(nameserver, 'A')
            for server_ip in server_ips[:1]:
                ns_ip = str(server_ip)
                tested_nameservers.append(ns_ip)
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, domain, lifetime=self.dns_timeout)
                    )
                    if zone:
                        record_count = len(zone.nodes.keys())
                        print(f"    {Colors.error('AXFR erlaubt:')} {nameserver} ({record_count} Records)")
                        return {
                            'zone_transfer': {
                                'status': 'allowed',
                                'successful_nameserver': nameserver,
                                'successful_nameserver_ip': ns_ip,
                                'record_count': record_count,
                                'tested_nameservers': tested_nameservers
                            }
                        }
                except Exception:
                    continue

        print(f"    {Colors.success('Nicht erlaubt oder gefiltert')}")
        return {
            'zone_transfer': {
                'status': 'not_allowed',
                'tested_nameservers': tested_nameservers
            }
        }

    def _assess_dns_configuration(
        self,
        spf_analysis: Dict[str, Any],
        dmarc_analysis: Dict[str, Any],
        dkim: Dict[str, Any],
        dnssec: Dict[str, Any],
        zone_transfer: Dict[str, Any],
        caa_records: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Verdichtet die Einzelbefunde zu einer kompakten DNS-Sicherheitsbewertung.

        Das Ziel ist keine überdramatische Risikologik, sondern ein gut lesbarer
        Härtungsstatus mit klaren Lücken und vorhandenen Schutzmaßnahmen.
        """
        findings = []
        strengths = []

        spf_status = spf_analysis.get('status')
        spf_all = spf_analysis.get('all_mechanism')
        if spf_status != 'configured':
            findings.append('SPF not configured')
        elif spf_all == 'hard_fail':
            strengths.append('SPF hard-fail enforcement present')
        elif spf_all == 'soft_fail':
            findings.append('SPF uses soft-fail enforcement')
        elif spf_all in {'allow_all', 'neutral', 'not_present'}:
            findings.append('SPF policy is weak or permissive')

        dmarc_status = dmarc_analysis.get('status')
        dmarc_policy = dmarc_analysis.get('policy')
        if dmarc_status != 'configured':
            findings.append('DMARC not configured')
        elif dmarc_policy == 'none':
            findings.append('DMARC is monitor-only')
        elif dmarc_policy in {'quarantine', 'reject'}:
            strengths.append(f"DMARC enforcement policy: {dmarc_policy}")

        if not dmarc_analysis.get('reporting_enabled'):
            findings.append('DMARC reporting not configured')
        elif dmarc_status == 'configured':
            strengths.append('DMARC reporting enabled')

        if dkim.get('status') == 'selectors_found':
            strengths.append('Common DKIM selectors detected via heuristic discovery')
        else:
            findings.append('No common DKIM selector detected during heuristic discovery')

        if dnssec.get('status') == 'enabled':
            strengths.append('DNSSEC indicators detected')
        else:
            findings.append('DNSSEC not detected')

        if zone_transfer.get('status') == 'allowed':
            findings.append('Zone transfer allowed')
        elif zone_transfer.get('status') == 'not_allowed':
            strengths.append('Zone transfer not allowed or filtered')

        if caa_records:
            strengths.append('CAA issuance policy configured')
        else:
            findings.append('CAA policy not configured')

        if 'Zone transfer allowed' in findings:
            status = 'high_exposure'
            summary = 'high exposure - authoritative DNS disclosure risk'
        elif not findings:
            status = 'well_hardened'
            summary = 'well hardened configuration'
        elif len(findings) <= 2 and len(strengths) >= 3:
            status = 'partially_hardened'
            summary = 'partially hardened configuration'
        else:
            status = 'baseline_gaps'
            summary = 'baseline configuration with hardening gaps'

        return {
            'dns_configuration_assessment': {
                'status': status,
                'summary': summary,
                'findings': findings,
                'strengths': strengths
            }
        }

    def _normalize_txt_record(self, record: Any) -> str:
        """Normalisiert TXT-Antworten aus dnspython in eine lesbare Zeichenkette."""
        if hasattr(record, 'strings'):
            parts = [
                part.decode('utf-8', errors='replace') if isinstance(part, bytes) else str(part)
                for part in record.strings
            ]
            return ''.join(parts).strip()

        if hasattr(record, 'to_text'):
            return record.to_text().strip('"')

        return str(record).strip().strip('"')

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

        if results.get('soa_record'):
            print(f"SOA: {Colors.success('AVAILABLE')}")
        else:
            print(f"SOA: {Colors.warning('NOT AVAILABLE')}")

        if results.get('dmarc_record'):
            print(f"DMARC: {Colors.success('CONFIGURED')}")
        else:
            print(f"DMARC: {Colors.warning('NOT CONFIGURED')}")

        if results.get('dkim', {}).get('status') == 'selectors_found':
            selector_count = len(results.get('dkim', {}).get('selectors', []) or [])
            print(f"DKIM: {Colors.success(f'{selector_count} SELECTOR(S) DISCOVERED')}")
        else:
            print(f"DKIM: {Colors.warning('NO COMMON SELECTORS DETECTED')}")

        if results.get('dnssec', {}).get('status') == 'enabled':
            print(f"DNSSEC: {Colors.success('DETECTED')}")
        else:
            print(f"DNSSEC: {Colors.warning('NOT DETECTED')}")

        assessment_summary = (
            results.get('dns_configuration_assessment', {}).get('summary')
            or 'not assessed'
        )
        print(f"DNS Assessment: {Colors.info(str(assessment_summary).upper())}")
        
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

        
