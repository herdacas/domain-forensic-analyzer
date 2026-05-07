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
            'dkim', 'mail', 'k1', 'amazonses', 's1', 'smtp'
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
        if not DomainValidator.is_valid_domain(domain):
            error_msg = f"Ungueltige Domain: {domain}"
            return {'error': error_msg, 'analysis_status': 'fehlgeschlagen'}

        clean_domain = DomainValidator.clean_domain(domain)
        
        # Das Basisschema bleibt absichtlich klein und stabil.
        results = {
            'domain': clean_domain,
            'ipv4': None,
            'ipv6': None,
            'reverse_dns': None,
            'a_record_ttl': None,
            'mx_records': [],
            'mx_record_ttl': None,
            'ns_records': [],
            'ns_record_ttl': None,
            'soa_record': {},
            'txt_records': [],
            'spf_record': None,
            'spf_analysis': {},
            'spf_includes': [],
            'dmarc_record': None,
            'dmarc_analysis': {},
            'dkim': {},
            'caa_records': [],
            'dnssec': {},
            'zone_transfer': {},
            'dns_configuration_assessment': {},
        }
        
        results.update(self._resolve_ipv4(clean_domain))
        results.update(self._resolve_ipv6(clean_domain))
        results.update(self._resolve_a_ttl(clean_domain))

        if results.get('ipv4'):
            results.update(self._reverse_dns_lookup(results['ipv4']))

        results.update(self._analyze_mx_records(clean_domain))
        results.update(self._resolve_mx_ttl(clean_domain))
        results.update(self._analyze_ns_records(clean_domain))
        results.update(self._resolve_ns_ttl(clean_domain))

        results.update(self._analyze_soa_record(clean_domain))
        results.update(self._analyze_txt_records(clean_domain))
        results.update(self._analyze_spf_record(results.get('txt_records', [])))
        results.update(self._analyze_spf_policy(results.get('spf_record')))
        results.update(self._resolve_spf_includes_chain(results.get('spf_record'), clean_domain))
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
            
            return {'ipv4': ipv4_address}

        except socket.gaierror:
            return {'ipv4': None}
        except Exception:
            return {'ipv4': None}
    
    def _resolve_ipv6(self, domain: str) -> Dict[str, Optional[str]]:
        """Prueft, ob eine IPv6-Aufloesung vorhanden ist."""
        try:
            with self._socket_timeout():
                addr_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
            
            if addr_info:
                ipv6_address = addr_info[0][4][0]
                return {'ipv6': ipv6_address}

            return {'ipv6': None}

        except (socket.gaierror, OSError):
            return {'ipv6': None}
    
    def _reverse_dns_lookup(self, ip_address: str) -> Dict[str, Optional[str]]:
        """Fuehrt den PTR-Lookup fuer die aufgeloeste IPv4-Adresse durch."""
        try:
            with self._socket_timeout():
                hostname = socket.gethostbyaddr(ip_address)[0]
            
            return {'reverse_dns': hostname}

        except (socket.herror, socket.gaierror, OSError):
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
            return None
        except Exception:
            return None

        if result.returncode != 0:
            return None

        return result.stdout or ""

    def _analyze_mx_records(self, domain: str) -> Dict[str, List[Dict[str, str]]]:
        """Ermittelt MX-Records via dnspython fuer vollstaendige FQDNs."""
        try:
            answer = self._create_resolver().resolve(domain, 'MX')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return {'mx_records': []}
        except Exception:
            return {'mx_records': []}

        seen: set = set()
        mx_records: List[Dict[str, str]] = []
        for rdata in sorted(answer, key=lambda r: r.preference):
            server = str(rdata.exchange).rstrip('.')
            if not server or server.lower() in seen:
                continue
            seen.add(server.lower())
            mx_records.append({'priority': str(rdata.preference), 'server': server})
        return {'mx_records': mx_records}
    
    def _analyze_ns_records(self, domain: str) -> Dict[str, List[str]]:
        """Ermittelt NS-Records ueber nslookup und normalisiert das Ergebnis."""
        output = self._query_nslookup('NS', domain)
        if output is None:
            return {'ns_records': []}

        ns_records = self._parse_ns_records(output, domain)
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
        records = self._resolve_dns_records(domain, 'SOA')
        if not records:
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
        return {'soa_record': soa_record}

    def _analyze_txt_records(self, domain: str) -> Dict[str, List[str]]:
        """Ermittelt TXT-Records fuer SPF- und Policy-bezogene Hinweise."""
        records = self._resolve_dns_records(domain, 'TXT')
        txt_records = [self._normalize_txt_record(record) for record in records]
        txt_records = [record for record in txt_records if record]
        return {'txt_records': txt_records}

    def _analyze_spf_record(self, txt_records: List[str]) -> Dict[str, Optional[str]]:
        """Extrahiert den SPF-Record aus bereits gelesenen TXT-Records."""
        spf_record = next((record for record in txt_records if record.lower().startswith('v=spf1')), None)
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
        records = self._resolve_dns_records(f'_dmarc.{domain}', 'TXT')
        normalized_records = [self._normalize_txt_record(record) for record in records]
        dmarc_record = next((record for record in normalized_records if record.lower().startswith('v=dmarc1')), None)
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
        rua = directives.get('rua')
        ruf = directives.get('ruf')
        has_reporting = bool(rua or ruf)

        analysis = {
            'status': 'missing' if not dmarc_record else 'configured',
            'policy': policy or 'not_set',
            'subdomain_policy': directives.get('sp') or policy or 'not_set',
            'reporting_enabled': has_reporting,
            'rua': rua,
            'ruf': ruf,
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

        status = 'selectors_found' if discovered else 'not_detected'

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
        records = self._resolve_dns_records(domain, 'CAA')
        caa_records = [
            {
                'flags': int(record.flags),
                'tag': self._normalize_caa_field(record.tag),
                'value': self._normalize_caa_field(record.value)
            }
            for record in records
        ]
        return {'caa_records': caa_records}

    def _analyze_dnssec(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Prueft, ob DNSSEC-Hinweise wie DS oder DNSKEY vorhanden sind."""
        ds_records = self._resolve_dns_records(domain, 'DS')
        dnskey_records = self._resolve_dns_records(domain, 'DNSKEY')

        dnssec = {
            'has_ds': bool(ds_records),
            'has_dnskey': bool(dnskey_records),
            'status': 'enabled' if ds_records or dnskey_records else 'not_detected'
        }
        return {'dnssec': dnssec}

    def _analyze_zone_transfer(self, domain: str, nameservers: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Prueft, ob ein offener AXFR gegen autoritative Nameserver moeglich ist.

        Bereits ein erfolgreicher Transfer waere fuer ein professionelles Tool
        ein sehr relevanter Befund.
        """
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

    # ------------------------------------------------------------------
    # TTL helpers
    # ------------------------------------------------------------------

    def _resolve_a_ttl(self, domain: str) -> Dict[str, Any]:
        """Ermittelt den TTL des A-Records via dnspython rrset."""
        try:
            answer = self._create_resolver().resolve(domain, 'A')
            return {'a_record_ttl': int(answer.rrset.ttl)}
        except Exception:
            return {'a_record_ttl': None}

    def _resolve_mx_ttl(self, domain: str) -> Dict[str, Any]:
        """Ermittelt den TTL des MX-Records via dnspython rrset."""
        try:
            answer = self._create_resolver().resolve(domain, 'MX')
            return {'mx_record_ttl': int(answer.rrset.ttl)}
        except Exception:
            return {'mx_record_ttl': None}

    def _resolve_ns_ttl(self, domain: str) -> Dict[str, Any]:
        """Ermittelt den TTL des NS-Records via dnspython rrset."""
        try:
            answer = self._create_resolver().resolve(domain, 'NS')
            return {'ns_record_ttl': int(answer.rrset.ttl)}
        except Exception:
            return {'ns_record_ttl': None}

    # ------------------------------------------------------------------
    # SPF include-chain resolution (MAX_DEPTH = 2)
    # ------------------------------------------------------------------

    _SPF_MAX_DEPTH = 2

    def _resolve_spf_includes_chain(self, spf_record: Optional[str], domain: str) -> Dict[str, Any]:
        """
        Loest SPF include-Verweise rekursiv auf (max. 2 Ebenen).

        Gibt eine flache Liste von Eintraegen zurueck, wobei jeder Eintrag
        den aufgeloesten Domain-Namen, die Tiefe und den gefundenen SPF-Record
        enthaelt.  Bei Fehler oder fehlender SPF-Antwort wird 'record' None
        gesetzt und 'error' befuellt.
        """
        flat: List[Dict[str, Any]] = []
        self._walk_spf(spf_record, depth=1, seen=set(), flat=flat)
        return {'spf_includes': flat}

    def _walk_spf(
        self,
        spf_record: Optional[str],
        depth: int,
        seen: set,
        flat: List[Dict[str, Any]],
    ) -> None:
        """Rekursiver Walker fuer SPF include-Kette."""
        if not spf_record or depth > self._SPF_MAX_DEPTH:
            return

        tokens = spf_record.split()
        targets: List[str] = []
        for token in tokens:
            lower = token.lower()
            if lower.startswith('include:') and ':' in token:
                targets.append(token.split(':', 1)[1].strip())
            elif lower.startswith('redirect=') and '=' in token:
                targets.append(token.split('=', 1)[1].strip())

        for target in targets:
            if target in seen:
                continue
            seen.add(target)

            entry: Dict[str, Any] = {
                'domain': target,
                'depth': depth,
                'record': None,
                'error': None,
            }
            try:
                txt_records = self._resolve_dns_records(target, 'TXT')
                normalized = [self._normalize_txt_record(r) for r in txt_records]
                included_spf = next(
                    (r for r in normalized if r.lower().startswith('v=spf1')),
                    None,
                )
                entry['record'] = included_spf
            except Exception as exc:
                entry['error'] = str(exc)

            flat.append(entry)

            if entry['record'] and depth < self._SPF_MAX_DEPTH:
                self._walk_spf(entry['record'], depth + 1, seen, flat)

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

        
