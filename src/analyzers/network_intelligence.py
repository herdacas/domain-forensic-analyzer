          
"""
Network Intelligence Module for Domain Forensic Analyzer
Advanced Network-Analyse und OPSEC-Assessment - LOGICALLY CORRECTED

Step 2.4 Implementation - Option A Quick Enhancement - COMPLETE
"""

import subprocess
import platform
import sys
import os
import time
import urllib.request
import urllib.error
import socket
import re
import requests as _requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from typing import Dict, List, Optional, Any
from datetime import datetime

# Foundation-Module importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.utils.colors import Colors
from config.settings import get_settings

class NetworkIntelligence:
    """
    Enhanced Network-Analyse fuer forensische Untersuchungen
    
    Fuehrt Traceroute-Analyse, OPSEC-Assessment und Hop-Intelligence
    durch. Analysiert Netzwerkpfade mit realistischer Risk-Bewertung.
    """
    
    def __init__(self):
        """Initialisiert Network Intelligence mit Enhanced-Features"""
        self.results = {}
        self.settings = get_settings()
        self.traceroute_timeout_regional = self.settings.scan_settings.traceroute_timeout_regional
        self.traceroute_timeout_international = self.settings.scan_settings.traceroute_timeout_international
        self.encoding = self.settings.scan_settings.traceroute_encoding
        self.max_traceroute_hops = getattr(self.settings.scan_settings, 'max_traceroute_hops', 15)

        # Plattform-spezifische Konfiguration
        self.platform = platform.system().lower()
        self.is_windows = self.platform == 'windows'
        # Probe timeout is intentionally lower than the overall command timeout so
        # partial routes return faster without losing the useful "where did it stop?"
        # context for the report. We also stop after a short no-response streak,
        # because later asterisks rarely add investigative value but add a lot of wait.
        self.traceroute_probe_timeout_ms = 2000 if self.is_windows else 2500
        self.max_consecutive_no_response_hops = 3
        
        # CORRECTED: Echte Consumer-ISP Patterns (nicht National Carrier)
        self.consumer_isp_patterns = [
            'comcast', 'charter', 'cox', 'centurylink', 'frontier', 'windstream',
            'mediacom', 'suddenlink', 'optimum', 'spectrum', 'xfinity',
            'virgin', 'sky', 'bt.home', 'talktalk', 'plusnet'  # UK Consumer
        ]
        
        # National/Business ISPs (nicht als Consumer eingestuft)
        self.national_isp_patterns = [
            'telekom', 'vodafone', 'orange', 'verizon.net', 'att.net'
        ]
        
        # Internationale Backbone-Indikatoren
        self.international_indicators = [
            'telia', 'level3', 'gttsolutions', 'cogent', 'he.net', 'ntt.net',
            'sprint', 'seabone', 'retn.net', 'lumen', 'zayo'
        ]
    
    def analyze_network(self, ip_address: str, domain: str = None) -> Dict[str, Any]:
        """Enhanced Network Intelligence-Analyse"""
        print(Colors.header("NETWORK ANALYSIS"))
        print(Colors.investigation_separator(60))
        
        if not ip_address:
            error_msg = "Keine IP-Adresse fuer Netzwerk-Analyse verfuegbar"
            print(Colors.error(error_msg))
            return {'error': error_msg, 'analysis_status': 'fehlgeschlagen'}
        
        print(f"Analysiere Netzwerkpfad zu: {Colors.format_ip(ip_address)}")
        if domain:
            print(f"Zugehoerige Domain: {Colors.format_domain(domain)}")
        
        # Ergebnis-Dictionary initialisieren
        results = {
            'target_ip': ip_address,
            'target_domain': domain,
            'timestamp': datetime.now().isoformat(),
            'traceroute_data': {},
            'enhanced_network_path': [],
            'connectivity_test': {},
            'opsec_assessment': {},
            'route_classification': {},
            'hop_intelligence': {},
            'analysis_status': 'gestartet'
        }
        
        # Konnektivitaets-Tests
        print(f"\n{Colors.section_header('CONNECTIVITY', 50)}")
        connectivity = self._test_connectivity(ip_address, domain)
        results['connectivity_test'] = connectivity

        # HTTP/S behavior analysis (headers, redirects, HSTS)
        if domain:
            results['http_behavior'] = self._test_http_behavior(domain)
        else:
            results['http_behavior'] = {'available': False, 'assessment': 'unavailable'}
        
        # Traceroute-Analyse
        print(f"\n{Colors.section_header('TRACEROUTE', 50)}")
        traceroute_data = self._perform_traceroute(ip_address)
        results['traceroute_data'] = traceroute_data
        
        # Enhanced Netzwerkpfad-Analyse
        if traceroute_data.get('status') in ['success', 'partial'] and traceroute_data.get('hops'):
            print(f"\n{Colors.section_header('NETWORK PATH', 50)}")
            enhanced_path = self._analyze_enhanced_network_path(traceroute_data.get('hops', []))
            results['enhanced_network_path'] = enhanced_path
            
            # Hop-Intelligence
            print(f"\n{Colors.section_header('HOP INTELLIGENCE', 50)}")
            hop_intelligence = self._gather_hop_intelligence(enhanced_path)
            results['hop_intelligence'] = hop_intelligence
            
            # Route-Klassifikation
            route_classification = self._classify_route(enhanced_path, hop_intelligence)
            results['route_classification'] = route_classification
            
            # Enhanced OPSEC-Assessment
            print(f"\n{Colors.section_header('OPSEC ASSESSMENT', 50)}")
            opsec_assessment = self._assess_enhanced_opsec_risks(enhanced_path, hop_intelligence, route_classification)
            results['opsec_assessment'] = opsec_assessment
        
        # Analyse abschliessen
        results['analysis_status'] = 'abgeschlossen'
        self.results = results
        
        # Enhanced Zusammenfassung anzeigen
        self._display_enhanced_summary(results)
        return results
    
    def _test_connectivity(self, ip_address: str, domain: str = None) -> Dict[str, Any]:
        """Testet Konnektivitaetsaspekte"""
        print(f"  {Colors.info('Konnektivitaets-Tests:')} Pruefe Erreichbarkeit...")
        
        connectivity = {
            'ping_reachable': False,
            'http_accessible': False,
            'https_accessible': False,
            'response_times': {}
        }
        
        # Ping-Test
        ping_result = self._test_ping(ip_address)
        connectivity['ping_reachable'] = ping_result['reachable']
        if ping_result.get('avg_time'):
            connectivity['response_times']['ping'] = ping_result['avg_time']
        
        # HTTP/HTTPS-Tests
        if domain:
            http_result = self._test_http_connectivity(domain)
            connectivity.update(http_result)
        
        # Ergebnisse anzeigen
        if connectivity['ping_reachable']:
            ping_time = connectivity['response_times'].get('ping', 'unknown')
            print(f"    {Colors.success('Ping:')} Erreichbar ({ping_time})")
        else:
            print(f"    {Colors.warning('Ping:')} Nicht erreichbar oder gefiltert")
        
        if domain:
            if connectivity['https_accessible']:
                print(f"    {Colors.success('HTTPS:')} Verfuegbar")
            elif connectivity['http_accessible']:
                print(f"    {Colors.warning('HTTP:')} Verfuegbar (unsicher)")
            else:
                print(f"    {Colors.error('Web-Services:')} Nicht erreichbar")
        
        return connectivity
    
    def _test_ping(self, ip_address: str) -> Dict[str, Any]:
        """Plattformspezifischer Ping-Test"""
        try:
            if self.is_windows:
                cmd = ['ping', '-n', '3', ip_address]
            else:
                cmd = ['ping', '-c', '3', ip_address]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                encoding=self.encoding if self.is_windows else 'utf-8',
                errors='replace'
            )
            
            if result.returncode == 0:
                avg_time = self._extract_ping_time(result.stdout)
                return {'reachable': True, 'avg_time': avg_time}
            else:
                return {'reachable': False}
                
        except Exception:
            return {'reachable': False}
    
    def _extract_ping_time(self, ping_output: str) -> Optional[str]:
        """Extrahiert Ping-Zeit"""
        lines = ping_output.lower().split('\n')
        for line in lines:
            if 'average' in line or 'mittelwert' in line or 'durchschnitt' in line:
                time_match = re.search(r'(\d+(?:\.\d+)?)\s*ms', line)
                if time_match:
                    return f"{time_match.group(1)}ms"
        return None
    
    def _test_http_connectivity(self, domain: str) -> Dict[str, Any]:
        """Testet HTTP/HTTPS-Konnektivitaet"""
        connectivity = {'http_accessible': False, 'https_accessible': False}
        
        # HTTPS-Test
        try:
            url = f"https://{domain}"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Domain-Forensic-Analyzer/3.4')
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    connectivity['https_accessible'] = True
        except:
            pass
        
        # HTTP-Test (falls HTTPS fehlschlaegt)
        if not connectivity['https_accessible']:
            try:
                url = f"http://{domain}"
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'Domain-Forensic-Analyzer/3.4')
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        connectivity['http_accessible'] = True
            except:
                pass
        
        return connectivity

    def _test_http_behavior(self, domain: str) -> Dict[str, Any]:
        """
        Probe HTTP and HTTPS separately with redirect tracking.
        Uses requests with allow_redirects=False for each hop.
        """
        result: Dict[str, Any] = {
            'available': False,
            'http_status': None,
            'https_status': None,
            'server': None,
            'hsts': False,
            'hsts_max_age': None,
            'hsts_include_subdomains': False,
            'has_redirect': False,
            'redirect_chain': [],
            'assessment': 'unavailable',
        }

        session = _requests.Session()
        session.headers['User-Agent'] = 'Domain-Forensic-Analyzer/1.0'

        # --- HTTP probe (single hop, no redirect following) ---
        try:
            r = session.get(
                f"http://{domain}",
                allow_redirects=False,
                timeout=10,
                verify=False,
            )
            result['http_status'] = r.status_code
            if r.status_code in (301, 302, 303, 307, 308):
                result['has_redirect'] = True
                result['redirect_chain'] = [
                    {'url': f"http://{domain}", 'status': r.status_code}
                ]
                location = r.headers.get('Location', '')
                if location and not location.startswith('http'):
                    location = f"http://{domain}{location}"
                if location:
                    result['redirect_chain'].append({'url': location, 'status': None})
        except Exception:
            pass

        # --- HTTPS probe: follow up to 5 hops manually ---
        try:
            url = f"https://{domain}"
            visited: set = set()
            chain: list = []
            final_resp = None

            for _ in range(5):
                if url in visited:
                    break
                visited.add(url)
                resp = session.get(url, allow_redirects=False, timeout=10, verify=False)
                chain.append({'url': url, 'status': resp.status_code})
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '')
                    if not location:
                        break
                    if not location.startswith('http'):
                        from urllib.parse import urlparse
                        p = urlparse(url)
                        location = f"{p.scheme}://{p.netloc}{location}"
                    url = location
                else:
                    final_resp = resp
                    break

            if final_resp is not None:
                result['https_status'] = final_resp.status_code
                result['available'] = True

                server = (
                    final_resp.headers.get('Server')
                    or final_resp.headers.get('server')
                )
                if server:
                    result['server'] = server.strip()

                hsts_val = (
                    final_resp.headers.get('Strict-Transport-Security')
                    or final_resp.headers.get('strict-transport-security')
                )
                if hsts_val:
                    result['hsts'] = True
                    for part in hsts_val.split(';'):
                        part = part.strip()
                        if part.lower().startswith('max-age='):
                            try:
                                result['hsts_max_age'] = int(part.split('=', 1)[1])
                            except ValueError:
                                pass
                        if part.lower() == 'includesubdomains':
                            result['hsts_include_subdomains'] = True

        except Exception:
            pass

        # --- Assessment ---
        https_ok = (
            result['https_status'] is not None
            and 200 <= result['https_status'] < 400
        )
        if https_ok and result['has_redirect'] and result['hsts']:
            result['assessment'] = 'strong'
        elif https_ok and result['hsts']:
            result['assessment'] = 'moderate'
        elif https_ok and result['has_redirect']:
            result['assessment'] = 'moderate'
        elif https_ok:
            result['assessment'] = 'weak'
        elif result['http_status'] is not None and not https_ok:
            result['assessment'] = 'unavailable'

        return result

    def _perform_traceroute(self, ip_address: str) -> Dict[str, Any]:
        """Fuehrt Traceroute durch"""
        print(f"  {Colors.info('Traceroute-Analyse:')} Ermittle Netzwerkpfad...")
        
        timeout = self.traceroute_timeout_international if self._is_likely_international_route(ip_address) else self.traceroute_timeout_regional
        metadata = {
            'command_timeout_seconds': timeout,
            'probe_timeout_ms': self.traceroute_probe_timeout_ms,
            'max_hops': self.max_traceroute_hops
        }

        process = None
        try:
            if self.is_windows:
                cmd = ['tracert', '-h', str(self.max_traceroute_hops), '-w', str(self.traceroute_probe_timeout_ms), ip_address]
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    encoding=self.encoding, errors='replace'
                )

                output_lines = []
                start_time = time.monotonic()
                consecutive_no_response_hops = 0

                while True:
                    if time.monotonic() - start_time > timeout:
                        return self._stop_traceroute_process(
                            process, output_lines, metadata,
                            f'Traceroute command timed out after {timeout}s'
                        )

                    line = process.stdout.readline() if process.stdout else ''
                    if line:
                        output_lines.append(line)
                        hop_info = self._parse_traceroute_line(line.strip())
                        if hop_info:
                            if hop_info.get('status') == 'responsive':
                                consecutive_no_response_hops = 0
                            else:
                                consecutive_no_response_hops += 1
                                if consecutive_no_response_hops >= self.max_consecutive_no_response_hops:
                                    return self._stop_traceroute_process(
                                        process, output_lines, metadata,
                                        f'Traceroute stopped after {self.max_consecutive_no_response_hops} consecutive no-response hops'
                                    )
                        continue

                    if process.poll() is not None:
                        break

                    time.sleep(0.05)

                remaining_stdout, _ = process.communicate(timeout=2)
                if remaining_stdout:
                    output_lines.append(remaining_stdout)

                full_output = ''.join(output_lines)
                if process.returncode == 0 or full_output:
                    hops = self._parse_traceroute_output(full_output)
                    metadata.update(self._summarize_traceroute_progress(hops))
                    return {'status': 'success', 'hops': hops, 'total_hops': len(hops), **metadata}
                return {'status': 'failed', 'error': 'No route found', **metadata}

            else:
                # Linux: use tracepath directly (pre-installed on most distributions)
                cmd = ['tracepath', '-m', str(self.max_traceroute_hops), ip_address]
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding='utf-8', errors='replace'
                )
                try:
                    stdout, _ = process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, _ = process.communicate()
                hops = self._parse_tracepath_output(stdout)
                # Apply the same early-stopping as the Windows path:
                # truncate after max_consecutive_no_response_hops consecutive timeouts
                trimmed, consecutive, stopped_early = [], 0, False
                for hop in hops:
                    trimmed.append(hop)
                    if hop['status'] != 'responsive':
                        consecutive += 1
                        if consecutive >= self.max_consecutive_no_response_hops:
                            stopped_early = True
                            break
                    else:
                        consecutive = 0
                hops = trimmed
                if hops:
                    metadata.update(self._summarize_traceroute_progress(hops))
                    if stopped_early:
                        return {
                            'status': 'partial',
                            'error': f'Traceroute stopped after {self.max_consecutive_no_response_hops} consecutive no-response hops',
                            'hops': hops, 'total_hops': len(hops), **metadata,
                        }
                    return {'status': 'success', 'hops': hops, 'total_hops': len(hops), **metadata}
                return {'status': 'failed', 'error': 'No route found', **metadata}

        except FileNotFoundError:
            tool = 'tracert' if self.is_windows else 'tracepath'
            install = '' if self.is_windows else ' - run: sudo apt install iputils-tracepath'
            return {'status': 'error', 'error': f'{tool} not found{install}', **metadata}
        except Exception as error:
            return {'status': 'error', 'error': str(error), **metadata}
        finally:
            if process and process.poll() is None:
                process.kill()

    def _parse_tracepath_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse tracepath output into hop list compatible with traceroute hop format."""
        hops = []
        seen = set()
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith('Resume:'):
                continue
            m = re.match(r'^\s*(\d+):?\s+(.*)', line)
            if not m:
                continue
            hop_num = int(m.group(1))
            if hop_num in seen:
                continue
            seen.add(hop_num)
            rest = m.group(2).strip()
            # Skip metadata-only lines from the first-hop LOCALHOST entry
            if '[LOCALHOST]' in rest or rest.startswith('pmtu'):
                continue
            if 'no reply' in rest:
                hops.append({'hop': hop_num, 'status': 'timeout', 'ip': None, 'hostname': None, 'latencies': []})
            else:
                tm = re.match(r'^(\S+)\s+([\d.]+)ms', rest)
                if tm:
                    host = tm.group(1)
                    # tracepath shows hostname or IP; put in both fields so
                    # downstream display (requires ip_address) and ISP pattern
                    # matching (requires hostname) both work correctly
                    hops.append({
                        'hop': hop_num, 'status': 'responsive',
                        'ip': host, 'hostname': host,
                        'latencies': [f"{tm.group(2)}ms"],
                    })
        return hops

    def _summarize_traceroute_progress(self, hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Leitet aus den bereits beobachteten Hops eine kompakte Fortschritts-Summary ab."""
        responsive_hops = [hop for hop in hops if hop.get('status') == 'responsive']
        unresponsive_hops = [hop for hop in hops if hop.get('status') != 'responsive']

        return {
            'last_responsive_hop': responsive_hops[-1]['hop'] if responsive_hops else None,
            'first_unresponsive_hop': unresponsive_hops[0]['hop'] if unresponsive_hops else None
        }

    def _stop_traceroute_process(self, process: subprocess.Popen, output_lines: List[str], metadata: Dict[str, Any], reason: str) -> Dict[str, Any]:
        """Stoppt tracert/traceroute kontrolliert und liefert die bis dahin beobachtete Route zurueck."""
        try:
            process.terminate()
            remaining_stdout, _ = process.communicate(timeout=2)
        except Exception:
            process.kill()
            remaining_stdout, _ = process.communicate()

        if remaining_stdout:
            output_lines.append(remaining_stdout)

        hops = self._parse_traceroute_output(''.join(output_lines))
        metadata.update(self._summarize_traceroute_progress(hops))
        if hops:
            return {
                'status': 'partial',
                'error': reason,
                'hops': hops,
                'total_hops': len(hops),
                **metadata
            }

        return {
            'status': 'timeout',
            'error': reason,
            'hops': [],
            'total_hops': 0,
            **metadata
        }
    
    def _is_likely_international_route(self, ip_address: str) -> bool:
        """Schaetzt internationale Route"""
        if ip_address.startswith(('192.168.', '10.', '172.')):
            return False
        german_ranges = ['80.', '81.', '82.', '83.', '84.', '85.', '86.', '87.', '88.', '89.']
        return not any(ip_address.startswith(r) for r in german_ranges)
    
    def _parse_traceroute_output(self, output: str) -> List[Dict[str, Any]]:
        """Parst Traceroute-Output"""
        hops = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or not line[0].isdigit():
                continue
                
            hop_info = self._parse_traceroute_line(line)
            if hop_info:
                hops.append(hop_info)
        
        return hops
    
    def _parse_traceroute_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parst einzelne Traceroute-Zeile"""
        parts = line.split()
        if len(parts) < 2:
            return None
        
        try:
            hop_number = int(parts[0])
            ip_address = None
            hostname = None
            
            # IP-Adresse finden
            for part in reversed(parts):
                if '[' in part and ']' in part:
                    ip_address = part.strip('[]')
                    break
                elif '.' in part and len(part.split('.')) == 4:
                    if all(p.isdigit() for p in part.split('.')):
                        ip_address = part
                        break
            
            # Hostname finden
            for part in parts[1:]:
                if '.' in part and not part.replace('.', '').replace('ms', '').isdigit() and '*' not in part:
                    if '[' not in part and ']' not in part:
                        hostname = part
                        break

            latency_matches = re.findall(r'<?\d+(?:\.\d+)?\s*ms', line.lower())
            latency_values = [match.replace(' ', '') for match in latency_matches]

            if not ip_address:
                hostname = None
            
            return {
                'hop': hop_number,
                'ip': ip_address,
                'hostname': hostname,
                'status': 'responsive' if ip_address else 'timeout',
                'latencies': latency_values
            }
        except:
            return None
    
    def _analyze_enhanced_network_path(self, hops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhanced Netzwerkpfad-Analyse"""
        print(f"  {Colors.info('Path Analysis:')} Inspecting {len(hops)} network hops...")
        
        enhanced_path = []
        
        for hop in hops:
            hop_analysis = {
                'hop_number': hop['hop'],
                'ip_address': hop['ip'],
                'hostname': hop['hostname'],
                'status': hop['status'],
                'latencies': hop.get('latencies', []),
                'provider_type': 'unknown',
                'is_consumer_isp': False,
                'is_national_isp': False,
                'is_international_backbone': False,
                'is_critical_hop': False,
                'hop_classification': 'unknown'
            }
            
            if hop['hostname']:
                hostname_lower = hop['hostname'].lower()
                
                # Consumer-ISP Detection (nur echte Consumer-ISPs)
                for isp_pattern in self.consumer_isp_patterns:
                    if isp_pattern in hostname_lower:
                        hop_analysis['is_consumer_isp'] = True
                        hop_analysis['provider_type'] = 'consumer_isp'
                        hop_analysis['is_critical_hop'] = True
                        break
                
                # National ISP Detection
                if not hop_analysis['is_consumer_isp']:
                    for isp_pattern in self.national_isp_patterns:
                        if isp_pattern in hostname_lower:
                            hop_analysis['is_national_isp'] = True
                            hop_analysis['provider_type'] = 'national_isp'
                            break
                
                # International Backbone Detection
                for backbone_pattern in self.international_indicators:
                    if backbone_pattern in hostname_lower:
                        hop_analysis['is_international_backbone'] = True
                        hop_analysis['provider_type'] = 'international_backbone'
                        hop_analysis['is_critical_hop'] = True
                        break
            
            # Hop-Klassifikation
            if hop['status'] != 'responsive':
                hop_analysis['hop_classification'] = 'no_response'
            elif hop_analysis['is_consumer_isp']:
                hop_analysis['hop_classification'] = 'opsec_risk'
            elif hop_analysis['is_international_backbone']:
                hop_analysis['hop_classification'] = 'backbone_transit'
            elif hop_analysis['is_national_isp']:
                hop_analysis['hop_classification'] = 'national_isp'
            elif hop['hop'] == 1:
                hop_analysis['hop_classification'] = 'local_gateway'
            else:
                hop_analysis['hop_classification'] = 'transit'
            
            enhanced_path.append(hop_analysis)
        
        # Full hop-by-hop output, including timeouts, so the route remains auditable.
        print(f"  {Colors.info('Hop-by-hop route:')}")
        for hop in enhanced_path:
            indicator = self._get_hop_indicator(hop)
            hop_number = hop['hop_number']

            if hop['status'] == 'responsive' and hop['ip_address']:
                ip_display = hop['ip_address']
                print(f"    {Colors.dim(f'Hop {hop_number:2d}:')} {Colors.format_ip(ip_display)} {indicator}")

                if hop.get('latencies'):
                    print(f"         {Colors.dim('-> RTT:')} {', '.join(hop['latencies'])}")

                if hop['is_consumer_isp']:
                    print(f"         {Colors.warning('-> Consumer ISP detected')} ({hop['hostname']})")
                elif hop['is_international_backbone']:
                    print(f"         {Colors.info('-> International Backbone')} ({hop['hostname']})")
                elif hop['is_national_isp']:
                    print(f"         {Colors.success('-> National ISP')} ({hop['hostname']})")
                elif hop['hostname']:
                    print(f"         {Colors.dim(f'-> {hop['hostname']}')}")
            else:
                print(f"    {Colors.dim(f'Hop {hop_number:2d}:')} * * * {Colors.warning('[TIMEOUT]')}")
                
        responsive_hops = [h for h in enhanced_path if h['status'] == 'responsive']
        critical_hops = [h for h in enhanced_path if h['is_critical_hop']]
        consumer_hops = [h for h in enhanced_path if h['is_consumer_isp']]
        national_hops = [h for h in enhanced_path if h['is_national_isp']]
        
        print(f"  {Colors.success('Responsive Hops:')} {len(responsive_hops)}")
        print(f"  {Colors.info('National ISP Hops:')} {len(national_hops)}")
        print(f"  {Colors.warning('Critical Hops:')} {len(critical_hops)}")
        
        if consumer_hops:
            print(f"  {Colors.error('Consumer-ISP Hops:')} {len(consumer_hops)} erkannt")
            for hop in consumer_hops:
                print(f"    Hop {hop['hop_number']}: {hop['hostname']} ({hop['ip_address']})")
        else:
            print(f"  {Colors.success('Consumer-ISP Hops:')} Keine erkannt (Gut für OPSEC)")
        
        return enhanced_path
    
    def _get_hop_indicator(self, hop: Dict[str, Any]) -> str:
        """Hop-Indikatoren"""
        classification = hop['hop_classification']
        
        if classification == 'opsec_risk':
            return Colors.error('[OPSEC-RISK]')
        elif classification == 'no_response':
            return Colors.warning('[NO-RESPONSE]')
        elif classification == 'backbone_transit':
            return Colors.warning('[BACKBONE]')
        elif classification == 'national_isp':
            return Colors.info('[NATIONAL-ISP]')
        elif classification == 'local_gateway':
            return Colors.success('[GATEWAY]')
        else:
            return Colors.dim('[TRANSIT]')
    
    def _gather_hop_intelligence(self, enhanced_path: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Hop-Intelligence ohne Fake-Daten"""
        print(f"  {Colors.info('Hop-Intelligence:')} Analysiere Provider-Informationen...")
        
        hop_intelligence = {
            'total_hops_analyzed': len(enhanced_path),
            'responsive_hops': 0,
            'provider_analysis': {},
            'intelligence_summary': {}
        }
        
        responsive_hops = [hop for hop in enhanced_path if hop['status'] == 'responsive' and hop['ip_address']]
        hop_intelligence['responsive_hops'] = len(responsive_hops)
        
        print(f"    {Colors.info('Responsive Hops für Analyse:')} {len(responsive_hops)}")
        
        # Provider-Analyse für responsive Hops
        provider_types = {}
        for hop in responsive_hops:
            if hop['hostname']:
                provider_info = self._analyze_provider_from_hostname(hop['hostname'])
                if provider_info:
                    hop_intelligence['provider_analysis'][hop['ip_address']] = provider_info
                    
                    provider_type = provider_info['type']
                    provider_types[provider_type] = provider_types.get(provider_type, 0) + 1
        
        # Intelligence Summary
        hop_intelligence['intelligence_summary'] = {
            'providers_identified': len(hop_intelligence['provider_analysis']),
            'provider_types': provider_types,
            'consumer_isps_detected': len([h for h in enhanced_path if h['is_consumer_isp']]),
            'national_isps_detected': len([h for h in enhanced_path if h['is_national_isp']]),
            'backbones_detected': len([h for h in enhanced_path if h['is_international_backbone']])
        }
        
        summary = hop_intelligence['intelligence_summary']
        print(f"    {Colors.success('Intelligence-Summary:')}")
        print(f"      Provider identifiziert: {summary['providers_identified']}")
        print(f"      National ISPs: {summary['national_isps_detected']}")
        print(f"      Consumer ISPs: {summary['consumer_isps_detected']}")
        print(f"      International Backbones: {summary['backbones_detected']}")
        
        return hop_intelligence
    
    def _analyze_provider_from_hostname(self, hostname: str) -> Optional[Dict[str, str]]:
        """Realistische Provider-Analyse"""
        hostname_lower = hostname.lower()
        
        providers = {
            'telekom': {'provider': 'Deutsche Telekom AG', 'type': 'National ISP', 'country': 'Deutschland'},
            'vodafone': {'provider': 'Vodafone GmbH', 'type': 'National ISP', 'country': 'Deutschland'},
            'level3': {'provider': 'Level 3 Communications', 'type': 'Tier-1 Backbone', 'country': 'USA'},
            'cogent': {'provider': 'Cogent Communications', 'type': 'Tier-1 Backbone', 'country': 'USA'},
            'he.net': {'provider': 'Hurricane Electric', 'type': 'Tier-1 Backbone', 'country': 'USA'},
            'telia': {'provider': 'Telia Company AB', 'type': 'Tier-1 Backbone', 'country': 'Schweden'},
            'github': {'provider': 'GitHub Inc.', 'type': 'Platform Service', 'country': 'USA'},
            'cloudflare': {'provider': 'Cloudflare Inc.', 'type': 'CDN Service', 'country': 'USA'},
            'comcast': {'provider': 'Comcast Corporation', 'type': 'Consumer ISP', 'country': 'USA'},
            'charter': {'provider': 'Charter Communications', 'type': 'Consumer ISP', 'country': 'USA'},
            'verizon.home': {'provider': 'Verizon Consumer', 'type': 'Consumer ISP', 'country': 'USA'}
        }
        
        for pattern, info in providers.items():
            if pattern in hostname_lower:
                return info
        
        return None
    
    def _classify_route(self, enhanced_path: List[Dict[str, Any]], hop_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Route-Klassifikation"""
        classification = {
            'route_type': 'standard',
            'contains_consumer_isp': False,
            'contains_national_isp': False,
            'contains_international_backbone': False,
            'privacy_level': 'good',
            'intelligence_availability': 'medium'
        }
        
        consumer_hops = [hop for hop in enhanced_path if hop['is_consumer_isp']]
        national_hops = [hop for hop in enhanced_path if hop['is_national_isp']]
        backbone_hops = [hop for hop in enhanced_path if hop['is_international_backbone']]
        
        classification['contains_consumer_isp'] = len(consumer_hops) > 0
        classification['contains_national_isp'] = len(national_hops) > 0
        classification['contains_international_backbone'] = len(backbone_hops) > 0
        
        if consumer_hops:
            classification['route_type'] = 'consumer_isp_route'
        elif backbone_hops:
            classification['route_type'] = 'backbone_route'
        elif national_hops:
            classification['route_type'] = 'national_isp_route'
        else:
            classification['route_type'] = 'standard_route'
        
        if len(consumer_hops) >= 2:
            classification['privacy_level'] = 'low'
        elif len(consumer_hops) == 1:
            classification['privacy_level'] = 'medium'
        elif len(backbone_hops) > 0:
            classification['privacy_level'] = 'good'
        else:
            classification['privacy_level'] = 'good'
        
        return classification
    
    def _assess_enhanced_opsec_risks(self, enhanced_path: List[Dict[str, Any]], hop_intelligence: Dict[str, Any], route_classification: Dict[str, Any]) -> Dict[str, Any]:
        """Realistisches OPSEC-Assessment"""
        print(f"  {Colors.info('Enhanced OPSEC-Assessment:')} Analysiere Attribution-Risiken...")
        
        assessment = {
            'risk_level': 'low',
            'risk_factors': [],
            'recommendations': [],
            'analyst_attribution_risk': 'low',
            'intelligence_exposure': 'low'
        }
        
        consumer_hops = [h for h in enhanced_path if h['is_consumer_isp']]
        national_hops = [h for h in enhanced_path if h['is_national_isp']]
        backbone_hops = [h for h in enhanced_path if h['is_international_backbone']]
        
        if consumer_hops:
            assessment['risk_factors'].append(f'{len(consumer_hops)} Consumer-ISP(s) in path')
            assessment['recommendations'].append('Monitor for additional OPSEC measures')
            assessment['risk_level'] = 'medium'
            assessment['analyst_attribution_risk'] = 'medium'
            print(f"    {Colors.warning(f'{len(consumer_hops)} Consumer-ISP(s):')} Moderate OPSEC concern")
        else:
            print(f"    {Colors.success('Consumer-ISPs:')} Keine erkannt")
        
        if national_hops:
            assessment['risk_factors'].append(f'{len(national_hops)} National ISP(s) in path')
            print(f"    {Colors.info(f'{len(national_hops)} National ISP(s):')} Standard für Deutschland")
        
        if backbone_hops:
            print(f"    {Colors.success(f'{len(backbone_hops)} International Backbone(s):')} Gut für Anonymität")
        
        provider_count = hop_intelligence.get('intelligence_summary', {}).get('providers_identified', 0)
        if provider_count >= 3:
            assessment['intelligence_exposure'] = 'medium'
        elif provider_count >= 1:
            assessment['intelligence_exposure'] = 'low'
        else:
            assessment['intelligence_exposure'] = 'minimal'
        
        if len(consumer_hops) == 0 and len(backbone_hops) > 0:
            assessment['risk_level'] = 'low'
            assessment['analyst_attribution_risk'] = 'low'
            print(f"    {Colors.success('Privacy-Level:')} Gut (Professional Route)")
        elif len(consumer_hops) == 1:
            assessment['risk_level'] = 'low'
            assessment['analyst_attribution_risk'] = 'low'
            print(f"    {Colors.success('Privacy-Level:')} Akzeptabel (Standard Route)")
        elif len(consumer_hops) >= 2:
            assessment['risk_level'] = 'medium'
            assessment['analyst_attribution_risk'] = 'medium'
            print(f"    {Colors.warning('Privacy-Level:')} Moderate Concerns")
        else:
            assessment['risk_level'] = 'low'
            assessment['analyst_attribution_risk'] = 'low'
            print(f"    {Colors.success('Privacy-Level:')} Gut")
        
        if assessment['risk_level'] == 'low':
            assessment['recommendations'].append('Current route provides good anonymity for standard analysis')
            print(f"    {Colors.success('OPSEC-Status:')} Route suitable for forensic analysis")
        else:
            print(f"    {Colors.info('OPSEC-Status:')} Standard precautions recommended")
        
        return assessment
    
    def _display_enhanced_summary(self, results: Dict[str, Any]) -> None:
        """Enhanced Summary"""
        print(f"\n{Colors.investigation_separator(60)}")
        print(Colors.header("ENHANCED NETWORK INTELLIGENCE SUMMARY"))
        print(Colors.investigation_separator(60))
        
        print(f"Target IP: {Colors.format_ip(results['target_ip'])}")
        if results.get('target_domain'):
            print(f"Target Domain: {Colors.format_domain(results['target_domain'])}")
        
        connectivity = results.get('connectivity_test', {})
        if connectivity.get('ping_reachable'):
            ping_time = connectivity.get('response_times', {}).get('ping', 'unknown')
            print(f"Connectivity: {Colors.success('REACHABLE')} ({ping_time})")
        else:
            print(f"Connectivity: {Colors.warning('LIMITED/FILTERED')}")
        
        traceroute = results.get('traceroute_data', {})
        if traceroute.get('status') == 'success':
            hop_count = traceroute.get('total_hops', 0)
            print(f"Network Path: {Colors.success(f'{hop_count} hops analyzed')}")
            
            enhanced_path = results.get('enhanced_network_path', [])
            critical_hops = len([h for h in enhanced_path if h.get('is_critical_hop')])
            if critical_hops > 0:
                print(f"Critical Hops: {Colors.warning(str(critical_hops))} (Intelligence-relevant)")
        
        route_class = results.get('route_classification', {})
        if route_class:
            route_type = route_class.get('route_type', 'unknown').replace('_', ' ').title()
            print(f"Route Type: {Colors.info(route_type)}")
        
        opsec = results.get('opsec_assessment', {})
        if opsec:
            risk_level = opsec.get('risk_level', 'unknown').upper()
            risk_colored = Colors.error(risk_level) if risk_level == 'HIGH' else Colors.warning(risk_level) if risk_level == 'MEDIUM' else Colors.success(risk_level)
            print(f"OPSEC Risk Level: {risk_colored}")
            
            intel_exposure = opsec.get('intelligence_exposure', 'unknown').upper()
            if intel_exposure != 'UNKNOWN':
                print(f"Intelligence Exposure: {Colors.info(intel_exposure)}")
        
        print(Colors.investigation_separator(60))
        print(f"Analysis Status: {Colors.success('COMPLETE')}")
        print(Colors.investigation_separator(60))
    
    def get_results(self) -> Dict[str, Any]:
        """Gibt Analyseergebnisse zurueck"""
        return self.results
    
    def get_opsec_assessment(self) -> Dict[str, Any]:
        """Gibt OPSEC-Assessment zurueck"""
        return self.results.get('opsec_assessment', {})

# Test-Funktion
def main():
    """Test-Funktion fuer Enhanced Network Intelligence"""
    print(Colors.header("ENHANCED NETWORK INTELLIGENCE TEST - STEP 2.4"))
    print(Colors.investigation_separator(60))
    
    test_ip = "140.82.121.4"
    test_domain = "github.com"
    
    analyzer = NetworkIntelligence()
    
    print(f"\n{Colors.section_header(f'TEST: {test_domain.upper()}', 60)}")
    
    results = analyzer.analyze_network(test_ip, test_domain)
    
    if results.get('error'):
        print(Colors.error(f"Test fehlgeschlagen: {results['error']}"))
    else:
        traceroute_status = results.get('traceroute_data', {}).get('status', 'unknown')
        opsec_risk = results.get('opsec_assessment', {}).get('risk_level', 'unknown')
        critical_hops = len([h for h in results.get('enhanced_network_path', []) if h.get('is_critical_hop')])
        
        print(f"\n{Colors.success('ENHANCED TEST ERFOLGREICH:')}")
        print(f"  Traceroute Status: {traceroute_status}")
        print(f"  OPSEC Risk Level: {opsec_risk}")
        print(f"  Critical Hops Found: {critical_hops}")
        print(f"  Enhanced Features: Aktiviert")
    
    print(f"\n{Colors.investigation_separator(60)}")
    print(Colors.success("ENHANCED NETWORK INTELLIGENCE STEP 2.4 - TESTING COMPLETE"))
    print(Colors.investigation_separator(60))

if __name__ == "__main__":
    main()
