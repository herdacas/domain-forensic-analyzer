"""
Network Intelligence Module for Domain Forensic Analyzer.
"""

import os
import platform
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests as _requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config.settings import get_settings


class NetworkIntelligence:
    """Network analysis: traceroute, connectivity, HTTP/S behavior, OPSEC assessment."""

    def __init__(self):
        self.results = {}
        self.settings = get_settings()
        self.traceroute_timeout_regional = self.settings.scan_settings.traceroute_timeout_regional
        self.traceroute_timeout_international = self.settings.scan_settings.traceroute_timeout_international
        self.encoding = self.settings.scan_settings.traceroute_encoding
        self.max_traceroute_hops = getattr(self.settings.scan_settings, 'max_traceroute_hops', 15)

        self.platform = platform.system().lower()
        self.is_windows = self.platform == 'windows'
        # Probe timeout lower than command timeout so partial routes return faster;
        # we stop after a short no-response streak since later asterisks add little value.
        self.traceroute_probe_timeout_ms = 2000 if self.is_windows else 2500
        self.max_consecutive_no_response_hops = 3

        # Consumer ISPs (residential, not carrier/national)
        self.consumer_isp_patterns = [
            'comcast', 'charter', 'cox', 'centurylink', 'frontier', 'windstream',
            'mediacom', 'suddenlink', 'optimum', 'spectrum', 'xfinity',
            'virgin', 'sky', 'bt.home', 'talktalk', 'plusnet',
        ]

        self.national_isp_patterns = [
            'telekom', 'vodafone', 'orange', 'verizon.net', 'att.net',
        ]

        self.international_indicators = [
            'telia', 'level3', 'gttsolutions', 'cogent', 'he.net', 'ntt.net',
            'sprint', 'seabone', 'retn.net', 'lumen', 'zayo',
        ]

    def analyze_network(self, ip_address: str, domain: str = None) -> Dict[str, Any]:
        """Run full network intelligence analysis and return structured result dict."""
        if not ip_address:
            return {'error': 'No IP address available for network analysis', 'analysis_status': 'fehlgeschlagen'}

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
            'analysis_status': 'gestartet',
        }

        results['connectivity_test'] = self._test_connectivity(ip_address, domain)

        if domain:
            results['http_behavior'] = self._test_http_behavior(domain)
        else:
            results['http_behavior'] = {'available': False, 'assessment': 'unavailable'}

        traceroute_data = self._perform_traceroute(ip_address)
        results['traceroute_data'] = traceroute_data

        if traceroute_data.get('status') in ['success', 'partial'] and traceroute_data.get('hops'):
            enhanced_path = self._analyze_enhanced_network_path(traceroute_data.get('hops', []))
            results['enhanced_network_path'] = enhanced_path

            hop_intelligence = self._gather_hop_intelligence(enhanced_path)
            results['hop_intelligence'] = hop_intelligence

            route_classification = self._classify_route(enhanced_path, hop_intelligence)
            results['route_classification'] = route_classification

            opsec_assessment = self._assess_enhanced_opsec_risks(enhanced_path, hop_intelligence, route_classification)
            results['opsec_assessment'] = opsec_assessment

        results['analysis_status'] = 'abgeschlossen'
        self.results = results
        return results

    def _test_connectivity(self, ip_address: str, domain: str = None) -> Dict[str, Any]:
        """Test ping and HTTP/S reachability."""
        connectivity = {
            'ping_reachable': False,
            'http_accessible': False,
            'https_accessible': False,
            'response_times': {},
        }

        ping_result = self._test_ping(ip_address)
        connectivity['ping_reachable'] = ping_result['reachable']
        if ping_result.get('avg_time'):
            connectivity['response_times']['ping'] = ping_result['avg_time']

        if domain:
            connectivity.update(self._test_http_connectivity(domain))

        return connectivity

    def _test_ping(self, ip_address: str) -> Dict[str, Any]:
        """Platform-specific ping test."""
        try:
            cmd = ['ping', '-n', '3', ip_address] if self.is_windows else ['ping', '-c', '3', ip_address]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                encoding=self.encoding if self.is_windows else 'utf-8',
                errors='replace',
            )
            if result.returncode == 0:
                return {'reachable': True, 'avg_time': self._extract_ping_time(result.stdout)}
            return {'reachable': False}
        except Exception:
            return {'reachable': False}

    def _extract_ping_time(self, ping_output: str) -> Optional[str]:
        """Extract average RTT from ping output."""
        for line in ping_output.lower().split('\n'):
            if 'average' in line or 'mittelwert' in line or 'durchschnitt' in line:
                m = re.search(r'(\d+(?:\.\d+)?)\s*ms', line)
                if m:
                    return f"{m.group(1)}ms"
        return None

    def _test_http_connectivity(self, domain: str) -> Dict[str, Any]:
        """Test basic HTTP/S reachability (used for connectivity_test dict)."""
        connectivity = {'http_accessible': False, 'https_accessible': False}

        try:
            req = urllib.request.Request(f"https://{domain}")
            req.add_header('User-Agent', 'Domain-Forensic-Analyzer/3.4')
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    connectivity['https_accessible'] = True
        except Exception:
            pass

        if not connectivity['https_accessible']:
            try:
                req = urllib.request.Request(f"http://{domain}")
                req.add_header('User-Agent', 'Domain-Forensic-Analyzer/3.4')
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        connectivity['http_accessible'] = True
            except Exception:
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
            'csp': None,
            'x_frame_options': None,
            'has_redirect': False,
            'redirect_chain': [],
            'assessment': 'unavailable',
        }

        session = _requests.Session()
        session.headers['User-Agent'] = 'Domain-Forensic-Analyzer/1.0'

        try:
            r = session.get(f"http://{domain}", allow_redirects=False, timeout=10, verify=False)
            result['http_status'] = r.status_code
            if r.status_code in (301, 302, 303, 307, 308):
                result['has_redirect'] = True
                result['redirect_chain'] = [{'url': f"http://{domain}", 'status': r.status_code}]
                location = r.headers.get('Location', '')
                if location and not location.startswith('http'):
                    location = f"http://{domain}{location}"
                if location:
                    result['redirect_chain'].append({'url': location, 'status': None})
        except Exception:
            pass

        try:
            url = f"https://{domain}"
            visited: set = set()
            final_resp = None

            for _ in range(5):
                if url in visited:
                    break
                visited.add(url)
                resp = session.get(url, allow_redirects=False, timeout=10, verify=False)
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

                server = final_resp.headers.get('Server') or final_resp.headers.get('server')
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

                csp_val = (
                    final_resp.headers.get('Content-Security-Policy')
                    or final_resp.headers.get('content-security-policy')
                )
                if csp_val:
                    result['csp'] = csp_val.strip()

                xfo_val = (
                    final_resp.headers.get('X-Frame-Options')
                    or final_resp.headers.get('x-frame-options')
                )
                if xfo_val:
                    result['x_frame_options'] = xfo_val.strip().upper()

        except Exception:
            pass

        https_ok = result['https_status'] is not None and 200 <= result['https_status'] < 400
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
        """Run platform-appropriate traceroute and return hop list."""
        timeout = (
            self.traceroute_timeout_international
            if self._is_likely_international_route(ip_address)
            else self.traceroute_timeout_regional
        )
        metadata = {
            'command_timeout_seconds': timeout,
            'probe_timeout_ms': self.traceroute_probe_timeout_ms,
            'max_hops': self.max_traceroute_hops,
        }

        process = None
        try:
            if self.is_windows:
                cmd = ['tracert', '-h', str(self.max_traceroute_hops), '-w', str(self.traceroute_probe_timeout_ms), ip_address]
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    encoding=self.encoding, errors='replace',
                )

                output_lines = []
                start_time = time.monotonic()
                consecutive_no_response_hops = 0

                while True:
                    if time.monotonic() - start_time > timeout:
                        return self._stop_traceroute_process(
                            process, output_lines, metadata,
                            f'Traceroute command timed out after {timeout}s',
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
                                        f'Traceroute stopped after {self.max_consecutive_no_response_hops} consecutive no-response hops',
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
                # Linux: use tracepath (pre-installed on most distributions)
                cmd = ['tracepath', '-m', str(self.max_traceroute_hops), ip_address]
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding='utf-8', errors='replace',
                )
                try:
                    stdout, _ = process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, _ = process.communicate()
                hops = self._parse_tracepath_output(stdout)
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
        seen: set = set()
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
        """Return last responsive and first unresponsive hop numbers from a hop list."""
        responsive = [h for h in hops if h.get('status') == 'responsive']
        unresponsive = [h for h in hops if h.get('status') != 'responsive']
        return {
            'last_responsive_hop': responsive[-1]['hop'] if responsive else None,
            'first_unresponsive_hop': unresponsive[0]['hop'] if unresponsive else None,
        }

    def _stop_traceroute_process(self, process: subprocess.Popen, output_lines: List[str], metadata: Dict[str, Any], reason: str) -> Dict[str, Any]:
        """Terminate traceroute process and return partial results collected so far."""
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
            return {'status': 'partial', 'error': reason, 'hops': hops, 'total_hops': len(hops), **metadata}
        return {'status': 'timeout', 'error': reason, 'hops': [], 'total_hops': 0, **metadata}

    def _is_likely_international_route(self, ip_address: str) -> bool:
        """Heuristic: non-private, non-German IP prefix is likely international."""
        if ip_address.startswith(('192.168.', '10.', '172.')):
            return False
        german_ranges = ['80.', '81.', '82.', '83.', '84.', '85.', '86.', '87.', '88.', '89.']
        return not any(ip_address.startswith(r) for r in german_ranges)

    def _parse_traceroute_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Windows tracert output into hop list."""
        hops = []
        for line in output.split('\n'):
            line = line.strip()
            if not line or not line[0].isdigit():
                continue
            hop_info = self._parse_traceroute_line(line)
            if hop_info:
                hops.append(hop_info)
        return hops

    def _parse_traceroute_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single tracert line into a hop dict."""
        parts = line.split()
        if len(parts) < 2:
            return None

        try:
            hop_number = int(parts[0])
            ip_address = None
            hostname = None

            for part in reversed(parts):
                if '[' in part and ']' in part:
                    ip_address = part.strip('[]')
                    break
                elif '.' in part and len(part.split('.')) == 4:
                    if all(p.isdigit() for p in part.split('.')):
                        ip_address = part
                        break

            for part in parts[1:]:
                if '.' in part and not part.replace('.', '').replace('ms', '').isdigit() and '*' not in part:
                    if '[' not in part and ']' not in part:
                        hostname = part
                        break

            latency_matches = re.findall(r'<?\d+(?:\.\d+)?\s*ms', line.lower())
            latency_values = [m.replace(' ', '') for m in latency_matches]

            if not ip_address:
                hostname = None

            return {
                'hop': hop_number,
                'ip': ip_address,
                'hostname': hostname,
                'status': 'responsive' if ip_address else 'timeout',
                'latencies': latency_values,
            }
        except Exception:
            return None

    def _analyze_enhanced_network_path(self, hops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Classify each hop by provider type and OPSEC relevance."""
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
                'hop_classification': 'unknown',
            }

            if hop['hostname']:
                hostname_lower = hop['hostname'].lower()

                for pattern in self.consumer_isp_patterns:
                    if pattern in hostname_lower:
                        hop_analysis['is_consumer_isp'] = True
                        hop_analysis['provider_type'] = 'consumer_isp'
                        hop_analysis['is_critical_hop'] = True
                        break

                if not hop_analysis['is_consumer_isp']:
                    for pattern in self.national_isp_patterns:
                        if pattern in hostname_lower:
                            hop_analysis['is_national_isp'] = True
                            hop_analysis['provider_type'] = 'national_isp'
                            break

                for pattern in self.international_indicators:
                    if pattern in hostname_lower:
                        hop_analysis['is_international_backbone'] = True
                        hop_analysis['provider_type'] = 'international_backbone'
                        hop_analysis['is_critical_hop'] = True
                        break

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

        return enhanced_path

    def _gather_hop_intelligence(self, enhanced_path: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build provider intelligence summary from classified hops."""
        hop_intelligence: Dict[str, Any] = {
            'total_hops_analyzed': len(enhanced_path),
            'responsive_hops': 0,
            'provider_analysis': {},
            'intelligence_summary': {},
        }

        responsive_hops = [h for h in enhanced_path if h['status'] == 'responsive' and h['ip_address']]
        hop_intelligence['responsive_hops'] = len(responsive_hops)

        provider_types: Dict[str, int] = {}
        for hop in responsive_hops:
            if hop['hostname']:
                provider_info = self._analyze_provider_from_hostname(hop['hostname'])
                if provider_info:
                    hop_intelligence['provider_analysis'][hop['ip_address']] = provider_info
                    ptype = provider_info['type']
                    provider_types[ptype] = provider_types.get(ptype, 0) + 1

        hop_intelligence['intelligence_summary'] = {
            'providers_identified': len(hop_intelligence['provider_analysis']),
            'provider_types': provider_types,
            'consumer_isps_detected': len([h for h in enhanced_path if h['is_consumer_isp']]),
            'national_isps_detected': len([h for h in enhanced_path if h['is_national_isp']]),
            'backbones_detected': len([h for h in enhanced_path if h['is_international_backbone']]),
        }

        return hop_intelligence

    def _analyze_provider_from_hostname(self, hostname: str) -> Optional[Dict[str, str]]:
        """Map a known hostname pattern to a provider record."""
        hostname_lower = hostname.lower()

        providers = {
            'telekom':      {'provider': 'Deutsche Telekom AG',    'type': 'National ISP',    'country': 'Germany'},
            'vodafone':     {'provider': 'Vodafone GmbH',          'type': 'National ISP',    'country': 'Germany'},
            'level3':       {'provider': 'Level 3 Communications', 'type': 'Tier-1 Backbone', 'country': 'USA'},
            'cogent':       {'provider': 'Cogent Communications',  'type': 'Tier-1 Backbone', 'country': 'USA'},
            'he.net':       {'provider': 'Hurricane Electric',     'type': 'Tier-1 Backbone', 'country': 'USA'},
            'telia':        {'provider': 'Telia Company AB',       'type': 'Tier-1 Backbone', 'country': 'Sweden'},
            'github':       {'provider': 'GitHub Inc.',            'type': 'Platform Service', 'country': 'USA'},
            'cloudflare':   {'provider': 'Cloudflare Inc.',        'type': 'CDN Service',     'country': 'USA'},
            'comcast':      {'provider': 'Comcast Corporation',    'type': 'Consumer ISP',    'country': 'USA'},
            'charter':      {'provider': 'Charter Communications', 'type': 'Consumer ISP',    'country': 'USA'},
            'verizon.home': {'provider': 'Verizon Consumer',       'type': 'Consumer ISP',    'country': 'USA'},
        }

        for pattern, info in providers.items():
            if pattern in hostname_lower:
                return info
        return None

    def _classify_route(self, enhanced_path: List[Dict[str, Any]], hop_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Classify route type and privacy level from hop classifications."""
        consumer_hops = [h for h in enhanced_path if h['is_consumer_isp']]
        national_hops = [h for h in enhanced_path if h['is_national_isp']]
        backbone_hops = [h for h in enhanced_path if h['is_international_backbone']]

        classification: Dict[str, Any] = {
            'contains_consumer_isp': bool(consumer_hops),
            'contains_national_isp': bool(national_hops),
            'contains_international_backbone': bool(backbone_hops),
            'intelligence_availability': 'medium',
        }

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
        else:
            classification['privacy_level'] = 'good'

        return classification

    def _assess_enhanced_opsec_risks(self, enhanced_path: List[Dict[str, Any]], hop_intelligence: Dict[str, Any], route_classification: Dict[str, Any]) -> Dict[str, Any]:
        """Assess OPSEC attribution risk from route characteristics."""
        assessment = {
            'risk_level': 'low',
            'risk_factors': [],
            'recommendations': [],
            'analyst_attribution_risk': 'low',
            'intelligence_exposure': 'low',
        }

        consumer_hops = [h for h in enhanced_path if h['is_consumer_isp']]
        national_hops = [h for h in enhanced_path if h['is_national_isp']]
        backbone_hops = [h for h in enhanced_path if h['is_international_backbone']]

        if consumer_hops:
            assessment['risk_factors'].append(f'{len(consumer_hops)} Consumer-ISP(s) in path')
            assessment['recommendations'].append('Monitor for additional OPSEC measures')
            assessment['risk_level'] = 'medium'
            assessment['analyst_attribution_risk'] = 'medium'

        if national_hops:
            assessment['risk_factors'].append(f'{len(national_hops)} National ISP(s) in path')

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
        elif len(consumer_hops) == 1:
            assessment['risk_level'] = 'low'
            assessment['analyst_attribution_risk'] = 'low'
        elif len(consumer_hops) >= 2:
            assessment['risk_level'] = 'medium'
            assessment['analyst_attribution_risk'] = 'medium'
        else:
            assessment['risk_level'] = 'low'
            assessment['analyst_attribution_risk'] = 'low'

        if assessment['risk_level'] == 'low':
            assessment['recommendations'].append('Current route provides good anonymity for standard analysis')

        return assessment

    def get_results(self) -> Dict[str, Any]:
        """Return last analysis results."""
        return self.results

    def get_opsec_assessment(self) -> Dict[str, Any]:
        """Return OPSEC assessment from last analysis."""
        return self.results.get('opsec_assessment', {})
