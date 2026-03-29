"""
Domain Forensic Analyzer - Enhanced Module Integration
Professional OSINT Tool with Robust Error Handling & Multi-API Intelligence

Portfolio-Ready | Clean Code | Industry Standards | Production-Grade
"""

import sys
import os
import platform
import time
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from dataclasses import dataclass

# External Dependencies
try:
    from loguru import logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

# Foundation-Module importieren
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.utils.colors import Colors
from src.utils.validators import DomainValidator
from src.core.result_aggregator import create_result_aggregator, UnifiedResult

# Core-Module importieren - ENHANCED WITH NEW APIS
try:
    from src.core.security_manager import create_security_manager
    from src.analyzers.dns_analyzer import DNSAnalyzer
    from src.analyzers.cdn_detector import CDNDetector
    from src.analyzers.subdomain_scanner import SubdomainScanner
    from src.analyzers.network_intelligence import NetworkIntelligence
    from src.analyzers.securitytrails_client import SecurityTrailsClient
    from src.analyzers.abuseipdb_client import AbuseIPDBClient          # NEW API
    from src.analyzers.virustotal_client import VirusTotalClient        # NEW API
    CORE_MODULES_AVAILABLE = True
except ImportError as error:
    CORE_MODULES_AVAILABLE = False
    print(f"Core modules import error: {error}")

@dataclass
class ModuleExecutionResult:
    """Module execution result with performance metrics"""
    success: bool
    result: Dict[str, Any]
    execution_time: float
    error_message: Optional[str] = None
    timeout_occurred: bool = False

class DomainAnalyzer:
    """
    Professional Domain Forensic Analysis Orchestrator
    Enhanced with Robust Error Handling, Performance Monitoring & Multi-API Intelligence
    """
    
    def __init__(self):
        """Initialize Domain Analyzer with enhanced multi-API module integration"""
        # Platform Detection
        self.platform = platform.system().lower()
        
        # Paths (Cross-Platform)
        self.project_root = Path(__file__).parent.parent.parent
        self.logs_dir = self.project_root / "logs"
        
        # Create directories if not exist
        self.logs_dir.mkdir(exist_ok=True)
        
        # Initialize Logging
        self._setup_logging()
        
        # Core Modules with Enhanced API Integration
        self.modules = {}
        self.module_execution_order = [
            'dns', 'cdn', 'network', 'subdomain', 
            'securitytrails', 'abuseipdb', 'virustotal'  # ENHANCED WITH NEW APIS
        ]
        
        # Module-specific timeouts (seconds) - ENHANCED
        self.module_timeouts = {
            'dns': 30,
            'cdn': 45, 
            'network': 60,
            'subdomain': 180,
            'securitytrails': 30,
            'abuseipdb': 30,         # NEW API TIMEOUT
            'virustotal': 30         # NEW API TIMEOUT
        }
        
        # Analysis State
        self.current_analysis = None
        self.execution_metrics = {}
        
        # Initialize system
        self._initialize_system()
        
        # Initialize result aggregator
        self.result_aggregator = create_result_aggregator()
    
    def _setup_logging(self) -> None:
        """Setup comprehensive logging for analysis tracking"""
        if LOGURU_AVAILABLE:
            logger.remove()
            log_file = self.logs_dir / f"domain_analyzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            logger.add(
                str(log_file),
                format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {message}",
                level="DEBUG",
                rotation="50 MB"
            )
            self.logger = logger
            self.logger.info("Domain Analyzer session started", platform=self.platform)
        else:
            import logging
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger('DomainAnalyzer')
    
    def _initialize_system(self) -> None:
        """Initialize system components"""
        if not CORE_MODULES_AVAILABLE:
            return
        
        try:
            self._initialize_modules()
            self.logger.info("System initialization complete", modules_loaded=len(self.modules))
        except Exception as error:
            self.logger.error("System initialization failed", error=str(error))
    
    def _initialize_modules(self) -> None:
        """Initialize all core analyzer modules - ENHANCED WITH NEW APIS"""
        module_classes = {
            'dns': DNSAnalyzer,
            'cdn': CDNDetector,
            'subdomain': SubdomainScanner,
            'network': NetworkIntelligence,
            'securitytrails': SecurityTrailsClient,
            'abuseipdb': AbuseIPDBClient,        # NEW API MODULE
            'virustotal': VirusTotalClient       # NEW API MODULE
        }
        
        for module_name, module_class in module_classes.items():
            try:
                self.modules[module_name] = module_class()
                self.logger.debug(f"{module_name.title()} module initialized")
            except Exception as error:
                self.logger.warning(f"Failed to initialize {module_name}", error=str(error))
    
    def analyze_domain(self, domain: str) -> UnifiedResult:
        """Main Domain Analysis Function with Enhanced Multi-API Error Handling"""
        # Input validation
        if not DomainValidator.is_valid_domain(domain):
            raise ValueError(f"Invalid domain format: {domain}")
        
        clean_domain = DomainValidator.clean_domain(domain)
        start_time = datetime.now()
        
        self.logger.info("Starting enhanced multi-API domain analysis", domain=clean_domain)
        
        # Initialize analysis state
        self.current_analysis = {
            'domain': clean_domain,
            'start_time': start_time,
            'modules_to_run': self.module_execution_order,
            'results': {},
            'errors': [],
            'warnings': []
        }
        self.execution_metrics = {}
        
        # Execute analysis modules with enhanced workflow
        self._execute_analysis_workflow_enhanced()
        
        # Calculate final metrics
        execution_time = (datetime.now() - start_time).total_seconds()
        
        self.logger.info("Enhanced analysis completed", 
                        domain=clean_domain,
                        execution_time=execution_time,
                        successful_modules=len([m for m in self.execution_metrics.values() if m.success]),
                        failed_modules=len([m for m in self.execution_metrics.values() if not m.success]),
                        apis_used=len([m for m in ['securitytrails', 'abuseipdb', 'virustotal'] 
                                     if m in self.modules and self.execution_metrics.get(m, {}).success]))
        
        # Create unified result using aggregator
        result = self.result_aggregator.aggregate_results(
            domain=clean_domain,
            module_results=self.current_analysis['results'],
            execution_time=execution_time
        )
        
        return result
    
    def _execute_analysis_workflow_enhanced(self) -> None:
        """Execute analysis workflow with enhanced error handling and performance tracking"""
        modules_to_run = [m for m in self.current_analysis['modules_to_run'] if m in self.modules]
        
        if not modules_to_run:
            self.logger.warning("No modules available for execution")
            return
        
        print(f"\nStarting OSINT Analysis with Enhanced Multi-API Error Handling...")
        start_time = time.time()
        
        # Execute modules with enhanced progress tracking
        for i, module_name in enumerate(modules_to_run, 1):
            progress = int((i-1) / len(modules_to_run) * 100)
            print(f"   [{progress:3d}%] {module_name.title()} Analysis...", end="", flush=True)
            
            # Execute module with timeout and performance tracking
            execution_result = self._execute_module_with_timeout(module_name)
            self.execution_metrics[module_name] = execution_result
            
            # Store result
            self.current_analysis['results'][module_name] = execution_result.result
            
            # Display result with timing
            if execution_result.success:
                status_icon = "COMPLETE"
                timing = f"({execution_result.execution_time:.1f}s)"
            elif execution_result.timeout_occurred:
                status_icon = "TIMEOUT"
                timing = f"({execution_result.execution_time:.1f}s)"
            else:
                status_icon = "FAILED"
                timing = f"({execution_result.execution_time:.1f}s)"
            
            print(f" {status_icon} {timing}")
        
        # Enhanced completion summary with API statistics
        total_time = time.time() - start_time
        successful = len([m for m in self.execution_metrics.values() if m.success])
        failed = len([m for m in self.execution_metrics.values() if not m.success and not m.timeout_occurred])
        timeout = len([m for m in self.execution_metrics.values() if m.timeout_occurred])
        
        # API-specific statistics
        api_modules = ['securitytrails', 'abuseipdb', 'virustotal']
        api_success = len([m for m in api_modules if m in self.execution_metrics and self.execution_metrics[m].success])
        
        print(f"   [100%] Analysis Complete: {successful}/{len(modules_to_run)} successful | "
              f"{failed} failed | {timeout} timeout | APIs: {api_success}/3 | Total: {total_time:.1f}s")
        
        # Log performance summary
        self.logger.info("Enhanced workflow completed",
                        total_modules=len(modules_to_run),
                        successful=successful,
                        failed=failed,
                        timeout=timeout,
                        api_success=api_success,
                        total_time=f"{total_time:.2f}s")
    
    def _execute_module_with_timeout(self, module_name: str) -> ModuleExecutionResult:
        """Execute single module with timeout and performance monitoring"""
        module = self.modules.get(module_name)
        if not module:
            return ModuleExecutionResult(
                success=False,
                result={'error': 'Module not available', 'analysis_status': 'failed'},
                execution_time=0.0,
                error_message="Module not available"
            )
        
        domain = self.current_analysis['domain']
        timeout = self.module_timeouts.get(module_name, 60)
        start_time = time.time()
        
        # Shared result container for thread communication
        result_container = {'result': None, 'error': None}
        
        def execute_module():
            """Thread target function for module execution"""
            try:
                result_container['result'] = self._call_module_function(module_name, module, domain)
            except Exception as error:
                result_container['error'] = error
        
        # Execute with timeout using threading
        thread = threading.Thread(target=execute_module, daemon=True)
        thread.start()
        thread.join(timeout)
        
        execution_time = time.time() - start_time
        
        # Check execution result
        if thread.is_alive():
            # Timeout occurred
            self.logger.warning(f"{module_name} analysis timeout", 
                              domain=domain, 
                              timeout=timeout,
                              execution_time=execution_time)
            
            return ModuleExecutionResult(
                success=False,
                result=self._get_fallback_result(module_name, "timeout"),
                execution_time=execution_time,
                error_message=f"Module timeout after {timeout}s",
                timeout_occurred=True
            )
        
        elif result_container['error']:
            # Module execution failed
            error = result_container['error']
            self.logger.error(f"{module_name} analysis failed", 
                            domain=domain, 
                            error=str(error),
                            execution_time=execution_time)
            
            return ModuleExecutionResult(
                success=False,
                result=self._get_fallback_result(module_name, "error", str(error)),
                execution_time=execution_time,
                error_message=str(error)
            )
        
        else:
            # Module execution successful
            result = result_container['result']
            self.logger.debug(f"{module_name} analysis completed", 
                            domain=domain,
                            execution_time=execution_time,
                            status=result.get('analysis_status'))
            
            return ModuleExecutionResult(
                success=True,
                result=result,
                execution_time=execution_time
            )
    
    def _call_module_function(self, module_name: str, module: Any, domain: str) -> Dict[str, Any]:
        """Call the appropriate function for each module type - ENHANCED WITH NEW APIS"""
        if module_name == 'dns':
            return module.analyze_domain(domain)
        
        elif module_name == 'cdn':
            # Enhanced dependency chain - try to get IP from previous results
            dns_result = self.current_analysis['results'].get('dns', {})
            ip_address = dns_result.get('ipv4')
            
            if not ip_address:
                # Try fallback data if main result failed
                fallback_data = dns_result.get('fallback_data', {})
                ip_address = fallback_data.get('ipv4')
            
            if ip_address:
                return module.analyze_infrastructure(ip_address, domain)
            else:
                raise Exception("No IP address available from DNS analysis")
        
        elif module_name == 'network':
            # Enhanced dependency chain for network module
            dns_result = self.current_analysis['results'].get('dns', {})
            ip_address = dns_result.get('ipv4')
            
            if not ip_address:
                # Try fallback data
                fallback_data = dns_result.get('fallback_data', {})
                ip_address = fallback_data.get('ipv4')
            
            if ip_address:
                return module.analyze_network(ip_address, domain)
            else:
                raise Exception("No IP address available from DNS analysis")
        
        elif module_name == 'subdomain':
            return module.scan_subdomains(domain)
        
        elif module_name == 'securitytrails':
            return module.analyze_domain_intelligence(domain)
        
        elif module_name == 'abuseipdb':
            # NEW API: Get IP from DNS analysis for reputation check
            dns_result = self.current_analysis['results'].get('dns', {})
            ip_address = dns_result.get('ipv4')
            
            if not ip_address:
                # Try fallback data
                fallback_data = dns_result.get('fallback_data', {})
                ip_address = fallback_data.get('ipv4')
            
            if ip_address:
                return module.analyze_ip_reputation(ip_address, domain)
            else:
                raise Exception("No IP address available for reputation analysis")
        
        elif module_name == 'virustotal':
            # NEW API: Direct domain reputation analysis
            return module.analyze_domain_reputation(domain)
        
        else:
            raise Exception(f"Unknown module: {module_name}")
    
    def _get_fallback_result(self, module_name: str, failure_type: str, error_details: str = "") -> Dict[str, Any]:
        """Generate fallback result for failed modules - ENHANCED WITH NEW APIS"""
        base_result = {
            'analysis_status': 'failed',
            'error': error_details,
            'failure_type': failure_type,
            'failure_timestamp': datetime.now().isoformat()
        }
        
        # Module-specific fallback data - ENHANCED
        fallback_data = {
            'dns': {
                'ipv4': None,
                'ipv6': None,
                'nameservers': [],
                'mail_servers': []
            },
            'cdn': {
                'provider_name': 'Unknown',
                'provider_type': 'Unknown',
                'protection_level': 'Unknown',
                'location': {'country': 'Unknown', 'city': 'Unknown'}
            },
            'network': {
                'connectivity_test': {'status': 'unknown'},
                'opsec_assessment': {'risk_level': 'unknown'},
                'traceroute_data': {'total_hops': 0}
            },
            'subdomain': {
                'discovered_assets': [],
                'total_found': 0
            },
            'securitytrails': {
                'api_status': 'failed',
                'domain_details': {'subdomain_count': 0}
            },
            'abuseipdb': {                                  # NEW API FALLBACK
                'api_status': 'failed',
                'ip_address': 'unknown',
                'abuse_confidence': 0,
                'reputation_intelligence': {
                    'risk_level': 'UNKNOWN',
                    'risk_description': 'Analysis failed'
                }
            },
            'virustotal': {                                 # NEW API FALLBACK
                'api_status': 'failed',
                'domain': 'unknown',
                'threat_analysis': {
                    'total_security_vendors': 0,
                    'malicious_detections': 0,
                    'suspicious_detections': 0
                },
                'threat_intelligence': {
                    'threat_level': 'UNKNOWN',
                    'threat_description': 'Analysis failed'
                }
            }
        }
        
        if module_name in fallback_data:
            base_result['fallback_data'] = fallback_data[module_name]
        
        return base_result

def display_intro():
    """Display professional intro - ENHANCED"""
    print(Colors.header("DOMAIN FORENSIC ANALYZER"))
    print(Colors.investigation_separator(80))
    print("Professional OSINT Tool | Network Intelligence | Asset Discovery")
    print("Multi-API Threat Intelligence | Enhanced Security Analysis")
    print(Colors.investigation_separator(80))
    print(f"Platform: {Colors.info(platform.system())} | "
          f"Modules: {Colors.success('7 Core Analyzers')} | "  # UPDATED COUNT
          f"APIs: {Colors.success('3 Intelligence Sources')} | "
          f"Status: {Colors.success('Ready')}")

def get_domain_input() -> str:
    """Get domain input - single line style"""
    while True:
        try:
            domain = input(f"\nTarget domain: ").strip()
            
            if not domain:
                print("Please enter a domain.")
                continue
            
            if domain.lower() in ['exit', 'quit', 'q']:
                print("Goodbye!")
                sys.exit(0)
            
            if DomainValidator.is_valid_domain(domain):
                return DomainValidator.clean_domain(domain)
            else:
                print("Invalid domain format. Try again.")
                
        except KeyboardInterrupt:
            print("\nGoodbye!")
            sys.exit(0)

def display_comprehensive_summary_fixed(result: UnifiedResult) -> None:
    """Display comprehensive summary using calculated values from result - ENHANCED WITH NEW APIS"""
    print(f"\n{Colors.investigation_separator(80)}")
    print(Colors.header(f"ANALYSIS COMPLETE: {result.domain.upper()}"))
    print(Colors.investigation_separator(80))
    
    # Execution Overview
    print(f"Execution Time: {Colors.info(f'{result.total_execution_time:.1f}s')}")
    print(f"Modules Success: {Colors.success(f'{len(result.modules_successful)}/{len(result.modules_executed)}')}")
    print(f"Overall Risk: {Colors.highlight(result.overall_risk_level.upper())}")
    
    # Module-by-Module Summary  
    print(f"\n{Colors.section_header('MODULE RESULTS', 60)}")
    
    # DNS Foundation
    dns_result = result.results.get('dns', {})
    if dns_result.get('analysis_status') == 'abgeschlossen':
        ip = dns_result.get('ipv4', 'Unknown')
        reverse_dns = dns_result.get('reverse_dns', 'Not available')
        
        nameservers = (dns_result.get('nameservers', []) or 
                      dns_result.get('ns_records', []) or 
                      dns_result.get('name_servers', []) or [])
        nameserver_count = len(nameservers) if nameservers else 0
        
        print(f"DNS Foundation: COMPLETE {Colors.format_ip(ip)}")
        print(f"   ├─ Nameservers: {Colors.info(str(nameserver_count))}")
        if reverse_dns and reverse_dns != 'Not available':
            print(f"   └─ Reverse DNS: {Colors.dim(reverse_dns[:50])}...")
    else:
        print(f"DNS Foundation: FAILED")
    
    # Infrastructure
    cdn_result = result.results.get('cdn', {})
    if cdn_result.get('analysis_status') == 'abgeschlossen':
        provider = cdn_result.get('provider_name', 'Unknown')
        provider_type = cdn_result.get('provider_type', 'Unknown')  
        protection = cdn_result.get('protection_level', 'Unknown')
        
        location = (cdn_result.get('location') or 
                   cdn_result.get('geolocation') or 
                   cdn_result.get('geo_data') or {})
        
        if location and isinstance(location, dict):
            country = location.get('country', 'Unknown')
            city = location.get('city', 'Unknown')
        else:
            country = cdn_result.get('country', 'Unknown')
            city = cdn_result.get('city', 'Unknown')
        
        print(f"Infrastructure: COMPLETE {provider} ({provider_type})")
        print(f"   ├─ Protection: {Colors.info(protection)}")
        print(f"   └─ Location: {Colors.info(f'{city}, {country}')}")
    else:
        print(f"Infrastructure: FAILED")
    
    # Asset Discovery
    subdomain_result = result.results.get('subdomain', {})
    if subdomain_result.get('analysis_status') == 'abgeschlossen':
        total_assets = result.total_assets_found
        sensitive_assets_count = result.sensitive_assets_found
        
        print(f"Asset Discovery: COMPLETE {total_assets} Subdomains")
        print(f"   ├─ Total Assets: {Colors.highlight(str(total_assets))}")
        print(f"   └─ Sensitive: {Colors.warning(str(sensitive_assets_count))} (Risk Level: {result.overall_risk_level.upper()})")
        
        # Show risk assessment
        if sensitive_assets_count > 0:
            if sensitive_assets_count >= 20:
                risk_color = Colors.error
                risk_text = "HIGH RISK"
            elif sensitive_assets_count >= 10:
                risk_color = Colors.warning
                risk_text = "MEDIUM RISK"
            else:
                risk_color = Colors.info
                risk_text = "LOW RISK"
            
            print(f"   Risk Assessment: {risk_color(risk_text)}")
    else:
        print(f"Asset Discovery: FAILED")
    
    # Network Intelligence
    network_result = result.results.get('network', {})
    if network_result.get('analysis_status') == 'abgeschlossen':
        connectivity = network_result.get('connectivity_test', {})
        opsec = network_result.get('opsec_assessment', {})
        traceroute = network_result.get('traceroute_data', {})
        
        response_times = connectivity.get('response_times', {}) if isinstance(connectivity, dict) else {}
        ping_time = response_times.get('ping', 'Unknown') if isinstance(response_times, dict) else 'Unknown'
        risk_level = opsec.get('risk_level', 'unknown').upper() if isinstance(opsec, dict) else 'UNKNOWN'
        hop_count = traceroute.get('total_hops', 0) if isinstance(traceroute, dict) else 0
        
        risk_color = Colors.success if risk_level == 'LOW' else Colors.warning if risk_level == 'MEDIUM' else Colors.error
        print(f"Network Path: COMPLETE {hop_count} Hops analyzed")
        print(f"   ├─ Connectivity: {Colors.info(ping_time)}")
        print(f"   └─ OPSEC Risk: {risk_color(risk_level)}")
    else:
        print(f"Network Path: FAILED")
    
    # SecurityTrails
    st_result = result.results.get('securitytrails', {})
    if st_result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
        api_status = st_result.get('api_status', 'unknown')
        domain_details = st_result.get('domain_details', {})
        subdomain_count = domain_details.get('subdomain_count', 0) if isinstance(domain_details, dict) else 0
        
        status_text = "Demo-Mode" if api_status == 'demo_mode' else "Live API"
        print(f"Intelligence: COMPLETE {status_text}")
        print(f"   └─ Historical Subdomains: {Colors.info(str(subdomain_count))}")
    else:
        print(f"Intelligence: FAILED")
    
    # AbuseIPDB - NEW API DISPLAY
    abuse_result = result.results.get('abuseipdb', {})
    if abuse_result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
        api_status = abuse_result.get('api_status', 'unknown')
        abuse_confidence = abuse_result.get('abuse_confidence', 0)
        reputation_intel = abuse_result.get('reputation_intelligence', {})
        risk_level = reputation_intel.get('risk_level', 'UNKNOWN')
        
        status_text = "Demo-Mode" if api_status == 'demo_mode' else "Live API"
        risk_color = Colors.error if risk_level == 'CRITICAL' else Colors.warning if risk_level == 'HIGH' else Colors.success
        print(f"IP Reputation: COMPLETE {status_text}")
        print(f"   ├─ Abuse Confidence: {Colors.info(f'{abuse_confidence}%')}")
        print(f"   └─ Risk Level: {risk_color(risk_level)}")
    else:
        print(f"IP Reputation: FAILED")
    
    # VirusTotal - NEW API DISPLAY
    vt_result = result.results.get('virustotal', {})
    if vt_result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
        api_status = vt_result.get('api_status', 'unknown')
        threat_analysis = vt_result.get('threat_analysis', {})
        malicious = threat_analysis.get('malicious_detections', 0)
        suspicious = threat_analysis.get('suspicious_detections', 0)
        total_vendors = threat_analysis.get('total_security_vendors', 0)
        threat_intel = vt_result.get('threat_intelligence', {})
        threat_level = threat_intel.get('threat_level', 'UNKNOWN')
        
        status_text = "Demo-Mode" if api_status == 'demo_mode' else "Live API"
        threat_color = Colors.error if threat_level == 'CRITICAL' else Colors.warning if threat_level == 'HIGH' else Colors.success
        print(f"Domain Reputation: COMPLETE {status_text}")
        print(f"   ├─ Threat Detection: {Colors.info(f'{malicious + suspicious}/{total_vendors} vendors')}")
        print(f"   └─ Threat Level: {threat_color(threat_level)}")
    else:
        print(f"Domain Reputation: FAILED")
    
    # Enhanced Risk Assessment Summary
    if result.sensitive_assets_found > 0 or abuse_result.get('abuse_confidence', 0) > 25 or vt_result.get('threat_analysis', {}).get('malicious_detections', 0) > 0:
        print(f"\n{Colors.section_header('ENHANCED RISK ASSESSMENT', 60)}")
        
        # Multi-factor risk assessment
        risk_factors = []
        
        if result.sensitive_assets_found >= 20:
            risk_factors.append("High number of sensitive assets")
        elif result.sensitive_assets_found >= 3:
            risk_factors.append("Moderate sensitive asset exposure")
        
        # IP reputation risks
        abuse_confidence = abuse_result.get('abuse_confidence', 0)
        if abuse_confidence > 50:
            risk_factors.append(f"High IP abuse confidence ({abuse_confidence}%)")
        elif abuse_confidence > 25:
            risk_factors.append(f"Moderate IP reputation risk ({abuse_confidence}%)")
        
        # Domain reputation risks
        malicious = vt_result.get('threat_analysis', {}).get('malicious_detections', 0)
        if malicious > 0:
            risk_factors.append(f"Domain flagged by {malicious} security vendors")
        
        # Overall risk calculation
        if malicious > 0 or abuse_confidence > 75:
            overall_risk = "CRITICAL"
            risk_color = Colors.error
        elif result.sensitive_assets_found >= 10 or abuse_confidence > 50:
            overall_risk = "HIGH"
            risk_color = Colors.warning
        elif result.sensitive_assets_found >= 3 or abuse_confidence > 25:
            overall_risk = "MEDIUM"
            risk_color = Colors.warning
        else:
            overall_risk = "LOW"
            risk_color = Colors.info
        
        print(f"Multi-Source Risk Level: {risk_color(overall_risk)}")
        
        if risk_factors:
            print(f"Risk Factors:")
            for factor in risk_factors[:3]:  # Top 3 factors
                print(f"   • {factor}")
    
    # Final Summary
    print(f"\n{Colors.investigation_separator(80)}")
    print(f"Enhanced Analysis Complete | Detailed Log: {Colors.dim('logs/domain_analyzer_*.log')}")
    print(f"Total Assets: {Colors.highlight(str(result.total_assets_found))} | "
          f"Sensitive: {Colors.warning(str(result.sensitive_assets_found))} | "
          f"Risk: {Colors.info(result.overall_risk_level.upper())} | "
          f"Time: {Colors.info(f'{result.total_execution_time:.1f}s')}")
    print(Colors.investigation_separator(80))

def main():
    """Main single-run interface with enhanced multi-API support"""
    try:
        # Display enhanced intro
        display_intro()
        
        # Initialize analyzer
        analyzer = DomainAnalyzer()
        
        # Get domain input
        domain = get_domain_input()
        
        # Run enhanced analysis
        result = analyzer.analyze_domain(domain)
        
        # Display enhanced results
        display_comprehensive_summary_fixed(result)
        
        print(f"\nEnhanced analysis complete. Check logs for detailed information.")
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted. Goodbye!")
    except Exception as error:
        print(f"Analysis failed: {error}")

if __name__ == "__main__":
    main()