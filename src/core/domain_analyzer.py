          
"""
Domain Forensic Analyzer - Multi-API Domain Analysis Tool
OSINT Tool for domain intelligence gathering and threat assessment
"""

import sys
import os
import platform
import time
import threading
import socket
import requests
import getpass
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from dataclasses import dataclass

# Try to import advanced logging library, fallback to basic logging if not available
try:
    from loguru import logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

# Import utility modules for colors and domain validation
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.utils.colors import Colors
from src.utils.validators import DomainValidator
from src.core.result_aggregator import create_result_aggregator, UnifiedResult

# Import all analyzer modules and check if they load successfully
try:
    from src.core.security_manager import create_security_manager
    from src.analyzers.dns_analyzer import DNSAnalyzer
    from src.analyzers.cdn_detector import CDNDetector
    from src.analyzers.dns_history_analyzer import DNSHistoryAnalyzer
    from src.analyzers.subdomain_scanner import SubdomainScanner
    from src.analyzers.network_intelligence import NetworkIntelligence
    from src.analyzers.securitytrails_client import SecurityTrailsClient
    from src.analyzers.abuseipdb_client import AbuseIPDBClient
    from src.analyzers.virustotal_client import VirusTotalClient
    CORE_MODULES_AVAILABLE = True
except ImportError as error:
    CORE_MODULES_AVAILABLE = False
    print(f"Core modules import error: {error}")

try:
    from src.analyzers.whois import get_whois
    WHOIS_MODULE_AVAILABLE = True
except ImportError as error:
    get_whois = None
    WHOIS_MODULE_AVAILABLE = False
    print(f"WHOIS module import error: {error}")

@dataclass
class ModuleExecutionResult:
    """Stores the result and performance data for each analyzer module"""
    success: bool
    result: Dict[str, Any]
    execution_time: float
    error_message: Optional[str] = None
    timeout_occurred: bool = False


class ThreadAwareStdoutRouter:
    """Route stdout per thread so worker output can be muted safely."""

    def __init__(self, target):
        self._target = target
        self._local = threading.local()

    def mute_current_thread(self) -> None:
        self._local.muted = True

    def unmute_current_thread(self) -> None:
        self._local.muted = False

    def write(self, data):
        if getattr(self._local, 'muted', False):
            return len(data)
        return self._target.write(data)

    def flush(self) -> None:
        if getattr(self._local, 'muted', False):
            return
        self._target.flush()

    def __getattr__(self, name):
        return getattr(self._target, name)


if not isinstance(sys.stdout, ThreadAwareStdoutRouter):
    sys.stdout = ThreadAwareStdoutRouter(sys.stdout)

class DomainAnalyzer:
    """
    Main class that coordinates all domain analysis modules
    Handles module execution, timeouts, error recovery, and result aggregation
    """
    
    def __init__(self):
        """Set up the analyzer with all modules and configuration"""
        # Detect operating system for cross-platform compatibility
        self.platform = platform.system().lower()
        
        # Set up file paths for logs and data
        self.project_root = Path(__file__).parent.parent.parent
        self.logs_dir = self.project_root / "logs"
        
        # Create logs directory if it doesn't exist
        self.logs_dir.mkdir(exist_ok=True)
        
        # Set up logging system
        self._setup_logging()
        
        # Dictionary to store analyzer module instances
        self.modules = {}
        
        # Order in which modules will be executed
        self.module_execution_order = [
            'dns', 'whois', 'dns_history', 'cdn', 'network', 'subdomain',
            'securitytrails', 'abuseipdb', 'virustotal'
        ]
        
        # Maximum time each module is allowed to run before being stopped
        self.module_timeouts = {
            'dns': 30,
            'whois': 30,
            'dns_history': 90,
            'cdn': 45, 
            'network': 90,
            'subdomain': 180,
            'securitytrails': 30,
            'abuseipdb': 30,
            'virustotal': 30
        }
        
        # Variables to track current analysis state
        self.current_analysis = None
        self.execution_metrics = {}
        
        # Initialize all analyzer modules
        self._initialize_system()
        
        # Set up result aggregation system
        self.result_aggregator = create_result_aggregator()
    
    def _setup_logging(self) -> None:
        """Configure logging to file with timestamps and rotation"""
        if LOGURU_AVAILABLE:
            # Remove default logger and add custom file logger
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
            # Fallback to basic Python logging
            import logging
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger('DomainAnalyzer')
    
    def _initialize_system(self) -> None:
        """Start up all analyzer modules if they imported correctly"""
        if not CORE_MODULES_AVAILABLE:
            return
        
        try:
            self._initialize_modules()
            self.logger.info("System initialization complete", modules_loaded=len(self.modules))
        except Exception as error:
            self.logger.error("System initialization failed", error=str(error))
    
    def _initialize_modules(self) -> None:
        """Create instances of all analyzer modules and store them"""
        module_classes = {
            'dns': DNSAnalyzer,
            'whois': get_whois if WHOIS_MODULE_AVAILABLE else None,
            'dns_history': DNSHistoryAnalyzer,
            'cdn': CDNDetector,
            'subdomain': SubdomainScanner,
            'network': NetworkIntelligence,
            'securitytrails': SecurityTrailsClient,
            'abuseipdb': AbuseIPDBClient,
            'virustotal': VirusTotalClient
        }
        
        # Try to create each module, log warnings for any that fail
        for module_name, module_class in module_classes.items():
            try:
                if module_class is None:
                    raise ImportError(f"{module_name} module not available")
                self.modules[module_name] = module_class if module_name == 'whois' else module_class()
                self.logger.debug(f"{module_name.title()} module initialized")
            except Exception as error:
                self.logger.warning(f"Failed to initialize {module_name}", error=str(error))
    
    def analyze_domain(self, domain: str) -> UnifiedResult:
        """Main function to analyze a domain using all available modules"""
        # Check if domain format is valid
        if not DomainValidator.is_valid_domain(domain):
            raise ValueError(f"Invalid domain format: {domain}")
        
        # Clean the domain input and start timing
        clean_domain = DomainValidator.clean_domain(domain)
        start_time = datetime.now()
        
        self.logger.info("Starting multi-API domain analysis", domain=clean_domain)
        
        # Set up tracking variables for this analysis
        self.current_analysis = {
            'domain': clean_domain,
            'start_time': start_time,
            'modules_to_run': self.module_execution_order,
            'results': {},
            'errors': [],
            'warnings': []
        }
        self.execution_metrics = {}
        
        # Run all the analyzer modules
        self._execute_analysis_workflow()
        
        # Calculate how long everything took
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Log summary statistics
        self.logger.info("Analysis completed", 
                        domain=clean_domain,
                        execution_time=execution_time,
                        successful_modules=len([m for m in self.execution_metrics.values() if m.success]),
                        failed_modules=len([m for m in self.execution_metrics.values() if not m.success]),
                        apis_used=len([m for m in ['securitytrails', 'abuseipdb', 'virustotal'] 
                                     if m in self.modules and self.execution_metrics.get(m, {}).success]))
        
        # Combine all results into a unified format
        result = self.result_aggregator.aggregate_results(
            domain=clean_domain,
            module_results=self.current_analysis['results'],
            execution_time=execution_time
        )
        
        return result
    
    def _execute_analysis_workflow(self) -> None:
        """Run all modules in sequence with progress tracking and error handling"""
        # Only run modules that loaded successfully
        modules_to_run = [m for m in self.current_analysis['modules_to_run'] if m in self.modules]
        
        if not modules_to_run:
            self.logger.warning("No modules available for execution")
            return
        
        print(f"\nStarting analysis...")
        start_time = time.time()
        
        # Execute each module and track progress
        for i, module_name in enumerate(modules_to_run, 1):
            module_label = module_name.replace('_', ' ').title()
            print(f"   [{i}/{len(modules_to_run)}] {module_label}...", end="", flush=True)
            
            # Run the module with timeout protection
            execution_result = self._execute_module_with_timeout(module_name)
            self.execution_metrics[module_name] = execution_result
            
            # Store the result for later use
            self.current_analysis['results'][module_name] = execution_result.result
            
            # Show what happened with timing
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
        
        # Show final statistics
        total_time = time.time() - start_time
        successful = len([m for m in self.execution_metrics.values() if m.success])
        failed = len([m for m in self.execution_metrics.values() if not m.success and not m.timeout_occurred])
        timeout = len([m for m in self.execution_metrics.values() if m.timeout_occurred])
        
        # Count how many live API-backed modules succeeded
        api_modules = ['securitytrails', 'abuseipdb', 'virustotal']
        api_success = len([m for m in api_modules if m in self.execution_metrics and self.execution_metrics[m].success])
        whois_result = self.current_analysis['results'].get('whois', {})
        whois_used_api = (
            self.execution_metrics.get('whois') is not None
            and self.execution_metrics['whois'].success
            and whois_result.get('source') == 'WhoisXML API'
        )
        if whois_used_api:
            api_success += 1
        dns_history_result = self.current_analysis['results'].get('dns_history', {})
        dns_history_used_external = bool([
            source for source in dns_history_result.get('data_sources', [])
            if source != 'Native Fallback'
        ])
        if dns_history_used_external:
            api_success += 1
        api_total = 5 if 'dns_history' in modules_to_run else (4 if 'whois' in modules_to_run else 3)
        
        print(f"   [done] Analysis complete: {successful}/{len(modules_to_run)} successful | "
              f"{failed} failed | {timeout} timeout | APIs: {api_success}/{api_total} | Total: {total_time:.1f}s")
        
        # Log detailed statistics
        self.logger.info("Workflow completed",
                        total_modules=len(modules_to_run),
                        successful=successful,
                        failed=failed,
                        timeout=timeout,
                        api_success=api_success,
                        api_total=api_total,
                        total_time=f"{total_time:.2f}s")
    
    def _execute_module_with_timeout(self, module_name: str) -> ModuleExecutionResult:
        """Run a single module with timeout protection and performance monitoring"""
        module = self.modules.get(module_name)

        if not module:
            # Return failure result if module doesn't exist
            return ModuleExecutionResult(
                success=False,
                result={'error': 'Module not available', 'analysis_status': 'failed'},
                execution_time=0.0,
                error_message="Module not available"
            )
        
        domain = self.current_analysis['domain']
        timeout = self.module_timeouts.get(module_name, 60)
        start_time = time.time()
        
        # Container to share results between threads
        result_container = {'result': None, 'error': None}
        
        def execute_module():
            """Function that runs in separate thread to enable timeout"""
            stdout_router = sys.stdout if isinstance(sys.stdout, ThreadAwareStdoutRouter) else None
            try:
                if stdout_router:
                    stdout_router.mute_current_thread()
                result_container['result'] = self._call_module_function(module_name, module, domain)
            except Exception as error:
                result_container['error'] = error
            finally:
                if stdout_router:
                    stdout_router.unmute_current_thread()
        
        # Start module in separate thread and wait for completion or timeout
        thread = threading.Thread(target=execute_module, daemon=True)
        thread.start()
        thread.join(timeout)
        
        execution_time = time.time() - start_time
        
        # Check what happened with the module execution
        if thread.is_alive():
            # Module took too long and was stopped
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
            # Module crashed with an error
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
            # Module completed successfully
            result = result_container['result']
            if not isinstance(result, dict):
                self.logger.error(f"{module_name} analysis returned invalid result",
                                domain=domain,
                                result_type=str(type(result)),
                                execution_time=execution_time)
                return ModuleExecutionResult(
                    success=False,
                    result=self._get_fallback_result(module_name, "error", "Invalid module result"),
                    execution_time=execution_time,
                    error_message="Invalid module result"
                )
            if result.get('analysis_status') == 'failed':
                error_message = str(result.get('error') or 'Module reported failure')
                self.logger.error(f"{module_name} analysis reported failure",
                                domain=domain,
                                error=error_message,
                                execution_time=execution_time)
                return ModuleExecutionResult(
                    success=False,
                    result=result,
                    execution_time=execution_time,
                    error_message=error_message
                )
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
        """Call the correct function for each type of analyzer module"""
        if module_name == 'dns':
            return module.analyze_domain(domain)

        elif module_name == 'whois':
            result = module(domain)
            if not isinstance(result, dict):
                raise Exception("Invalid WHOIS result")
            if result.get('error'):
                result.setdefault('analysis_status', 'failed')
                result.setdefault('failure_type', 'error')
                return result
            result.setdefault('analysis_status', 'abgeschlossen')
            return result

        elif module_name == 'dns_history':
            return module.analyze_dns_history(domain)
        
        elif module_name == 'cdn':
            # CDN analyzer needs IP address from DNS results
            dns_result = self.current_analysis['results'].get('dns', {})
            ip_address = dns_result.get('ipv4')
            
            if not ip_address:
                # Try backup data if main DNS result failed
                fallback_data = dns_result.get('fallback_data', {})
                ip_address = fallback_data.get('ipv4')
            
            if ip_address:
                return module.analyze_infrastructure(ip_address, domain)
            else:
                raise Exception("No IP address available from DNS analysis")
        
        elif module_name == 'network':
            # Network analyzer also needs IP address from DNS
            dns_result = self.current_analysis['results'].get('dns', {})
            ip_address = dns_result.get('ipv4')
            
            if not ip_address:
                # Try backup data
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
            # AbuseIPDB checks IP reputation, so needs IP from DNS
            dns_result = self.current_analysis['results'].get('dns', {})
            ip_address = dns_result.get('ipv4')
            
            if not ip_address:
                # Try backup data
                fallback_data = dns_result.get('fallback_data', {})
                ip_address = fallback_data.get('ipv4')
            
            if ip_address:
                return module.analyze_ip_reputation(ip_address, domain)
            else:
                raise Exception("No IP address available for reputation analysis")
        
        elif module_name == 'virustotal':
            # VirusTotal can check domain directly
            return module.analyze_domain_reputation(domain)
        
        else:
            raise Exception(f"Unknown module: {module_name}")
    
    def _get_fallback_result(self, module_name: str, failure_type: str, error_details: str = "") -> Dict[str, Any]:
        """Create a safe fallback result when a module fails"""
        base_result = {
            'analysis_status': 'failed',
            'error': error_details,
            'failure_type': failure_type,
            'failure_timestamp': datetime.now().isoformat()
        }
        
        # Provide appropriate fallback data for each module type
        domain = self.current_analysis.get('domain', 'unknown') if self.current_analysis else 'unknown'
        fallback_data = {
            'dns': {
                'ipv4': None,
                'ipv6': None,
                'nameservers': [],
                'mail_servers': []
            },
            'whois': {
                'source': 'failed',
                'domain': domain,
                'registrar': None,
                'creation_date': None,
                'expiration_date': None,
                'updated_date': None,
                'name_servers': [],
                'registrant_name': None,
                'registrant_organization': None,
                'registrant_country': None
            },
            'dns_history': {
                'domain': domain,
                'data_sources': [],
                'timeline_span': {'start_date': None, 'end_date': None, 'days': 0},
                'major_changes': 0,
                'timeline': [],
                'pattern_analysis': {
                    'change_frequency': 'not assessed',
                    'infrastructure_stability': 'unknown',
                    'suspicious_patterns': ['analysis failed'],
                    'risk_level': 'UNKNOWN'
                },
                'historical_risk_events': []
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
            'abuseipdb': {
                'api_status': 'failed',
                'ip_address': 'unknown',
                'abuse_confidence': 0,
                'reputation_intelligence': {
                    'risk_level': 'UNKNOWN',
                    'risk_description': 'Analysis failed'
                }
            },
            'virustotal': {
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

def get_external_ip() -> str:
    """Get our external IP address for forensic documentation"""
    try:
        # Try multiple services for reliability
        services = [
            'https://api.ipify.org',
            'https://checkip.amazonaws.com',
            'https://ipinfo.io/ip'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    return response.text.strip()
            except:
                continue
        
        return "Unknown"
    except:
        return "Unknown"

def get_local_ip() -> str:
    """Get our local IP address"""
    try:
        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "Unknown"

def get_system_metadata() -> dict:
    """Collect system metadata for forensic documentation"""
    try:
        hostname = socket.gethostname()
        username = getpass.getuser()
        system_info = {
            'hostname': hostname,
            'username': username,
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.machine()
        }
        return system_info
    except:
        return {
            'hostname': 'Unknown',
            'username': 'Unknown', 
            'platform': 'Unknown',
            'platform_version': 'Unknown',
            'architecture': 'Unknown'
        }

def assess_opsec_risk(external_ip: str, local_ip: str) -> dict:
    """Assess OPSEC risks for forensic analysis"""
    
    # Check if we're behind NAT
    behind_nat = external_ip != local_ip and local_ip.startswith(('192.168.', '10.', '172.'))
    
    # Check if using VPN/Proxy (simple heuristic)
    potential_vpn = False
    try:
        # Common VPN/hosting providers (simplified check)
        if any(keyword in external_ip for keyword in ['amazonaws', 'digitalocean', 'vpn']):
            potential_vpn = True
    except:
        pass
    
    # Calculate risk levels
    attribution_risk = "LOW" if behind_nat else "MEDIUM"
    stealth_level = "HIGH" if potential_vpn else "MEDIUM" if behind_nat else "LOW"
    
    analysis_type = "PASSIVE OSINT"  # We're only doing passive analysis
    
    return {
        'attribution_risk': attribution_risk,
        'stealth_level': stealth_level,
        'analysis_type': analysis_type,
        'behind_nat': behind_nat,
        'potential_vpn': potential_vpn
    }

def display_forensic_header(domain: str, start_time: datetime) -> dict:
    """Display comprehensive forensic analysis header with metadata"""
    
    # Collect forensic metadata
    print("Collecting forensic metadata...", end="", flush=True)
    
    external_ip = get_external_ip()
    local_ip = get_local_ip()
    system_metadata = get_system_metadata()
    opsec_assessment = assess_opsec_risk(external_ip, local_ip)
    
    # Generate session ID
    session_id = start_time.strftime('%Y%m%d-%H%M%S')
    
    print(" COMPLETE")
    
    # Display forensic header
    print(f"\n{Colors.investigation_separator(80)}")
    print(Colors.header(f"DOMAIN FORENSIC ANALYZER - SESSION: {session_id}"))
    print(f"{Colors.investigation_separator(80)}")
    
    # Analysis metadata
    print(f"Analysis Timestamp: {Colors.highlight(start_time.strftime('%Y-%m-%d %H:%M:%S UTC'))}")
    print(f"Target Domain: {Colors.warning(domain.upper())}")
    print(f"Session ID: {Colors.info(session_id)}")
    
    # Analyst location and system info
    print(f"\nAnalyst Metadata:")
    print(f"├── External IP: {Colors.format_ip(external_ip)}")
    print(f"├── Local IP: {Colors.dim(local_ip)}")
    print(f"├── Hostname: {Colors.info(system_metadata['hostname'])}")
    print(f"├── Username: {Colors.dim(system_metadata['username'])}")
    system_info_text = f"{system_metadata['platform']} {platform.release()} ({system_metadata['architecture']})"
    print(f"└── System: {Colors.info(system_info_text)}")


    # OPSEC Assessment
    risk_color = (Colors.success if opsec_assessment['attribution_risk'] == 'LOW' else 
                 Colors.warning if opsec_assessment['attribution_risk'] == 'MEDIUM' else Colors.error)
    
    stealth_color = (Colors.success if opsec_assessment['stealth_level'] == 'HIGH' else 
                    Colors.warning if opsec_assessment['stealth_level'] == 'MEDIUM' else Colors.error)
    
    print(f"\nOPSEC Assessment:")
    print(f"├── Analysis Type: {Colors.info(opsec_assessment['analysis_type'])}")
    print(f"├── Attribution Risk: {risk_color(opsec_assessment['attribution_risk'])}")
    print(f"├── Stealth Level: {stealth_color(opsec_assessment['stealth_level'])}")
    
    # Network topology info
    if opsec_assessment['behind_nat']:
        print(f"├── Network Topology: {Colors.success('NAT Protected')}")
    else:
        print(f"├── Network Topology: {Colors.warning('Direct Connection')}")
        
    if opsec_assessment['potential_vpn']:
        print(f"└── Proxy/VPN: {Colors.success('Detected')}")
    else:
        print(f"└── Proxy/VPN: {Colors.dim('Not Detected')}")
    
    print(f"\n{Colors.investigation_separator(80)}")
    print("OSINT Tool | Network Intelligence | Asset Discovery")
    print("Multi-API Threat Intelligence | Security Analysis")
    print(f"{Colors.investigation_separator(80)}")
    print(f"Platform: {Colors.info(platform.system())} | "
          f"Modules: {Colors.success('9 Core Analyzers')} | "
          f"APIs: {Colors.success('5 Intelligence Sources')} | "
          f"Status: {Colors.success('Ready')}")
    
    # Return metadata for logging
    return {
        'session_id': session_id,
        'timestamp': start_time,
        'external_ip': external_ip,
        'local_ip': local_ip,
        'system_metadata': system_metadata,
        'opsec_assessment': opsec_assessment
    }

def get_domain_input() -> str:
    """Get domain name from user input with validation - minimal version for pre-header use"""
    print(Colors.header("DOMAIN FORENSIC ANALYZER"))
    print("Target Domain Selection")
    print(Colors.investigation_separator(40))
    
    while True:
        try:
            domain = input(f"Enter target domain: ").strip()
            
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


def _compute_risk_summary(result: UnifiedResult) -> Tuple[str, List[str], str]:
    """Compute a concise overall risk summary for display."""
    vt_result = result.results.get('virustotal', {})
    abuse_result = result.results.get('abuseipdb', {})
    subdomain_result = result.results.get('subdomain', {})
    risk_factors = []
    overall_risk = "LOW"

    wildcard_detected = bool(
        subdomain_result.get('wildcard_detected')
        or subdomain_result.get('dns_configuration', {}).get('wildcard_detected', False)
    )

    if not wildcard_detected:
        if result.sensitive_assets_found >= 20:
            risk_factors.append(f"Excessive attack surface ({result.sensitive_assets_found} sensitive assets)")
            overall_risk = "HIGH"
        elif result.sensitive_assets_found >= 10:
            risk_factors.append(f"Large attack surface ({result.sensitive_assets_found} sensitive assets)")
            overall_risk = "MEDIUM"

    malicious_detections = vt_result.get('threat_analysis', {}).get('malicious_detections', 0)
    if malicious_detections >= 3:
        risk_factors.append(f"Domain flagged as malicious by {malicious_detections} security vendors")
        overall_risk = "HIGH"
    elif malicious_detections > 0:
        risk_factors.append(f"Limited malicious detections at VirusTotal ({malicious_detections} vendors)")
        if overall_risk == "LOW":
            overall_risk = "MEDIUM"

    abuse_confidence = abuse_result.get('abuse_confidence', 0)
    if abuse_confidence > 50:
        risk_factors.append(f"High IP abuse confidence ({abuse_confidence}%)")
        if overall_risk != "CRITICAL":
            overall_risk = "HIGH"
    elif abuse_confidence > 25:
        risk_factors.append(f"Moderate IP abuse reports ({abuse_confidence}%)")
        if overall_risk == "LOW":
            overall_risk = "MEDIUM"

    if overall_risk == "CRITICAL":
        recommendation = "LIKELY MALICIOUS - Multiple high-confidence indicators"
    elif overall_risk == "HIGH":
        recommendation = "ELEVATED RISK - Further validation recommended"
    elif overall_risk == "MEDIUM":
        recommendation = "REVIEW REQUIRED - Mixed or limited risk signals"
    else:
        recommendation = "NO MALICIOUS INDICATORS - Low risk profile"

    return overall_risk, risk_factors, recommendation


def _display_traceroute_details(traceroute_data: Dict[str, Any], enhanced_path: List[Dict[str, Any]]) -> None:
    """Render the full traceroute without truncating hops."""
    traceroute_status = traceroute_data.get('status', 'unknown')
    command_timeout = traceroute_data.get('command_timeout_seconds')
    probe_timeout_ms = traceroute_data.get('probe_timeout_ms')
    max_hops = traceroute_data.get('max_hops')
    hops = traceroute_data.get('hops', []) or []
    last_responsive_hop = traceroute_data.get('last_responsive_hop')
    first_unresponsive_hop = traceroute_data.get('first_unresponsive_hop')

    if traceroute_status not in ['success', 'partial']:
        if traceroute_status == 'timeout':
            print(f"├── Status: {Colors.warning('TIMEOUT')}")
            print(f"├── Traceroute: {Colors.dim('incomplete')}")
        else:
            print(f"├── Status: {Colors.error('FAILED')}")
            print(f"├── Traceroute: {Colors.error('UNAVAILABLE')}")
        if command_timeout:
            print(f"├── Command Timeout: {Colors.info(f'{command_timeout}s')}")
        if probe_timeout_ms:
            print(f"├── Probe Timeout: {Colors.info(f'{probe_timeout_ms}ms')} per hop")
        if max_hops:
            print(f"├── Max Hops: {Colors.info(str(max_hops))}")
        error_text = traceroute_data.get('error')
        if error_text:
            print(f"└── Detail: {Colors.dim(error_text)}")
        return

    if traceroute_status == 'partial':
        print(f"├── Status: {Colors.warning('PARTIAL')}")
        print(f"├── Traceroute: {Colors.info(f'{len(hops)} hops observed before stop')}")
        print(f"├── Last Responsive Hop: {Colors.info(str(last_responsive_hop))}")
        print(f"├── Timeout Observed From Hop: {Colors.warning(str(first_unresponsive_hop))}")
        print(f"├── Command Timeout: {Colors.info(f'{command_timeout}s')}")
        print(f"├── Probe Timeout: {Colors.info(f'{probe_timeout_ms}ms')} per hop")
        print(f"├── Max Hops: {Colors.info(str(max_hops))}")
        error_text = traceroute_data.get('error')
        if error_text:
            print(f"├── Detail: {Colors.dim(error_text)}")
    else:
        print(f"├── Traceroute: {Colors.info(f'{len(hops)} hops')}")

    if not hops:
        print(f"└── No hop data returned")
        return

    enhanced_by_hop = {
        hop.get('hop_number'): hop for hop in enhanced_path if isinstance(hop, dict)
    }

    for index, hop in enumerate(hops):
        branch = "└──" if index == len(hops) - 1 else "├──"
        hop_number = hop.get('hop', index + 1)
        ip_address = hop.get('ip') or '*'
        hostname = hop.get('hostname') or ''
        status = hop.get('status', 'unknown').upper()
        latencies = hop.get('latencies', []) or []

        hop_details = enhanced_by_hop.get(hop_number, {})
        classification = hop_details.get('hop_classification')
        type_label = classification.replace('_', ' ').upper() if classification else 'UNKNOWN'
        if index == len(hops) - 1 and status == 'RESPONSIVE':
            type_label = 'TARGET'

        print(f"{branch} Hop {hop_number}: {ip_address}")

        child_prefix = "    " if index == len(hops) - 1 else "│   "
        detail_lines = []

        if hostname:
            detail_lines.append(f"Hostname: {hostname}")
        elif ip_address == '*':
            detail_lines.append("Hostname: not resolved")

        if latencies:
            detail_lines.append(f"RTT: {' | '.join(latencies)}")
        elif ip_address == '*' or status != 'RESPONSIVE':
            detail_lines.append("RTT: not available")

        type_value = type_label if status == 'RESPONSIVE' else f"{type_label} | {status}"
        detail_lines.append(f"Type: {type_value}")

        for detail_index, detail_line in enumerate(detail_lines):
            detail_branch = "└──" if detail_index == len(detail_lines) - 1 else "├──"
            print(f"{child_prefix}{detail_branch} {detail_line}")


def _get_subdomain_categories(subdomain_result: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Return asset categories across old and new result keys."""
    return (
        subdomain_result.get('asset_categories')
        or subdomain_result.get('categorized_assets')
        or {}
    )


def _extract_nameserver_entries(dns_result: Dict[str, Any]) -> List[str]:
    """Normalize nameserver entries for display."""
    raw_nameservers = (
        dns_result.get('nameservers')
        or dns_result.get('ns_records')
        or dns_result.get('name_servers')
        or []
    )
    entries = []
    for nameserver in raw_nameservers:
        if isinstance(nameserver, dict):
            value = nameserver.get('server') or nameserver.get('hostname') or nameserver.get('name')
        else:
            value = str(nameserver)
        if value:
            entries.append(value.strip().rstrip(',.'))
    return entries


def _extract_mail_server_entries(dns_result: Dict[str, Any]) -> List[str]:
    """Normalize MX entries for display."""
    raw_mail_servers = dns_result.get('mail_servers') or dns_result.get('mx_records') or []
    domain = str(dns_result.get('domain', '')).strip().rstrip('.')
    entries = []
    for mail_server in raw_mail_servers:
        if isinstance(mail_server, dict):
            server = (
                mail_server.get('server')
                or mail_server.get('hostname')
                or mail_server.get('mail_server')
            )
            priority = mail_server.get('priority')
            if server and priority is not None:
                clean_server = str(server).strip().rstrip(',.')
                if clean_server and '.' not in clean_server and domain:
                    clean_server = f"{clean_server}.{domain}"
                clean_priority = str(priority).strip().rstrip(',.')
                entries.append(f"{clean_server} (priority {clean_priority})")
            elif server:
                clean_server = str(server).strip().rstrip(',.')
                if clean_server and '.' not in clean_server and domain:
                    clean_server = f"{clean_server}.{domain}"
                entries.append(clean_server)
        else:
            value = str(mail_server)
            if value:
                clean_value = value.strip().rstrip(',.')
                if clean_value and '.' not in clean_value and domain:
                    clean_value = f"{clean_value}.{domain}"
                entries.append(clean_value)
    return entries


def _format_policy_record(value: Any, max_length: int = 90) -> str:
    """Render long policy-style DNS records in a compact single-line form."""
    text = str(value or '').strip()
    if not text:
        return 'not configured'
    return text if len(text) <= max_length else f"{text[:max_length - 3]}..."


def _summarize_caa_entries(dns_result: Dict[str, Any]) -> List[str]:
    """Render compact CAA labels for display."""
    entries = []
    for record in dns_result.get('caa_records', []) or []:
        if not isinstance(record, dict):
            continue
        tag = str(record.get('tag', '')).strip()
        value = str(record.get('value', '')).strip()
        if tag and value:
            entries.append(f"{tag} {value}")
    return entries


def _format_spf_analysis(spf_analysis: Dict[str, Any]) -> str:
    """Render a short SPF assessment summary for the report."""
    if not spf_analysis or spf_analysis.get('status') != 'configured':
        return 'not configured'
    return str(spf_analysis.get('summary') or 'configured')


def _format_dmarc_analysis(dmarc_analysis: Dict[str, Any]) -> str:
    """Render a compact DMARC configuration summary."""
    if not dmarc_analysis or dmarc_analysis.get('status') != 'configured':
        return 'not configured'
    return str(dmarc_analysis.get('summary') or 'configured')


def _format_dkim_discovery(dkim_result: Dict[str, Any]) -> str:
    """Summarize heuristic DKIM selector discovery in one line."""
    selectors = dkim_result.get('selectors', []) or []
    if not selectors:
        return 'no common selectors detected (heuristic discovery only)'
    selector_names = [
        str(entry.get('selector')).strip()
        for entry in selectors[:3]
        if isinstance(entry, dict) and entry.get('selector')
    ]
    if not selector_names:
        return 'selectors discovered via heuristic lookup'
    return f"{len(selectors)} discovered via heuristic lookup ({', '.join(selector_names)})"


def _format_dns_config_assessment(assessment: Dict[str, Any]) -> str:
    """Render the overall DNS configuration assessment summary."""
    if not assessment:
        return 'not assessed'
    return str(assessment.get('summary') or 'not assessed')


def _format_dns_assessment_findings(assessment: Dict[str, Any], max_items: int = 2) -> str:
    """Render the most relevant DNS hardening findings as a compact list."""
    findings = assessment.get('findings', []) if isinstance(assessment, dict) else []
    if not findings:
        return 'no material hardening gaps observed'
    return '; '.join(str(item) for item in findings[:max_items])


def _format_history_value(values: Any, max_items: int = 3, max_length: int = 86) -> str:
    """Render DNS history values compactly for the forensic summary."""
    if not values:
        return 'none'
    if isinstance(values, str):
        items = [values]
    elif isinstance(values, (list, tuple, set)):
        items = [str(item) for item in values if str(item).strip()]
    else:
        items = [str(values)]
    if not items:
        return 'none'
    rendered = ', '.join(items[:max_items])
    if len(items) > max_items:
        rendered += f", +{len(items) - max_items} more"
    return rendered if len(rendered) <= max_length else f"{rendered[:max_length - 3]}..."


def _format_history_date(value: Any) -> str:
    """Render ISO-like history timestamps as dates when possible."""
    if not value or value == 'unknown':
        return 'unknown date'
    text = str(value)
    return text[:10] if len(text) >= 10 else text


def _format_whois_value(value: Any, default: str = 'Unknown') -> str:
    """Render WHOIS values that may be scalar, list-like, or missing."""
    if value is None:
        return default
    if isinstance(value, (list, tuple, set)):
        cleaned = [str(item).strip() for item in value if str(item).strip()]
        return ', '.join(cleaned) if cleaned else default
    text = str(value).strip()
    return text if text else default


def _format_whois_nameservers(value: Any) -> List[str]:
    """Normalize WHOIS nameserver data for display."""
    if not value:
        return []
    if isinstance(value, str):
        nameservers = [value]
    elif isinstance(value, (list, tuple, set)):
        nameservers = list(value)
    else:
        nameservers = [str(value)]
    normalized = []
    seen = set()
    for nameserver in nameservers:
        text = str(nameserver).strip().rstrip('.')
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(text)
    return normalized


def _build_sensitive_asset_lookup(subdomain_result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Map discovered subdomains to their sensitive-asset metadata."""
    sensitive_lookup = {}
    for sensitive in subdomain_result.get('sensitive_assets', []) or []:
        asset = sensitive.get('asset', {}) if isinstance(sensitive, dict) else {}
        full_domain = asset.get('full_domain')
        if full_domain:
            sensitive_lookup[full_domain] = sensitive
    return sensitive_lookup


def _get_edge_protection_summary(cdn_result: Dict[str, Any]) -> Tuple[str, str]:
    """Summarize CDN/WAF presence explicitly, including negative findings."""
    provider = cdn_result.get('provider_name', 'Unknown')
    features = cdn_result.get('features', []) or []
    protection_level = str(cdn_result.get('protection_level', 'unknown')).lower()
    provider_type = str(cdn_result.get('infrastructure_type', 'direct')).lower()

    if provider in ['Unknown', 'Unknown/Direct'] or provider_type == 'direct':
        return "No CDN/WAF detected", "Origin appears directly exposed"

    waf_present = any('waf' in str(feature).lower() for feature in features) or protection_level == 'high'
    if waf_present:
        return f"{provider} detected", "WAF / edge protection available"
    return f"{provider} detected", "No explicit WAF capability identified"


def _format_provider_type(provider_type: Any) -> str:
    """Render provider types with stable casing."""
    value = str(provider_type or 'Unknown').strip().lower()
    if value == 'cdn':
        return 'CDN'
    if value == 'direct':
        return 'Direct'
    if value == 'cloud':
        return 'Cloud'
    if value == 'platform':
        return 'Platform'
    if value == 'unknown':
        return 'Unknown'
    return str(provider_type).strip().title()


def _format_category_name(category: str) -> str:
    """Render category names with stable casing."""
    category_lower = str(category).lower()
    if category_lower == 'api':
        return 'API'
    if category_lower == 'dev':
        return 'Dev'
    return str(category).title()


def _count_execution_outcomes(result: UnifiedResult) -> Tuple[int, int, int]:
    """Count successful, failed, and timeout module outcomes."""
    successful = len(result.modules_successful)
    failed = 0
    timeout = 0

    for module_result in result.results.values():
        if not isinstance(module_result, dict):
            continue
        if module_result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
            continue
        if module_result.get('failure_type') == 'timeout':
            timeout += 1
        else:
            failed += 1

    return successful, failed, timeout


def _extract_vt_category_signals(vt_result: Dict[str, Any]) -> List[str]:
    """Normalize VirusTotal category hints for display."""
    categories = vt_result.get('categories', {}) or {}
    if not isinstance(categories, dict):
        return []

    def format_category_label(value: Any) -> str:
        text = str(value).strip()
        if not text:
            return ""
        if text.islower():
            if "/" in text:
                return "/".join(part.strip().title() for part in text.split("/"))
            return text.title()
        return text

    signals = []
    seen = set()
    for source_name, category_value in categories.items():
        source_text = str(source_name).strip()
        category_text = format_category_label(category_value)

        if not category_text:
            continue

        if source_text and source_text.lower() not in category_text.lower():
            signal = f"{category_text} ({source_text})"
        else:
            signal = category_text

        normalized = signal.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        signals.append(signal)

    return signals

def display_forensic_summary(result: UnifiedResult) -> None:
    """
    Display forensic analysis results with a concise summary first and full details after.
    """
    overall_risk, risk_factors, recommendation = _compute_risk_summary(result)
    risk_color = (Colors.error if overall_risk == "CRITICAL" else
                 Colors.warning if overall_risk in ["HIGH", "MEDIUM"] else Colors.success)

    vt_result = result.results.get('virustotal', {})
    abuse_result = result.results.get('abuseipdb', {})
    st_result = result.results.get('securitytrails', {})
    dns_result = result.results.get('dns', {})
    whois_result = result.results.get('whois', {})
    dns_history_result = result.results.get('dns_history', {})
    cdn_result = result.results.get('cdn', {})
    network_result = result.results.get('network', {})
    subdomain_result = result.results.get('subdomain', {})
    wildcard_detected = bool(
        subdomain_result.get('wildcard_detected')
        or subdomain_result.get('dns_configuration', {}).get('wildcard_detected', False)
    )
    successful_modules, failed_modules, timeout_modules = _count_execution_outcomes(result)
    asset_summary_label = "Candidates" if wildcard_detected else "Assets"
    sensitive_summary_label = "Sensitive Candidates" if wildcard_detected else "Sensitive"

    print(f"\n{Colors.investigation_separator(80)}")
    print(Colors.header(f"DOMAIN FORENSIC ANALYSIS: {result.domain.upper()}"))
    print(f"Summary: Risk {risk_color(overall_risk)} | {asset_summary_label} {Colors.highlight(str(result.total_assets_found))} | "
          f"{sensitive_summary_label} {Colors.warning(str(result.sensitive_assets_found))} | "
          f"Modules {Colors.info(f'{len(result.modules_successful)}/{len(result.modules_executed)}')} | "
          f"Time {Colors.info(f'{result.total_execution_time:.1f}s')}")
    print(Colors.investigation_separator(80))

    print(f"\n{Colors.section_header('SUMMARY', 50)}")
    print(f"├── Domain: {Colors.warning(result.domain.upper())}")
    print(f"├── Overall Risk: {risk_color(overall_risk)}")
    print(f"├── Recommendation: {risk_color(recommendation)}")
    if risk_factors:
        print(f"├── Key Risk Factors:")
        for factor in risk_factors[:3]:
            print(f"│   ├── {factor}")
    print(f"└── Execution: {Colors.info(f'{result.total_execution_time:.1f}s')} | "
          f"{Colors.info(f'{len(result.modules_successful)}/{len(result.modules_executed)} modules successful')}")

    print(f"\n{Colors.section_header('TARGET', 50)}")
    if dns_result.get('analysis_status') == 'abgeschlossen':
        ip = dns_result.get('ipv4', 'Unknown')
        ipv6 = dns_result.get('ipv6', 'Not configured')
        reverse_dns = dns_result.get('reverse_dns', 'Not available')
        nameservers = _extract_nameserver_entries(dns_result)
        mail_servers = _extract_mail_server_entries(dns_result)

        print(f"├── IPv4: {Colors.format_ip(ip)}")
        if ipv6 and ipv6 != 'Not configured':
            print(f"├── IPv6: {Colors.info(ipv6)}")
        print(f"├── Nameservers: {Colors.info(str(len(nameservers)))} configured")
        if nameservers:
            for nameserver in nameservers:
                print(f"│   ├── {nameserver}")
        reverse_dns_text = reverse_dns if reverse_dns and reverse_dns != 'Not available' else 'not available'
        print(f"├── Reverse DNS: {Colors.dim(reverse_dns_text)}")
        print(f"└── Mail Servers: {Colors.info(str(len(mail_servers)))} configured")
        if mail_servers:
            for mail_server in mail_servers:
                print(f"    ├── {mail_server}")
    else:
        print(f"├── DNS: {Colors.error('FAILED')}")
        print(f"└── Unable to resolve domain")

    print(f"\n{Colors.section_header('WHOIS REGISTRATION', 50)}")
    if whois_result.get('analysis_status') == 'abgeschlossen':
        registrar = _format_whois_value(
            whois_result.get('registrar') or whois_result.get('registrarName')
        )
        creation_date = _format_whois_value(
            whois_result.get('creation_date') or whois_result.get('createdDate')
        )
        expiration_date = _format_whois_value(
            whois_result.get('expiration_date') or whois_result.get('expiresDate')
        )
        updated_date = _format_whois_value(
            whois_result.get('updated_date') or whois_result.get('updatedDate')
        )
        registrant_name = _format_whois_value(
            whois_result.get('registrant_name') or (whois_result.get('registrant') or {}).get('name'),
            'Not disclosed'
        )
        registrant_org = _format_whois_value(
            whois_result.get('registrant_organization') or (whois_result.get('registrant') or {}).get('organization'),
            'Not disclosed'
        )
        registrant_country = _format_whois_value(
            whois_result.get('registrant_country') or (whois_result.get('registrant') or {}).get('country')
        )
        nameservers = _format_whois_nameservers(whois_result.get('name_servers') or whois_result.get('nameServers'))
        nameserver_source = 'WHOIS'
        if not nameservers and dns_result.get('analysis_status') == 'abgeschlossen':
            nameservers = _extract_nameserver_entries(dns_result)
            nameserver_source = 'DNS fallback'
        source = _format_whois_value(whois_result.get('source'))

        print(f"├── Registrar: {Colors.info(registrar)}")
        print(f"├── Created: {Colors.info(creation_date)}")
        print(f"├── Expires: {Colors.info(expiration_date)}")
        print(f"├── Updated: {Colors.info(updated_date)}")
        print(f"├── Registrant: {Colors.dim(registrant_name)}")
        if registrant_org != 'Not disclosed':
            print(f"├── Organization: {Colors.dim(registrant_org)}")
        print(f"├── Country: {Colors.dim(registrant_country)}")
        nameserver_label = f"{len(nameservers)} listed"
        if nameserver_source != 'WHOIS':
            nameserver_label += f" ({nameserver_source})"
        print(f"├── Nameservers: {Colors.info(nameserver_label)}")
        for nameserver in nameservers[:5]:
            print(f"│   ├── {nameserver}")
        print(f"└── Source: {Colors.dim(source)}")
    elif whois_result:
        error_text = whois_result.get('error') or whois_result.get('failure_type') or 'Data unavailable'
        print(f"├── WHOIS: {Colors.warning('UNAVAILABLE')}")
        print(f"└── Detail: {Colors.dim(str(error_text))}")
    else:
        print(f"└── WHOIS: {Colors.error('NOT RUN')}")

    print(f"\n{Colors.section_header('DNS FORENSICS', 50)}")
    if dns_result.get('analysis_status') == 'abgeschlossen':
        soa_record = dns_result.get('soa_record', {}) or {}
        txt_records = dns_result.get('txt_records', []) or []
        spf_record = dns_result.get('spf_record')
        spf_analysis = dns_result.get('spf_analysis', {}) or {}
        dmarc_record = dns_result.get('dmarc_record')
        dmarc_analysis = dns_result.get('dmarc_analysis', {}) or {}
        dkim = dns_result.get('dkim', {}) or {}
        caa_entries = _summarize_caa_entries(dns_result)
        dnssec = dns_result.get('dnssec', {}) or {}
        zone_transfer = dns_result.get('zone_transfer', {}) or {}
        dns_config_assessment = dns_result.get('dns_configuration_assessment', {}) or {}

        soa_primary = soa_record.get('primary_nameserver', 'not available')
        soa_serial = soa_record.get('serial', 'not available')
        print(f"├── SOA Primary NS: {Colors.info(str(soa_primary))}")
        print(f"├── SOA Serial: {Colors.info(str(soa_serial))}")
        print(f"├── TXT Records: {Colors.info(str(len(txt_records)))} observed")
        print(f"├── SPF Policy: {Colors.info(_format_policy_record(spf_record))}")
        print(f"├── SPF Analysis: {Colors.info(_format_spf_analysis(spf_analysis))}")
        print(f"├── DMARC Policy: {Colors.info(_format_policy_record(dmarc_record))}")
        print(f"├── DMARC Status: {Colors.info(_format_dmarc_analysis(dmarc_analysis))}")
        print(f"├── DKIM Selectors: {Colors.info(_format_dkim_discovery(dkim))}")
        if caa_entries:
            print(f"├── CAA Policy: {Colors.info(', '.join(caa_entries[:3]))}")
        else:
            print(f"├── CAA Policy: {Colors.dim('not configured')}")
        dnssec_status = 'enabled' if dnssec.get('status') == 'enabled' else 'not detected'
        print(f"├── DNSSEC: {Colors.info(dnssec_status)}")
        print(f"├── DNS Config Assessment: {Colors.info(_format_dns_config_assessment(dns_config_assessment))}")
        zone_status = zone_transfer.get('status', 'unknown')
        if zone_status == 'allowed':
            zone_label = f"allowed via {zone_transfer.get('successful_nameserver', 'unknown')}"
            print(f"├── Zone Transfer: {Colors.error(zone_label)}")
        elif zone_status == 'not_allowed':
            print(f"├── Zone Transfer: {Colors.success('not allowed or filtered')}")
        else:
            print(f"├── Zone Transfer: {Colors.dim('not tested')}")
        print(f"└── Assessment Findings: {Colors.info(_format_dns_assessment_findings(dns_config_assessment))}")
    else:
        print(f"└── DNS Forensics: {Colors.error('UNAVAILABLE')}")

    print(f"\n{Colors.section_header('DNS HISTORY TIMELINE', 50)}")
    if dns_history_result.get('analysis_status') == 'abgeschlossen':
        data_sources = dns_history_result.get('data_sources', []) or []
        timeline_span = dns_history_result.get('timeline_span', {}) or {}
        timeline = dns_history_result.get('timeline', []) or []
        pattern_analysis = dns_history_result.get('pattern_analysis', {}) or {}
        historical_risk_events = dns_history_result.get('historical_risk_events', []) or []

        start_date = timeline_span.get('start_date') or 'unknown'
        end_date = timeline_span.get('end_date') or 'unknown'
        span_days = timeline_span.get('days', 0)
        print(f"├── Data Sources: {Colors.info(', '.join(data_sources) if data_sources else 'none')}")
        print(f"├── Timeline Span: {Colors.info(f'{start_date} to {end_date} ({span_days} days)')}")
        print(f"├── Major Changes: {Colors.info(str(dns_history_result.get('major_changes', 0)))} detected")

        if timeline:
            for event in timeline[:5]:
                print(f"├── {_format_history_date(event.get('date'))}: {Colors.info(event.get('change_type', 'Historical change'))}")
                print(f"│   ├── Source: {event.get('source', 'unknown')}")
                print(f"│   ├── Previous: {_format_history_value(event.get('previous'))}")
                print(f"│   ├── New: {_format_history_value(event.get('new'))}")
                print(f"│   └── Change Type: {event.get('classification', 'unclassified')}")
        else:
            print(f"├── Timeline: {Colors.dim('no historical events returned')}")

        suspicious_patterns = pattern_analysis.get('suspicious_patterns', ['not assessed'])
        if isinstance(suspicious_patterns, list):
            suspicious_text = '; '.join(str(item) for item in suspicious_patterns[:3])
        else:
            suspicious_text = str(suspicious_patterns)

        print(f"├── Pattern Analysis:")
        print(f"│   ├── Change Frequency: {Colors.info(str(pattern_analysis.get('change_frequency', 'not assessed')))}")
        print(f"│   ├── Infrastructure Stability: {Colors.info(str(pattern_analysis.get('infrastructure_stability', 'unknown')))}")
        print(f"│   ├── Suspicious Patterns: {Colors.info(suspicious_text)}")
        print(f"│   └── Risk Assessment: {Colors.warning(str(pattern_analysis.get('risk_level', 'UNKNOWN')))}")
        if historical_risk_events:
            print(f"└── Historical Risk Events: {Colors.warning('; '.join(str(item) for item in historical_risk_events[:3]))}")
        else:
            print(f"└── Historical Risk Events: {Colors.success('none detected')}")
    elif dns_history_result:
        print(f"├── DNS History: {Colors.warning('UNAVAILABLE')}")
        print(f"└── Detail: {Colors.dim(str(dns_history_result.get('error') or 'No timeline data available'))}")
    else:
        print(f"└── DNS History: {Colors.error('NOT RUN')}")

    print(f"\n{Colors.section_header('INFRASTRUCTURE', 50)}")
    if cdn_result.get('analysis_status') == 'abgeschlossen':
        provider = cdn_result.get('provider_name', 'Unknown')
        provider_type = cdn_result.get('provider_type') or cdn_result.get('infrastructure_type', 'Unknown')
        protection = str(cdn_result.get('protection_level', 'Unknown')).title()
        location = (cdn_result.get('location') or 
                   cdn_result.get('geolocation') or 
                   cdn_result.get('geo_data') or {})

        if location and isinstance(location, dict):
            country = location.get('country', 'Unknown')
            city = location.get('city', 'Unknown')
        else:
            country = cdn_result.get('country', 'Unknown')
            city = cdn_result.get('city', 'Unknown')
        
        edge_summary, waf_summary = _get_edge_protection_summary(cdn_result)
        print(f"├── Infrastructure: {Colors.info(provider)} ({_format_provider_type(provider_type)})")
        print(f"├── Protection Level: {Colors.info(protection)}")
        print(f"├── Edge Protection: {Colors.info(edge_summary)}")
        print(f"├── WAF Assessment: {Colors.info(waf_summary)}")
        print(f"└── Location: {Colors.info(f'{city}, {country}')}")
    else:
        print(f"└── CDN / Hosting: {Colors.error('UNAVAILABLE')}")

    print(f"\n{Colors.section_header('NETWORK PATH', 50)}")
    if network_result.get('analysis_status') == 'abgeschlossen':
        connectivity = network_result.get('connectivity_test', {})
        traceroute = network_result.get('traceroute_data', {})
        enhanced_path = network_result.get('enhanced_network_path', [])
        response_times = connectivity.get('response_times', {}) if isinstance(connectivity, dict) else {}
        ping_time = response_times.get('ping', 'Unknown') if isinstance(response_times, dict) else 'Unknown'
        ping_reachable = bool(connectivity.get('ping_reachable')) if isinstance(connectivity, dict) else False

        if ping_reachable and ping_time != 'Unknown':
            print(f"├── Connectivity: {Colors.info(f'Ping reachable ({ping_time} latency)')}")
        elif ping_reachable:
            print(f"├── Connectivity: {Colors.info('Ping reachable')}")
        else:
            print(f"├── Connectivity: {Colors.warning('Ping unavailable or filtered')}")
        _display_traceroute_details(traceroute, enhanced_path)
    else:
        failure_type = network_result.get('failure_type')
        if failure_type == 'timeout':
            print(f"├── Status: {Colors.warning('TIMEOUT')}")
            print(f"├── Traceroute: {Colors.dim('incomplete')}")
            print(f"└── Detail: {Colors.dim('Network analysis exceeded configured timeout')}")
        else:
            print(f"└── Network Path: {Colors.error('UNAVAILABLE')}")

    print(f"\n{Colors.section_header('ATTACK SURFACE', 50)}")
    if subdomain_result.get('analysis_status') == 'abgeschlossen':
        total_assets = result.total_assets_found
        sensitive_assets_count = result.sensitive_assets_found
        asset_categories = _get_subdomain_categories(subdomain_result)
        discovered_assets = subdomain_result.get('discovered_assets', [])
        sensitive_lookup = _build_sensitive_asset_lookup(subdomain_result)

        total_label = "DNS-resolved Candidates" if wildcard_detected else "Total Subdomains"
        total_suffix = "identified via DNS wildcard" if wildcard_detected else "discovered"
        print(f"├── {total_label}: {Colors.highlight(str(total_assets))} {total_suffix}")
        sensitive_label = "Sensitive Candidates" if wildcard_detected else "Sensitive Assets"
        sensitive_suffix = "matched sensitive patterns" if wildcard_detected else "identified"
        print(f"├── {sensitive_label}: {Colors.warning(str(sensitive_assets_count))} {sensitive_suffix}")

        if asset_categories:
            for category, assets in asset_categories.items():
                if assets and len(assets) > 0:
                    if category.lower() in ['admin', 'api', 'dev']:
                        print(f"├── {_format_category_name(category)}: {Colors.error(str(len(assets)))} (SENSITIVE)")
                    else:
                        print(f"├── {_format_category_name(category)}: {Colors.info(str(len(assets)))}")

        sensitive_assets = subdomain_result.get('sensitive_assets', []) or []
        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sensitive_assets = sorted(
            sensitive_assets,
            key=lambda item: (
                risk_order.get(str(item.get('risk_level', '')).upper(), 99),
                str((item.get('asset') or {}).get('full_domain', ''))
            )
        )

        if wildcard_detected:
            if discovered_assets:
                print(f"├── Example Candidates:")
                for asset in sorted(discovered_assets, key=lambda item: item.get('full_domain', item.get('subdomain', '')))[:5]:
                    full_domain = asset.get('full_domain') or asset.get('subdomain', 'unknown')
                    sensitive_meta = sensitive_lookup.get(full_domain, {})
                    risk_level = str(sensitive_meta.get('risk_level', '')).upper()
                    risk_reason = sensitive_meta.get('risk_reason')
                    line = full_domain
                    if risk_level:
                        line += f" [{risk_level}]"
                    if risk_reason:
                        line += f" - {risk_reason}"
                    print(f"│   ├── {line}")
            print(f"├── Validation Note: {Colors.warning('Wildcard DNS is enabled; DNS resolution alone does not prove host existence')}")
            print(f"└── DNS Config: {Colors.info('WILDCARD ENABLED')} (Enumeration resistance)")
        else:
            if sensitive_assets:
                print(f"├── Findings:")
                for asset in sensitive_assets[:3]:
                    asset_data = asset.get('asset', {}) if isinstance(asset, dict) else {}
                    subdomain = asset_data.get('full_domain') or asset_data.get('subdomain', 'unknown')
                    risk = str(asset.get('risk_level', 'unknown')).upper()
                    reason = asset.get('risk_reason', 'unknown')
                    risk_color = Colors.error if risk == 'CRITICAL' else Colors.warning
                    print(f"│   ├── {risk_color(subdomain)} [{risk}] - {reason}")

            if discovered_assets:
                print(f"├── Discovered Subdomains:")
                for asset in sorted(discovered_assets, key=lambda item: item.get('full_domain', item.get('subdomain', ''))):
                    full_domain = asset.get('full_domain') or asset.get('subdomain', 'unknown')
                    sensitive_meta = sensitive_lookup.get(full_domain, {})
                    risk_level = str(sensitive_meta.get('risk_level', '')).upper()
                    risk_reason = sensitive_meta.get('risk_reason')
                    line = full_domain
                    if risk_level:
                        line += f" [{risk_level}]"
                    if risk_reason:
                        line += f" - {risk_reason}"
                    print(f"│   ├── {line}")

            print(f"└── DNS Config: {Colors.success('Standard Resolution')}")
    else:
        print(f"├── Subdomain Analysis: {Colors.error('FAILED')}")
        print(f"└── Unable to assess attack surface")

    print(f"\n{Colors.section_header('THREAT INTELLIGENCE', 50)}")
    if vt_result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
        api_status = vt_result.get('api_status', 'unknown')
        threat_analysis = vt_result.get('threat_analysis', {})
        threat_intel = vt_result.get('threat_intelligence', {})
        malicious = threat_analysis.get('malicious_detections', 0)
        suspicious = threat_analysis.get('suspicious_detections', 0)
        total_vendors = threat_analysis.get('total_security_vendors', 0)
        reputation_score = threat_intel.get('reputation_score', vt_result.get('reputation', 0))
        category_signals = _extract_vt_category_signals(vt_result)
        status_text = "Demo-Mode" if api_status == 'demo_mode' else "Live Data"

        if malicious >= 3:
            threat_color = Colors.error
            threat_text = f"MALICIOUS ({malicious}/{total_vendors} vendors)"
        elif malicious > 0:
            threat_color = Colors.warning
            threat_text = f"REVIEW ({malicious}/{total_vendors} malicious vendors)"
        elif suspicious >= 3:
            threat_color = Colors.warning
            threat_text = f"SUSPICIOUS ({suspicious}/{total_vendors} vendors)"
        else:
            threat_color = Colors.success
            threat_text = f"CLEAN ({malicious + suspicious}/{total_vendors} vendors)"
        
        print(f"├── Domain Reputation: {threat_color(threat_text)} [{status_text}]")
        print(f"├── VT Reputation Score: {Colors.info(str(reputation_score))}")
        if category_signals:
            print(f"├── VT Category Signals: {Colors.info(', '.join(category_signals[:5]))}")
    else:
        print(f"├── Domain Reputation: {Colors.error('ANALYSIS FAILED')}")

    if abuse_result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
        api_status = abuse_result.get('api_status', 'unknown')
        abuse_confidence = abuse_result.get('abuse_confidence', 0)
        country_code = abuse_result.get('country_code', 'Unknown')
        status_text = "Demo-Mode" if api_status == 'demo_mode' else "Live Data"

        if abuse_confidence > 50:
            abuse_color = Colors.error
            abuse_text = f"HIGH ABUSE ({abuse_confidence}%)"
        elif abuse_confidence > 25:
            abuse_color = Colors.warning
            abuse_text = f"MODERATE ABUSE ({abuse_confidence}%)"
        else:
            abuse_color = Colors.success
            abuse_text = f"CLEAN ({abuse_confidence}%)"

        print(f"├── IP Reputation: {abuse_color(abuse_text)} [{status_text}]")
        if country_code != 'Unknown':
            print(f"├── Geographic Risk: {Colors.info(country_code)}")
    else:
        print(f"├── IP Reputation: {Colors.error('ANALYSIS FAILED')}")

    if st_result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
        api_status = st_result.get('api_status', 'unknown')
        domain_details = st_result.get('domain_details', {})
        subdomain_count = domain_details.get('subdomain_count', 0) if isinstance(domain_details, dict) else 0
        status_text = "Demo-Mode" if api_status == 'demo_mode' else "Live Data"

        if subdomain_count > 0:
            print(f"├── SecurityTrails History: {Colors.info(f'{subdomain_count} subdomains in historical dataset')} [{status_text}]")
        else:
            print(f"├── SecurityTrails History: {Colors.dim('No historical data')} [{status_text}]")
    else:
        print(f"├── SecurityTrails History: {Colors.error('ANALYSIS FAILED')}")

    print(f"\n{Colors.section_header('RISK ASSESSMENT', 50)}")
    print(f"├── Overall Risk: {risk_color(overall_risk)}")
    if risk_factors:
        print(f"├── Risk Factors:")
        for factor in risk_factors:
            print(f"│   ├── {factor}")
    print(f"└── Recommendation: {risk_color(recommendation)}")

    print(f"\n{Colors.section_header('EXECUTION', 50)}")
    print(f"├── Execution Time: {Colors.info(f'{result.total_execution_time:.1f} seconds')}")
    print(f"├── Modules Executed: {Colors.success(str(successful_modules))} successful, {Colors.error(str(failed_modules))} failed, {Colors.warning(str(timeout_modules))} timeout")

    api_statuses = []
    if st_result.get('api_status') == 'live_data':
        api_statuses.append("SecurityTrails")
    if abuse_result.get('api_status') == 'live_data':
        api_statuses.append("AbuseIPDB")
    if vt_result.get('api_status') == 'live_data':
        api_statuses.append("VirusTotal")
    if whois_result.get('source') == 'WhoisXML API':
        api_statuses.append("WhoisXML")
    dns_history_sources = [
        source for source in dns_history_result.get('data_sources', [])
        if source != 'Native Fallback'
    ]
    if dns_history_sources:
        api_statuses.append(f"DNS History ({', '.join(dns_history_sources[:3])})")
    
    if api_statuses:
        print(f"├── Live APIs Used: {Colors.success(', '.join(api_statuses))}")
    else:
        print(f"├── Live APIs Used: {Colors.warning('Demo Mode - Configure API keys')}")

    print(f"└── Detailed Logs: {Colors.dim(f'logs/domain_analyzer_*.log')}")

    print(f"\n{Colors.investigation_separator(80)}")
    print(f"FORENSIC ANALYSIS COMPLETE")
    print(Colors.investigation_separator(80))

def main():
    """Main program entry point with forensic metadata collection"""
    try:
        # Record analysis start time immediately
        analysis_start_time = datetime.now()
        
        # Get domain input first (before showing header)
        domain = get_domain_input()
        
        # Display comprehensive forensic header with metadata
        forensic_metadata = display_forensic_header(domain, analysis_start_time)
        
        # Initialize the domain analyzer with all modules
        analyzer = DomainAnalyzer()
        
        # Log forensic metadata to analyzer
        if hasattr(analyzer, 'logger'):
            analyzer.logger.info("Forensic session started", 
                               session_id=forensic_metadata['session_id'],
                               external_ip=forensic_metadata['external_ip'],
                               target_domain=domain,
                               opsec_risk=forensic_metadata['opsec_assessment']['attribution_risk'])
        
        # Execute comprehensive domain analysis
        result = analyzer.analyze_domain(domain)
        
        # Display clean forensic analysis results
        display_forensic_summary(result)
        
        # Add forensic session closure
        print(f"\nForensic session {forensic_metadata['session_id']} complete.")
        print(f"Check logs for detailed technical information and audit trail.")
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted. Goodbye!")
    except Exception as error:
        print(f"Analysis failed: {error}")

if __name__ == "__main__":
    main()
