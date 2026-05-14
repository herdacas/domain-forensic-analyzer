"""
Domain Forensic Analyzer - Multi-API Domain Analysis Tool
OSINT Tool for domain intelligence gathering and threat assessment
"""

import getpass
import platform
import socket
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# Try to import advanced logging library, fallback to basic logging if not available
try:
    from loguru import logger

    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

# Import utility modules for colors and domain validation
sys.path.append(str(Path(__file__).parent.parent.parent))
from config.settings import MODULE_TIMEOUTS
from src.core.result_aggregator import UnifiedResult, create_result_aggregator
from src.core.result_formatter import display_forensic_summary
from src.utils.colors import Colors
from src.utils.validators import DomainValidator

# Import all analyzer modules and check if they load successfully
try:
    from src.analyzers.abuseipdb_client import AbuseIPDBClient
    from src.analyzers.cdn_detector import CDNDetector
    from src.analyzers.dns_analyzer import DNSAnalyzer
    from src.analyzers.dns_history_analyzer import DNSHistoryAnalyzer
    from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
    from src.analyzers.network_intelligence import NetworkIntelligence
    from src.analyzers.securitytrails_client import SecurityTrailsClient
    from src.analyzers.ssl_analyzer import SSLAnalyzer
    from src.analyzers.subdomain_scanner import SubdomainScanner
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
        if getattr(self._local, "muted", False):
            return len(data)
        return self._target.write(data)

    def flush(self) -> None:
        if getattr(self._local, "muted", False):
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
            "dns",
            "whois",
            "dns_history",
            "cdn",
            "network",
            "subdomain",
            "ssl",
            "securitytrails",
            "abuseipdb",
            "virustotal",
            "ip_history",
        ]

        # Maximum time each module is allowed to run before being stopped
        self.module_timeouts = dict(MODULE_TIMEOUTS)

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
            log_file = (
                self.logs_dir
                / f"domain_analyzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            )
            logger.add(
                str(log_file),
                format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {message}",
                level="DEBUG",
                rotation="50 MB",
            )
            self.logger = logger
            self.logger.info("Domain Analyzer session started", platform=self.platform)
        else:
            # Fallback to basic Python logging
            import logging

            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger("DomainAnalyzer")

    def _initialize_system(self) -> None:
        """Start up all analyzer modules if they imported correctly"""
        if not CORE_MODULES_AVAILABLE:
            return

        try:
            self._initialize_modules()
            self.logger.info(
                "System initialization complete", modules_loaded=len(self.modules)
            )
        except Exception as error:
            self.logger.error("System initialization failed", error=str(error))

    def _initialize_modules(self) -> None:
        """Create instances of all analyzer modules and store them"""
        module_classes = {
            "dns": DNSAnalyzer,
            "whois": get_whois if WHOIS_MODULE_AVAILABLE else None,
            "dns_history": DNSHistoryAnalyzer,
            "cdn": CDNDetector,
            "subdomain": SubdomainScanner,
            "network": NetworkIntelligence,
            "securitytrails": SecurityTrailsClient,
            "abuseipdb": AbuseIPDBClient,
            "virustotal": VirusTotalClient,
            "ip_history": IPHistoryAnalyzer,
            "ssl": SSLAnalyzer,
        }

        # Try to create each module, log warnings for any that fail
        for module_name, module_class in module_classes.items():
            try:
                if module_class is None:
                    raise ImportError(f"{module_name} module not available")
                self.modules[module_name] = (
                    module_class if module_name == "whois" else module_class()
                )
                self.logger.debug(f"{module_name.title()} module initialized")
            except Exception as error:
                self.logger.warning(
                    f"Failed to initialize {module_name}", error=str(error)
                )

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
            "domain": clean_domain,
            "start_time": start_time,
            "modules_to_run": self.module_execution_order,
            "results": {},
            "errors": [],
            "warnings": [],
        }
        self.execution_metrics = {}

        # Run all the analyzer modules
        self._execute_analysis_workflow()

        # Calculate how long everything took
        execution_time = (datetime.now() - start_time).total_seconds()

        # Log summary statistics
        self.logger.info(
            "Analysis completed",
            domain=clean_domain,
            execution_time=execution_time,
            successful_modules=len(
                [m for m in self.execution_metrics.values() if m.success]
            ),
            failed_modules=len(
                [m for m in self.execution_metrics.values() if not m.success]
            ),
            apis_used=len(
                [
                    m
                    for m in ["securitytrails", "abuseipdb", "virustotal"]
                    if m in self.modules and self.execution_metrics.get(m, {}).success
                ]
            ),
        )

        # Combine all results into a unified format
        result = self.result_aggregator.aggregate_results(
            domain=clean_domain,
            module_results=self.current_analysis["results"],
            execution_time=execution_time,
        )

        return result

    def _execute_analysis_workflow(self) -> None:
        """Run all modules in sequence with progress tracking and error handling"""
        # Only run modules that loaded successfully
        modules_to_run = [
            m for m in self.current_analysis["modules_to_run"] if m in self.modules
        ]

        if not modules_to_run:
            self.logger.warning("No modules available for execution")
            return

        print(f"\nStarting analysis...")
        start_time = time.time()

        # Execute each module and track progress
        for i, module_name in enumerate(modules_to_run, 1):
            module_label = module_name.replace("_", " ").title()
            print(
                f"   [{i}/{len(modules_to_run)}] {module_label}...", end="", flush=True
            )

            # Run the module with timeout protection
            execution_result = self._execute_module_with_timeout(module_name)
            self.execution_metrics[module_name] = execution_result

            # Store the result for later use
            self.current_analysis["results"][module_name] = execution_result.result

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
        successful, failed, timeout, skipped, api_success, api_total = (
            self._compute_execution_statistics(modules_to_run)
        )

        skipped_part = f" | {skipped} skipped (passive)" if skipped else ""
        print(
            f"   [done] Analysis complete: {successful}/{len(modules_to_run)} successful{skipped_part} | "
            f"{failed} failed | {timeout} timeout | APIs: {api_success}/{api_total} | Total: {total_time:.1f}s"
        )

        self.logger.info(
            "Workflow completed",
            total_modules=len(modules_to_run),
            successful=successful,
            failed=failed,
            timeout=timeout,
            api_success=api_success,
            api_total=api_total,
            total_time=f"{total_time:.2f}s",
        )

    def _compute_execution_statistics(
        self, modules_to_run: List[str]
    ) -> Tuple[int, int, int, int, int, int]:
        """Return (successful, failed, timeout, skipped, api_success, api_total)."""
        results = self.current_analysis["results"]
        skipped = sum(1 for m in modules_to_run if results.get(m, {}).get("skipped"))
        successful = (
            len([m for m in self.execution_metrics.values() if m.success]) - skipped
        )
        failed = len(
            [
                m
                for m in self.execution_metrics.values()
                if not m.success and not m.timeout_occurred
            ]
        )
        timeout = len(
            [m for m in self.execution_metrics.values() if m.timeout_occurred]
        )

        api_modules = ["securitytrails", "abuseipdb", "virustotal"]
        api_success = len(
            [
                m
                for m in api_modules
                if m in self.execution_metrics and self.execution_metrics[m].success
            ]
        )

        whois_result = results.get("whois", {})
        if (
            self.execution_metrics.get("whois") is not None
            and self.execution_metrics["whois"].success
            and whois_result.get("source") == "WhoisXML API"
        ):
            api_success += 1

        dns_history_result = results.get("dns_history", {})
        if any(
            s != "Native Fallback" for s in dns_history_result.get("data_sources", [])
        ):
            api_success += 1

        if (
            self.execution_metrics.get("ip_history") is not None
            and self.execution_metrics["ip_history"].success
        ):
            api_success += 1

        base = (
            5
            if "dns_history" in modules_to_run
            else (4 if "whois" in modules_to_run else 3)
        )
        api_total = base + (1 if "ip_history" in modules_to_run else 0)

        return successful, failed, timeout, skipped, api_success, api_total

    def _execute_module_with_timeout(self, module_name: str) -> ModuleExecutionResult:
        """Run a single module with timeout protection and performance monitoring"""
        module = self.modules.get(module_name)

        if not module:
            # Return failure result if module doesn't exist
            return ModuleExecutionResult(
                success=False,
                result={"error": "Module not available", "analysis_status": "failed"},
                execution_time=0.0,
                error_message="Module not available",
            )

        domain = self.current_analysis["domain"]
        timeout = self.module_timeouts.get(module_name, 60)
        start_time = time.time()

        # Container to share results between threads
        result_container = {"result": None, "error": None}

        def execute_module():
            """Function that runs in separate thread to enable timeout"""
            stdout_router = (
                sys.stdout if isinstance(sys.stdout, ThreadAwareStdoutRouter) else None
            )
            try:
                if stdout_router:
                    stdout_router.mute_current_thread()
                result_container["result"] = self._call_module_function(
                    module_name, module, domain
                )
            except Exception as error:
                result_container["error"] = error
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
            self.logger.warning(
                f"{module_name} analysis timeout",
                domain=domain,
                timeout=timeout,
                execution_time=execution_time,
            )

            return ModuleExecutionResult(
                success=False,
                result=self._get_fallback_result(module_name, "timeout"),
                execution_time=execution_time,
                error_message=f"Module timeout after {timeout}s",
                timeout_occurred=True,
            )

        elif result_container["error"]:
            # Module crashed with an error
            error = result_container["error"]
            self.logger.error(
                f"{module_name} analysis failed",
                domain=domain,
                error=str(error),
                execution_time=execution_time,
            )

            return ModuleExecutionResult(
                success=False,
                result=self._get_fallback_result(module_name, "error", str(error)),
                execution_time=execution_time,
                error_message=str(error),
            )

        else:
            # Module completed successfully
            result = result_container["result"]
            if not isinstance(result, dict):
                self.logger.error(
                    f"{module_name} analysis returned invalid result",
                    domain=domain,
                    result_type=str(type(result)),
                    execution_time=execution_time,
                )
                return ModuleExecutionResult(
                    success=False,
                    result=self._get_fallback_result(
                        module_name, "error", "Invalid module result"
                    ),
                    execution_time=execution_time,
                    error_message="Invalid module result",
                )
            if result.get("analysis_status") == "failed":
                error_message = str(result.get("error") or "Module reported failure")
                self.logger.error(
                    f"{module_name} analysis reported failure",
                    domain=domain,
                    error=error_message,
                    execution_time=execution_time,
                )
                return ModuleExecutionResult(
                    success=False,
                    result=result,
                    execution_time=execution_time,
                    error_message=error_message,
                )
            self.logger.debug(
                f"{module_name} analysis completed",
                domain=domain,
                execution_time=execution_time,
                status=result.get("analysis_status"),
            )

            return ModuleExecutionResult(
                success=True, result=result, execution_time=execution_time
            )

    def _call_module_function(
        self, module_name: str, module: Any, domain: str
    ) -> Dict[str, Any]:
        """Call the correct function for each type of analyzer module"""
        if module_name == "dns":
            return module.analyze_domain(domain)

        elif module_name == "whois":
            result = module(domain)
            if not isinstance(result, dict):
                raise Exception("Invalid WHOIS result")
            if result.get("error"):
                raise Exception(str(result["error"]))
            result.setdefault("analysis_status", "abgeschlossen")
            return result

        elif module_name == "dns_history":
            return module.analyze_dns_history(domain)

        elif module_name == "cdn":
            # CDN analyzer needs IP address from DNS results
            dns_result = self.current_analysis["results"].get("dns", {})
            ip_address = dns_result.get("ipv4")
            rdns_hostname = dns_result.get("reverse_dns")

            if not ip_address:
                fallback_data = dns_result.get("fallback_data", {})
                ip_address = fallback_data.get("ipv4")
                if not rdns_hostname:
                    rdns_hostname = fallback_data.get("reverse_dns")

            if ip_address:
                return module.analyze_infrastructure(ip_address, domain, rdns_hostname)
            else:
                raise Exception("No IP address available from DNS analysis")

        elif module_name == "network":
            # Network analyzer also needs IP address from DNS
            dns_result = self.current_analysis["results"].get("dns", {})
            ip_address = dns_result.get("ipv4")

            if not ip_address:
                # Try backup data
                fallback_data = dns_result.get("fallback_data", {})
                ip_address = fallback_data.get("ipv4")

            if ip_address:
                return module.analyze_network(ip_address, domain)
            else:
                raise Exception("No IP address available from DNS analysis")

        elif module_name == "subdomain":
            return module.scan_subdomains(domain)

        elif module_name == "securitytrails":
            return module.analyze_domain_intelligence(domain)

        elif module_name == "abuseipdb":
            # AbuseIPDB checks IP reputation, so needs IP from DNS
            dns_result = self.current_analysis["results"].get("dns", {})
            ip_address = dns_result.get("ipv4")

            if not ip_address:
                # Try backup data
                fallback_data = dns_result.get("fallback_data", {})
                ip_address = fallback_data.get("ipv4")

            if ip_address:
                return module.analyze_ip_reputation(ip_address, domain)
            else:
                raise Exception("No IP address available for reputation analysis")

        elif module_name == "virustotal":
            # VirusTotal can check domain directly
            return module.analyze_domain_reputation(domain)

        elif module_name == "ip_history":
            current = self.current_analysis or {}
            dns_result = current.get("results", {}).get("dns", {})
            ip_address = dns_result.get("ipv4")
            if not ip_address:
                ip_address = dns_result.get("fallback_data", {}).get("ipv4")
            if ip_address:
                return module.analyze_reverse_ip(ip_address, domain)
            else:
                raise Exception("No IP address available for reverse IP analysis")

        elif module_name == "ssl":
            return module.analyze_ssl(domain)

        else:
            raise Exception(f"Unknown module: {module_name}")

    def _get_fallback_result(
        self, module_name: str, failure_type: str, error_details: str = ""
    ) -> Dict[str, Any]:
        """Create a safe fallback result when a module fails"""
        base_result = {
            "analysis_status": "failed",
            "error": error_details,
            "failure_type": failure_type,
            "failure_timestamp": datetime.now().isoformat(),
        }

        # Provide appropriate fallback data for each module type
        domain = (
            self.current_analysis.get("domain", "unknown")
            if self.current_analysis
            else "unknown"
        )
        fallback_data = {
            "dns": {"ipv4": None, "ipv6": None, "nameservers": [], "mail_servers": []},
            "whois": {
                "source": "failed",
                "domain": domain,
                "registrar": None,
                "creation_date": None,
                "expiration_date": None,
                "updated_date": None,
                "name_servers": [],
                "registrant_name": None,
                "registrant_organization": None,
                "registrant_country": None,
            },
            "dns_history": {
                "domain": domain,
                "data_sources": [],
                "timeline_span": {"start_date": None, "end_date": None, "days": 0},
                "major_changes": 0,
                "timeline": [],
                "pattern_analysis": {
                    "change_frequency": "not assessed",
                    "infrastructure_stability": "unknown",
                    "suspicious_patterns": ["analysis failed"],
                    "risk_level": "UNKNOWN",
                },
                "historical_risk_events": [],
            },
            "cdn": {
                "provider_name": "Unknown",
                "provider_type": "Unknown",
                "protection_level": "Unknown",
                "location": {"country": "Unknown", "city": "Unknown"},
            },
            "network": {
                "connectivity_test": {"status": "unknown"},
                "opsec_assessment": {"risk_level": "unknown"},
                "traceroute_data": {"total_hops": 0},
            },
            "subdomain": {"discovered_assets": [], "total_found": 0},
            "securitytrails": {
                "api_status": "failed",
                "domain_details": {"subdomain_count": 0},
            },
            "abuseipdb": {
                "api_status": "failed",
                "ip_address": "unknown",
                "abuse_confidence": 0,
                "reputation_intelligence": {
                    "risk_level": "UNKNOWN",
                    "risk_description": "Analysis failed",
                },
            },
            "virustotal": {
                "api_status": "failed",
                "domain": "unknown",
                "threat_analysis": {
                    "total_security_vendors": 0,
                    "malicious_detections": 0,
                    "suspicious_detections": 0,
                },
                "threat_intelligence": {
                    "threat_level": "UNKNOWN",
                    "threat_description": "Analysis failed",
                },
            },
            "ip_history": {
                "ip_address": "unknown",
                "domain": domain,
                "sources": {},
                "total_co_hosted": 0,
                "top_co_hosted": [],
            },
            "ssl": {
                "domain": domain,
                "available": False,
                "error": "module did not run",
            },
        }

        if module_name in fallback_data:
            base_result["fallback_data"] = fallback_data[module_name]

        return base_result


def get_external_ip() -> str:
    """Get our external IP address for forensic documentation"""
    try:
        # Try multiple services for reliability
        services = [
            "https://api.ipify.org",
            "https://checkip.amazonaws.com",
            "https://ipinfo.io/ip",
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
            "hostname": hostname,
            "username": username,
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
        }
        return system_info
    except:
        return {
            "hostname": "Unknown",
            "username": "Unknown",
            "platform": "Unknown",
            "platform_version": "Unknown",
            "architecture": "Unknown",
        }


def assess_opsec_risk(external_ip: str, local_ip: str) -> dict:
    """Assess OPSEC risks for forensic analysis"""

    behind_nat = external_ip != local_ip and local_ip.startswith(
        ("192.168.", "10.", "172.")
    )

    # VPN/proxy detection: check rDNS of external IP for known provider strings
    potential_vpn = False
    try:
        rdns = socket.getfqdn(external_ip).lower()
        if any(
            k in rdns
            for k in (
                "mullvad",
                "nordvpn",
                "expressvpn",
                "protonvpn",
                "privateinternetaccess",
                "torguard",
                "hidemyass",
                "vyprvpn",
                "ipvanish",
                "surfshark",
            )
        ):
            potential_vpn = True
    except Exception:
        pass

    attribution_risk = "LOW" if behind_nat else "MEDIUM"
    stealth_level = "HIGH" if potential_vpn else "MEDIUM"

    return {
        "attribution_risk": attribution_risk,
        "stealth_level": stealth_level,
        "analysis_type": "MIXED - Passive APIs + Active Probes",
        "behind_nat": behind_nat,
        "potential_vpn": potential_vpn,
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
    session_id = start_time.strftime("%Y%m%d-%H%M%S")

    print(" COMPLETE")

    # Display forensic header
    print(f"\n{Colors.investigation_separator(80)}")
    print(Colors.header(f"DOMAIN FORENSIC ANALYZER - SESSION: {session_id}"))
    print(f"{Colors.investigation_separator(80)}")

    # Analysis metadata
    print(
        f"Analysis Timestamp: {Colors.highlight(start_time.strftime('%Y-%m-%d %H:%M:%S UTC'))}"
    )
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
    risk_color = (
        Colors.success
        if opsec_assessment["attribution_risk"] == "LOW"
        else (
            Colors.warning
            if opsec_assessment["attribution_risk"] == "MEDIUM"
            else Colors.error
        )
    )

    stealth_color = (
        Colors.success
        if opsec_assessment["stealth_level"] == "HIGH"
        else (
            Colors.warning
            if opsec_assessment["stealth_level"] == "MEDIUM"
            else Colors.error
        )
    )

    print(f"\nOPSEC Assessment:")
    print(f"├── Analysis Type: {Colors.info(opsec_assessment['analysis_type'])}")
    print(f"├── Attribution Risk: {risk_color(opsec_assessment['attribution_risk'])}")
    print(f"├── Stealth Level: {stealth_color(opsec_assessment['stealth_level'])}")

    if opsec_assessment["behind_nat"]:
        print(f"├── Network Topology: {Colors.success('NAT Protected')}")
    else:
        print(f"├── Network Topology: {Colors.warning('Direct Connection')}")

    if opsec_assessment["potential_vpn"]:
        print(f"├── Proxy/VPN: {Colors.success('Detected')}")
    else:
        print(f"├── Proxy/VPN: {Colors.dim('Not Detected')}")

    print(f"├── Active Probes (target sees your IP):")
    print(f"│   ├── DNS resolution (direct nameserver query)")
    print(f"│   ├── Traceroute (ICMP packets to target)")
    print(f"│   ├── Ping (ICMP to target)")
    print(f"│   ├── HTTP/S connectivity check")
    print(f"│   ├── Zone transfer attempt (direct to NS)")
    print(f"│   ├── Subdomain DNS probes")
    print(f"│   └── SSL/TLS handshake (direct connection to target:443)")
    print(f"└── Passive Sources (target does not see your IP):")
    print(f"    ├── VirusTotal, AbuseIPDB, WhoisXML")
    print(f"    ├── SecurityTrails, RobTex, HackerTarget, Mnemonic PDNS")
    print(f"    └── crt.sh, CertSpotter, ip-api.com")

    print(f"\n{Colors.investigation_separator(80)}")
    print("OSINT Tool | Network Intelligence | Asset Discovery")
    print("Multi-API Threat Intelligence | Security Analysis")
    print(f"{Colors.investigation_separator(80)}")
    print(
        f"Platform: {Colors.info(platform.system())} | "
        f"Modules: {Colors.success('11 Core Analyzers')} | "
        f"APIs: {Colors.success('5 Intelligence Sources')} | "
        f"Status: {Colors.success('Ready')}"
    )

    # Return metadata for logging
    return {
        "session_id": session_id,
        "timestamp": start_time,
        "external_ip": external_ip,
        "local_ip": local_ip,
        "system_metadata": system_metadata,
        "opsec_assessment": opsec_assessment,
    }


def get_domain_input() -> str:
    """Get domain name from user input or CLI argument with validation."""
    # Accept domain from command-line argument if provided; skip -- flags.
    domain_args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if domain_args:
        candidate = domain_args[0].strip()
        domain, msg = DomainValidator.preprocess_domain(candidate)
        if domain is None:
            print(msg)
            sys.exit(1)
        if msg:
            print(f"[input] {msg}")
        return domain

    print(Colors.header("DOMAIN FORENSIC ANALYZER"))
    print("Target Domain Selection")
    print(Colors.investigation_separator(40))

    while True:
        try:
            raw = input(f"Enter target domain: ").strip()

            if not raw:
                print("Please enter a domain.")
                continue

            if raw.lower() in ["exit", "quit", "q"]:
                print("Goodbye!")
                sys.exit(0)

            domain, msg = DomainValidator.preprocess_domain(raw)
            if domain is None:
                print(f"  {msg}")
                continue
            if msg:
                print(f"  [input] {msg}")
            return domain

        except KeyboardInterrupt:
            print("\nGoodbye!")
            sys.exit(0)


def main():
    """Main program entry point with forensic metadata collection"""
    from src.core.report_exporter import ReportExporter

    analysis_start_time = datetime.now()
    exporter = ReportExporter()
    forensic_metadata: dict = {}
    result = None

    try:
        domain = get_domain_input()

        forensic_metadata = display_forensic_header(domain, analysis_start_time)

        analyzer = DomainAnalyzer()

        if hasattr(analyzer, "logger"):
            analyzer.logger.info(
                "Forensic session started",
                session_id=forensic_metadata["session_id"],
                external_ip=forensic_metadata["external_ip"],
                target_domain=domain,
                opsec_risk=forensic_metadata["opsec_assessment"]["attribution_risk"],
            )

        result = analyzer.analyze_domain(domain)

        display_forensic_summary(result)

        print(f"\nForensic session {forensic_metadata['session_id']} complete.")
        print(f"Check logs for detailed technical information and audit trail.")

        if result is not None:
            exporter.export(
                domain=domain,
                result=result,
                forensic_metadata=forensic_metadata,
                scan_duration=(datetime.now() - analysis_start_time).total_seconds(),
            )

    except KeyboardInterrupt:
        print("\nAnalysis interrupted. Goodbye!")
    except Exception as error:
        print(f"Analysis failed: {error}")


if __name__ == "__main__":
    main()
