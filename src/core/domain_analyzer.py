"""Domain Forensic Analyzer — orchestrator and module runner."""

import platform
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from loguru import logger

    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

sys.path.append(str(Path(__file__).parent.parent.parent))
from config.settings import MODULE_TIMEOUTS
from src.core.result_aggregator import UnifiedResult, create_result_aggregator
from src.core.result_formatter import display_forensic_summary
from src.core.stdout_router import ModuleExecutionResult, ThreadAwareStdoutRouter
from src.utils.validators import DomainValidator

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


class DomainAnalyzer:
    """Coordinates 11 analyzer modules: execution order, timeouts, and result aggregation."""

    def __init__(self):
        self.platform = platform.system().lower()
        self.project_root = Path(__file__).parent.parent.parent
        self.logs_dir = self.project_root / "logs"
        self.logs_dir.mkdir(exist_ok=True)
        self._setup_logging()
        self.modules = {}
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

        self.module_timeouts = dict(MODULE_TIMEOUTS)
        self.current_analysis = None
        self.execution_metrics = {}
        self._initialize_system()
        self.result_aggregator = create_result_aggregator()

    def _setup_logging(self) -> None:
        if LOGURU_AVAILABLE:
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
            import logging

            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger("DomainAnalyzer")

    def _initialize_system(self) -> None:
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
        """Run all 11 modules against the domain and return aggregated results."""
        if not DomainValidator.is_valid_domain(domain):
            raise ValueError(f"Invalid domain format: {domain}")

        clean_domain = DomainValidator.clean_domain(domain)
        start_time = datetime.now()

        self.logger.info("Starting multi-API domain analysis", domain=clean_domain)

        self.current_analysis = {
            "domain": clean_domain,
            "start_time": start_time,
            "modules_to_run": self.module_execution_order,
            "results": {},
            "errors": [],
            "warnings": [],
        }
        self.execution_metrics = {}
        self._execute_analysis_workflow()
        execution_time = (datetime.now() - start_time).total_seconds()

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

        result = self.result_aggregator.aggregate_results(
            domain=clean_domain,
            module_results=self.current_analysis["results"],
            execution_time=execution_time,
        )

        return result

    def _execute_analysis_workflow(self) -> None:
        modules_to_run = [
            m for m in self.current_analysis["modules_to_run"] if m in self.modules
        ]

        if not modules_to_run:
            self.logger.warning("No modules available for execution")
            return

        print(f"\nStarting analysis...")
        start_time = time.time()

        for i, module_name in enumerate(modules_to_run, 1):
            module_label = module_name.replace("_", " ").title()
            print(
                f"   [{i}/{len(modules_to_run)}] {module_label}...", end="", flush=True
            )

            execution_result = self._execute_module_with_timeout(module_name)
            self.execution_metrics[module_name] = execution_result
            self.current_analysis["results"][module_name] = execution_result.result

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
            return ModuleExecutionResult(
                success=False,
                result={"error": "Module not available", "analysis_status": "failed"},
                execution_time=0.0,
                error_message="Module not available",
            )

        domain = self.current_analysis["domain"]
        timeout = self.module_timeouts.get(module_name, 60)
        start_time = time.time()

        result_container = {"result": None, "error": None}

        def execute_module():
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

        thread = threading.Thread(target=execute_module, daemon=True)
        thread.start()
        thread.join(timeout)

        execution_time = time.time() - start_time

        if thread.is_alive():
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
            dns_result = self.current_analysis["results"].get("dns", {})
            ip_address = dns_result.get("ipv4")

            if not ip_address:
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
            dns_result = self.current_analysis["results"].get("dns", {})
            ip_address = dns_result.get("ipv4")

            if not ip_address:
                fallback_data = dns_result.get("fallback_data", {})
                ip_address = fallback_data.get("ipv4")

            if ip_address:
                return module.analyze_ip_reputation(ip_address, domain)
            else:
                raise Exception("No IP address available for reputation analysis")

        elif module_name == "virustotal":
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
        base_result = {
            "analysis_status": "failed",
            "error": error_details,
            "failure_type": failure_type,
            "failure_timestamp": datetime.now().isoformat(),
        }

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


