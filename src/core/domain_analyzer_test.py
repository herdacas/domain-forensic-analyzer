"""
Core Domain Analyzer for Domain Forensic Analyzer
Professional OSINT Tool - Main Orchestrator

Cross-Platform Compatible | Future Web-Interface Ready | Security-First
"""

import sys
import os
import platform
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass

# External Dependencies
try:
    from loguru import logger
    from tqdm import tqdm
    EXTERNAL_DEPS_AVAILABLE = True
except ImportError:
    EXTERNAL_DEPS_AVAILABLE = False
    # Fallback für Development ohne Dependencies
    print("External dependencies not installed. Run: pip install -r requirements.txt")

# Foundation-Module importieren
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.utils.colors import Colors
from src.utils.validators import DomainValidator

# Core-Module importieren
try:
    from src.core.security_manager import create_security_manager
    from src.analyzers.dns_analyzer import DNSAnalyzer
    from src.analyzers.cdn_detector import CDNDetector
    from src.analyzers.subdomain_scanner import SubdomainScanner
    from src.analyzers.network_intelligence import NetworkIntelligence
    from src.analyzers.securitytrails_client import SecurityTrailsClient
    CORE_MODULES_AVAILABLE = True
except ImportError as error:
    CORE_MODULES_AVAILABLE = False
    print(f"Core modules import error: {error}")

@dataclass
class DomainAnalysisResult:
    """
    Structured analysis result - Interface-agnostic
    Can be used by CLI, Web-Interface, API in the future
    """
    domain: str
    timestamp: str
    execution_time: float
    modules_executed: int
    modules_successful: int
    total_assets_found: int
    sensitive_assets_found: int
    overall_risk_level: str
    results: Dict[str, Any]
    errors: List[str]
    warnings: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'domain': self.domain,
            'timestamp': self.timestamp,
            'execution_time': self.execution_time,
            'modules_executed': self.modules_executed,
            'modules_successful': self.modules_successful,
            'total_assets_found': self.total_assets_found,
            'sensitive_assets_found': self.sensitive_assets_found,
            'overall_risk_level': self.overall_risk_level,
            'results': self.results,
            'errors': self.errors,
            'warnings': self.warnings
        }

class DomainAnalyzer:
    """
    Professional Domain Forensic Analysis Orchestrator
    
    Cross-Platform OSINT Tool that coordinates all 5 core analyzer modules
    to provide comprehensive domain intelligence and security assessment.
    
    ARCHITECTURE:
    - Interface-agnostic business logic
    - Cross-platform compatibility (Windows/Linux)
    - Professional logging system
    - Future-ready for Web/API interfaces
    - Security-first design
    """
    
    def __init__(self, log_level: str = "INFO", log_file: Optional[str] = None):
        """
        Initialisiert Domain Analyzer mit Cross-Platform-Support
        
        Args:
            log_level (str): Logging-Level (DEBUG, INFO, WARNING, ERROR)
            log_file (str): Optional log file path
        """
        # Platform Detection
        self.platform = platform.system().lower()
        self.is_windows = self.platform == 'windows'
        self.is_linux = self.platform == 'linux'
        
        # Paths (Cross-Platform)
        self.project_root = Path(__file__).parent.parent.parent
        self.config_dir = self.project_root / "config"
        self.logs_dir = self.project_root / "logs"
        
        # Create directories if not exist
        self.logs_dir.mkdir(exist_ok=True)
        
        # Initialize Logging
        self._setup_logging(log_level, log_file)
        
        # Security Manager
        self.security_manager = None
        
        # Core Modules
        self.modules = {}
        self.module_execution_order = [
            'dns', 'cdn', 'network', 'subdomain', 'securitytrails'
        ]
        
        # Analysis State
        self.current_analysis = None
        self.analysis_results = {}
        
        # Initialize system
        self._initialize_system()
    
    def _setup_logging(self, log_level: str, log_file: Optional[str]) -> None:
        """
        Setup Professional Logging System
        
        Args:
            log_level (str): Logging level
            log_file (str): Optional custom log file
        """
        if not EXTERNAL_DEPS_AVAILABLE:
            # Fallback: Standard Python logging
            import logging
            logging.basicConfig(
                level=getattr(logging, log_level.upper()),
                format='%(asctime)s | %(levelname)s | %(message)s'
            )
            self.logger = logging.getLogger('DomainAnalyzer')
            return
        
        # Remove default logger
        logger.remove()
        
        # Console output with colors
        logger.add(
            sys.stderr,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
            level=log_level.upper(),
            colorize=True
        )
        
        # File output
        if not log_file:
            log_file = self.logs_dir / f"domain_analyzer_{datetime.now().strftime('%Y%m%d')}.log"
        
        logger.add(
            str(log_file),
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
            level="DEBUG",  # File gets everything
            rotation="10 MB",
            retention="7 days",
            compression="zip"
        )
        
        self.logger = logger
        
        # Log system startup
        self.logger.info("Domain Analyzer initialized", 
                        platform=self.platform,
                        python_version=platform.python_version())
    
    def _initialize_system(self) -> None:
        """
        Initialize all system components
        """
        if not CORE_MODULES_AVAILABLE:
            self.logger.error("Core modules not available - check imports")
            return
        
        try:
            # Security Manager
            self.logger.debug("Initializing security manager")
            self.security_manager = create_security_manager()
            
            # Core Analysis Modules
            self.logger.debug("Initializing core analysis modules")
            self._initialize_modules()
            
            self.logger.info("System initialization complete",
                           modules_loaded=len(self.modules),
                           platform=self.platform)
            
        except Exception as error:
            self.logger.error("System initialization failed", error=str(error))
            raise
    
    def _initialize_modules(self) -> None:
        """
        Initialize all core analyzer modules
        """
        module_classes = {
            'dns': DNSAnalyzer,
            'cdn': CDNDetector,
            'subdomain': SubdomainScanner,
            'network': NetworkIntelligence,
            'securitytrails': SecurityTrailsClient
        }
        
        for module_name, module_class in module_classes.items():
            try:
                self.modules[module_name] = module_class()
                self.logger.debug(f"{module_name.title()} module initialized")
            except Exception as error:
                self.logger.warning(f"Failed to initialize {module_name} module", error=str(error))
    
    def analyze_domain(self, domain: str, 
                      modules_to_run: Optional[List[str]] = None,
                      parallel: bool = False) -> DomainAnalysisResult:
        """
        Main Domain Analysis Function - Interface Agnostic
        
        Args:
            domain (str): Domain to analyze
            modules_to_run (list): Optional specific modules to run
            parallel (bool): Future: Parallel execution (not implemented yet)
            
        Returns:
            DomainAnalysisResult: Structured analysis results
        """
        # Input validation
        if not DomainValidator.is_valid_domain(domain):
            error_msg = f"Invalid domain format: {domain}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        clean_domain = DomainValidator.clean_domain(domain)
        start_time = datetime.now()
        
        self.logger.info("Starting comprehensive domain analysis", 
                        domain=clean_domain,
                        platform=self.platform)
        
        # Initialize analysis state
        self.current_analysis = {
            'domain': clean_domain,
            'start_time': start_time,
            'modules_to_run': modules_to_run or self.module_execution_order,
            'results': {},
            'errors': [],
            'warnings': []
        }
        
        # Execute analysis modules
        self._execute_analysis_workflow()
        
        # Calculate metrics
        execution_time = (datetime.now() - start_time).total_seconds()
        analysis_metrics = self._calculate_analysis_metrics()
        
        # Create structured result
        result = DomainAnalysisResult(
            domain=clean_domain,
            timestamp=start_time.isoformat(),
            execution_time=execution_time,
            modules_executed=analysis_metrics['modules_executed'],
            modules_successful=analysis_metrics['modules_successful'],
            total_assets_found=analysis_metrics['total_assets'],
            sensitive_assets_found=analysis_metrics['sensitive_assets'],
            overall_risk_level=analysis_metrics['risk_level'],
            results=self.current_analysis['results'],
            errors=self.current_analysis['errors'],
            warnings=self.current_analysis['warnings']
        )
        
        # Log completion
        self.logger.success("Domain analysis completed",
                          domain=clean_domain,
                          execution_time=f"{execution_time:.1f}s",
                          modules_successful=analysis_metrics['modules_successful'],
                          total_assets=analysis_metrics['total_assets'])
        
        return result
    
    def _execute_analysis_workflow(self) -> None:
        """
        Execute the main analysis workflow with progress tracking
        """
        modules_to_run = [m for m in self.current_analysis['modules_to_run'] if m in self.modules]
        
        if not modules_to_run:
            self.logger.error("No valid modules to execute")
            return
        
        # Progress bar (if available)
        if EXTERNAL_DEPS_AVAILABLE:
            progress_bar = tqdm(modules_to_run, 
                              desc="🔍 OSINT Analysis", 
                              unit="module",
                              colour="green")
        else:
            progress_bar = modules_to_run
        
        # Execute modules in order
        for module_name in progress_bar:
            self._execute_single_module(module_name)
            
            # Update progress description
            if EXTERNAL_DEPS_AVAILABLE and hasattr(progress_bar, 'set_description'):
                successful = len([r for r in self.current_analysis['results'].values() 
                                if 'error' not in r])
                progress_bar.set_description(f"🔍 OSINT Analysis ({successful}/{len(modules_to_run)} successful)")
    
    def _execute_single_module(self, module_name: str) -> None:
        """
        Execute single analysis module with error handling
        
        Args:
            module_name (str): Name of module to execute
        """
        module = self.modules.get(module_name)
        if not module:
            error_msg = f"Module {module_name} not available"
            self.logger.error(error_msg)
            self.current_analysis['errors'].append(error_msg)
            return
        
        domain = self.current_analysis['domain']
        
        try:
            self.logger.debug(f"Starting {module_name} analysis", domain=domain)
            
            # Module-specific execution
            if module_name == 'dns':
                result = module.analyze_domain(domain)
            elif module_name == 'cdn':
                # CDN needs IP from DNS
                dns_result = self.current_analysis['results'].get('dns', {})
                ip_address = dns_result.get('ipv4')
                if ip_address:
                    result = module.analyze_infrastructure(ip_address, domain)
                else:
                    raise Exception("No IP address available from DNS analysis")
            elif module_name == 'network':
                # Network needs IP from DNS
                dns_result = self.current_analysis['results'].get('dns', {})
                ip_address = dns_result.get('ipv4')
                if ip_address:
                    result = module.analyze_network(ip_address, domain)
                else:
                    raise Exception("No IP address available from DNS analysis")
            elif module_name == 'subdomain':
                result = module.scan_subdomains(domain)
            elif module_name == 'securitytrails':
                result = module.analyze_domain_intelligence(domain)
            else:
                raise Exception(f"Unknown module execution method for {module_name}")
            
            # Store result
            self.current_analysis['results'][module_name] = result
            
            self.logger.success(f"{module_name.title()} analysis completed", 
                              domain=domain,
                              status=result.get('analysis_status', 'unknown'))
            
        except Exception as error:
            error_msg = f"{module_name} analysis failed: {str(error)}"
            self.logger.error(error_msg, domain=domain)
            
            self.current_analysis['errors'].append(error_msg)
            self.current_analysis['results'][module_name] = {
                'error': str(error),
                'analysis_status': 'failed'
            }
    
    def _calculate_analysis_metrics(self) -> Dict[str, Any]:
        """
        Calculate analysis metrics from results
        
        Returns:
            dict: Analysis metrics
        """
        results = self.current_analysis['results']
        
        # Module success metrics
        modules_executed = len(results)
        modules_successful = len([r for r in results.values() 
                                if r.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']])
        
        # Asset metrics
        total_assets = 0
        sensitive_assets = 0
        
        # From subdomain scanner
        subdomain_result = results.get('subdomain', {})
        if 'discovered_assets' in subdomain_result:
            discovered_assets = subdomain_result['discovered_assets']
            total_assets += len(discovered_assets)
            
            # Count sensitive assets
            for asset in discovered_assets:
                if asset.get('risk_level') in ['critical', 'high']:
                    sensitive_assets += 1
        
        # Risk level assessment
        if sensitive_assets > 10:
            risk_level = 'high'
        elif sensitive_assets > 3:
            risk_level = 'medium'
        elif sensitive_assets > 0:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        return {
            'modules_executed': modules_executed,
            'modules_successful': modules_successful,
            'total_assets': total_assets,
            'sensitive_assets': sensitive_assets,
            'risk_level': risk_level
        }
    
    def get_available_modules(self) -> List[str]:
        """
        Get list of available analysis modules
        
        Returns:
            list: Available module names
        """
        return list(self.modules.keys())
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        Get system information for debugging
        
        Returns:
            dict: System information
        """
        return {
            'platform': self.platform,
            'python_version': platform.python_version(),
            'external_deps_available': EXTERNAL_DEPS_AVAILABLE,
            'core_modules_available': CORE_MODULES_AVAILABLE,
            'available_modules': self.get_available_modules(),
            'security_manager_available': self.security_manager is not None
        }

# CLI Interface Functions (Future expansion point)
def main_cli():
    """
    Command-Line Interface entry point
    Future expansion for advanced CLI features
    """
    if len(sys.argv) < 2:
        print("Usage: python -m src.core.domain_analyzer <domain>")
        print("Example: python -m src.core.domain_analyzer github.com")
        return
    
    domain = sys.argv[1]
    
    try:
        # Initialize analyzer
        analyzer = DomainAnalyzer(log_level="INFO")
        
        # Run analysis
        result = analyzer.analyze_domain(domain)
        
        # Display summary (basic CLI output)
        _display_cli_summary(result)
        
    except Exception as error:
        print(f"Analysis failed: {error}")
        if EXTERNAL_DEPS_AVAILABLE:
            logger.error("CLI analysis failed", error=str(error))

def _display_cli_summary(result: DomainAnalysisResult) -> None:
    """
    Display basic CLI summary of analysis results
    
    Args:
        result (DomainAnalysisResult): Analysis results
    """
    print(f"\n{Colors.header('DOMAIN ANALYSIS SUMMARY')}")
    print(f"Domain: {Colors.format_domain(result.domain)}")
    print(f"Execution Time: {Colors.info(f'{result.execution_time:.1f}s')}")
    print(f"Modules Successful: {Colors.success(f'{result.modules_successful}/{result.modules_executed}')}")
    
    if result.total_assets_found > 0:
        print(f"Assets Found: {Colors.highlight(str(result.total_assets_found))}")
        
    if result.sensitive_assets_found > 0:
        color_func = Colors.error if result.sensitive_assets_found > 5 else Colors.warning
        print(f"Sensitive Assets: {color_func(str(result.sensitive_assets_found))}")
    
    print(f"Risk Level: {Colors.info(result.overall_risk_level.upper())}")
    
    if result.errors:
        print(f"Errors: {Colors.error(str(len(result.errors)))}")
    
    print(f"\nDetailed results saved to: {Colors.dim('logs/domain_analyzer_*.log')}")

# Future Web Interface entry point
def main_web():
    """
    Future: Web Interface entry point
    Placeholder for Flask/FastAPI integration
    """
    pass

# Future API Interface entry point  
def main_api():
    """
    Future: REST API entry point
    Placeholder for API server
    """
    pass

# Test function
def main():
    """
    Test function for Core Domain Analyzer
    """
    print(Colors.header("CORE DOMAIN ANALYZER TEST - STEP 2.2"))
    print(Colors.investigation_separator(60))
    
    # System info
    analyzer = DomainAnalyzer(log_level="DEBUG")
    system_info = analyzer.get_system_info()
    
    print(f"Platform: {Colors.info(system_info['platform'])}")
    print(f"External Dependencies: {Colors.success('Available') if system_info['external_deps_available'] else Colors.warning('Missing')}")
    print(f"Available Modules: {Colors.highlight(str(len(system_info['available_modules'])))}")
    
    # Test analysis
    test_domain = "github.com"
    
    print(f"\n{Colors.section_header(f'TEST ANALYSIS: {test_domain.upper()}', 60)}")
    
    try:
        result = analyzer.analyze_domain(test_domain)
        
        print(f"\n{Colors.success('ANALYSIS COMPLETED:')}")
        print(f"  Domain: {result.domain}")
        print(f"  Execution Time: {result.execution_time:.1f}s")
        print(f"  Modules Successful: {result.modules_successful}/{result.modules_executed}")
        print(f"  Assets Found: {result.total_assets_found}")
        print(f"  Risk Level: {result.overall_risk_level}")
        
    except Exception as error:
        print(f"{Colors.error('ANALYSIS FAILED:')} {error}")
    
    print(f"\n{Colors.investigation_separator(60)}")
    print(Colors.success("CORE DOMAIN ANALYZER STEP 2.2 - TESTING COMPLETE"))
    print(Colors.investigation_separator(60))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main_cli()
    else:
        main()