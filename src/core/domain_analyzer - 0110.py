          
"""
Domain Forensic Analyzer - Complete Final Version
Professional OSINT Tool - All 4 Critical Bugs Fixed

Final Bug-Fixes | Clean Logging | Single-Line Input | Production-Ready
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
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

# Foundation-Module importieren
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.utils.colors import Colors
from src.utils.validators import DomainValidator
from src.core.result_aggregator import create_result_aggregator, UnifiedResult

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
    All Bugs Fixed - Final Production Version
    """
    
    def __init__(self):
        """
        Initialisiert Domain Analyzer - Final Bug-Fixed Version
        """
        # Platform Detection
        self.platform = platform.system().lower()
        
        # Paths (Cross-Platform)
        self.project_root = Path(__file__).parent.parent.parent
        self.logs_dir = self.project_root / "logs"
        
        # Create directories if not exist
        self.logs_dir.mkdir(exist_ok=True)
        
        # Initialize Logging
        self._setup_logging()
        
        # Core Modules
        self.modules = {}
        self.module_execution_order = [
            'dns', 'cdn', 'network', 'subdomain', 'securitytrails'
        ]
        
        # Analysis State
        self.current_analysis = None
        
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
        """Initialize all core analyzer modules"""
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
                self.logger.warning(f"Failed to initialize {module_name}", error=str(error))
    
    def analyze_domain(self, domain: str) -> UnifiedResult:
        """
        Main Domain Analysis Function - Final Bug-Fixed Version
        """
        # Input validation
        if not DomainValidator.is_valid_domain(domain):
            raise ValueError(f"Invalid domain format: {domain}")
        
        clean_domain = DomainValidator.clean_domain(domain)
        start_time = datetime.now()
        
        self.logger.info("Starting domain analysis", domain=clean_domain)
        
        # Initialize analysis state
        self.current_analysis = {
            'domain': clean_domain,
            'start_time': start_time,
            'modules_to_run': self.module_execution_order,
            'results': {},
            'errors': [],
            'warnings': []
        }
        
        # Execute analysis modules
        self._execute_analysis_workflow()
        
        # Calculate metrics - FINAL BUG-FIXED
        execution_time = (datetime.now() - start_time).total_seconds()
        analysis_metrics = self._calculate_analysis_metrics_fixed()
        
        self.logger.info("Analysis completed", 
                        domain=clean_domain,
                        execution_time=execution_time,
                        total_assets=analysis_metrics['total_assets'],
                        sensitive_assets=analysis_metrics['sensitive_assets'],
                        risk_level=analysis_metrics['risk_level'])
        
         # Create unified result using aggregator
        result = self.result_aggregator.aggregate_results(
            domain=clean_domain,
            module_results=self.current_analysis['results'],
            execution_time=execution_time
        )
        
        return result
    
    def _execute_analysis_workflow(self) -> None:
        """Execute analysis workflow with progress tracking"""
        modules_to_run = [m for m in self.current_analysis['modules_to_run'] if m in self.modules]
        
        if not modules_to_run:
            return
        
        print(f"\n{Colors.info('🔍 Starting OSINT Analysis...')}")
        
        # Execute modules with simple progress
        for i, module_name in enumerate(modules_to_run, 1):
            progress = int((i-1) / len(modules_to_run) * 100)
            print(f"   [{progress:3d}%] {module_name.title()} Analysis...", end="", flush=True)
            
            self._execute_single_module(module_name)
            
            # Show result
            if self.current_analysis['results'].get(module_name, {}).get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
                print(f" {Colors.success('✅')}")
            else:
                print(f" {Colors.error('❌')}")
        
        successful = len([r for r in self.current_analysis['results'].values() 
                         if r.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']])
        print(f"   [100%] Complete: {Colors.success(f'{successful}/{len(modules_to_run)} modules successful')}")
    
    def _execute_single_module(self, module_name: str) -> None:
        """Execute single analysis module"""
        module = self.modules.get(module_name)
        if not module:
            return
        
        domain = self.current_analysis['domain']
        
        try:
            self.logger.debug(f"Starting {module_name} analysis", domain=domain)
            
            # Module-specific execution
            if module_name == 'dns':
                result = module.analyze_domain(domain)
            elif module_name == 'cdn':
                dns_result = self.current_analysis['results'].get('dns', {})
                ip_address = dns_result.get('ipv4')
                if ip_address:
                    result = module.analyze_infrastructure(ip_address, domain)
                else:
                    raise Exception("No IP address available")
            elif module_name == 'network':
                dns_result = self.current_analysis['results'].get('dns', {})
                ip_address = dns_result.get('ipv4')
                if ip_address:
                    result = module.analyze_network(ip_address, domain)
                else:
                    raise Exception("No IP address available")
            elif module_name == 'subdomain':
                result = module.scan_subdomains(domain)
            elif module_name == 'securitytrails':
                result = module.analyze_domain_intelligence(domain)
            else:
                raise Exception(f"Unknown module: {module_name}")
            
            # Store result
            self.current_analysis['results'][module_name] = result
            self.logger.success(f"{module_name.title()} analysis completed", 
                              domain=domain, 
                              status=result.get('analysis_status'))
            
        except Exception as error:
            self.current_analysis['errors'].append(f"{module_name}: {str(error)}")
            self.current_analysis['results'][module_name] = {
                'error': str(error),
                'analysis_status': 'failed'
            }
            self.logger.error(f"{module_name} analysis failed", domain=domain, error=str(error))
    
    def _calculate_analysis_metrics_fixed(self) -> Dict[str, Any]:
        """
        FINAL BUG-FIX: Calculate analysis metrics with comprehensive key detection
        """
        results = self.current_analysis['results']
        
        # Module success metrics
        modules_executed = len(results)
        modules_successful = len([r for r in results.values() 
                                if r.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']])
        
        # Asset metrics - FINAL FIX with comprehensive key search
        total_assets = 0
        sensitive_assets = 0
        
        # From subdomain scanner - COMPLETELY FIXED
        subdomain_result = results.get('subdomain', {})
        self.logger.debug("Extracting asset metrics", subdomain_status=subdomain_result.get('analysis_status'))
        
        if subdomain_result.get('analysis_status') == 'abgeschlossen':
            
            # DEBUG: Print all keys to find the correct one
            self.logger.debug("Subdomain result keys", keys=list(subdomain_result.keys()))
            
            # COMPREHENSIVE KEY SEARCH - try every possible variation
            discovered_assets = None
            possible_asset_keys = [
                'discovered_assets', 'assets', 'found_assets', 'enumerated_assets', 
                'subdomains', 'subdomain_list', 'asset_list', 'results', 'data',
                'categorized_assets', 'all_assets', 'subdomain_assets'
            ]
            
            for key in possible_asset_keys:
                assets_data = subdomain_result.get(key, [])
                if assets_data and isinstance(assets_data, list) and len(assets_data) > 0:
                    discovered_assets = assets_data
                    self.logger.info(f"Found assets using key: {key}", count=len(assets_data))
                    break
            
            # If list-based keys don't work, try dict-based structure
            if not discovered_assets:
                # Maybe assets are categorized in a dict structure
                for key in subdomain_result.keys():
                    value = subdomain_result[key]
                    if isinstance(value, dict):
                        # Look for asset lists within this dict
                        for subkey, subvalue in value.items():
                            if isinstance(subvalue, list) and len(subvalue) > 0:
                                # Check if this looks like an asset list
                                if len(subvalue) > 0 and isinstance(subvalue[0], dict):
                                    first_item = subvalue[0]
                                    if 'subdomain' in first_item or 'domain' in first_item or 'risk_level' in first_item:
                                        discovered_assets = subvalue
                                        self.logger.info(f"Found assets in nested structure: {key}.{subkey}", count=len(subvalue))
                                        break
                        if discovered_assets:
                            break
            
            # If still no assets found, extract from subdomain_result directly
            if not discovered_assets:
                # Sometimes the entire result IS the asset list
                if isinstance(subdomain_result, list):
                    discovered_assets = subdomain_result
                else:
                    # Build asset list from any dict that contains subdomain info
                    temp_assets = []
                    for key, value in subdomain_result.items():
                        if isinstance(value, dict) and ('subdomain' in value or 'domain' in value):
                            temp_assets.append(value)
                        elif isinstance(value, list):
                            for item in value:
                                if isinstance(item, dict) and ('subdomain' in item or 'domain' in item):
                                    temp_assets.append(item)
                    if temp_assets:
                        discovered_assets = temp_assets
                        self.logger.info("Extracted assets from mixed structure", count=len(temp_assets))
            
            # Process discovered assets
            if discovered_assets and isinstance(discovered_assets, list):
                total_assets = len(discovered_assets)
                
                # Count sensitive assets - FIXED with comprehensive risk level detection
                for asset in discovered_assets:
                    if isinstance(asset, dict):
                        # Try multiple risk level key variations
                        risk_level = None
                        for risk_key in ['risk_level', 'risk', 'level', 'priority', 'sensitivity']:
                            risk_value = asset.get(risk_key)
                            if risk_value:
                                risk_level = str(risk_value).lower().strip()
                                break
                        
                        # If no risk_level found, infer from subdomain name
                        if not risk_level:
                            subdomain_name = asset.get('subdomain', asset.get('domain', '')).lower()
                            if any(admin_term in subdomain_name for admin_term in ['admin', 'administrator', 'manage', 'control', 'panel']):
                                risk_level = 'critical'
                            elif any(api_term in subdomain_name for api_term in ['api', 'rest', 'graphql', 'webhook']):
                                risk_level = 'high'
                            elif any(dev_term in subdomain_name for dev_term in ['dev', 'test', 'staging']):
                                risk_level = 'high'
                        
                        # Count if sensitive
                        if risk_level and risk_level in ['critical', 'high']:
                            sensitive_assets += 1
                
                self.logger.info("Asset metrics calculated successfully", 
                               total_assets=total_assets, 
                               sensitive_assets=sensitive_assets)
            else:
                self.logger.warning("No assets found in subdomain result", result_type=type(subdomain_result))
        
        # Risk level assessment - FIXED thresholds
        if sensitive_assets >= 20:
            risk_level = 'high'
        elif sensitive_assets >= 10:
            risk_level = 'medium'  
        elif sensitive_assets >= 3:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        self.logger.info("Final risk assessment", 
                        sensitive_count=sensitive_assets, 
                        risk_level=risk_level)
        
        return {
            'modules_executed': modules_executed,
            'modules_successful': modules_successful,
            'total_assets': total_assets,
            'sensitive_assets': sensitive_assets,
            'risk_level': risk_level
        }

def display_intro():
    """Display professional intro"""
    print(Colors.header("DOMAIN FORENSIC ANALYZER"))
    print(Colors.investigation_separator(80))
    print("Professional OSINT Tool | Network Intelligence | Asset Discovery")
    print("Cross-Platform | Security-First | Production-Ready")
    print(Colors.investigation_separator(80))
    print(f"Platform: {Colors.info(platform.system())} | "
          f"Modules: {Colors.success('5 Core Analyzers')} | "
          f"Status: {Colors.success('Ready')}")

def get_domain_input() -> str:
    """Get domain input - single line style"""
    while True:
        try:
            domain = input(f"\n{Colors.info('🎯 Target domain:')} ").strip()
            
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
    """
    FINAL: Display comprehensive summary using calculated values from result
    """
    print(f"\n{Colors.investigation_separator(80)}")
    print(Colors.header(f"ANALYSIS COMPLETE: {result.domain.upper()}"))
    print(Colors.investigation_separator(80))
    
    # Execution Overview
    print(f"Execution Time: {Colors.info(f'{result.total_execution_time:.1f}s')}")
    print(f"📊 Modules Success: {Colors.success(f'{result.modules_successful}/{result.modules_executed}')}")
    print(f"🎯 Overall Risk: {Colors.highlight(result.overall_risk_level.upper())}")
    
    # Module-by-Module Summary  
    print(f"\n{Colors.section_header('MODULE RESULTS', 60)}")
    
    # DNS Foundation - WORKING
    dns_result = result.results.get('dns', {})
    if dns_result.get('analysis_status') == 'abgeschlossen':
        ip = dns_result.get('ipv4', 'Unknown')
        reverse_dns = dns_result.get('reverse_dns', 'Not available')
        
        nameservers = (dns_result.get('nameservers', []) or 
                      dns_result.get('ns_records', []) or 
                      dns_result.get('name_servers', []) or [])
        nameserver_count = len(nameservers) if nameservers else 0
        
        print(f"🌐 DNS Foundation: {Colors.success('✅')} {Colors.format_ip(ip)}")
        print(f"   ├─ Nameservers: {Colors.info(str(nameserver_count))}")
        if reverse_dns and reverse_dns != 'Not available':
            print(f"   └─ Reverse DNS: {Colors.dim(reverse_dns[:50])}...")
    else:
        print(f"🌐 DNS Foundation: {Colors.error('❌')} Failed")
    
    # Infrastructure - WORKING
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
        
        print(f"🏗️ Infrastructure: {Colors.success('✅')} {provider} ({provider_type})")
        print(f"   ├─ Protection: {Colors.info(protection)}")
        print(f"   └─ Location: {Colors.info(f'{city}, {country}')}")
    else:
        print(f"🏗️ Infrastructure: {Colors.error('❌')} Failed")
    
    # Asset Discovery - NOW USES CALCULATED VALUES FROM RESULT
    subdomain_result = result.results.get('subdomain', {})
    if subdomain_result.get('analysis_status') == 'abgeschlossen':
        
        # Use the calculated values from the metrics function instead of recalculating
        total_assets = result.total_assets_found
        sensitive_assets_count = result.sensitive_assets_found
        
        print(f"🎯 Asset Discovery: {Colors.success('✅')} {total_assets} Subdomains")
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
            
            print(f"   🔴 Risk Assessment: {risk_color(risk_text)}")
    else:
        print(f"🎯 Asset Discovery: {Colors.error('❌')} Failed")
    
    # Network Intelligence - WORKING
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
        print(f"🌐 Network Path: {Colors.success('✅')} {hop_count} Hops analyzed")
        print(f"   ├─ Connectivity: {Colors.info(ping_time)}")
        print(f"   └─ OPSEC Risk: {risk_color(risk_level)}")
    else:
        print(f"🌐 Network Path: {Colors.error('❌')} Failed")
    
    # SecurityTrails - WORKING
    st_result = result.results.get('securitytrails', {})
    if st_result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
        api_status = st_result.get('api_status', 'unknown')
        domain_details = st_result.get('domain_details', {})
        subdomain_count = domain_details.get('subdomain_count', 0) if isinstance(domain_details, dict) else 0
        
        status_text = "Demo-Mode" if api_status == 'demo_mode' else "Active API"
        status_color = Colors.warning if api_status == 'demo_mode' else Colors.success
        print(f"📊 Intelligence: {status_color('✅')} {status_text}")
        print(f"   └─ Historical Subdomains: {Colors.info(str(subdomain_count))}")
    else:
        print(f"📊 Intelligence: {Colors.error('❌')} Failed")
    
    # Risk Assessment Summary
    if result.sensitive_assets_found > 0:
        print(f"\n{Colors.section_header('RISK ASSESSMENT', 60)}")
        
        if result.sensitive_assets_found >= 20:
            risk_color = Colors.error
            risk_text = "HIGH RISK"
            recommendations = ["Immediate security review required", "Reduce administrative surface exposure"]
        elif result.sensitive_assets_found >= 10:
            risk_color = Colors.warning  
            risk_text = "MEDIUM RISK"
            recommendations = ["Review access controls for sensitive endpoints", "Implement additional monitoring"]
        elif result.sensitive_assets_found >= 3:
            risk_color = Colors.info
            risk_text = "LOW RISK"
            recommendations = ["Monitor sensitive endpoints", "Maintain current security practices"]
        else:
            risk_color = Colors.success
            risk_text = "MINIMAL RISK"
            recommendations = ["Continue current security practices"]
        
        print(f"⚠️  Sensitive Assets: {risk_color(str(result.sensitive_assets_found))}")
        print(f"🎯 Risk Level: {risk_color(risk_text)}")
        
        # Show recommendations
        if recommendations:
            print(f"💡 Recommendations:")
            for rec in recommendations[:2]:
                print(f"   • {rec}")
    
    # Final Summary
    print(f"\n{Colors.investigation_separator(80)}")
    print(f"✅ Analysis Complete | Detailed Log: {Colors.dim('logs/domain_analyzer_*.log')}")
    print(f"📊 Total Assets: {Colors.highlight(str(result.total_assets_found))} | "
          f"Sensitive: {Colors.warning(str(result.sensitive_assets_found))} | "
          f"Risk: {Colors.info(result.overall_risk_level.upper())} | "
          f"Time: {Colors.info(f'{result.total_execution_time:.1f}s')}")
    print(Colors.investigation_separator(80))

def main():
    """
    Main single-run interface
    """
    try:
        # Display intro
        display_intro()
        
        # Initialize analyzer
        analyzer = DomainAnalyzer()
        
        # Get domain input
        domain = get_domain_input()
        
        # Run analysis
        result = analyzer.analyze_domain(domain)
        
        # Display results
        display_comprehensive_summary_fixed(result)
        
        print(f"\n{Colors.info('Analysis complete. Check logs for detailed information.')}")
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted. Goodbye!")
    except Exception as error:
        print(f"Analysis failed: {error}")

if __name__ == "__main__":
    main()
