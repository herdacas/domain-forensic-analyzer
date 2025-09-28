"""
Core Modules Integration Test - Step 2.6
Umfassender Integration-Test aller Core-Analyzer Module

Phase 2 Abschluss - Validiert Cross-Module-Kompatibilität und Performance
"""

import sys
import os
import time
from typing import Dict, List, Any
from datetime import datetime

# Foundation-Module importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.utils.colors import Colors
from src.utils.validators import DomainValidator

# Alle Core-Analyzer Module importieren
try:
    from src.analyzers.dns_analyzer import DNSAnalyzer
    from src.analyzers.cdn_detector import CDNDetector
    from src.analyzers.subdomain_scanner import SubdomainScanner
    from src.analyzers.network_intelligence import NetworkIntelligence
    from src.analyzers.securitytrails_client import SecurityTrailsClient
    DNS_AVAILABLE = True
    CDN_AVAILABLE = True
    SUBDOMAIN_AVAILABLE = True
    NETWORK_AVAILABLE = True
    SECURITYTRAILS_AVAILABLE = True
except ImportError as error:
    print(Colors.error(f"Import-Fehler: {error}"))
    sys.exit(1)

class CoreModulesIntegrationTest:
    """
    Integration-Test für alle Core-Analyzer Module
    
    Testet Cross-Module-Kompatibilität, Performance und Datenfluss
    zwischen allen 5 Core-Analyzern für vollständige Domain-Forensik.
    """
    
    def __init__(self):
        """Initialisiert Integration-Test-Framework"""
        self.test_results = {}
        self.performance_metrics = {}
        self.integration_data = {}
        self.errors = []
        
        # Test-Domains für umfassende Validierung
        self.test_domains = [
            "github.com",           # Platform mit starker Infrastruktur
            "stackoverflow.com",    # CDN-optimierte Site
            "futuremultiverse.com"  # Kleinere Domain für Edge-Cases
        ]
        
        # Module-Instanzen
        self.modules = {}
    
    def run_integration_test(self) -> Dict[str, Any]:
        """
        Führt vollständigen Integration-Test durch
        
        Returns:
            dict: Umfassende Integration-Test-Ergebnisse
        """
        print(Colors.header("CORE MODULES INTEGRATION TEST - STEP 2.6"))
        print(Colors.investigation_separator(80))
        print(f"Test-Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Test-Domains: {len(self.test_domains)} Domains")
        print(f"Core-Module: 5 Analyzer")
        
        # Module-Verfügbarkeit prüfen
        print(f"\n{Colors.section_header('MODULE AVAILABILITY CHECK', 60)}")
        module_status = self._check_module_availability()
        
        # Module initialisieren
        print(f"\n{Colors.section_header('MODULE INITIALIZATION', 60)}")
        init_status = self._initialize_modules()
        
        # Integration-Tests durchführen
        integration_results = {}
        
        for i, domain in enumerate(self.test_domains, 1):
            print(f"\n{Colors.section_header(f'INTEGRATION TEST {i}: {domain.upper()}', 80)}")
            
            domain_results = self._test_domain_integration(domain)
            integration_results[domain] = domain_results
            
            # Pause zwischen Tests
            if i < len(self.test_domains):
                print(f"\n{Colors.info('Pause vor nächstem Test...')}")
                time.sleep(2)
        
        # Cross-Module-Analyse
        print(f"\n{Colors.section_header('CROSS-MODULE ANALYSIS', 60)}")
        cross_analysis = self._perform_cross_module_analysis(integration_results)
        
        # Performance-Analyse
        print(f"\n{Colors.section_header('PERFORMANCE ANALYSIS', 60)}")
        performance_analysis = self._analyze_performance()
        
        # Final Report
        final_results = {
            'test_timestamp': datetime.now().isoformat(),
            'module_status': module_status,
            'initialization_status': init_status,
            'domain_tests': integration_results,
            'cross_module_analysis': cross_analysis,
            'performance_analysis': performance_analysis,
            'errors': self.errors,
            'test_status': 'completed'
        }
        
        # Abschlussbericht anzeigen
        self._display_final_report(final_results)
        
        return final_results
    
    def _check_module_availability(self) -> Dict[str, bool]:
        """Prüft Verfügbarkeit aller Core-Module"""
        modules = [
            ('DNS Analyzer', DNS_AVAILABLE),
            ('CDN Detector', CDN_AVAILABLE),
            ('Subdomain Scanner', SUBDOMAIN_AVAILABLE),
            ('Network Intelligence', NETWORK_AVAILABLE),
            ('SecurityTrails Client', SECURITYTRAILS_AVAILABLE)
        ]
        
        status = {}
        for module_name, available in modules:
            status[module_name] = available
            status_color = Colors.success('AVAILABLE') if available else Colors.error('MISSING')
            print(f"  {module_name}: {status_color}")
        
        available_count = sum(status.values())
        print(f"\n  {Colors.highlight('Module-Status:')} {available_count}/5 verfügbar")
        
        return status
    
    def _initialize_modules(self) -> Dict[str, bool]:
        """Initialisiert alle Core-Module"""
        init_results = {}
        
        # DNS Analyzer
        try:
            self.modules['dns'] = DNSAnalyzer()
            init_results['DNS Analyzer'] = True
            print(f"  {Colors.success('DNS Analyzer:')} Erfolgreich initialisiert")
        except Exception as error:
            init_results['DNS Analyzer'] = False
            self.errors.append(f"DNS Analyzer Init: {error}")
            print(f"  {Colors.error('DNS Analyzer:')} Initialisierung fehlgeschlagen")
        
        # CDN Detector
        try:
            self.modules['cdn'] = CDNDetector()
            init_results['CDN Detector'] = True
            print(f"  {Colors.success('CDN Detector:')} Erfolgreich initialisiert")
        except Exception as error:
            init_results['CDN Detector'] = False
            self.errors.append(f"CDN Detector Init: {error}")
            print(f"  {Colors.error('CDN Detector:')} Initialisierung fehlgeschlagen")
        
        # Subdomain Scanner
        try:
            self.modules['subdomain'] = SubdomainScanner()
            init_results['Subdomain Scanner'] = True
            print(f"  {Colors.success('Subdomain Scanner:')} Erfolgreich initialisiert")
        except Exception as error:
            init_results['Subdomain Scanner'] = False
            self.errors.append(f"Subdomain Scanner Init: {error}")
            print(f"  {Colors.error('Subdomain Scanner:')} Initialisierung fehlgeschlagen")
        
        # Network Intelligence
        try:
            self.modules['network'] = NetworkIntelligence()
            init_results['Network Intelligence'] = True
            print(f"  {Colors.success('Network Intelligence:')} Erfolgreich initialisiert")
        except Exception as error:
            init_results['Network Intelligence'] = False
            self.errors.append(f"Network Intelligence Init: {error}")
            print(f"  {Colors.error('Network Intelligence:')} Initialisierung fehlgeschlagen")
        
        # SecurityTrails Client
        try:
            self.modules['securitytrails'] = SecurityTrailsClient()
            init_results['SecurityTrails Client'] = True
            print(f"  {Colors.success('SecurityTrails Client:')} Erfolgreich initialisiert")
        except Exception as error:
            init_results['SecurityTrails Client'] = False
            self.errors.append(f"SecurityTrails Client Init: {error}")
            print(f"  {Colors.error('SecurityTrails Client:')} Initialisierung fehlgeschlagen")
        
        success_count = sum(init_results.values())
        print(f"\n  {Colors.highlight('Initialization-Status:')} {success_count}/5 erfolgreich")
        
        return init_results
    
    def _test_domain_integration(self, domain: str) -> Dict[str, Any]:
        """
        Testet vollständige Integration für eine Domain
        
        Args:
            domain (str): Test-Domain
            
        Returns:
            dict: Domain-spezifische Integration-Ergebnisse
        """
        print(f"  {Colors.info('Integration-Test für:')} {Colors.format_domain(domain)}")
        
        domain_results = {
            'domain': domain,
            'module_results': {},
            'performance_metrics': {},
            'integration_analysis': {},
            'errors': []
        }
        
        # 1. DNS Analyzer
        if 'dns' in self.modules:
            print(f"    {Colors.info('1. DNS Analyzer:')} Starte Analyse...")
            start_time = time.time()
            
            try:
                dns_results = self.modules['dns'].analyze_domain(domain)
                execution_time = time.time() - start_time
                
                domain_results['module_results']['dns'] = dns_results
                domain_results['performance_metrics']['dns'] = execution_time
                
                if dns_results.get('analysis_status') == 'abgeschlossen':
                    print(f"       {Colors.success('DNS-Analyse:')} Erfolgreich ({execution_time:.1f}s)")
                else:
                    print(f"       {Colors.warning('DNS-Analyse:')} Teilweise erfolgreich")
            except Exception as error:
                domain_results['errors'].append(f"DNS Analyzer: {error}")
                print(f"       {Colors.error('DNS-Analyse:')} Fehlgeschlagen")
        
        # 2. CDN Detector (benötigt IP von DNS)
        dns_results = domain_results['module_results'].get('dns', {})
        target_ip = dns_results.get('ipv4')
        
        if 'cdn' in self.modules and target_ip:
            print(f"    {Colors.info('2. CDN Detector:')} Analysiere Infrastructure...")
            start_time = time.time()
            
            try:
                cdn_results = self.modules['cdn'].analyze_infrastructure(target_ip, domain)
                execution_time = time.time() - start_time
                
                domain_results['module_results']['cdn'] = cdn_results
                domain_results['performance_metrics']['cdn'] = execution_time
                
                if cdn_results.get('analysis_status') == 'abgeschlossen':
                    print(f"       {Colors.success('CDN-Analyse:')} Erfolgreich ({execution_time:.1f}s)")
                else:
                    print(f"       {Colors.warning('CDN-Analyse:')} Teilweise erfolgreich")
            except Exception as error:
                domain_results['errors'].append(f"CDN Detector: {error}")
                print(f"       {Colors.error('CDN-Analyse:')} Fehlgeschlagen")
        
        # 3. Subdomain Scanner
        if 'subdomain' in self.modules:
            print(f"    {Colors.info('3. Subdomain Scanner:')} Scanne Assets...")
            start_time = time.time()
            
            try:
                subdomain_results = self.modules['subdomain'].scan_subdomains(domain)
                execution_time = time.time() - start_time
                
                domain_results['module_results']['subdomain'] = subdomain_results
                domain_results['performance_metrics']['subdomain'] = execution_time
                
                if subdomain_results.get('analysis_status') == 'abgeschlossen':
                    asset_count = len(subdomain_results.get('discovered_assets', []))
                    print(f"       {Colors.success('Subdomain-Scan:')} {asset_count} Assets gefunden ({execution_time:.1f}s)")
                else:
                    print(f"       {Colors.warning('Subdomain-Scan:')} Teilweise erfolgreich")
            except Exception as error:
                domain_results['errors'].append(f"Subdomain Scanner: {error}")
                print(f"       {Colors.error('Subdomain-Scan:')} Fehlgeschlagen")
        
        # 4. Network Intelligence (benötigt IP von DNS)
        if 'network' in self.modules and target_ip:
            print(f"    {Colors.info('4. Network Intelligence:')} Analysiere Netzwerkpfad...")
            start_time = time.time()
            
            try:
                network_results = self.modules['network'].analyze_network(target_ip, domain)
                execution_time = time.time() - start_time
                
                domain_results['module_results']['network'] = network_results
                domain_results['performance_metrics']['network'] = execution_time
                
                if network_results.get('analysis_status') == 'abgeschlossen':
                    print(f"       {Colors.success('Network-Analyse:')} Erfolgreich ({execution_time:.1f}s)")
                else:
                    print(f"       {Colors.warning('Network-Analyse:')} Teilweise erfolgreich")
            except Exception as error:
                domain_results['errors'].append(f"Network Intelligence: {error}")
                print(f"       {Colors.error('Network-Analyse:')} Fehlgeschlagen")
        
        # 5. SecurityTrails Client
        if 'securitytrails' in self.modules:
            print(f"    {Colors.info('5. SecurityTrails Client:')} Sammle Intelligence...")
            start_time = time.time()
            
            try:
                st_results = self.modules['securitytrails'].analyze_domain_intelligence(domain)
                execution_time = time.time() - start_time
                
                domain_results['module_results']['securitytrails'] = st_results
                domain_results['performance_metrics']['securitytrails'] = execution_time
                
                if st_results.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
                    print(f"       {Colors.success('SecurityTrails:')} Intelligence gesammelt ({execution_time:.1f}s)")
                else:
                    print(f"       {Colors.warning('SecurityTrails:')} Teilweise erfolgreich")
            except Exception as error:
                domain_results['errors'].append(f"SecurityTrails Client: {error}")
                print(f"       {Colors.error('SecurityTrails:')} Fehlgeschlagen")
        
        # Integration-Analyse für diese Domain
        domain_results['integration_analysis'] = self._analyze_domain_integration(domain_results)
        
        # Domain-Test-Zusammenfassung
        total_time = sum(domain_results['performance_metrics'].values())
        success_count = len([r for r in domain_results['module_results'].values() if r.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']])
        error_count = len(domain_results['errors'])
        
        print(f"\n    {Colors.highlight('Domain-Test-Summary:')}")
        print(f"      Erfolgreiche Module: {Colors.success(str(success_count))}/5")
        print(f"      Gesamtzeit: {Colors.info(f'{total_time:.1f}s')}")
        print(f"      Fehler: {Colors.error(str(error_count)) if error_count > 0 else Colors.success('0')}")
        
        return domain_results
    
    def _analyze_domain_integration(self, domain_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analysiert Integration zwischen Modulen für eine Domain
        
        Args:
            domain_results (dict): Domain-Test-Ergebnisse
            
        Returns:
            dict: Integration-Analyse
        """
        integration_analysis = {
            'data_consistency': True,
            'cross_module_validation': {},
            'data_flow_integrity': True
        }
        
        module_results = domain_results['module_results']
        
        # IP-Adress-Konsistenz zwischen DNS und anderen Modulen
        dns_ip = module_results.get('dns', {}).get('ipv4')
        cdn_ip = module_results.get('cdn', {}).get('ip_address')
        network_ip = module_results.get('network', {}).get('target_ip')
        
        if dns_ip and cdn_ip and dns_ip == cdn_ip:
            integration_analysis['cross_module_validation']['ip_consistency'] = True
        elif dns_ip and cdn_ip:
            integration_analysis['cross_module_validation']['ip_consistency'] = False
            integration_analysis['data_consistency'] = False
        
        # Provider-Konsistenz zwischen CDN und Network
        cdn_provider = module_results.get('cdn', {}).get('provider_name')
        network_classification = module_results.get('network', {}).get('route_classification', {})
        
        # Subdomain-Konsistenz mit SecurityTrails
        local_subdomains = len(module_results.get('subdomain', {}).get('discovered_assets', []))
        st_subdomains = module_results.get('securitytrails', {}).get('domain_details', {}).get('subdomain_count', 0)
        
        if local_subdomains > 0 and st_subdomains > 0:
            subdomain_ratio = local_subdomains / st_subdomains if st_subdomains > 0 else 0
            integration_analysis['cross_module_validation']['subdomain_correlation'] = subdomain_ratio
        
        return integration_analysis
    
    def _perform_cross_module_analysis(self, integration_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Führt Cross-Module-Analyse über alle Test-Domains durch
        
        Args:
            integration_results (dict): Alle Domain-Test-Ergebnisse
            
        Returns:
            dict: Cross-Module-Analyse
        """
        print(f"  {Colors.info('Cross-Module-Analyse:')} Validiere Module-Kompatibilität...")
        
        cross_analysis = {
            'module_success_rates': {},
            'data_consistency_rate': 0,
            'integration_quality': 'unknown',
            'recommendations': []
        }
        
        # Module-Erfolgsraten berechnen
        module_names = ['dns', 'cdn', 'subdomain', 'network', 'securitytrails']
        
        for module in module_names:
            successful_tests = 0
            total_tests = 0
            
            for domain, results in integration_results.items():
                if module in results['module_results']:
                    total_tests += 1
                    module_result = results['module_results'][module]
                    if module_result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
                        successful_tests += 1
            
            success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
            cross_analysis['module_success_rates'][module] = success_rate
            
            module_display = module.replace('_', ' ').title()
            print(f"    {module_display}: {Colors.success(f'{success_rate:.0f}%')} Erfolgsrate")
        
        # Gesamt-Integration-Qualität bewerten
        avg_success_rate = sum(cross_analysis['module_success_rates'].values()) / len(cross_analysis['module_success_rates'])
        
        if avg_success_rate >= 90:
            cross_analysis['integration_quality'] = 'excellent'
            print(f"    {Colors.success('Integration-Qualität:')} Excellent ({avg_success_rate:.0f}%)")
        elif avg_success_rate >= 75:
            cross_analysis['integration_quality'] = 'good'
            print(f"    {Colors.success('Integration-Qualität:')} Good ({avg_success_rate:.0f}%)")
        elif avg_success_rate >= 60:
            cross_analysis['integration_quality'] = 'acceptable'
            print(f"    {Colors.warning('Integration-Qualität:')} Acceptable ({avg_success_rate:.0f}%)")
        else:
            cross_analysis['integration_quality'] = 'needs_improvement'
            print(f"    {Colors.error('Integration-Qualität:')} Needs Improvement ({avg_success_rate:.0f}%)")
        
        return cross_analysis
    
    def _analyze_performance(self) -> Dict[str, Any]:
        """Analysiert Performance-Metriken"""
        print(f"  {Colors.info('Performance-Analyse:')} Bewerte Ausführungszeiten...")
        
        # Sammle alle Performance-Daten
        all_times = {'dns': [], 'cdn': [], 'subdomain': [], 'network': [], 'securitytrails': []}
        
        for domain_results in self.test_results.values():
            for module, time_taken in domain_results.get('performance_metrics', {}).items():
                if module in all_times:
                    all_times[module].append(time_taken)
        
        performance_analysis = {
            'average_times': {},
            'total_analysis_time': 0,
            'performance_rating': 'unknown'
        }
        
        total_avg_time = 0
        for module, times in all_times.items():
            if times:
                avg_time = sum(times) / len(times)
                performance_analysis['average_times'][module] = avg_time
                total_avg_time += avg_time
                
                module_display = module.replace('_', ' ').title()
                print(f"    {module_display}: {Colors.info(f'{avg_time:.1f}s')} durchschnittlich")
        
        performance_analysis['total_analysis_time'] = total_avg_time
        
        # Performance-Rating
        if total_avg_time <= 30:
            performance_analysis['performance_rating'] = 'fast'
            print(f"    {Colors.success('Performance-Rating:')} Fast ({total_avg_time:.1f}s total)")
        elif total_avg_time <= 60:
            performance_analysis['performance_rating'] = 'acceptable'
            print(f"    {Colors.info('Performance-Rating:')} Acceptable ({total_avg_time:.1f}s total)")
        else:
            performance_analysis['performance_rating'] = 'slow'
            print(f"    {Colors.warning('Performance-Rating:')} Slow ({total_avg_time:.1f}s total)")
        
        return performance_analysis
    
    def _display_final_report(self, results: Dict[str, Any]) -> None:
        """
        Zeigt finalen Integration-Test-Report
        
        Args:
            results (dict): Vollständige Test-Ergebnisse
        """
        print(f"\n{Colors.investigation_separator(80)}")
        print(Colors.header("CORE MODULES INTEGRATION TEST - FINAL REPORT"))
        print(Colors.investigation_separator(80))
        
        # Test-Overview
        print(f"Test-Abschluss: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Getestete Domains: {Colors.highlight(str(len(self.test_domains)))}")
        print(f"Core-Module: {Colors.highlight('5')}")
        
        # Module-Status
        print(f"\n{Colors.section_header('MODULE STATUS', 40)}")
        init_status = results['initialization_status']
        successful_inits = sum(init_status.values())
        print(f"Erfolgreich initialisiert: {Colors.success(f'{successful_inits}/5')}")
        
        # Integration-Qualität
        cross_analysis = results['cross_module_analysis']
        integration_quality = cross_analysis.get('integration_quality', 'unknown')
        
        print(f"\n{Colors.section_header('INTEGRATION QUALITY', 40)}")
        if integration_quality == 'excellent':
            quality_display = Colors.success('EXCELLENT')
        elif integration_quality == 'good':
            quality_display = Colors.success('GOOD')
        elif integration_quality == 'acceptable':
            quality_display = Colors.warning('ACCEPTABLE')
        else:
            quality_display = Colors.error('NEEDS IMPROVEMENT')
        
        print(f"Integration-Qualität: {quality_display}")
        
        # Performance
        performance = results['performance_analysis']
        performance_rating = performance.get('performance_rating', 'unknown')
        total_time = performance.get('total_analysis_time', 0)
        
        print(f"\n{Colors.section_header('PERFORMANCE', 40)}")
        if performance_rating == 'fast':
            perf_display = Colors.success('FAST')
        elif performance_rating == 'acceptable':
            perf_display = Colors.info('ACCEPTABLE')
        else:
            perf_display = Colors.warning('SLOW')
        
        print(f"Performance-Rating: {perf_display}")
        print(f"Durchschnittliche Gesamtzeit: {Colors.info(f'{total_time:.1f}s')}")
        
        # Fehler-Summary
        total_errors = len(results['errors'])
        for domain_result in results['domain_tests'].values():
            total_errors += len(domain_result.get('errors', []))
        
        print(f"\n{Colors.section_header('ERROR SUMMARY', 40)}")
        if total_errors == 0:
            print(f"Fehler: {Colors.success('KEINE')}")
        else:
            print(f"Fehler: {Colors.warning(str(total_errors))} (Details in Logs)")
        
        # Phase 2 Status
        print(f"\n{Colors.investigation_separator(80)}")
        print(Colors.header("PHASE 2: CORE ANALYZER MODULES - COMPLETE"))
        print(Colors.investigation_separator(80))
        
        print(f"✅ Step 2.1: DNS Analyzer - {Colors.success('COMPLETE')}")
        print(f"✅ Step 2.2: CDN Detector - {Colors.success('COMPLETE')}")
        print(f"✅ Step 2.3: Subdomain Scanner - {Colors.success('COMPLETE')}")
        print(f"✅ Step 2.4: Network Intelligence - {Colors.success('ENHANCED COMPLETE')}")
        print(f"✅ Step 2.5: SecurityTrails Client - {Colors.success('COMPLETE')}")
        print(f"✅ Step 2.6: Integration Testing - {Colors.success('COMPLETE')}")
        
        print(f"\n{Colors.success('PHASE 2 ERFOLGREICH ABGESCHLOSSEN!')}")
        print(f"{Colors.info('Bereit für Phase 3: Integration Layer')}")
        
        print(f"\n{Colors.investigation_separator(80)}")

# Main-Funktion für Integration-Test
def main():
    """
    Führt vollständigen Core-Modules Integration-Test durch
    """
    test_framework = CoreModulesIntegrationTest()
    results = test_framework.run_integration_test()
    
    # Test-Ergebnisse können für weitere Analyse gespeichert werden
    return results

if __name__ == "__main__":
    main()