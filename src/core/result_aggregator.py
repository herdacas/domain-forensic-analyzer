"""
Result Aggregator for Domain Forensic Analyzer
Unified Output Format für alle Module-Ergebnisse

ASSET EXTRACTION BUG FIXED - Übernimmt bewährte Logik aus original Code
"""

import json
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

class ConfidenceLevel(Enum):
    """Confidence-Level für Datenqualität"""
    HIGH = "high"
    MEDIUM = "medium" 
    LOW = "low"
    UNKNOWN = "unknown"

class DataSource(Enum):
    """Datenquellen für Tracking"""
    DNS_ANALYSIS = "dns_analysis"
    CDN_DETECTION = "cdn_detection"
    SUBDOMAIN_SCAN = "subdomain_scan"
    NETWORK_INTEL = "network_intelligence"
    SECURITYTRAILS = "securitytrails"
    WHOIS = "whois"
    DNS_HISTORY = "dns_history"
    AGGREGATED = "aggregated"

@dataclass
class StandardizedAsset:
    """Standardisierte Asset-Struktur"""
    asset_id: str
    asset_type: str  # subdomain, ip, certificate, etc.
    value: str  # actual asset value
    risk_level: str  # critical, high, medium, low, minimal
    confidence: ConfidenceLevel
    source: DataSource
    metadata: Dict[str, Any]
    discovered_at: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class StandardizedInfrastructure:
    """Standardisierte Infrastructure-Info"""
    provider_name: str
    provider_type: str  # cdn, cloud, hosting, platform
    protection_level: str  # high, medium, low, minimal
    location: Dict[str, str]  # country, city, region
    asn_info: Dict[str, Any]
    confidence: ConfidenceLevel
    source: DataSource
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class StandardizedNetworkPath:
    """Standardisierte Network-Path-Info"""
    total_hops: int
    responsive_hops: int
    connectivity_status: str
    opsec_risk_level: str
    response_times: Dict[str, str]
    route_type: str
    confidence: ConfidenceLevel
    source: DataSource
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class UnifiedResult:
    """Unified Result Structure für alle Module-Ergebnisse"""
    
    # Basic Info
    domain: str
    analysis_timestamp: str
    total_execution_time: float
    
    # Module Success Tracking
    modules_executed: List[str]
    modules_successful: List[str]
    modules_failed: List[str]
    
    # Aggregated Assets
    total_assets_found: int
    assets: List[StandardizedAsset]
    sensitive_assets_found: int
    critical_assets_count: int
    
    # Infrastructure Intelligence
    infrastructure: Optional[StandardizedInfrastructure]
    
    # Network Intelligence
    network_path: Optional[StandardizedNetworkPath]
    
    # DNS Intelligence
    dns_info: Dict[str, Any]
    
    # Risk Assessment
    overall_risk_level: str
    risk_factors: List[str]
    risk_score: float  # 0.0 - 10.0
    
    # Intelligence Sources
    intelligence_sources: List[DataSource]
    data_freshness: Dict[str, str]  # source -> timestamp
    
    # Metadata
    confidence_metrics: Dict[str, ConfidenceLevel]
    warnings: List[str]
    errors: List[str]
    
    # Compatibility fallback for legacy summary function
    results: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON export"""
        result = asdict(self)
        # Convert enums to strings for JSON serialization
        for asset in result['assets']:
            asset['confidence'] = asset['confidence'].value
            asset['source'] = asset['source'].value
        
        if result['infrastructure']:
            result['infrastructure']['confidence'] = result['infrastructure']['confidence'].value
            result['infrastructure']['source'] = result['infrastructure']['source'].value
            
        if result['network_path']:
            result['network_path']['confidence'] = result['network_path']['confidence'].value
            result['network_path']['source'] = result['network_path']['source'].value
            
        result['intelligence_sources'] = [source.value for source in result['intelligence_sources']]
        result['confidence_metrics'] = {k: v.value for k, v in result['confidence_metrics'].items()}
        
        return result
    
    def to_json(self, indent: int = 2) -> str:
        """Export as JSON string"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

class ResultAggregator:
    """
    Aggregiert und standardisiert Results von allen Core-Modulen
    """
    
    def __init__(self):
        self.supported_modules = [
            'dns', 'whois', 'dns_history', 'cdn', 'subdomain', 'network', 'securitytrails'
        ]
    
    def aggregate_results(self, domain: str, module_results: Dict[str, Any], 
                         execution_time: float) -> UnifiedResult:
        """
        Hauptfunktion: Aggregiert alle Module-Results zu UnifiedResult
        
        Args:
            domain: Analysierte Domain
            module_results: Dict mit Results aller Module
            execution_time: Gesamte Ausführungszeit
            
        Returns:
            UnifiedResult: Standardisierte, aggregierte Ergebnisse
        """
        # Basic tracking
        modules_executed = list(module_results.keys())
        _ok_statuses = {'abgeschlossen', 'demo_abgeschlossen', 'quota_exceeded', 'skipped'}
        modules_successful = [name for name, result in module_results.items()
                              if result.get('analysis_status') in _ok_statuses]
        modules_failed = [name for name in modules_executed if name not in modules_successful]
        
        # Standardize assets from all modules - FIXED WITH ROBUST EXTRACTION
        all_assets = self._extract_and_standardize_assets_fixed(module_results)
        
        # Aggregate infrastructure info
        infrastructure = self._aggregate_infrastructure(module_results)
        
        # Aggregate network intelligence
        network_path = self._aggregate_network_intelligence(module_results)
        
        # Extract DNS info
        dns_info = self._extract_dns_info(module_results)
        
        # Calculate risk metrics
        risk_metrics = self._calculate_risk_metrics(all_assets, infrastructure, network_path)
        
        # Track data sources and freshness
        intelligence_sources = self._identify_intelligence_sources(module_results)
        data_freshness = self._calculate_data_freshness(module_results)
        
        # Collect warnings and errors
        warnings, errors = self._collect_issues(module_results)
        
        # Calculate confidence metrics
        confidence_metrics = self._calculate_confidence_metrics(module_results, all_assets)
        
        return UnifiedResult(
            domain=domain,
            analysis_timestamp=datetime.now().isoformat(),
            total_execution_time=execution_time,
            modules_executed=modules_executed,
            modules_successful=modules_successful,
            modules_failed=modules_failed,
            total_assets_found=len(all_assets),
            assets=all_assets,
            sensitive_assets_found=len([a for a in all_assets if a.risk_level in ['critical', 'high']]),
            critical_assets_count=len([a for a in all_assets if a.risk_level == 'critical']),
            infrastructure=infrastructure,
            network_path=network_path,
            dns_info=dns_info,
            overall_risk_level=risk_metrics['level'],
            risk_factors=risk_metrics['factors'],
            risk_score=risk_metrics['score'],
            intelligence_sources=intelligence_sources,
            data_freshness=data_freshness,
            confidence_metrics=confidence_metrics,
            warnings=warnings,
            errors=errors,
            results=module_results  # Fallback compatibility
        )
    
    def _extract_and_standardize_assets_fixed(self, module_results: Dict[str, Any]) -> List[StandardizedAsset]:
        """
        FIXED: Robuste Asset-Extraktion basierend auf bewährter Logik
        Übernimmt die comprehensive search logic aus dem ursprünglichen Code
        """
        assets = []
        
        # Subdomain assets - FIXED mit comprehensive key search
        subdomain_result = module_results.get('subdomain', {})
        if subdomain_result.get('analysis_status') == 'abgeschlossen':
            wildcard_detected = bool(
                subdomain_result.get('wildcard_detected')
                or subdomain_result.get('dns_configuration', {}).get('wildcard_detected', False)
            )
            sensitive_assets = subdomain_result.get('sensitive_assets', [])
            risk_by_subdomain = {}

            if isinstance(sensitive_assets, list):
                for sensitive_entry in sensitive_assets:
                    if not isinstance(sensitive_entry, dict):
                        continue

                    asset_data = sensitive_entry.get('asset', {})
                    if not isinstance(asset_data, dict):
                        continue

                    subdomain_value = asset_data.get('subdomain') or asset_data.get('domain')
                    risk_value = sensitive_entry.get('risk_level')

                    if subdomain_value and risk_value:
                        risk_by_subdomain[str(subdomain_value).lower().strip()] = str(risk_value).lower().strip()
            
            # COMPREHENSIVE KEY SEARCH - genau wie im original code
            discovered_assets = None
            possible_asset_keys = [
                'discovered_assets', 'assets', 'found_assets', 'enumerated_assets', 
                'subdomains', 'subdomain_list', 'asset_list', 'results', 'data',
                'categorized_assets', 'all_assets', 'subdomain_assets'
            ]
            
            # Try list-based keys first
            for key in possible_asset_keys:
                assets_data = subdomain_result.get(key, [])
                if assets_data and isinstance(assets_data, list) and len(assets_data) > 0:
                    discovered_assets = assets_data
                    break
            
            # If list-based keys don't work, try dict-based structure
            if not discovered_assets:
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
            
            # Process discovered assets with risk level detection
            if discovered_assets and isinstance(discovered_assets, list):
                for asset in discovered_assets:
                    if isinstance(asset, dict):
                        # Get subdomain name
                        subdomain_name = asset.get('subdomain', asset.get('domain', ''))
                        if not subdomain_name:
                            continue
                        
                        # Try multiple risk level key variations
                        risk_level = None
                        for risk_key in ['risk_level', 'risk', 'level', 'priority', 'sensitivity']:
                            risk_value = asset.get(risk_key)
                            if risk_value:
                                risk_level = str(risk_value).lower().strip()
                                break

                        # Prefer explicit risk from subdomain scanner sensitive_assets
                        subdomain_key = subdomain_name.lower().strip()
                        if subdomain_key in risk_by_subdomain:
                            risk_level = risk_by_subdomain[subdomain_key]
                        
                        # If no risk_level found, infer from subdomain name
                        if not risk_level:
                            subdomain_lower = subdomain_name.lower()
                            if any(admin_term in subdomain_lower for admin_term in ['admin', 'administrator', 'manage', 'control', 'panel']):
                                risk_level = 'critical'
                            elif any(api_term in subdomain_lower for api_term in ['api', 'rest', 'graphql', 'webhook']):
                                risk_level = 'high'
                            elif any(dev_term in subdomain_lower for dev_term in ['dev', 'test', 'staging']):
                                risk_level = 'high'
                            else:
                                risk_level = 'informational'
                        
                        # Wildcard domains: candidates only, never critical/high
                        if wildcard_detected:
                            risk_level = 'informational'

                        # Create standardized asset
                        standardized = StandardizedAsset(
                            asset_id=f"subdomain_{subdomain_name}",
                            asset_type="subdomain",
                            value=subdomain_name,
                            risk_level=risk_level,
                            confidence=ConfidenceLevel.HIGH,
                            source=DataSource.SUBDOMAIN_SCAN,
                            metadata=asset,
                            discovered_at=datetime.now().isoformat()
                        )
                        assets.append(standardized)
        
        return assets
    
    def _aggregate_infrastructure(self, module_results: Dict[str, Any]) -> Optional[StandardizedInfrastructure]:
        """Aggregiert Infrastructure-Info aus CDN-Modul"""
        cdn_result = module_results.get('cdn', {})
        if cdn_result.get('analysis_status') != 'abgeschlossen':
            return None
        
        # Extract location safely
        location = cdn_result.get('location', {})
        if not isinstance(location, dict):
            location = {
                'country': cdn_result.get('country', 'Unknown'),
                'city': cdn_result.get('city', 'Unknown')
            }
        
        return StandardizedInfrastructure(
            provider_name=cdn_result.get('provider_name', 'Unknown'),
            provider_type=cdn_result.get('provider_type', 'Unknown'),
            protection_level=cdn_result.get('protection_level', 'Unknown'),
            location=location,
            asn_info={
                'asn': cdn_result.get('asn'),
                'organization': cdn_result.get('organization')
            },
            confidence=ConfidenceLevel.HIGH,
            source=DataSource.CDN_DETECTION
        )
    
    def _aggregate_network_intelligence(self, module_results: Dict[str, Any]) -> Optional[StandardizedNetworkPath]:
        """Aggregiert Network-Intelligence aus Network-Modul"""
        network_result = module_results.get('network', {})
        if network_result.get('analysis_status') != 'abgeschlossen':
            return None
        
        connectivity = network_result.get('connectivity_test', {})
        opsec = network_result.get('opsec_assessment', {})
        traceroute = network_result.get('traceroute_data', {})
        
        return StandardizedNetworkPath(
            total_hops=traceroute.get('total_hops', 0) if traceroute else 0,
            responsive_hops=traceroute.get('responsive_hops', 0) if traceroute else 0,
            connectivity_status="reachable" if connectivity.get('ping') else "unknown",
            opsec_risk_level=opsec.get('risk_level', 'unknown') if opsec else 'unknown',
            response_times=connectivity.get('response_times', {}) if connectivity else {},
            route_type=traceroute.get('route_type', 'unknown') if traceroute else 'unknown',
            confidence=ConfidenceLevel.HIGH,
            source=DataSource.NETWORK_INTEL
        )
    
    def _extract_dns_info(self, module_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extrahiert DNS-Informationen"""
        dns_result = module_results.get('dns', {})
        return {
            'ipv4': dns_result.get('ipv4'),
            'ipv6': dns_result.get('ipv6'),
            'reverse_dns': dns_result.get('reverse_dns'),
            'nameservers': (
                dns_result.get('nameservers')
                or dns_result.get('ns_records')
                or []
            ),
            'mail_servers': (
                dns_result.get('mail_servers')
                or dns_result.get('mx_records')
                or []
            ),
            'soa_record': dns_result.get('soa_record', {}),
            'txt_records': dns_result.get('txt_records', []),
            'spf_record': dns_result.get('spf_record'),
            'spf_analysis': dns_result.get('spf_analysis', {}),
            'dmarc_record': dns_result.get('dmarc_record'),
            'dmarc_analysis': dns_result.get('dmarc_analysis', {}),
            'dkim': dns_result.get('dkim', {}),
            'caa_records': dns_result.get('caa_records', []),
            'dnssec': dns_result.get('dnssec', {}),
            'zone_transfer': dns_result.get('zone_transfer', {}),
            'dns_configuration_assessment': dns_result.get('dns_configuration_assessment', {})
        }
    
    def _calculate_risk_metrics(self, assets: List[StandardizedAsset], 
                               infrastructure: Optional[StandardizedInfrastructure],
                               network_path: Optional[StandardizedNetworkPath]) -> Dict[str, Any]:
        """Berechnet Risk-Metriken"""
        sensitive_count = len([a for a in assets if a.risk_level in ['critical', 'high']])
        critical_count = len([a for a in assets if a.risk_level == 'critical'])
        
        # Risk factors
        factors = []
        if critical_count > 0:
            factors.append(f"{critical_count} critical assets exposed")
        if sensitive_count > 5:
            factors.append("High number of sensitive assets")
        if infrastructure and infrastructure.protection_level == 'minimal':
            factors.append("Minimal infrastructure protection")
        
        # Risk level calculation
        if sensitive_count >= 20:
            level = 'high'
            score = 8.0 + min(2.0, critical_count * 0.5)
        elif sensitive_count >= 10:
            level = 'medium'
            score = 5.0 + min(3.0, sensitive_count * 0.2)
        elif sensitive_count >= 3:
            level = 'low'
            score = 2.0 + min(3.0, sensitive_count * 0.5)
        else:
            level = 'minimal'
            score = min(2.0, sensitive_count * 0.5)
        
        return {
            'level': level,
            'factors': factors,
            'score': round(score, 1)
        }
    
    def _identify_intelligence_sources(self, module_results: Dict[str, Any]) -> List[DataSource]:
        """Identifiziert verwendete Intelligence-Quellen"""
        sources = []
        
        for module_name, result in module_results.items():
            if result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
                source_map = {
                    'dns': DataSource.DNS_ANALYSIS,
                    'cdn': DataSource.CDN_DETECTION,
                    'subdomain': DataSource.SUBDOMAIN_SCAN,
                    'network': DataSource.NETWORK_INTEL,
                    'securitytrails': DataSource.SECURITYTRAILS,
                    'whois': DataSource.WHOIS,
                    'dns_history': DataSource.DNS_HISTORY
                }
                if module_name in source_map:
                    sources.append(source_map[module_name])
        
        return sources
    
    def _calculate_data_freshness(self, module_results: Dict[str, Any]) -> Dict[str, str]:
        """Berechnet Data-Freshness pro Quelle"""
        freshness = {}
        current_time = datetime.now().isoformat()
        
        for module_name, result in module_results.items():
            if result.get('analysis_status') in ['abgeschlossen', 'demo_abgeschlossen']:
                freshness[module_name] = current_time
        
        return freshness
    
    def _collect_issues(self, module_results: Dict[str, Any]) -> tuple[List[str], List[str]]:
        """Sammelt Warnings und Errors"""
        warnings = []
        errors = []
        
        for module_name, result in module_results.items():
            if result.get('analysis_status') == 'failed':
                errors.append(f"{module_name}: {result.get('error', 'Unknown error')}")
            elif result.get('analysis_status') == 'demo_abgeschlossen':
                warnings.append(f"{module_name}: Running in demo mode - consider configuring API key")
        
        return warnings, errors
    
    def _calculate_confidence_metrics(self, module_results: Dict[str, Any], 
                                    assets: List[StandardizedAsset]) -> Dict[str, ConfidenceLevel]:
        """Berechnet Confidence-Metriken"""
        metrics = {}
        
        # Overall confidence based on successful modules
        successful_modules = len([r for r in module_results.values() 
                                if r.get('analysis_status') == 'abgeschlossen'])
        total_modules = len(module_results)
        
        if successful_modules == total_modules:
            metrics['overall'] = ConfidenceLevel.HIGH
        elif successful_modules >= total_modules * 0.6:
            metrics['overall'] = ConfidenceLevel.MEDIUM
        else:
            metrics['overall'] = ConfidenceLevel.LOW
        
        # Asset discovery confidence
        if len(assets) > 0:
            metrics['asset_discovery'] = ConfidenceLevel.HIGH
        else:
            metrics['asset_discovery'] = ConfidenceLevel.LOW
        
        return metrics

def create_result_aggregator() -> ResultAggregator:
    """Factory function für ResultAggregator"""
    return ResultAggregator()
