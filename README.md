Domain Forensic Analyzer v3.4
🎯 Projektübersicht
Domain Forensic Analyzer ist ein professionelles OSINT-Tool (Open Source Intelligence) für forensische Domain-Untersuchungen und Sicherheitsanalysen. Das Tool wurde speziell für Penetration Tester, Forensiker, Security Researcher und IT-Sicherheitsprofis entwickelt, um umfassende Strukturanalysen von Domains durchzuführen.

Zielsetzung
Erste Strukturanalyse von Domains für forensische Untersuchungen
Infrastruktur-Mapping zur Identifizierung von Hosting-Providern und CDNs
Asset Discovery zur Aufdeckung von Subdomains und sensiblen Interfaces
Intelligence Gathering durch Integration externer Datenquellen
Professional Reporting für dokumentierte Untersuchungsergebnisse
📊 Aktueller Entwicklungsstand
Version: 3.4 (Phase 1.3 - Modularisierung)
Status: In aktiver Entwicklung - Migration von monolithischer zu modularer Architektur

Abgeschlossene Funktionalität (Monolithische Version):
✅ DNS Foundation Analysis - Vollständige DNS-Auflösung und Record-Analyse
✅ Infrastructure Classification - CDN- und Provider-Erkennung
✅ Enhanced Asset Discovery - 40+ Subdomain-Kategorien mit Wildcard-Detection
✅ Network Intelligence - Traceroute-Analyse mit OPSEC-Assessment
✅ Certificate Analysis - SSL/TLS-Zertifikat-Untersuchung
✅ SecurityTrails Integration - Historische Domain-Intelligence
✅ Professional Terminal Output - Strukturierte, farbkodierte Berichte
✅ JSON Export - Maschinenlesbare Datenexporte
Aktueller Migrationsstatus:
✅ GitHub Repository Structure - Professionelle Projektstruktur
✅ Development Environment - VS Code + GitHub Copilot Integration
🔄 Module Extraction - Aufteilen des monolithischen Codes
❌ Integration Layer - Orchestrierung der Module
❌ Testing Framework - Unit- und Integrationstests
🛠️ Funktionsweise und Features
Core-Analysefunktionen
1. DNS Foundation Analysis
• IPv4/IPv6 Address Resolution
• Reverse DNS Lookup für Infrastructure-Mapping
• MX Records Analysis (Mail-Server-Konfiguration)
• NS Records Discovery (Authoritative Name Server)
• DNS Record Validation und Error-Handling
2. Infrastructure Classification
• CDN Detection (Cloudflare, AWS CloudFront, Fastly, etc.)
• Hosting Provider Classification (Cloud, Platform, Direct)
• Geographic Location Analysis (Country, City, ASN)
• Organization Identification (IP-based)
• Protection Level Assessment (DDoS, WAF, Security Features)
3. Enhanced Asset Discovery
• Subdomain Enumeration (40+ Kategorien)
  ├── Administrative: admin, control, manage, cpanel
  ├── API Endpoints: api, rest, graphql, webhook
  ├── Development: dev, test, staging, beta, alpha
  ├── Services: auth, login, sso, oauth
  └── Commerce: shop, store, cart, payment
• Wildcard DNS Detection und Strategy-Adjustment
• Multi-threaded Scanning für Performance
• Asset Categorization und Risk-Assessment
4. Network Intelligence
• Advanced Traceroute Analysis (Windows CP850 optimiert)
• OPSEC Risk Assessment (ISP-Detection für Analyst-Attribution)
• Route Classification (International vs Regional)
• Network Timeout-Management
• Connectivity Testing (HTTP/HTTPS Protocols)
5. Certificate Analysis
• SSL/TLS Certificate Chain Analysis
• Certificate Authority Identification
• Validity Period Assessment
• Subject Alternative Names (SAN) Extraction
• Wildcard Certificate Detection
6. Intelligence Integration
• SecurityTrails API Integration
  ├── Historical DNS Records
  ├── Domain Age Analysis
  ├── Subdomain History
  └── Co-hosted Domain Discovery
• VirusTotal API Integration (geplant)
• Passive DNS Integration (geplant)
Output und Reporting
Professional Terminal Output
• Strukturierte Investigation Phases (1-5)
• Farbkodierte Status-Indikatoren
• Executive Summary mit Risk Assessment
• Technical Details mit forensischer Tiefe
• Investigation ID und Timestamp-Tracking
Data Export Formats
• JSON Export für weitere Datenverarbeitung
• CSV Export für Tabellenkalkulation (geplant)
• PDF Reports für Management-Präsentation (geplant)
• Timeline Visualization für historische Analyse (geplant)
🏗️ Technische Architektur
Aktuelle Architektur (Ziel-Design)
domain-forensic-analyzer/
├── main.py                     # Application Entry Point
├── config/
│   └── settings.py            # Configuration Management
├── src/
│   ├── analyzers/             # Core Analysis Modules
│   │   ├── dns_analyzer.py
│   │   ├── cdn_detector.py
│   │   ├── subdomain_scanner.py
│   │   ├── certificate_analyzer.py
│   │   ├── network_intelligence.py
│   │   └── securitytrails_client.py
│   ├── utils/                 # Utility Functions
│   │   ├── colors.py          # Terminal Formatting
│   │   ├── validators.py      # Input Validation
│   │   └── formatters.py      # Output Formatting
│   └── reports/               # Report Generation
│       ├── console_reporter.py
│       ├── json_reporter.py
│       └── pdf_reporter.py
├── tests/                     # Testing Framework
└── docs/                      # Documentation
Design Principles
Modulare Architektur - Jedes Modul eigenständig testbar
Dependency Injection - Saubere Modul-Interfaces
Error-First Design - Robuste Fehlerbehandlung
Configuration-Driven - Flexible Anpassung ohne Code-Änderungen
Professional Standards - Enterprise-Ready Code Quality
🚀 Installation und Verwendung
Systemanforderungen
• Python 3.8+
• Windows 10/11 (Linux/macOS Support geplant)
• Administrator-Rechte (für erweiterte Netzwerk-Analyse)
• Internetverbindung (für API-Zugriffe)
Installation
# Repository klonen
git clone https://github.com/username/domain-forensic-analyzer.git
cd domain-forensic-analyzer

# Dependencies installieren
pip install -r requirements.txt

# Umgebungsvariablen konfigurieren
cp .env.example .env
# API-Keys in .env eintragen
Basis-Verwendung
# Standard-Analyse
python main.py

# Mit spezifischen Parametern
python main.py --domain example.com --output json

# Batch-Modus
python main.py --batch domains.txt --output-dir results/
API-Integration
# SecurityTrails API-Key setzen
export SECURITYTRAILS_API_KEY="your_api_key_here"

# VirusTotal API-Key setzen
export VIRUSTOTAL_API_KEY="your_api_key_here"
📋 Beispielanwendungen
Use Case 1: Penetration Testing - Reconnaissance Phase
Ziel: Erste Strukturanalyse einer Ziel-Domain
Ablauf:
1. DNS-Auflösung und Infrastructure-Mapping
2. Subdomain-Discovery für Attack-Surface-Mapping
3. CDN-Detection für Origin-Server-Discovery
4. Certificate-Analysis für zusätzliche Domains
5. Professional Report für Testing-Dokumentation
Use Case 2: Incident Response - Threat Intelligence
Ziel: Verdächtige Domain analysieren
Ablauf:
1. Historische DNS-Daten via SecurityTrails
2. Co-hosted Domain Discovery
3. Infrastructure-Provider-Analyse
4. Timeline-Analysis für Aktivitätsmuster
5. Threat-Intelligence-Report
Use Case 3: Due Diligence - Sicherheitsbewertung
Ziel: Sicherheitsbewertung eines Geschäftspartners
Ablauf:
1. Vollständige Asset-Discovery
2. Sicherheits-Feature-Assessment (CDN, WAF)
3. Exposed Services und Admin-Interfaces
4. Risk-Scoring und Executive Summary
5. Compliance-Report
Beispiel-Output (Auszug)
======================================================================
  DOMAIN FORENSIC INVESTIGATION INITIATED
======================================================================
Target Domain: stackoverflow.com
Investigation ID: INV-20250119-143052
Started: 2025-01-19 14:30:52

[1] NETWORK FOUNDATION ANALYSIS
============================================================
DNS Resolution Analysis:
   Primary IPv4: 172.64.155.249
   Reverse DNS: Not disclosed
   IPv6 Support: Not configured
   MX Records: 2 mail servers configured

[2] INFRASTRUCTURE CLASSIFICATION
============================================================
Infrastructure Assessment:
   Service Type: Content Delivery Network (CDN)
   Provider: Cloudflare
   Protection Level: High (DDoS, WAF, Bot Management)
   Geographic Location: United States, San Francisco

RISK ASSESSMENT:
   Overall Risk Level: MEDIUM
   Risk Factors:
   - CDN Infrastructure: Origin server bypass applicable
   - Sensitive interfaces exposed (1)

INVESTIGATION STATUS: COMPLETE
📈 Entwicklungsroadmap
Phase 1: Foundation (Q1 2025)
[x] Repository Structure und Development Environment
[x] Modulare Architektur Design
[ ] Core Module Implementation
[ ] Basic Integration Layer
[ ] Unit Testing Framework
Phase 2: Enhancement (Q2 2025)
[ ] VirusTotal API Integration
[ ] Certificate Transparency Integration
[ ] Advanced Network Analysis (Port Scanning)
[ ] PDF Report Generation
[ ] Performance Optimization
Phase 3: Professional Features (Q3 2025)
[ ] Web Interface (Optional)
[ ] Database Integration für historische Daten
[ ] Machine Learning für Pattern Recognition
[ ] Multi-Threading für Large-Scale Analysis
[ ] Enterprise Configuration Management
Phase 4: Community & Scale (Q4 2025)
[ ] Linux/macOS Cross-Platform Support
[ ] Plugin Architecture für Custom Modules
[ ] Community Contributions Framework
[ ] Professional Documentation
[ ] Performance Benchmarking
🔬 Technische Details
Unterstützte DNS Record Types
• A Records (IPv4 Address)
• AAAA Records (IPv6 Address)
• MX Records (Mail Exchange)
• NS Records (Name Server)
• TXT Records (geplant: SPF, DMARC, DKIM)
• CNAME Records (geplant)
CDN/Provider Detection
Supported Providers:
• Cloudflare (comprehensive detection)
• AWS CloudFront
• Fastly
• DigitalOcean
• Google Cloud Platform
• GitHub Pages
• Custom Provider Extension möglich
Performance Characteristics
• Standard Domain Analysis: <30 Sekunden
• Enhanced Subdomain Discovery: 1-3 Minuten
• International Domains: Extended timeouts
• API-dependent Features: Rate-limit-aware
• Multi-threading: 8-12 concurrent requests
📄 Lizenz und Beitrag
Lizenz
Dieses Projekt steht unter der MIT License - siehe LICENSE für Details.

Beiträge (Contributions)
Beiträge sind willkommen! Bitte lesen Sie CONTRIBUTING.md für Details zum Code of Conduct und dem Prozess für Pull Requests.

Entwicklerrichtlinien
• Deutsche Kommentare und Dokumentation
• Professional Code Standards (PEP 8)
• Unit Tests für alle neuen Features
• Keine Emojis/Symbole in Code-Kommentaren
• Error-First Exception Handling
• Comprehensive Logging
Support und Community
• GitHub Issues: Bug Reports und Feature Requests
• Security Issues: Responsible Disclosure via Email
• Documentation: Verbesserungsvorschläge willkommen
• Testing: Community-Feedback für verschiedene Umgebungen
🎯 Disclaimer
Wichtiger Hinweis: Dieses Tool ist ausschließlich für legale Sicherheitsanalysen und autorisierte Penetration Tests bestimmt. Die Verwendung für unbefugte Angriffe oder illegale Aktivitäten ist strengstens untersagt. Der Benutzer trägt die vollständige Verantwortung für die rechtmäßige Verwendung dieses Tools.

Das Tool sammelt ausschließlich öffentlich verfügbare Informationen und führt keine aktiven Angriffe oder Sicherheitsverletzungen durch.

Domain Forensic Analyzer v3.4 - Professional OSINT Tool for Security Professionals Entwickelt für forensische Untersuchungen und Sicherheitsanalysen