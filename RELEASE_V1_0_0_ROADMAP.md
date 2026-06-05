# Release V1.0.0 Roadmap — Coding Agent Arbeitsplan

**Projekt:** herdacas/domain-forensic-analyzer  
**Ziel:** Produktionsreifer V1.0.0-Release  
**Status:** In Planung  

---

## 📋 ANWEISUNG FÜR CODING AGENT

### Autonome Arbeitsweise
Der Coding Agent arbeitet **vollständig autonom** innerhalb jeder Phase. Folgende Berechtigungen sind ab sofort freigegeben:

- ✅ Push auf `main` und Feature-Branches
- ✅ Pull Requests erstellen & mergen
- ✅ Dateien erstellen, ändern, löschen
- ✅ Commits durchführen
- ✅ Branches anlegen/löschen
- ✅ GitHub Actions konfigurieren
- ✅ Repository-Settings anpassen (im Rahmen der Phasen)

### Arbeitsabfolge pro Phase

1. **Planung:** Agent liest Phase-Anforderungen
2. **Implementierung:** Agent arbeitet autonom, erstellt PRs mit detaillierten Commit-Messages
3. **Selbst-Validierung:** Agent verifiziert eigene Arbeit (Tests laufen, Linting passt, Funktionalität gegeben)
4. **Report:** Agent erstellt Completion-Report mit:
   - Was wurde fertiggestellt
   - Welche Dateien/PRs wurden geändert
   - Test-Results & Coverage
   - Links zu Commits/PRs
5. **User-Verifikation:** User überprüft Report und gibt Go/No-Go für nächste Phase
6. **Nächste Phase:** Agent startet autonome Arbeit an Phase N+1

### Anforderungen an Reports
Nach jeder Phase:
- [ ] Kurze Zusammenfassung (3-5 Sätze)
- [ ] Checkliste: Was wurde abgehakt?
- [ ] Commits/PRs mit Links
- [ ] Test-Coverage-Bericht (wenn applicable)
- [ ] Keine blockierenden Issues
- [ ] Ready für User-Review

---

## ⚠️ WICHTIG: VERSION MANAGEMENT

### Status vor Phase 1
**`__version__` wurde in einer vorherigen Session bereits auf `"1.0.0"` gesetzt.**

Aktueller Status:
- ✅ `src/__init__.py`: `__version__ = "1.0.0"` (bereits gesetzt)

### Agent-Anweisung: Version-Handling

**Phase 1 (Test-Suite):**
- ❌ NICHT anfassen — Version bleibt, wie sie ist
- Keine Änderungen an `__version__` oder anderen Version-Strings
- Fokus: Tests aufbauen

**Phase 2 (CI/CD Pipeline):**
- ❌ NICHT anfassen — Version bleibt, wie sie ist
- Fokus: GitHub Actions Workflow

**Phase 3 (Packaging):**
- ✅ **HIER AKTIV:** Version-Management durchführen
- Überprüfe aktuellen `__version__` in `src/__init__.py`
- **Erwarteter Status:** Bereits `"1.0.0"` (gesetzt von vorheriger Session)
- **Falls bereits 1.0.0:** Keine Änderung nötig — Dokumentiere im Report: "✅ Version bereits konsistent auf 1.0.0"
- **Falls nicht 1.0.0:** Setze auf `"1.0.0"` in allen Dateien:
  - `src/__init__.py`
  - `setup.py` / `pyproject.toml` (wenn vorhanden)
  - Aktualisiere `CHANGELOG.md` und erwähne die Versionierung
- Verifiziere Konsistenz über alle Dateien

**Phase 6 (Finalisierung & Release):**
- ✅ Final-Check: `__version__` überall `"1.0.0"` (sollte nach Phase 3 OK sein)
- Setze Git-Tag `v1.0.0`

### Wichtig für Agent-Dokumentation (claude.md)
Speichere diese Information in deiner internen Arbeitsmappe:
```
⚠️ VERSION STATUS
- v1.0.0 wurde bereits in vorheriger Session gesetzt
- Phase 1-2: NICHT anfassen
- Phase 3: Überprüfen & ggf. konsolidieren
- Phase 6: Final-Check vor Release-Tag
```

---

## 🎯 PHASEN-ÜBERSICHT

| Phase | Titel | Autonomie | User-Verif. |
|-------|-------|-----------|------------|
| 1 | Test-Suite | ✅ Voll | Nach Abschluss |
| 2 | CI/CD Pipeline | ✅ Voll | Nach Abschluss |
| 3 | Packaging | ✅ Voll | Nach Abschluss |
| 4 | Cross-Platform OPSEC | ✅ Voll | Nach Abschluss |
| 5 | Dokumentation | ✅ Voll | Nach Abschluss |
| 6 | Finalisierung & Release | ✅ Voll | Nach Abschluss |

---

## PHASE 1: Test-Suite (Unit + Integration)

### Anforderungen
- `tests/` Verzeichnis mit pytest-Struktur aufbauen
- Mock-Fixtures für alle externen APIs (VirusTotal, AbuseIPDB, SecurityTrails, WHOIS)
- Unit-Tests für kritische Module:
  - `tests/test_dns_analyzer.py`
  - `tests/test_ssl_analyzer.py`
  - `tests/test_whois.py`
  - `tests/test_cdn_detector.py`
  - `tests/test_validators.py`
- Integrationstests mit 3 Szenarien (example.com, github.com, expired-domain)
- `conftest.py` mit gemeinsamen Fixtures
- `pytest.ini` mit Coverage-Konfiguration
- **Ziel:** Min. 70% Code Coverage

### Deliverables
- ✅ tests/ Verzeichnis vollständig
- ✅ pytest.ini & conftest.py
- ✅ Alle Unit-Tests grün
- ✅ Coverage ≥ 70%
- ✅ PR mergen
- ✅ Report erstellen

### Autonome Arbeitsweise
Agent entscheidet selbst:
- Welche Test-Utilities nötig sind
- Wie Mock-Responses strukturiert sind
- Welche Edge-Cases getestet werden
- Wie conftest.py organisiert ist

---

## PHASE 2: CI/CD Pipeline (GitHub Actions)

### Anforderungen
- `.github/workflows/test.yml` erstellen mit:
  - Python 3.9+ Setup
  - `pip install -r requirements.txt`
  - `pytest tests/ -v --cov=src --cov-report=xml`
  - `pylint src/ --fail-under=8.0`
  - Trigger: Push + Pull Requests auf main
- Status-Badges ins README hinzufügen
- Coverage-Report (local oder Codecov)
- Workflow läuft erfolgreich bei jedem Push

### Deliverables
- ✅ `.github/workflows/test.yml` funktional
- ✅ Workflow erfolgreich auf main
- ✅ README mit Badges aktualisiert
- ✅ Coverage-Report sichtbar
- ✅ PR mergen
- ✅ Report erstellen

### Autonome Arbeitsweise
Agent konfiguriert Pipeline selbst:
- Matrix-Tests (mehrere Python-Versionen optional)
- Caching-Strategien
- Artifact-Upload (Coverage)
- Fehlerbehandlung

---

## PHASE 3: Packaging & Distribution

### Anforderungen
- `setup.py` und/oder `pyproject.toml` erstellen
  - Name: `domain-forensic-analyzer`
  - Version: `1.0.0`
  - Dependencies aus requirements.txt deklarieren
  - Entry-point optional: `dfa` command
- `__version__` Konsistenz-Check durchführen (siehe "VERSION MANAGEMENT" oben)
  - **Aktueller Status:** Bereits `1.0.0` gesetzt
  - Verifiziere, dass `src/__init__.py`, `setup.py`, etc. konsistent sind
- `CHANGELOG.md` erstellen mit:
  - V1.0.0 Highlights
  - Bugfixes seit v0.9
  - Known Limitations
- Installation testen: `pip install -e .`
- Package-Metadaten validieren

### Deliverables
- ✅ setup.py / pyproject.toml funktional
- ✅ Installierbarkeit verifiziert
- ✅ __version__ konsistent überall (und dokumentiert, dass es bereits 1.0.0 war)
- ✅ CHANGELOG.md vollständig
- ✅ PR mergen
- ✅ Report erstellen

### Autonome Arbeitsweise
Agent konfiguriert Packaging selbst:
- Setup-Tool-Wahl (setuptools vs. poetry vs. flit)
- Dependency-Resolution
- Metadata (description, keywords, etc.)
- Optional: README als long_description

---
## PHASE 4: Cross-Platform & OPSEC Validation (MANUAL TESTING WITH AGENT SCRIPTS)

### Ziel
Agent erstellt automatisierte Test-Skripte. User führt die 4 Szenarien manuell aus und liefert Reports zurück.

### Agent macht (Autonom):
- ✅ Erstellt 4 Test-Skripte (scenario_a.sh, scenario_b.sh, scenario_c.sh, scenario_d.sh)
- ✅ Skripte dokumentieren, was zu tun ist (VPN starten, etc.)
- ✅ Skripte generieren Reports als JSON in docs/examples/
- ✅ Erstellt VALIDATION_REPORT_TEMPLATE.md (Vorlage für Ergebnisse)
- ✅ Erstellt README_PHASE4_MANUAL.md mit Schritt-für-Schritt Anleitung

### User macht (Manuell):
- ✅ Szenario A: Linux + Direktverbindung → Führt scenario_a.sh aus
- ✅ Szenario B: Linux + VPN (NL/DE/AT) → Startet VPN, führt scenario_b.sh aus
- ✅ Szenario C: Windows + Direktverbindung → Führt scenario_c.sh aus
- ✅ Szenario D: Windows + VPN (AT/CH) → Startet VPN, führt scenario_d.sh aus
- ✅ Liefert 4 JSON-Reports dem Agent zurück

### Agent macht (Nach Reports erhalten):
- ✅ Vergleicht alle 4 Reports automatisch
- ✅ Füllt VALIDATION_REPORT.md mit Ergebnissen
- ✅ Erstellt Vergleichsmatrix
- ✅ Dokumentiert Abweichungen & deren Ursachen
- ✅ Archiviert Reports in docs/examples/

### Test-Skripte Details

**scenario_a.sh** (Linux + Direct):
```bash
#!/bin/bash
echo "=== PHASE 4: Szenario A (Linux + Direktverbindung) ==="
python -m src.run example.com --output-format json > docs/examples/scenario_a_linux_direct.json
echo "✅ Report gespeichert: docs/examples/scenario_a_linux_direct.json"
scenario_b.sh (Linux + VPN):

bash
#!/bin/bash
echo "=== PHASE 4: Szenario B (Linux + VPN) ==="
echo "⚠️ WICHTIG: VPN muss aktiv sein zu Niederlande/Deutschland/Österreich"
echo "Prüfe: curl https://ipinfo.io (sollte andere IP zeigen)"
echo "Drücke ENTER wenn VPN aktiv ist..."
read
python -m src.run example.com --output-format json > docs/examples/scenario_b_linux_vpn.json
echo "✅ Report gespeichert: docs/examples/scenario_b_linux_vpn.json"
scenario_c.bat (Windows + Direct):

batch
REM PHASE 4: Szenario C (Windows + Direktverbindung)
echo === PHASE 4: Szenario C (Windows + Direktverbindung) ===
python -m src.run example.com --output-format json > docs\examples\scenario_c_windows_direct.json
echo ✅ Report gespeichert: docs\examples\scenario_c_windows_direct.json
scenario_d.bat (Windows + VPN):

batch
REM PHASE 4: Szenario D (Windows + VPN)
echo === PHASE 4: Szenario D (Windows + VPN) ===
echo ⚠️ WICHTIG: VPN muss aktiv sein zu Österreich/Schweiz
echo Prüfe: curl https://ipinfo.io (sollte andere IP zeigen)
pause
python -m src.run example.com --output-format json > docs\examples\scenario_d_windows_vpn.json
echo ✅ Report gespeichert: docs\examples\scenario_d_windows_vpn.json
Validierungs-Checkliste pro Szenario
Nach Ausführung jedes Skripts überprüfen:

✅ Report wurde erstellt (JSON existiert)
✅ Keine Fehler in der Ausgabe
✅ OPSEC-Assessment vorhanden (VPN erkannt ja/nein?)
✅ DNS-Records lesbar
✅ SSL-Zertifikat Info da
✅ WHOIS-Daten vorhanden
✅ ASN korrekt (unterschiedlich bei VPN erwartet)
✅ Externe IP dokumentiert
Vergleichsmatrix (Agent erstellt nach allen 4 Reports)
Code
Domain   | OS      | Location | External_IP | VPN_Detected | ASN | DNS_OK | SSL_OK
─────────────────────────────────────────────────────────────────────────────────
example  | Linux   | Direct   | 1.2.3.4     | Nein         | DE  | ✅     | ✅
example  | Linux   | VPN-NL   | 5.6.7.8     | Ja (NL)      | NL  | ✅     | ✅
example  | Windows | Direct   | 1.2.3.4     | Nein         | DE  | ✅     | ✅
example  | Windows | VPN-AT   | 9.10.11.12  | Ja (AT)      | AT  | ✅     | ✅
Deliverables
Agent liefert:

✅ 4 Test-Skripte (scenario_a.sh, scenario_b.sh, scenario_c.bat, scenario_d.bat)
✅ README_PHASE4_MANUAL.md (Schritt-für-Schritt Anleitung)
✅ VALIDATION_REPORT_TEMPLATE.md (Vorlage zum Füllen)
✅ PR mit allen Skripten
User liefert:

✅ 4 JSON-Reports (nach manueller Ausführung)
Agent macht nach Reports:

✅ VALIDATION_REPORT.md mit Ergebnissen
✅ Vergleichsmatrix mit Analyse
✅ docs/examples/ mit allen 4 Reports
✅ Final PR mergen
Workflow
Agent erstellt Skripte & PR
User reviewt Skripte (sinnvoll?)
User gibt OK
User führt alle 4 Szenarien aus (manuell)
User liefert 4 JSON-Reports
Agent verarbeitet Reports → VALIDATION_REPORT.md
Agent erstellt Final PR
User reviewt & merged

---

## PHASE 5: Dokumentation vervollständigen

### Anforderungen
- `CONTRIBUTING.md` erstellen:
  - Entwicklungs-Setup (venv, pip install -r requirements.txt)
  - Branch-Naming (feature/*, fix/*, docs/*)
  - PR-Prozess & Review-Kriterien
  - Code-Style (Linting-Anforderungen)
  
- `SECURITY.md` erstellen:
  - ⚠️ Active Probes sind sichtbar für Target
  - VPN-Empfehlungen für OPSEC
  - API-Key Safety & .env handling
  - Known Security Limitations
  
- README.md ergänzen:
  - Platform Compatibility Matrix (Windows, Linux, macOS + Python Versions)
  - OPSEC-Business Rules & Threat Model
  - Example Reports / Screenshots
  - Troubleshooting Section
  - FAQ (häufige Fehlermeldungen + Lösungen)

- `docs/` Verzeichnis organisieren:
  - docs/VALIDATION_REPORT.md (von Phase 4)
  - docs/examples/ (Sample Reports)
  - docs/ARCHITECTURE.md (optional: Module Übersicht)

### Deliverables
- ✅ CONTRIBUTING.md vollständig
- ✅ SECURITY.md vollständig
- ✅ README.md erweitert
- ✅ docs/ organisiert
- ✅ Alle Links funktionieren (relative Paths)
- ✅ PR mergen
- ✅ Report erstellen

### Autonome Arbeitsweise
Agent schreibt Dokumentation selbst:
- Inhalte aus Code & Commits extrahieren
- Struktur & Styling konsistent
- Beispiele basierend auf echten Runs

---

## PHASE 6: Finalisierung & Release

### Anforderungen
- **Version-Check:** `__version__` überall auf `1.0.0` konsistent (sollte nach Phase 3 bereits OK sein)
  - `src/__init__.py`: `1.0.0`
  - `setup.py` / `pyproject.toml`: `1.0.0`
  - CHANGELOG.md: Aktualisiert mit V1.0.0 Abschnitt
  
- Git-Tag `v1.0.0` setzen mit Message:
  ```
  Release v1.0.0: Production-ready domain forensic analyzer
  
  - Full test suite (70%+ coverage)
  - CI/CD pipeline (GitHub Actions)
  - Cross-platform validation (Windows, Linux)
  - OPSEC integration verified
  - Complete documentation
  ```

- Final Check:
  - ✅ All phases completed
  - ✅ No open TODOs in code
  - ✅ CI/CD all green
  - ✅ Coverage ≥ 70%
  - ✅ No security issues (basic pylint check)

- Optional: Create GitHub Release (Release Notes aus CHANGELOG)

### Deliverables
- ✅ __version__ überall `1.0.0` (Final-Check)
- ✅ Git-Tag `v1.0.0` gesetzt
- ✅ Final PR/Commit
- ✅ GitHub Release (optional)
- ✅ Final Report erstellen

---

## GATING CRITERIA FÜR V1.0 RELEASE

Alle Kriterien müssen erfüllt sein, bevor Phase 6 abgeschlossen wird:

- [ ] **Test Coverage:** ≥ 70% Code Coverage
- [ ] **CI/CD Status:** Alle Workflow-Runs grün
- [ ] **Packaging:** `pip install -e .` funktioniert lokal
- [ ] **Cross-Platform:** Alle 4 Szenarien bestanden
- [ ] **OPSEC:** VPN/NAT Detection validiert
- [ ] **Code Quality:** pylint ≥ 8.0, keine offenen TODOs
- [ ] **Dokumentation:** README, CONTRIBUTING, SECURITY vollständig
- [ ] **Changelog:** CHANGELOG.md gefüllt & aktuell
- [ ] **Metadata:** __version__ konsistent (bereits 1.0.0)
- [ ] **Git:** Tag `v1.0.0` gesetzt

---

## TIMING (REIN INHALTLICH)

| Phase | Reihenfolge | Status |
|-------|------------|--------|
| 1 | Test-Suite | Muss vor Phase 2 abgeschlossen sein |
| 2 | CI/CD Pipeline | Muss vor Phase 3 abgeschlossen sein |
| 3 | Packaging | Muss vor Phase 4 abgeschlossen sein |
| 4 | Cross-Platform OPSEC | Muss vor Phase 5 abgeschlossen sein |
| 5 | Dokumentation | Muss vor Phase 6 abgeschlossen sein |
| 6 | Finalisierung & Release | Letzte Phase |

**Keine zeitlichen Schätzungen** — nur inhaltliche Abhängigkeiten zwischen Phasen.

---

## WORKFLOW: AGENT + USER

```
┌─────────────────────────────────────────────────────────┐
│ PHASE N: Agent arbeitet autonom                         │
│ - Branches erstellen (feature/phase-N-*)               │
│ - Commits durchführen (detaillierte Messages)          │
│ - Tests lokal laufen lassen                            │
│ - Self-validation: funktioniert alles?                 │
│ - PR erstellen mit Completion-Report                   │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Report: Was wurde fertiggestellt?                       │
│ - Checklist von Deliverables                           │
│ - Links zu Commits/PRs                                 │
│ - Test-Results & Coverage                              │
│ - Keine blockierenden Fehler?                          │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ USER VERIFIKATION: Ist Phase fertig?                    │
│ - Review Report                                        │
│ - Optional: Teste lokal                                │
│ - Go: "Phase OK, mach weiter" → Agent mergt PR         │
│ - No-Go: "Fehler hier: ...", Agent fixt                │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ PHASE N+1: Nächste Phase automatisch starten            │
│ (Agent wartet auf User-Signal "OK, go!")               │
└─────────────────────────────────────────────────────────┘
```

---

## COMMIT-MESSAGE FORMAT

Agent verwendet dieses Format für Commits:

```
feat(phase-1): Add pytest structure with DNS analyzer tests

- Setup tests/ directory with conftest.py
- Implement mock fixtures for external APIs
- Add unit tests for dns_analyzer module
- Configure pytest.ini with coverage settings
- Coverage: 72% (target: 70%+)

Closes #<issue-number>
```

Typ: `feat`, `fix`, `docs`, `chore`, `refactor`  
Scope: `phase-1`, `phase-2`, etc.  
Message: Kurz, prägnant  
Body: Details (wenn nötig)  

---

## AGENT START-SIGNAL

**Coding Agent startet mit Phase 1 nach User-Bestätigung:**

> "Agent, starte Phase 1: Test-Suite. Arbeite autonom bis zum Report, dann erwarte ich Verifikation."

Agent bestätigt mit:
> "Phase 1 gestartet. Branch: feature/phase-1-test-suite. Werde autonome Arbeit durchführen und berichte nach Completion."

---

## QUESTIONS FOR AGENT

Falls Agent unsicher ist:
- Frag immer nach, aber versuche zuerst selbst Lösungen zu finden
- Bei kritischen Decisions (z.B. Abhängigkeiten hinzufügen) kurz User konsultieren
- Fortschritt dokumentieren (z.B. "Schritt X von Y fertig")

---

**Status:** Ready for Phase 1 Start  
**Last Updated:** 2026-06-05  
**Maintained by:** Coding Agent (autonomous mode)
**Version Status:** v1.0.0 bereits in src/__init__.py gesetzt (vorherige Session)
