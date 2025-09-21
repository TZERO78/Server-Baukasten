# Changelog

Alle wesentlichen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

## [5.3.1] - 2025-09-21

### Added
- `modules/module_mail_setup.sh`: Neues msmtp-Modul (idempotent)
  - Validierung der SMTP-Variablen; optionaler Rollback (falls `rollback` vorhanden)
  - `/etc/msmtprc` (600) mit `user` + `passwordeval` über `/etc/msmtp.pass` (600)
  - Journald-Drop-in für Mail-Logs
  - TLS-sensitiver Reachability-Check (`--serverinfo` mit `--tls-starttls`/`--tls`) vor optionaler Test-Mail
  - `update-alternatives` nur setzen, wenn nötig (sendmail → msmtp)
- Docs: `docs/modules/mail_setup.md`

### Changed
- `modules/module_system_update.sh`: Umbau auf **1-Job-Flow** (deterministisch)
  - 03:30: `apt-get update` → `unattended-upgrade -d` → `apt-get autoremove --purge` → `apt-get autoclean`
  - **Auto-Reboot** nur bei Bedarf um **03:45** (`Automatic-Reboot`, `Automatic-Reboot-Time`, `Automatic-Reboot-WithUsers`)
  - **APT::Periodic vollständig deaktiviert** (`Update-Package-Lists`, `AutocleanInterval`, `Unattended-Upgrade` auf `"0"`)
  - **Keine** `apt-daily*`-Units erzeugen; falls vorhanden, werden sie lediglich deaktiviert
  - Timer deterministisch via Drop-In (`RandomizedDelaySec=0`, `Persistent=true`)
- Docs: `docs/modules/system_update.md`

### Security
- Mail-Modul: keine Klartext-Secrets in `/etc/msmtprc` (Nutzung von `passwordeval`), strikte Rechte (600)

### Behavior
- Mail-Reports nur, wenn `ENABLE_SYSTEM_MAIL=ja` **und** `NOTIFICATION_EMAIL` gesetzt
- Test-Mail wird nur versendet, wenn der SMTP-Server erreichbar ist

### Migration
- Prüfe, ob alte `apt-daily*`-Timer aktiv sind und deaktiviere sie bei Bedarf:
  - `systemctl disable --now apt-daily.timer apt-daily-upgrade.timer` (falls vorhanden)



## [5.3] - 2025-09-14

### Hinzugefügt (Added)
- **Kontrollierte Ausführung:** Eine neue `execute_step`-Engine im Hauptskript steuert und protokolliert jeden einzelnen Setup-Schritt.
- **Idempotentes Design:** Einführung von `idempotent_helpers`, damit das Skript sicher mehrfach ausgeführt werden kann.
- **Modulare Blaupause:** Eine neue `module_base.sh` dient als standardisierte Vorlage für alle Module.
- **Sichere Konfigurations-Verwaltung:** `config_helpers.sh` für robustes und sicheres Lesen von Konfigurationsdateien.
- **Selbstheilungs-Mechanismen:** `apt_repairs_helper.sh` erkennt und behebt häufige `apt`-Probleme automatisch.
- **Professionelles Error-Handling:** Ein globaler `trap`-Mechanismus mit intelligenter Fehlerbewertung und Rollback-Fähigkeit.
- **Finale Selbst-Verifikation:** Ein `module_verify` prüft am Ende des Setups die korrekte Installation und Integration aller Komponenten.

### Geändert (Changed)
- **Architektur-Refactoring:** Komplette Umstellung von einem einzelnen Skript auf ein modulares Framework (`/lib`, `/modules`).
- **Rolle des Hauptskripts:** `serverbaukasten.sh` agiert nun als zentraler "Dirigent", der nur noch den Ablauf steuert.

### Behoben (Fixed)
- Zahlreiche kleinere Bugfixes und Stabilitätsverbesserungen im gesamten Skript zur Erhöhung der Robustheit.

### Getestet (Tested)
- **Debian 13 (Trixie):** Die vollständige Funktionalität wurde auf einem VPS mit dem kommenden Debian 13 erfolgreich verifiziert. Das Skript ist damit zukunftssicher für das nächste Debian-Release.

## [5.2.1] - 2025-09-12

### Hinzugefügt
- **Modulares Config-System**: Neue `config_helper.sh` und `validation_helpers.sh` für bessere Code-Organisation
- **Secret-Management**: Optionale `*_FILE` Variablen für sichere Passwort-Handhabung aus Dateien
- **Log-Maskierung**: Automatische Zensierung von Passwörtern und Tokens in Debug-Ausgaben (`***redacted***`)
- **Erweiterte Bedingungslogik**: `!=` Operator für WHEN-Regeln in Config-Validierung
- **Debug-Modus**: Umfangreiche Debug-Ausgaben mit `DEBUG=1` für besseres Troubleshooting
- **Windows-Kompatibilität**: UTF-8 BOM Entfernung zusätzlich zu CRLF-Normalisierung
- **Automatische Kanonisierung**: Ländercodes werden automatisch in Großbuchstaben konvertiert

### Geändert
- **Breaking Change**: `SSH_PORT` Standard von 22 auf 2222 für bessere Sicherheit (>1024)
- Config-Validierung jetzt mit modularer Regel-Engine und bedingter Validierung
- `resolve_secret()` als no-op Funktion - macht nichts wenn `*_FILE` Variablen fehlen
- `cond_met()` unterstützt jetzt sowohl `=` als auch `!=` Operatoren
- Robuste Defaults werden vor der Validierung gesetzt (reduziert Konfigurationsfehler)

### Behoben
- Config-Injection-Schutz durch strengere Zeichen- und Syntax-Prüfung
- GeoIP Heimatland-Konflikt-Auflösung optimiert
- Debug-Fallback für `log_debug()` falls global nicht definiert

### Sicherheit
- **Command Injection Schutz**: Erweiterte Filterung verdächtiger Zeichen in Config-Dateien
- **Secret-Dateien**: Sichere Handhabung mit `umask 077` und Berechtigungsprüfung
- **Log-Sicherheit**: Sensitive Daten werden automatisch in Logs maskiert

### Dokumentation
- Umfangreiche Best-Practice-Beispiele für Secret-Management in Config-Datei
- Schritt-für-Schritt Anleitung für sichere Passwort-Handhabung
- Erweiterte Szenario-Beispiele mit Security-Fokus

### Technische Details
- Neue Helper-Funktionen: `is_choice_1_2()`, `is_yes_no()`, `is_secret_var()`
- Config-Normalisierung in separater Funktion mit temporären Dateien
- Validierungsregeln als Array-basiertes System für bessere Wartbarkeit

### Getestet auf
- ✅ Debian 12 mit verschiedenen Config-Kombinationen
- ✅ Windows-erstellte Config-Dateien (CRLF, UTF-8 BOM)
- ✅ Secret-Dateien und Klartext-Passwörter

## [5.2.0] - 2025-09-12

### Hinzugefügt
- **VPS-Provider-Erkennung**: Automatische Erkennung von 11+ Providern (IONOS, Hetzner, DigitalOcean, OVH, Contabo, Scaleway, Linode, AWS, Azure, GCP, Vultr, Netcup)
- **APT-Quellen-Reparatur**: Automatische Behebung defekter sources.list auf frischen VPS-Installationen
- **Provider-spezifische Fixes**: 
  - IONOS: Mirror-Listen-Entfernung
  - Hetzner: Veraltete Mirror-Bereinigung
  - OVH: Mirror-Ersetzung durch offizielle Quellen
- **Windows-Zeilenumbruch-Bereinigung**: Automatische CRLF→LF Konvertierung für Config-Dateien
- **Retry-Logik**: Intelligente Wiederholungsversuche bei APT-Operationen
- **Erweiterte Debug-Ausgaben**: Detaillierte Fehlerdiagnose für besseres Troubleshooting
- **apt_repair_helpers.sh**: Neues Helper-Modul für APT-Reparatur und Provider-Detection

### Behoben
- IONOS Debian 12 Mirror-Listen-Probleme
- Leere sources.list auf frischen VPS-Installationen
- GPG-Paket fehlt auf minimalen Installationen
- APT-Lock-Behandlung bei gleichzeitigen Prozessen
- Fehlende Basis-Pakete werden automatisch nachinstalliert

### Geändert
- `pre_flight_checks()` prüft jetzt APT-Quellen bei bekannten Problem-Providern
- Verbesserte Fehlerbehandlung und Recovery-Mechanismen
- Modulare Struktur mit separatem apt_repair_helpers
- Config-Dateien werden aus Sicherheitsgründen NICHT mehr gesichert (Klartext-Passwörter)

### Getestet auf
- ✅ IONOS VPS mit Debian 12 (bookworm)
- ⚠️ Andere Provider/OS-Kombinationen sind theoretisch unterstützt aber ungetestet

### Bekannte Einschränkungen
- Script ist noch nicht vollständig idempotent
- E-Mail-Benachrichtigungen nicht vollständig implementiert

## [5.1.0] - 2024-12-01

### Hinweis
Dies ist der Beginn der Changelog-Dokumentation. Frühere Versionen wurden nicht dokumentiert.

### Kernfunktionen (Zusammenfassung)
- **Sicherheit**:
  - NFTables Firewall mit modularer Konfiguration
  - CrowdSec IPS Integration mit Community Threat-Intelligence
  - GeoIP-Blocking für Länder-basierte Filterung
  - SSH-Härtung mit Key-Only-Authentication
  - AppArmor Mandatory Access Control
  - AIDE & RKHunter für Integritätsprüfung
  - Kernel-Härtung via sysctl (soweit auf VPS möglich)

- **Automation**:
  - Unattended-Upgrades für automatische Sicherheitsupdates
  - Systemd-Timer statt Cron für bessere Integration
  - Journald statt Logrotate für strukturiertes Logging

- **Container & Services**:
  - Docker Engine mit iptables-nft Backend
  - Portainer CE für Container-Management
  - Watchtower für automatische Container-Updates
  - Tailscale VPN Integration

- **Technologie-Stack**:
  - NFTables statt iptables
  - CrowdSec statt Fail2ban
  - systemd-timer statt cron
  - journald statt logrotate

### Unterstützte Systeme
- Debian 11 (Bullseye)
- Debian 12 (Bookworm)
- Ubuntu 20.04/22.04 (theoretisch)

## Versionshistorie vor 5.1.0

Frühere Versionen des Server-Baukastens wurden nicht in einer Changelog dokumentiert. 
Das Projekt wurde über mehrere Monate entwickelt und kontinuierlich verbessert.

---

## Legende

- `Hinzugefügt` für neue Features
- `Geändert` für Änderungen an bestehender Funktionalität
- `Veraltet` für Features, die bald entfernt werden
- `Entfernt` für entfernte Features
- `Behoben` für Bugfixes
- `Sicherheit` für Sicherheitsupdates
