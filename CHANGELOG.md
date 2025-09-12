# Changelog

Alle wesentlichen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

## [Unreleased]

### Geplant
- Vollständige Idempotenz für wiederholbare Ausführungen (insbesondere Überarbeitung von `module_cleanup`)
- Unterstützung für Ubuntu 22.04/24.04

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
