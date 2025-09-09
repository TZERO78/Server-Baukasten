# Server-Baukasten v5.1

Modulares Server-Hardening für Linux-Systeme

Ein Bash-Script das einen frischen Debian/Ubuntu-Server mit grundlegenden Sicherheitsmaßnahmen konfiguriert. Zielgruppe sind Home-Server und kleine VPS-Installationen.

## Konzept

Das Script implementiert mehrere Sicherheitsschichten: NFTables-Firewall, CrowdSec IPS, GeoIP-Blocking und Kernel-Härtung. Es ist als Ausgangsbasis gedacht, nicht als vollständige Enterprise-Lösung.

**Warum Bash statt Ansible/Puppet?**
- Keine Dependencies
- Nachvollziehbarer Code
- Funktioniert auf jedem Standard-Server
- Einfache Anpassung möglich

**Grenzen:**
- Nicht für Enterprise-Umgebungen
- Kann Bugs enthalten
- Erfordert manuelle Nachkonfiguration für spezifische Services

## Änderungen in v5.1

### GeoIP Boot-Service
- GeoIP-Sets werden automatisch nach Neustart wiederhergestellt
- Boot-Service `geoip-boot-restore.service` lädt IP-Listen beim Start
- Behebt das Problem mit leeren Sets nach Reboots

### Portainer-Stabilität
- Portainer bindet nur noch auf localhost (127.0.0.1)
- Behebt Netzwerk-Konflikte mit Tailscale-IPs
- Container starten stabil nach Neustarts

### Modulare Struktur
- GeoIP-Modul vollständig eigenständig
- Keine externen Dependencies zwischen Modulen
- Vereinfachte Wartung

## Migration von v4.x zu v5.x

v5.x ist nicht kompatibel zu v4.x. Komplettes Neu-Setup erforderlich.

## Projektstruktur

```
Server-Baukasten v5.1/
├── install.sh                    # Automatische Installation
├── serverbaukasten.sh            # Hauptskript
├── standard.conf                 # Konfigurationsvorlage
├── lib/                          # Kern-Bibliotheken
│   ├── core_helpers.sh           # Logging, sudo-Verwaltung
│   ├── ui_helpers.sh             # Benutzeroberfläche
│   ├── validation_helpers.sh     # Input-Validierung
│   ├── firewall_helpers.sh       # NFTables-Generierung
│   ├── crowdsec_helpers.sh       # CrowdSec-Integration
│   └── geoip_helpers.sh          # GeoIP-Management
├── modules/                      # Setup-Module
│   ├── module_cleanup.sh         # System-Bereinigung
│   ├── module_base.sh            # Basis-System
│   ├── module_security.sh        # Sicherheits-Architektur
│   ├── module_network.sh         # Tailscale VPN
│   ├── module_container.sh       # Docker-Engine
│   ├── module_deploy_containers.sh # Management-Container
│   ├── module_geoip.sh           # GeoIP-Blocking
│   ├── module_kernel_hardening.sh  # Kernel-Parameter
│   ├── module_system_update.sh     # Updates & Timer
│   ├── module_mail_setup.sh        # E-Mail-Benachrichtigungen
│   ├── module_journald_optimization.sh # Log-Optimierung
│   └── module_verify_setup.sh      # System-Verifikation
├── conf/                         # Konfigurationsvorlagen
│   ├── aide.conf.template        # AIDE Datei-Integritätsprüfung
│   └── rkhunter.conf.template     # RKHunter Rootkit-Scanner
└── components/                   # Automatisch heruntergeladene Tools
    ├── geoip-manager             # GeoIP-Verwaltungstool
    └── update-geoip-sets         # IP-Listen-Updates
```

## Installation

```bash
# Standard-Installation
curl -fsSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash
cd Server-Baukasten

# Konfiguration anpassen
cp standard.conf mein-server.conf
nano mein-server.conf

# Setup starten
sudo ./serverbaukasten.sh -c mein-server.conf
```

## Kommando-Optionen

| Option | Beschreibung |
|--------|--------------|
| `-c FILE` | Pfad zur Konfigurationsdatei (Pflicht) |
| `-t` | Test-Modus: Überspringt zeitintensive Schritte |
| `-v` | Verbose: Detaillierte Ausgaben |
| `-d` | Debug: Maximale Ausgaben |
| `-h` | Hilfe anzeigen |

## Sicherheitsarchitektur

### Layer 1: Modulare NFTables-Firewall
```
/etc/nftables.conf              # Loader
/etc/nftables.d/
├── 10-base-filter.conf         # Grundregeln
├── 20-crowdsec.conf            # CrowdSec-Sets & Chains
├── 30-geoip.conf              # GeoIP-Blocking
├── 40-tailscale.conf          # VPN-Regeln
├── 50-docker.conf             # Container-Forwarding
├── 60-services.conf           # SSH, ICMP, Services
└── 90-nat.conf               # NAT für Tailscale
```

### Layer 2: CrowdSec IPS
- Community-Intelligence: Globale Angriffsdaten
- Set-Integration: Nutzt NFTables-Sets
- Health-Checks: Automatische Neustart-Logik

### Layer 3: GeoIP-Blocking
- Management-Tool: `geoip-manager`
- Set-basierte Implementation
- Automatisches Wiederherstellen nach Boot

### Layer 4: Tailscale VPN
- VPN-only oder öffentlicher Modus
- Mesh-Netzwerk zwischen Geräten
- Subnet-Routing Support

### Layer 5: Integritäts-Monitoring
- AIDE: Datei-Integritätsprüfung (täglich)
- RKHunter: Rootkit-Scanner (wöchentlich)
- systemd-Timer statt Cron

## Docker-Integration

**Verbesserungen in v5.x:**
- iptables-nft Backend für Kompatibilität
- Systemd-Abhängigkeiten: Docker startet nach NFTables
- Modulare Container-Regeln
- Automatische Container: Portainer, Watchtower

**Container-Netzwerk-Konfiguration:**
```json
{
  "bip": "172.20.0.1/16",
  "fixed-cidr": "172.20.0.0/16", 
  "ipv6": true,
  "fixed-cidr-v6": "fd00:cafe:beef::/56",
  "log-driver": "journald",
  "live-restore": true,
  "userland-proxy": false
}
```

## GeoIP-Blocking

**Management-Tool:**
```bash
sudo geoip-manager status        # Status anzeigen
sudo geoip-manager update        # Listen aktualisieren
sudo geoip-manager country add RU    # Land hinzufügen
sudo geoip-manager country home DE   # Heimatland setzen
```

**Vorkonfigurierte Presets:**
- Standard: CN RU KP IR (ca. 70% Angriffsreduktion)
- Maximal: CN RU KP IR BY MM SY AF IQ LY (ca. 85% Angriffsreduktion)
- Minimal: CN RU (ca. 60% Angriffsreduktion)

## E-Mail-Integration

**msmtp-basierte Lösung:**
- STARTTLS, SMTP-Auth Support
- Gmail, Outlook, eigene Server
- Automatische Benachrichtigungen bei:
  - AIDE-Datei-Änderungen
  - RKHunter-Warnungen
  - CrowdSec-Bedrohungen
  - System-Update-Fehlern

## Automatisierung

**systemd-Timer:**
| Timer | Zeitplan | Beschreibung |
|-------|----------|--------------|
| `aide-check.timer` | Täglich 05:00 | Datei-Integritätsprüfung |
| `rkhunter-check.timer` | Sonntags 04:00 | Rootkit-Scanner |
| `geoip-update.timer` | Sonntags 02:00 | GeoIP-Listen-Update |
| `geoip-boot-restore.timer` | Bei Boot | GeoIP-Sets wiederherstellen |
| `crowdsec-healthcheck.timer` | Alle 5 Min | CrowdSec API-Überwachung |

## System-Management

**Wichtige Befehle:**
```bash
sudo geoip-manager status              # GeoIP-Status
sudo nft list ruleset | head -20       # Firewall-Status
sudo cscli metrics                     # CrowdSec-Statistiken
sudo docker ps -a                     # Container-Status
sudo systemctl list-timers            # Timer-Übersicht
sudo systemctl --failed               # Failed Services
```

## Setup-Prozess

Nach erfolgreichem Setup:

1. **SSH-Zugang testen:**
   ```bash
   ssh -p [SSH_PORT] [ADMIN_USER]@[SERVER_IP]
   ```

2. **SSH-Key einrichten (empfohlen):**
   ```bash
   ssh-keygen -t ed25519
   ssh-copy-id -p [SSH_PORT] [ADMIN_USER]@[SERVER_IP]
   ```

3. **Root-Konto sperren:**
   ```bash
   sudo passwd -l root
   ```

4. **System neustarten:**
   ```bash
   sudo reboot
   ```

5. **Nach Neustart verifizieren:**
   ```bash
   sudo geoip-manager status
   sudo systemctl --failed
   sudo docker ps
   ```

## Konfigurationsbeispiele

**VPS mit maximaler Sicherheit:**
```bash
ACCESS_MODEL="1"                           # VPN-only
SERVER_ROLE="1"                           # Docker-Host
ENABLE_GEOIP_BLOCKING="ja"
HOME_COUNTRY="DE"
BLOCKED_COUNTRIES="CN RU KP IR BY MM SY AF IQ LY"
ENABLE_SYSTEM_MAIL="ja"
INSTALL_PORTAINER="ja"
INSTALL_WATCHTOWER="ja"
```

**Öffentlicher Webserver:**
```bash
ACCESS_MODEL="2"                          # Öffentlich erreichbar
SERVER_ROLE="1"                          # Docker für Services
ENABLE_GEOIP_BLOCKING="ja"
BLOCKED_COUNTRIES="CN RU KP IR"
SSH_PORT="2222"                          # Non-Standard Port
```

## Systemanforderungen

**Mindestanforderungen:**
- RAM: 1GB (2GB für Docker empfohlen)
- Speicher: 8GB für Basis, 20GB für Docker
- OS: Debian 12 oder Ubuntu 22.04+

**Resource-Verbrauch:**
- NFTables: ~5MB RAM, minimal CPU
- CrowdSec: ~50MB RAM, niedrige CPU-Last
- GeoIP-Sets: ~10-50MB je nach Anzahl Länder

## Troubleshooting

**Docker startet nicht:**
```bash
sudo systemctl status nftables
sudo systemctl restart docker
```

**GeoIP-Sets leer:**
```bash
sudo geoip-manager update
sudo nft list set inet filter geoip_blocked_v4
```

**CrowdSec-Probleme:**
```bash
sudo systemctl restart crowdsec
sudo cscli metrics
```

**Setup-Logs:**
```bash
sudo journalctl -t server-baukasten -f
```

## Repository

- GitHub: [TZERO78/Server-Baukasten](https://github.com/TZERO78/Server-Baukasten)
- Issues: [GitHub Issues](https://github.com/TZERO78/Server-Baukasten/issues)
- Lizenz: MIT

## Lizenz

MIT-Lizenz - Copyright (c) 2025 Markus F. (TZERO78)
