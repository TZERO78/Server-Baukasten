# Server-Baukasten v5.1

Modulares Server-Hardening für Linux mit NFTables, CrowdSec, GeoIP-Blocking und Docker-Integration.

Pragmatisches Starter-Hardening für Home-Server & kleine VPS. Ein Bash-Skript das einen frischen Debian/Ubuntu-Server in ~20 Minuten mit einer konfigurierbaren Sicherheitsarchitektur ausstattet.

## Warum Bash statt Ansible/Puppet?

Bewusste Entscheidung für Einfachheit:

- **Keine Dependencies:** Läuft sofort auf jedem Standard-Server
- **Vollständig transparent:** Jede Zeile Code ist nachvollziehbar
- **Zielgruppe:** Home-User und VPS-Bastler, nicht Enterprise-Admins
- **Lerneffekt:** Du siehst genau, was konfiguriert wird
- **Portabilität:** Funktioniert überall wo Bash verfügbar ist

Ansible ist technisch "sauberer", aber für die Zielgruppe überdimensioniert. Dieses Script soll schnell und verständlich sein, nicht perfekt.

## Konzept

Der Server-Baukasten ist ein pragmatisches Starter-Tool mit drei Grundprinzipien:

**1. Solides Sicherheitsfundament**
Das Script implementiert mehrere Basisschutz-Schichten: NFTables-Firewall, CrowdSec IPS, GeoIP-Blocking und Kernel-Härtung. Es ist kein vollständiges Enterprise-System, sondern bietet eine sichere Ausgangsbasis für eigene Projekte.

**2. Einfachheit vor Perfektion**
Bewusst als simples Bash-Script entwickelt - transparent, nachvollziehbar, ohne externe Dependencies. Du behältst die volle Kontrolle und verstehst jeden Schritt.

**3. Reproduzierbares Setup**
Server-Konfiguration über Config-File. Ermöglicht identische, gehärtete Server-Setups - einmal für die virtuelle Maschine zum Testen und zweitens am echten VPS für die Produktion.

**Was es NICHT ist:** Eine vollautomatische Enterprise-Lösung. Es schafft das sichere Fundament - für spezifische Services musst du selbst Hand anlegen. Du kannst das Script jederzeit auf deine Bedürfnisse anpassen.

**Hinweis:** Das Script ist nicht perfekt und hat mit Sicherheit an der einen oder anderen Stelle noch kleine Bugs, die ich natürlich versuche zu beheben! Feedback und Bug-Reports sind immer willkommen.

**Eigenschaften:**
- Modulare Architektur mit separaten Komponenten
- Reproduzierbare Konfiguration über Config-Files  
- Kompatibel mit Docker ohne iptables-Konflikte
- Automatische GeoIP-Updates und Boot-Wiederherstellung
- Systemd-Timer statt Cron für Automatisierung

**Einschränkungen:**
- Nur Debian 12 und Ubuntu 22.04+ unterstützt
- Nicht für Produktionsumgebungen ohne weitere Anpassungen
- Erfordert grundlegende Linux-Kenntnisse
- Kann bestehende Firewall-Konfigurationen überschreiben

## Installation

```bash
# Automatische Installation aller Komponenten
curl -fsSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash
cd Server-Baukasten

# Konfiguration anpassen
cp standard.conf mein-server.conf
nano mein-server.conf

# Setup ausführen
sudo ./serverbaukasten.sh -c mein-server.conf

# Nach Setup: Obligatorischer Neustart
sudo reboot

# Nach Neustart: GeoIP-Sets laden
sudo geoip-manager update
```

## Kommando-Optionen

| Option | Beschreibung |
|--------|--------------|
| `-c FILE` | Pfad zur Konfigurationsdatei (obligatorisch) |
| `-t` | Test-Modus: Überspringt zeitintensive Schritte |
| `-v` | Verbose: Detaillierte Ausgaben |
| `-d` | Debug: Maximale Ausgaben |
| `-h` | Hilfe anzeigen |

## Projektstruktur

```
Server-Baukasten/
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
│   ├── module_security.sh        # Sicherheitsarchitektur
│   ├── module_geoip.sh           # GeoIP-Blocking (eigenständig)
│   ├── module_network.sh         # Tailscale VPN
│   ├── module_container.sh       # Docker Engine
│   ├── module_deploy_containers.sh # Management-Container
│   └── [weitere Module]
├── conf/                         # Konfigurationsvorlagen
└── components/                   # Auto-Download Tools
```

## Sicherheitsarchitektur

### Layer 1: NFTables Firewall
Modulare Konfiguration in `/etc/nftables.d/`:
- `10-base-filter.conf` - Grundregeln
- `20-crowdsec.conf` - CrowdSec-Integration  
- `30-geoip.conf` - GeoIP-Blocking
- `40-tailscale.conf` - VPN-Regeln
- `50-docker.conf` - Container-Forwarding
- `60-services.conf` - SSH, ICMP
- `90-nat.conf` - NAT für Tailscale

### Layer 2: CrowdSec IPS
- Community-basierte Angriffserkennung
- Set-basierte NFTables-Integration
- Automatische IP-Blacklists
- Health-Check und Auto-Restart

### Layer 3: GeoIP-Blocking
- Länder-basierte IP-Filterung
- Automatische Updates der IP-Listen
- Boot-Service für Set-Wiederherstellung
- Management via `geoip-manager` Tool

### Layer 4: Tailscale VPN
- Zero-Trust Netzwerk-Zugang
- Mesh-Verbindung zwischen Geräten
- Subnet-Routing Support
- Automatische Client-Updates

### Layer 5: Integritäts-Monitoring
- AIDE Datei-Integritätsprüfung
- RKHunter Rootkit-Scanner
- Systemd-Timer für Automatisierung
- E-Mail-Benachrichtigungen

## Docker-Integration

Das Script konfiguriert Docker mit iptables-nft Backend für Kompatibilität mit NFTables:

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

Automatisch installierte Container:
- Portainer (Container-Management auf localhost:9000)
- Watchtower (Automatische Updates)

## GeoIP-Management

```bash
# Status anzeigen
sudo geoip-manager status

# Länder verwalten
sudo geoip-manager country add RU
sudo geoip-manager country remove CN
sudo geoip-manager country home DE

# Listen aktualisieren
sudo geoip-manager update

# IP testen
sudo geoip-manager test 8.8.8.8
```

## Systemd-Timer

| Timer | Zeitplan | Funktion |
|-------|----------|----------|
| `aide-check.timer` | Täglich 05:00 | Datei-Integritätsprüfung |
| `rkhunter-check.timer` | Sonntags 04:00 | Rootkit-Scanner |
| `geoip-update.timer` | Sonntags 02:00 | GeoIP-Listen-Update |
| `geoip-boot-restore.service` | Bei Boot | GeoIP-Sets wiederherstellen |
| `crowdsec-healthcheck.timer` | Alle 5 Min | CrowdSec-Überwachung |

## Konfigurationsbeispiele

### VPN-only Server (Maximal-Sicherheit)
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

### Öffentlicher Server
```bash
ACCESS_MODEL="2"                          # Öffentlich
SERVER_ROLE="1"                          # Docker
ENABLE_GEOIP_BLOCKING="ja"
BLOCKED_COUNTRIES="CN RU KP IR"
SSH_PORT="2222"
```

### Minimaler Server
```bash
ACCESS_MODEL="1"                         # VPN-only
SERVER_ROLE="2"                         # Kein Docker
ENABLE_GEOIP_BLOCKING="nein"
ENABLE_SYSTEM_MAIL="nein"
```

## Systemanforderungen

**Minimum:**
- RAM: 1GB (2GB für Docker empfohlen)
- Speicher: 8GB (20GB für Docker)
- OS: Debian 12 oder Ubuntu 22.04+
- Netzwerk: Stabile Internetverbindung

**Typischer Ressourcenverbrauch:**
- NFTables: ~5MB RAM
- CrowdSec: ~50MB RAM
- GeoIP-Sets: ~10-50MB
- AIDE/RKHunter: Hoch während Scans, sonst minimal

## Nach dem Setup

### Wichtige Befehle
```bash
# System-Status
sudo systemctl --failed
sudo systemctl list-timers

# Sicherheits-Status
sudo geoip-manager status
sudo cscli metrics
sudo nft list ruleset | head -20

# Container-Status
sudo docker ps
curl -I http://127.0.0.1:9000
```

### SSH-Sicherheit
```bash
# SSH-Key einrichten
ssh-keygen -t ed25519
ssh-copy-id -p [SSH_PORT] [USER]@[SERVER_IP]

# Passwort-Login deaktivieren
sudo nano /etc/ssh/sshd_config
# PasswordAuthentication no
sudo systemctl restart ssh

# Root sperren
sudo passwd -l root
```

## Troubleshooting

### Docker startet nicht
```bash
sudo systemctl status nftables
sudo systemctl restart docker
sudo docker system info
```

### GeoIP-Sets leer
```bash
sudo geoip-manager update
sudo systemctl status geoip-boot-restore.service
sudo nft list set inet filter geoip_blocked_v4
```

### CrowdSec-Probleme
```bash
sudo systemctl status crowdsec crowdsec-bouncer-setonly
sudo cscli machines list
sudo cscli decisions list
```

### Log-Analyse
```bash
# Setup-Logs
sudo journalctl -t server-baukasten

# Sicherheitslogs
sudo journalctl -t crowdsec -t aide-check

# Service-Logs
sudo journalctl -u nftables -u docker -u tailscaled
```

## Änderungen in v5.1

### GeoIP Boot-Service
- Automatisches Wiederherstellen der GeoIP-Sets nach Neustart
- `geoip-boot-restore.service` läuft nach nftables, vor Docker
- Behebt leere Sets nach Reboots
- Keine manuellen Updates mehr erforderlich

### Portainer-Stabilität
- Localhost-Binding (127.0.0.1:9000) statt Tailscale-IP
- Behebt "cannot assign requested address" Fehler
- Stabile Container nach Neustarts
- SSH-Tunnel für externen Zugang

### Eigenständiges GeoIP-Modul
- Alle Funktionen in einem Modul ohne externe Dependencies
- Verbesserte Wartbarkeit und Debugging
- Atomare NFTables-Updates ohne Unterbrechungen

## Migration von v5.0

Ein Update ist nicht möglich. Führe ein komplettes Neu-Setup durch:

```bash
# Alte Installation sichern (falls nötig)
sudo tar -czf backup.tar.gz /etc/nftables.d/ /etc/geoip-*.conf

# v5.1 neu installieren
curl -fsSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash
cd Server-Baukasten
sudo ./serverbaukasten.sh -c neue-config.conf
```

## Support

- Repository: https://github.com/TZERO78/Server-Baukasten
- Issues: Über GitHub Issues für Bug-Reports und Feature-Requests
- Dokumentation: Siehe README und Code-Kommentare

## Lizenz

MIT-Lizenz - Copyright (c) 2025 Markus F. (TZERO78)

## Danksagungen

- **Christian (ion.it/Apfelcast)** für Linux-Security-Inspiration
- **ct3003** für praktische Server-Tipps  
- **Dennis Schröder (Raspberry Pi Cloud/ipv64.net)** für Ideen und Aufklärung
- **Geek Freaks** für Docker-Best-Practices
- Die **Open-Source-Community** für CrowdSec, Tailscale & NFTables
