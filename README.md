# 🏗️ Server-Baukasten

<!-- Badges -->
[![Release](https://img.shields.io/github/v/release/TZERO78/Server-Baukasten)](https://github.com/TZERO78/Server-Baukasten/releases)
[![License](https://img.shields.io/github/license/TZERO78/Server-Baukasten)](LICENSE)
[![Debian](https://img.shields.io/badge/Debian-12%20|%2013-red?logo=debian)](https://www.debian.org)
[![Last Commit](https://img.shields.io/github/last-commit/TZERO78/Server-Baukasten)](https://github.com/TZERO78/Server-Baukasten/commits/main)

Vollautomatische Härtung und Konfiguration für Debian- und Ubuntu-Server nach modernen, praxiserprobten Sicherheitsstandards. **Erfolgreich auf Debian 12 (Bookworm) und dem kommenden Debian 13 (Trixie) getestet.**

**Modulares Server-Hardening für Linux mit NFTables, CrowdSec, GeoIP-Blocking und Docker-Integration.**

Pragmatisches Starter-Hardening für Home-Server & kleine VPS. Ein Bash-Skript das einen frischen Debian/Ubuntu-Server in ~20 Minuten mit einer konfigurierbaren Sicherheitsarchitektur ausstattet.

## Warum Bash statt Ansible/Puppet?

Bewusste Entscheidung für Einfachheit:

- **Keine Dependencies:** Läuft sofort auf jedem Standard-Server
- **Vollständig transparent:** Jede Zeile Code ist nachvollziehbar
- **Zielgruppe:** Home-User und VPS-Bastler, nicht Enterprise-Admins
- **Lerneffekt:** Du siehst genau, was konfiguriert wird
- **Portabilität:** Funktioniert überall wo Bash verfügbar ist

Ansible ist technisch "sauberer", aber für die Zielgruppe überdimensioniert. Dieses Script soll schnell und verständlich sein, nicht perfekt.

## 📐 Konzept

Der Server-Baukasten ist ein pragmatisches Starter-Tool mit drei Grundprinzipien:

### 1. Solides Sicherheitsfundament
Das Script implementiert mehrere Basisschutz-Schichten: NFTables-Firewall, CrowdSec IPS, GeoIP-Blocking und Kernel-Härtung (soweit auf VPS möglich - keine Kernel-Module oder Dateisystem-Änderungen). Es ist kein vollständiges Enterprise-System, sondern bietet eine sichere Ausgangsbasis für eigene Projekte.

### 2. Einfachheit vor Perfektion
Bewusst als simples Bash-Script entwickelt - transparent, nachvollziehbar, ohne externe Dependencies. Der Code wurde mit Hilfe von KI ausführlich kommentiert und dokumentiert. Du behältst die volle Kontrolle und verstehst jeden Schritt.

### 3. Reproduzierbares Setup
Server-Konfiguration über Config-File. Ermöglicht identische, gehärtete Server-Setups - einmal für die virtuelle Maschine zum Testen und zweitens am echten VPS für die Produktion. Das Script ist noch nicht vollständig idempotent - dies wird nach und nach verbessert.

### 4. Moderne Technologie-Entscheidungen
Bewusst auf aktuelle Standards gesetzt statt auf Legacy-Tools:
- **NFTables** statt iptables (moderne Packet-Filterung)
- **CrowdSec** statt Fail2ban (Community-basierte Threat Intelligence)
- **systemd-timer** statt cron (bessere Integration und Logging)
- **journald** statt logrotate (strukturiertes Logging mit automatischer Rotation)
- **Docker** mit iptables-nft Backend (Hybrid-Lösung für Kompatibilität)

Pragmatischer Mix bei Sicherheitstools:
- **AIDE & RKHunter** bleiben im Einsatz, da moderne Alternativen (OSSEC, Wazuh) eigene Datenbanken benötigen und für Home-Server überdimensioniert sind
- **AppArmor** als bewährtes MAC-System - einfacher als SELinux, effektiver als nichts

## ⚠️ Was es NICHT ist

Eine vollautomatische Enterprise-Lösung. Es schafft das sichere Fundament - für spezifische Services musst du selbst Hand anlegen. Du kannst das Script jederzeit auf deine Bedürfnisse anpassen.

**Hinweis:** Das Script ist nicht perfekt und hat mit Sicherheit an der einen oder anderen Stelle noch kleine Bugs, die ich natürlich versuche zu beheben! Feedback und Bug-Reports sind immer willkommen.

## 🎯 Ziel

Automatisierte Einrichtung eines sicheren, produktionsbereiten Linux-Servers mit:

- Gehärteter Firewall (NFTables)
- Intrusion Prevention System (CrowdSec)
- Container-Support (Docker)
- VPN-Integration (Tailscale)
- GeoIP-Blocking
- Automatischen Sicherheitsupdates

## ✨ Features

### Sicherheit
- **NFTables Firewall** mit dynamischer Regel-Verwaltung
- **CrowdSec IPS** mit Community-Threat-Intelligence
- **GeoIP-Blocking** für unerwünschte Länder
- **SSH-Härtung** mit Key-Only-Auth und Brute-Force-Schutz
- **AppArmor** Mandatory Access Control
- **AIDE & RKHunter** für Integritätsprüfung
- **Kernel-Härtung** via sysctl

### Automation
- **Unattended-Upgrades** für automatische Sicherheitsupdates
- **Automatische Backup-Strategie** vor kritischen Änderungen
- **Self-Healing APT** repariert defekte Paketquellen
- **Provider-Detection** erkennt VPS-Anbieter automatisch

### Container & Services
- **Docker Engine** mit sicherer Konfiguration
- **Portainer CE** für Container-Management
- **Watchtower** für automatische Container-Updates
- **Tailscale VPN** Integration

## 📜 Versionshistorie & Änderungen

Alle detaillierten Änderungen für jede Version, inklusive neuer Features und Bugfixes, werden sorgfältig im [**CHANGELOG.md**](CHANGELOG.md) dokumentiert.

## 📋 Systemanforderungen

### Unterstützte Betriebssysteme
| OS | Version | Status |
|-----|---------|---------|
| Debian | 13 (Trixie) | ✅ Vollständig getestet |
| Debian | 12 (Bookworm) | ✅ Vollständig getestet |
| Debian | 11 (Bullseye) | ⚠️ Sollte funktionieren |
| Ubuntu | 22.04/24.04 | ⚠️ Ungetestet |

### Getestete VPS-Provider
| Provider | Status | Bemerkungen |
|----------|--------|-------------|
| IONOS | ✅ Getestet | Mirror-Listen werden automatisch repariert |
| Andere | ⚠️ Ungetestet | Theoretische Unterstützung vorhanden |

### Mindestanforderungen
- 2 GB RAM
- 10 GB Festplatte
- Root-Zugriff
- Internetverbindung

## 🚀 Installation

### Schnellstart

```bash
# 1. Als root einloggen
sudo -i

# 2. Arbeitsverzeichnis erstellen
mkdir -p /opt/scripts && cd /opt/scripts

# 3. Repository klonen
git clone https://github.com/TZERO78/Server-Baukasten.git
cd Server-Baukasten

# 4. Konfiguration anpassen
cp standard.conf mein-server.conf
nano mein-server.conf

# 5. Installation starten
./serverbaukasten.sh -c mein-server.conf
```

### Alternative: Direktinstallation via curl

```bash
mkdir -p /opt/scripts && cd /opt/scripts
curl -fsSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash
cd server-baukasten
cp standard.conf mein-server.conf
nano mein-server.conf
./serverbaukasten.sh -c mein-server.conf
```

## ⚙️ Konfiguration

### Wichtige Konfigurations-Parameter

```bash
# Basis-Einstellungen
SERVER_HOSTNAME="mein-server"
ADMIN_USER="administrator"
TIMEZONE="Europe/Berlin"
LOCALE="de_DE.UTF-8"

# Sicherheit
SSH_PORT="6262"  # Non-Standard SSH Port
ACCESS_MODEL="1"  # 1=VPN-Only, 2=Public
ENABLE_GEOIP_BLOCKING="ja"
BLOCKED_COUNTRIES="CN RU KP IR"
HOME_COUNTRY="DE"

# Services
SERVER_ROLE="1"  # 1=Docker-Server, 2=Einfacher Server
INSTALL_PORTAINER="ja"
INSTALL_WATCHTOWER="ja"

# Tailscale VPN (optional)
TAILSCALE_AUTH_KEY=""  # Aus Tailscale Admin Console
```

[Vollständige Konfigurations-Dokumentation](docs/CONFIGURATION.md)

## 📊 Module

Das Skript ist modular aufgebaut. Zu jedem Modul gibt es (oder folgt) eine eigene README unter `docs/modules/`.

| Modul | Beschreibung | Doku |
|---|---|---|
| `module_base` | System-Grundkonfiguration (NTP, Locale, User, Basics) | [docs/modules/base.md](docs/modules/base.md) |
| `module_security` | Firewall (nftables), SSH-Härtung, CrowdSec | [docs/modules/security.md](docs/modules/security.md) |
| `module_network` | Netzwerk & VPN (z. B. WireGuard) | [docs/modules/network.md](docs/modules/network.md) |
| `module_container` | Docker/Moby installieren & Basis-Setup | [docs/modules/container.md](docs/modules/container.md) |
| `module_deploy_containers` | Container-Stacks deployen (Compose etc.) | [docs/modules/deploy_containers.md](docs/modules/deploy_containers.md) |
| `module_geoip` | Länderbasiertes Blocking (GeoIP-Sets) | [docs/modules/geoip.md](docs/modules/geoip.md) |
| `module_install_services` | Basis-Dienste/Tools installieren | [docs/modules/install_services.md](docs/modules/install_services.md) |
| `module_journald_optimization` | journald persistent + Limits/Rotation | [docs/modules/journald_optimization.md](docs/modules/journald_optimization.md) |
| `module_kernel_hardening` | Kernel/Sysctl-Härtung | [docs/modules/kernel_hardening.md](docs/modules/kernel_hardening.md) |
| `module_mail_setup` | Systemweite Mail via msmtp | [docs/modules/mail_setup.md](docs/modules/mail_setup.md) |
| `module_prepare_install` | Vorbereitungen (Repos, Keys, Checks) | [docs/modules/prepare_install.md](docs/modules/prepare_install.md) |
| `module_cleanup` | Aufräumen von Altlasten/Paketen | [docs/modules/cleanup.md](docs/modules/cleanup.md) |
| `module_system_update` | Templatebasierte unattended-upgrades (Debian 12/13) | [docs/modules/system_update.md](docs/modules/system_update.md) |
| `module_verify_setup` | Finale Überprüfung/System-Checks | [docs/modules/verify_setup.md](docs/modules/verify_setup.md) |

## 🛠️ Verwendung

### Basis-Befehle

```bash
# Normal-Installation
./serverbaukasten.sh -c config.conf

# Debug-Modus
./serverbaukasten.sh -d -c config.conf

# Test-Modus (schnell, ohne zeitintensive Operationen)
./serverbaukasten.sh -t -c config.conf

# Hilfe anzeigen
./serverbaukasten.sh -h
```

### Nach der Installation

```bash
# Status prüfen
sudo systemctl status

# Firewall-Regeln anzeigen
sudo nft list ruleset

# CrowdSec Status
sudo cscli metrics

# GeoIP-Manager
sudo geoip-manager status

# Docker Status (falls installiert)
sudo docker ps
```

## 🔒 Sicherheitskonzept

### Defense in Depth
Das Script implementiert mehrere Sicherheitsebenen:

1. **Perimeter-Schutz**: GeoIP-Blocking, Rate-Limiting
2. **Netzwerk-Sicherheit**: NFTables Firewall, VPN-Only Access Option
3. **Angriffserkennung**: CrowdSec IPS mit Community Threat-Intelligence  
4. **System-Härtung**: SSH-Härtung, Kernel-Parameter (soweit auf VPS möglich)
5. **Monitoring**: AIDE, RKHunter, systemd-journald

### Automatische Updates
- Sicherheitsupdates via unattended-upgrades
- Container-Updates via Watchtower (optional)
- CrowdSec Threat-Intelligence Updates

**Hinweis**: E-Mail-Benachrichtigungen sind konfigurierbar aber optional.

## 📝 Wartung

### Logs prüfen
```bash
# System-Logs
journalctl -xe

# CrowdSec Logs
journalctl -u crowdsec

# Docker Logs
docker logs <container>
```

### Backup
Das Skript erstellt vereinzelt Backups vor kritischen Änderungen:
- APT sources.list (vor Reparatur)
- Andere System-Dateien bei Bedarf

**⚠️ Sicherheitshinweis**: Config-Dateien werden NICHT gesichert, da sie Passwörter im Klartext enthalten! Bewahre deine Config-Datei sicher und verschlüsselt auf.

**Wichtig**: Mache vor der Installation ein manuelles System-Backup!

## 🐛 Fehlerbehebung

### APT-Probleme
Werden automatisch erkannt und repariert (v5.2+)

### SSH-Zugang verloren
1. VPS-Provider Konsole nutzen
2. Firewall temporär deaktivieren: `nft flush ruleset`
3. SSH-Port prüfen: `grep Port /etc/ssh/sshd_config`

### Docker-Probleme
```bash
systemctl restart docker
docker system prune -a  # Vorsicht: Löscht alle ungenutzten Daten
```

## 🤝 Beitragen

Contributions sind willkommen!

1. Fork das Repository
2. Erstelle einen Feature Branch
3. Committe deine Änderungen
4. Push zum Branch
5. Öffne einen Pull Request

### Testen auf anderen Providern

Besonders gesucht: Tests auf
- Hetzner
- DigitalOcean
- AWS/Azure
- Anderen Debian/Ubuntu Versionen

Bitte öffne ein [Issue](https://github.com/TZERO78/Server-Baukasten/issues) mit deinen Erfahrungen.

## 📄 Lizenz

Dieses Projekt steht unter der MIT-Lizenz - siehe [LICENSE](LICENSE) für Details.

## 👥 Autoren

- **Markus F. (TZERO78)** - *Initial work*
- **KI-Assistenten** - *Code-Optimierung*

## 🙏 Danksagung

### Inspiration & Wissensquellen
- **Christian** (ion.it/Apfelcast) für Linux-Security-Inspiration
- **ct3003** für praktische Server-Tipps
- **Dennis Schröder** (Raspberry Pi Cloud/ipv64.net) für Ideen und Aufklärung
- **Geek Freaks** für Docker-Best-Practices

### Open-Source-Projekte
- [CrowdSec](https://www.crowdsec.net/) für das Community-basierte IPS
- [Tailscale](https://tailscale.com/) für das einfache Mesh-VPN
- [NFTables](https://netfilter.org/projects/nftables/) für moderne Packet-Filterung
- Die Debian/Linux Community

## ⚠️ Haftungsausschluss

Dieses Skript macht tiefgreifende Systemänderungen. 
- **Immer vorher ein Backup machen**
- **Erst in einer Test-Umgebung ausprobieren**
- **Keine Garantie für Produktivsysteme**

Der Autor übernimmt keine Haftung für Schäden oder Datenverlust.

## 📞 Support

- [Issues](https://github.com/TZERO78/Server-Baukasten/issues) für Bug-Reports
- [Discussions](https://github.com/TZERO78/Server-Baukasten/discussions) für Fragen

---

<div align="center">
  
**[Dokumentation](docs/) | [Changelog](CHANGELOG.md) | [Konfiguration](docs/CONFIGURATION.md) | [Wiki](../../wiki)**

Made with ❤️ in Germany

</div>
