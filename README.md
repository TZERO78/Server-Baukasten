# 🏗️ Server-Baukasten

**Vollautomatische Linux-Server-Härtung**

> 🚀 **Ein Skript, um einen neuen Linux-Server in 20 Minuten in eine uneinnehmbare Festung zu verwandeln.**

## ✨ Features

### 👻 **Unsichtbarer & Sicherer Zugang (Zero Trust)**
- **Tailscale VPN-Integration:** Macht den Server im öffentlichen Netz praktisch unsichtbar.
- **Keine offenen Ports:** Standardmäßig werden keine Dienste dem Internet ausgesetzt.
- **Reduzierte Angriffsfläche:** Die meisten Angriffe werden von vornherein unmöglich gemacht.
- **SSH-Härtung:** Zusätzlicher Schutz für den (Notfall-)Zugang.

### 🛡️ **Multi-Layer-Security (Falls Dienste doch erreichbar sein müssen)**
- **NFTables Firewall** mit Default-Drop-Policy
- **CrowdSec IPS** mit kollektiver Threat Intelligence
- **GeoIP-Blocking** zur Abwehr von Angriffen aus Risiko-Ländern
- **AppArmor** Mandatory Access Control

### 🐳 **Moderner Container Stack (optional)**
- **Docker** mit gehärteter Konfiguration
- **Portainer** Web-Management-Interface
- **Watchtower** automatische Container-Updates

### 📊 **Proaktives Monitoring & Wartung**
- **AIDE** File Integrity Monitoring & **RKHunter** Rootkit Detection
- **Strukturierte Logs** via journald & automatische Security-Updates
- **Tägliche System-Backups** mit Rotation
 
## 🚀 Quick Start

### Voraussetzungen
- Debian 12 (Bookworm) - frische Installation
- Root-Zugang via SSH
- Mindestens 1GB RAM (empfohlen: 2GB+)
- Tailscale-Account (kostenlos) für VPN-Zugang

### Installation

```bash
# 1. Script herunterladen
wget https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh
chmod +x serverbaukasten.sh

# 2. Interaktiver Modus (empfohlen für erste Installation)
sudo ./serverbaukasten.sh

# 3. Oder mit Konfigurationsdatei (für Automation)
sudo ./serverbaukasten.sh -c production-server.conf
```

## 🎯 Design-Philosophie

**Einfachheit durch Ein-Datei-Ansatz:**

Dieses Skript wurde bewusst als eine einzige, in sich geschlossene Datei konzipiert. Anstatt viele einzelne Konfigurations- und Skriptdateien verwalten zu müssen, lädst du einfach nur die `serverbaukasten.sh` auf deinen neuen Server, machst sie ausführbar und startest sie. Das macht den gesamten Prozess – besonders für Einsteiger – extrem einfach und nachvollziehbar.

**Deutsche Benutzerführung:**

Alle Ausgaben, Prompts und Hilfetexte sind bewusst in deutscher Sprache gehalten. Das macht die Server-Härtung für deutschsprachige Administratoren deutlich zugänglicher und verständlicher - keine kryptischen englischen Fehlermeldungen oder unklaren Abfragen mehr.

**Vorteile des Designs:**
- 🔥 **Ein Download, sofort einsatzbereit**
- 🛡️ **Keine versteckten Dependencies** 
- 📋 **Vollständig portable** (USB-Stick, Copy-Paste)
- 🔍 **Transparent** (gesamte Logik in einer Datei)
- 🎯 **Einsteiger-freundlich** (kein Dateien-Wirrwarr)
- 🇩🇪 **Deutsche Sprache** (verständliche Prompts und Meldungen)

### Nach der Installation

```bash
# Kritische Services prüfen
sudo systemctl status ssh nftables crowdsec

# Alle automatischen Timer anzeigen
sudo systemctl list-timers

# GeoIP-Status anzeigen  
sudo geoip-manager status

# Live-Logs verfolgen
sudo journalctl -t server-baukasten -f
```

## 📋 Konfigurationsoptionen

### Basis-Konfiguration
| Option | Standard | Beschreibung |
|--------|----------|--------------|
| `SERVER_HOSTNAME` | `$(hostname)` | Hostname des Servers |
| `SSH_PORT` | `22` | SSH-Port (empfohlen: ändern!) |
| `ADMIN_USER` | `admin` | Admin-Benutzername |
| `TIMEZONE` | `Europe/Berlin` | System-Zeitzone |

### Sicherheits-Features
| Option | Standard | Beschreibung |
|--------|----------|--------------|
| `ENABLE_GEOIP_BLOCKING` | `ja` | Länder-basiertes IP-Blocking |
| `BLOCKED_COUNTRIES` | `CN RU KP IR` | ISO-Ländercodes für Blocking |
| `CROWDSEC_BANTIME` | `48h` | Sperrdauer für erkannte Angreifer |

### Container-Setup (Server-Rolle: Docker)
| Option | Standard | Beschreibung |
|--------|----------|--------------|
| `INSTALL_PORTAINER` | `ja` | Docker Web-Management |
| `INSTALL_WATCHTOWER` | `ja` | Automatische Container-Updates |
| `DOCKER_IPV4_CIDR` | `172.20.0.0/16` | Docker-Netzwerk IPv4 |

## 🛡️ Sicherheits-Architektur

```
Internet Traffic
       ↓
🌍 GeoIP-Filter (Layer 1)
       ↓  
🛡️ CrowdSec IPS (Layer 2)
       ↓
🔥 NFTables Firewall (Layer 3)
       ↓
🔒 AppArmor MAC (Layer 4)
       ↓
📊 AIDE Monitoring (Layer 5)
       ↓
🏠 Protected Services
```

## 📊 Nach dem Setup

### Service-Verifikation
```bash
sudo ./verify-services.sh
```

## 📊 System-Status prüfen

### Service-Status verwalten
```bash
# Kritische Services prüfen
sudo systemctl status ssh nftables crowdsec apparmor

# Docker-Services (falls installiert)
sudo systemctl status docker containerd

# Alle Services auf einen Blick
sudo systemctl --failed
```

### Automatische Wartung überwachen
```bash
# Alle Timer anzeigen (Updates, Backups, Security-Scans)
sudo systemctl list-timers

# Spezifische Timer prüfen
sudo systemctl list-timers aide-check.timer
sudo systemctl list-timers geoip-update.timer
sudo systemctl list-timers system-backup.timer
```

### Firewall & Security-Status
```bash
# Firewall-Regeln anzeigen
sudo nft list ruleset | head -20

# GeoIP-Blocking-Status  
sudo geoip-manager status

# CrowdSec-Statistiken
sudo cscli metrics

# Container-Status (falls Docker installiert)
sudo docker ps -a
```

## 🔧 Erweiterte Nutzung

### Backup-System
Das Script richtet automatisch tägliche Backups ein:
```bash
# Manuelles Backup
sudo /usr/local/bin/system-backup

# Backup-Status prüfen
sudo systemctl list-timers system-backup.timer
```

### Log-Monitoring
```bash
# Live-Logs aller Services
sudo journalctl -f

# Nur Security-Events
sudo journalctl -t server-baukasten -t crowdsec

# AIDE Integrity-Checks
sudo journalctl -u aide-check.service
```

## 🧪 Testing & Verifikation

### Automatische Tests
```bash
# Basis-Funktionalität testen
sudo systemctl status ssh nftables crowdsec
sudo systemctl list-timers --all

# GeoIP-System testen  
sudo geoip-manager status

# Logs auf Fehler prüfen
sudo journalctl --since "1 hour ago" --priority=err
```

### Manuelle System-Verifikation
```bash
# 1. SSH-Zugang testen (KRITISCH!)
ssh -p [SSH_PORT] [ADMIN_USER]@[SERVER_IP]

# 2. Service-Status prüfen
sudo systemctl status ssh nftables crowdsec

# 3. Firewall-Regeln anzeigen
sudo nft list ruleset | head -20

# 4. Container-Status (falls Docker)
sudo docker ps -a

# 5. Automatische Timer prüfen
sudo systemctl list-timers
```

## 🤝 Beitragen

Contributions sind willkommen! 

1. Fork das Repository
2. Feature-Branch erstellen (`git checkout -b feature/awesome-feature`)
3. Änderungen committen (`git commit -m 'Add awesome feature'`)
4. Branch pushen (`git push origin feature/awesome-feature`)
5. Pull Request erstellen

### Entwicklung
```bash
# Script mit Verbose-Modus testen
sudo ./serverbaukasten.sh -v

# Debug-Modus für detaillierte Ausgaben
sudo ./serverbaukasten.sh -d

# Test-Modus (überspringt langsame Operationen)
sudo ./serverbaukasten.sh -t
```

## ⚠️ Wichtige Hinweise

- **SSH-Zugang testen** bevor Terminal schließen!
- **Backup wichtiger Daten** vor der Ausführung
- **Root-Passwort sperren** nach erfolgreicher Einrichtung: `sudo passwd -l root`
- **Firewall-Regeln prüfen** nach dem ersten Login

## 📄 Lizenz

Dieses Projekt steht unter der MIT-Lizenz - siehe [LICENSE](LICENSE) für Details.

## 🙏 Danksagungen

Dieses Projekt baut auf den Ideen und der Arbeit vieler anderer auf. Ein großer Dank geht an:

* [**CrowdSec**](https://crowdsec.net/) für ihre herausragende Arbeit im Bereich kollektiver Threat Intelligence.
* [**IPDeny**](https://www.ipdeny.com/) für die kostenlose Bereitstellung der GeoIP-Datenbanken.
* Die gesamte **Linux-Community** für unzählige Best Practices und jahrzehntelanges geteiltes Wissen.

Besonderer Dank für die Inspiration und die vielen Denkanstöße, die zu diesem Projekt geführt haben, gilt den YouTube-Kanälen:

* [**Christian's ion.it / Apfelcast**](https://www.youtube.com/@ionit-itservice)
* [**ct3003**](https://www.youtube.com/@ct3003)
* [**Raspberry Pi Cloud**](https://www.youtube.com/@RaspberryPiCloud)
* [**Geek Freaks**](https://www.youtube.com/@TheGeekFreaks)

⭐ **Star dieses Repository wenn es dir geholfen hat!** ⭐
