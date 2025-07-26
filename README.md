# 🏗️ Server-Baukasten

**Vollautomatische Linux-Server-Härtung**

> 🚀 **Ein Skript, um einen neuen Linux-Server in 20 Minuten in eine uneinnehmbare Festung zu verwandeln.**

## ✨ Features

### 🛡️ **Multi-Layer-Security**
- **NFTables Firewall** mit Default-Drop-Policy
- **CrowdSec IPS** mit kollektiver Threat Intelligence
- **GeoIP-Blocking** (21.590+ blockierte IPs aus Risiko-Ländern)
- **SSH-Härtung** mit Key-basierter Authentifizierung
- **AppArmor** Mandatory Access Control

### 🌍 **Intelligente Bedrohungsabwehr**
- **Automatisches Geo-Blocking** basierend auf Locale
- **Heimatland-Schutz** (wird niemals blockiert)
- **Tägliche IP-Listen-Updates** (vollautomatisch)
- **Zero-Maintenance** GeoIP-System

### 📊 **Proaktives Monitoring**
- **AIDE** File Integrity Monitoring
- **RKHunter** Rootkit Detection
- **Strukturierte Logs** via journald
- **E-Mail-Benachrichtigungen** bei Security-Events

### 🐳 **Modern Container Stack** (optional)
- **Docker** mit gehärteter Konfiguration
- **Portainer** Web-Management-Interface
- **Watchtower** automatische Container-Updates
- **Tailscale VPN** für sicheren Zugang

### ⚡ **Vollautomatische Wartung**
- **Automatische Security-Updates** via systemd-Timer
- **Tägliche System-Backups** mit Rotation
- **Health-Checks** alle 5 Minuten
- **Self-Healing** Services

## 🚀 Quick Start

### Voraussetzungen
- Debian 12 (Bookworm) - frische Installation
- Root-Zugang via SSH
- Mindestens 1GB RAM (empfohlen: 2GB+)
- Tailscale-Account (kostenlos) für VPN-Zugang

### Installation

```bash
# 1. Script herunterladen
wget https://raw.githubusercontent.com/username/server-baukasten/main/init_server.sh
chmod +x init_server.sh

# 2. Interaktiver Modus (empfohlen für erste Installation)
sudo ./init_server.sh

# 3. Oder mit Konfigurationsdatei (für Automation)
sudo ./init_server.sh -c production-server.conf
```

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

## 📚 Dokumentation

- [📋 Installation Guide](docs/installation.md)
- [⚙️ Konfiguration](docs/configuration.md)  
- [🔧 Troubleshooting](docs/troubleshooting.md)
- [🛡️ Security Features](docs/security-features.md)

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
sudo ./init_server.sh -v

# Debug-Modus für detaillierte Ausgaben
sudo ./init_server.sh -d

# Test-Modus (überspringt langsame Operationen)
sudo ./init_server.sh -t
```

## ⚠️ Wichtige Hinweise

- **SSH-Zugang testen** bevor Terminal schließen!
- **Backup wichtiger Daten** vor der Ausführung
- **Root-Passwort sperren** nach erfolgreicher Einrichtung: `sudo passwd -l root`
- **Firewall-Regeln prüfen** nach dem ersten Login

## 📄 Lizenz

Dieses Projekt steht unter der MIT-Lizenz - siehe [LICENSE](LICENSE) für Details.

## 🙏 Danksagungen

- [CrowdSec](https://crowdsec.net/) für kollektive Threat Intelligence
- [IPDeny](https://www.ipdeny.com/) für GeoIP-Datenbanken
- Der Linux-Community für unzählige Best Practices

---

⭐ **Star dieses Repository wenn es dir geholfen hat!** ⭐
