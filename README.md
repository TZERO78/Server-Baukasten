# 🏗️ Server-Baukasten

**Vollautomatische Linux-Server-Härtung mit modularer Multi-Layer-Security-Architektur**

> 🚀 **Ein Skript, um einen neuen Linux-Server in 20 Minuten in eine uneinnehmbare Festung zu verwandeln.**
>
> Das Hauptziel ist ein **von außen unsichtbarer Server**, der ausschließlich über ein sicheres VPN (Tailscale) erreichbar ist. Dadurch wird die Angriffsfläche gegen Null reduziert, noch bevor die Firewall überhaupt greift.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Debian](https://img.shields.io/badge/OS-Debian%2012-red.svg)](https://www.debian.org/)
[![Ubuntu](https://img.shields.io/badge/OS-Ubuntu%2022.04+-orange.svg)](https://ubuntu.com/)

## ✨ Features

### 🧩 **Modulare Architektur (NEU in v2.0)**
- **Eigenständige Komponenten:** GeoIP-Tools funktionieren unabhängig vom Hauptscript
- **Automatischer Download:** Komponenten werden bei Bedarf von GitHub geladen
- **Einfache Updates:** Einzelne Komponenten können separat aktualisiert werden
- **Wiederverwendbar:** Tools können in anderen Projekten genutzt werden

### 👻 **Unsichtbarer & Sicherer Zugang (Zero Trust)**
- **Tailscale VPN-Integration:** Macht den Server im öffentlichen Netz praktisch unsichtbar
- **Keine offenen Ports:** Standardmäßig werden keine Dienste dem Internet ausgesetzt
- **Reduzierte Angriffsfläche:** Die meisten Angriffe werden von vornherein unmöglich gemacht
- **SSH-Härtung:** Zusätzlicher Schutz für den (Notfall-)Zugang

### 🛡️ **Multi-Layer-Security (Falls Dienste doch erreichbar sein müssen)**
- **NFTables Firewall** mit Default-Drop-Policy und intelligenten Regeln
- **CrowdSec IPS** mit kollektiver Threat Intelligence und automatischer Angreifer-Abwehr
- **GeoIP-Blocking** zur intelligenten Abwehr von Angriffen aus Risiko-Ländern
- **AppArmor** Mandatory Access Control für Anwendungssicherheit
- **Kernel-Härtung** gegen DDoS-Angriffe und Performance-Optimierung

### 🌍 **Intelligentes GeoIP-Blocking (NEU)**
- **Heimatland-Schutz:** Automatische Erkennung aus der System-Locale
- **Konfliktvermeidung:** Verhindert versehentliche Aussperrung
- **Preset-Konfigurationen:** Standard, Maximal und Minimal-Schutz
- **Automatische Updates:** Wöchentliche Aktualisierung der IP-Listen
- **Statistiken & Management:** Umfassendes Verwaltungstool `geoip-manager`

### 🐳 **Moderner Container Stack (optional)**
- **Docker** mit gehärteter Konfiguration und benutzerdefinierten Netzwerken
- **Portainer** Web-Management-Interface für Container-Verwaltung
- **Watchtower** automatische Container-Updates mit konfigurierbaren Zeitplänen

### 📊 **Proaktives Monitoring & Wartung**
- **AIDE** File Integrity Monitoring mit journald-Integration
- **RKHunter** Rootkit Detection mit wöchentlichen Scans
- **Strukturierte Logs** via `journald` mit optimierten Aufbewahrungsrichtlinien
- **Automatische System-Updates** via systemd-Timer
- **Tägliche System-Backups** mit automatischer Rotation

### 📧 **Zentrale Benachrichtigungen**
- **msmtp-Integration** für systemweite E-Mail-Benachrichtigungen
- **SMTP-Flexibilität:** Unterstützt alle gängigen E-Mail-Provider
- **Intelligente Alerts:** Nur bei kritischen Ereignissen
- **Strukturierte Reports:** Tägliche Zusammenfassungen der Systemaktivität

## 🎯 Unterstützte Betriebssysteme

- **Debian 12 (Bookworm)** - Vollständig getestet ✅
- **Ubuntu 22.04 LTS+** - Nicht getestet
- **Ubuntu 24.04 LTS** - Nicht getestet

## 🚀 Quick Start

Es gibt zwei Wege, das Skript zu nutzen: den empfohlenen automatischen Weg über eine Konfigurationsdatei oder den interaktiven Modus.

### Empfohlener Weg (Automatisch via Konfigurationsdatei)

Dieser Weg ist ideal für wiederholbare Setups und die beste Methode für Produktionsumgebungen.

```bash
# 1. Skript und Standard-Konfiguration herunterladen
wget https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh
wget https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/standard.conf
chmod +x serverbaukasten.sh

# 2. Konfiguration anpassen
# Kopiere die Vorlage und trage DEINE Werte ein (Passwörter, E-Mail etc.)
cp standard.conf mein-server.conf
nano mein-server.conf

# 3. Skript ausführen (lädt automatisch benötigte Komponenten)
sudo ./serverbaukasten.sh -c mein-server.conf
```

**💡 Hinweis:** Das Skript lädt automatisch alle benötigten Komponenten von GitHub. Eine Internetverbindung ist während der Installation erforderlich.

### Alternativer Weg (Interaktiv)

Gut für die erste Einrichtung, wenn du dich durch die Optionen führen lassen möchtest.

```bash
# 1. Nur das Skript herunterladen
wget https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh
chmod +x serverbaukasten.sh

# 2. Skript starten und den Fragen folgen
sudo ./serverbaukasten.sh
```

### Erweiterte Optionen

```bash
# Test-Modus (überspringt zeitaufwändige Operationen)
sudo ./serverbaukasten.sh -t

# Verbose-Modus (detaillierte Ausgaben)
sudo ./serverbaukasten.sh -v

# Debug-Modus (maximale Ausgaben für Entwicklung)
sudo ./serverbaukasten.sh -d

# Hilfe anzeigen
sudo ./serverbaukasten.sh -h
```

## 🧩 Modulare Komponenten

Das System verwendet eine moderne modulare Architektur. Komponenten können auch einzeln installiert und verwendet werden:

### Einzelne Komponenten installieren
```bash
# Nur GeoIP-Manager installieren
curl -sSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/components/install-components.sh | sudo bash -s -- geoip-manager

# Nur GeoIP-Updater installieren  
curl -sSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/components/install-components.sh | sudo bash -s -- geoip-updater

# Alle verfügbaren Komponenten anzeigen
curl -sSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/components/install-components.sh | sudo bash -s -- --list
```

### Verfügbare Komponenten
- **geoip-manager:** Interaktives Management-Tool für GeoIP-Blocking
- **geoip-updater:** Automatischer Updater für IP-Listen (update-geoip-sets.sh)

*Weitere Komponenten (System-Backup, CrowdSec-Installer, Docker-Setup) sind in Entwicklung.*

## 🔐 Final Lockdown: Wichtigste Schritte nach der Installation

Das Skript hat die Festung gebaut, aber du schließt die Tore ab. Führe diese Schritte in der angegebenen Reihenfolge aus, um die maximale Sicherheit zu gewährleisten.

### 1. SSH-Zugang testen (KRITISCH!)
Öffne ein **neues** Terminal (schließe das alte noch nicht!) und stelle sicher, dass du dich mit dem neuen Port und deinem Admin-Benutzer anmelden kannst.
```bash
ssh -p [DEIN_SSH_PORT] [DEIN_ADMIN_USER]@[SERVER_IP]
```

### 2. SSH-Sicherheit maximieren (Public-Key-Verfahren)
Falls du während des Setups keinen SSH-Schlüssel hinterlegt hast, solltest du es jetzt tun.
```bash
# SSH-Key zur authorized_keys hinzufügen
echo "dein-public-key" >> ~/.ssh/authorized_keys

# SSH-Konfiguration bearbeiten
sudo nano /etc/ssh/sshd_config
# Setze: PasswordAuthentication no

# SSH-Dienst neu starten
sudo systemctl restart ssh
```

### 3. Root-Konto sperren
Nachdem du den `sudo`-Zugang für deinen Admin-Benutzer getestet hast, sperre den direkten Login für den `root`-Benutzer.
```bash
sudo passwd -l root
```

### 4. System neustarten
Ein abschließender Neustart stellt sicher, dass alle Dienste korrekt starten und die Konfigurationen geladen werden.
```bash
sudo reboot
```

### 5. GeoIP-Blocking aktivieren (nach dem Neustart)
Nach dem Neustart sind die GeoIP-Listen in der Firewall leer. Führe diesen Befehl aus, um sie sofort zu befüllen und den Länderschutz zu aktivieren.
```bash
geoip-manager update
```

## 🌍 GeoIP-Blocking Konfiguration

### Grundkonzept
Das GeoIP-System blockiert Verbindungen aus bestimmten Ländern basierend auf IP-Bereichen. Statistisch stammen über 80% aller Brute-Force-Angriffe aus wenigen Ländern.

### Heimatland-Schutz
- **Automatische Erkennung:** Wird aus der System-Locale abgeleitet (DE, US, FR, etc.)
- **Permanenter Schutz:** Heimatland wird NIEMALS blockiert
- **Konfliktauflösung:** System entfernt Heimatland automatisch aus Blocklisten

### Preset-Konfigurationen

| Preset | Länder | Angriffs-Reduktion | Beschreibung |
|--------|--------|---------------------|--------------|
| **Basis** | CN RU | ~60% | Minimaler Impact, blockiert Hauptbedrohungen |
| **Standard** | CN RU KP IR | ~70% | Ausgewogenes Verhältnis aus Sicherheit und Zugänglichkeit |
| **Maximal** | CN RU KP IR BY MM SY AF IQ LY | ~85% | Höchste Sicherheit, blockiert alle bekannten Risiko-Länder |

### Häufige Länder-Codes
```
Europäische Länder:
DE=Deutschland, AT=Österreich, CH=Schweiz, FR=Frankreich, IT=Italien
ES=Spanien, NL=Niederlande, BE=Belgien, SE=Schweden, NO=Norwegen

Weitere wichtige Länder:
US=USA, CA=Kanada, AU=Australien, JP=Japan, SG=Singapur

Häufige Bedrohungsquellen:
CN=China, RU=Russland, KP=Nordkorea, IR=Iran, BY=Belarus
```

## 🔧 System-Management nach dem Setup

### Services & Timer überprüfen
```bash
# Status der kritischen Dienste prüfen
sudo systemctl status ssh nftables crowdsec docker

# Alle automatischen Timer anzeigen (Updates, Backups, Scans)
sudo systemctl list-timers
```

### Firewall & Security
```bash
# Firewall-Regeln anzeigen
sudo nft list ruleset

# CrowdSec-Statistiken
sudo cscli metrics

# CrowdSec gebannte IPs anzeigen
sudo cscli decisions list
```

### GeoIP-Blocking verwalten
Das System installiert automatisch ein umfassendes Management-Tool:

| Befehl | Beschreibung |
|--------|-------------|
| `geoip-manager status` | Status, Konfiguration und Statistiken anzeigen |
| `geoip-manager update` | Manuelles Update der IP-Listen |
| `geoip-manager hits` | Blockierte/erlaubte Pakete anzeigen |
| `geoip-manager test <IP>` | IP-Adresse gegen GeoIP-Regeln testen |
| `geoip-manager allow <IP>` | IP zur Whitelist hinzufügen |
| `geoip-manager country list` | Aktuelle Länder-Konfiguration |
| `geoip-manager country add <CODE>` | Land zur Blockliste hinzufügen |
| `geoip-manager country remove <CODE>` | Land von Blockliste entfernen |
| `geoip-manager country home <CODE>` | Heimatland setzen |
| `geoip-manager logs [Anzahl]` | Update-Logs anzeigen |
| `geoip-manager help` | Vollständige Hilfe |

### Log-Management
```bash
# Live-Logs des Baukasten-Skripts verfolgen
sudo journalctl -t server-baukasten -f

# Alle Security-Logs der letzten Stunde auf Fehler prüfen
sudo journalctl --since "1 hour ago" --priority=err

# Spezifische Service-Logs
sudo journalctl -u ssh           # SSH-Logs
sudo journalctl -u crowdsec      # CrowdSec-Logs  
sudo journalctl -u geoip-update  # GeoIP-Update-Logs
sudo journalctl -u aide-check    # Integritäts-Logs
```

### Container-Management (falls Docker installiert)
```bash
# Alle Container anzeigen
docker ps -a

# Portainer-Status prüfen
docker logs portainer

# Watchtower-Logs anzeigen
docker logs watchtower
```

## 📋 Konfigurationsdatei-Referenz

### Basis-Konfiguration
```bash
# Server-Identität
SERVER_HOSTNAME="my-secure-server"
ADMIN_USER="admin"
ADMIN_PASSWORD="STRONG-PASSWORD-HERE"
ROOT_PASSWORD="STRONG-ROOT-PASSWORD"

# Netzwerk & Zugang
ACCESS_MODEL="1"          # 1=VPN (Tailscale), 2=Öffentlich
SSH_PORT="22"

# Lokalisierung
TIMEZONE="Europe/Berlin"
LOCALE="de_DE.UTF-8"     # Bestimmt auch das Heimatland für GeoIP

# Server-Typ
SERVER_ROLE="1"          # 1=Docker-Host, 2=Einfacher Server
```

### GeoIP-Konfiguration
```bash
# GeoIP-Blocking
ENABLE_GEOIP_BLOCKING="ja"
HOME_COUNTRY="DE"                    # Wird automatisch geschützt
BLOCKED_COUNTRIES="CN RU KP IR"      # Zu blockierende Länder
```

### Docker-Konfiguration
```bash
# Docker-Netzwerke (nur bei SERVER_ROLE="1")
DOCKER_IPV4_CIDR="172.20.0.0/16"
DOCKER_IPV6_CIDR="fd00:cafe:beef::/56"

# Management-Container
INSTALL_PORTAINER="ja"
INSTALL_WATCHTOWER="ja"
```

### E-Mail-Konfiguration
```bash
# E-Mail-Benachrichtigungen
ENABLE_SYSTEM_MAIL="ja"
NOTIFICATION_EMAIL="admin@example.com"

# SMTP-Server
SMTP_HOST="smtp.example.com"
SMTP_PORT="587"
SMTP_FROM="server@example.com"
SMTP_AUTH="ja"
SMTP_TLS_STARTTLS="ja"

# SMTP-Credentials
SMTP_USER="your-username"
SMTP_PASSWORD="your-password"
```

Eine vollständige Beispiel-Konfiguration findest du in der Datei [`standard.conf`](standard.conf).

## 🆕 Was ist neu in v2.0?

### Modulare Architektur
- **Komponenten-System:** GeoIP-Tools sind jetzt eigenständige, wiederverwendbare Komponenten
- **Automatischer Download:** Benötigte Komponenten werden automatisch von GitHub geladen
- **Einzelinstallation:** Tools können auch unabhängig vom Hauptscript installiert werden
- **Wartbarkeit:** Komponenten können einzeln aktualisiert werden ohne Neuinstallation

### Verbesserte Sicherheit
- **Sichere Berechtigungen:** Komponenten sind nur für root/sudo-Benutzer ausführbar
- **Robuste Downloads:** Fehlerbehandlung und Validierung für alle Komponenten-Downloads
- **Konsistente Namensgebung:** Klare Trennung zwischen Repository- und lokalen Dateinamen

### Erweiterte GeoIP-Features
- **Intelligenteres Blocking:** Verbesserte Länder-Erkennung und Heimatland-Schutz
- **Bessere Performance:** Chunking für große IP-Listen verhindert System-Überlastung
- **Detaillierte Statistiken:** Erweiterte Monitoring- und Analyse-Features

### Optimierte Logging-Systeme
- **journald-Integration:** Alle Services nutzen strukturierte Logs
- **Intelligente Aufbewahrung:** Verschiedene Aufbewahrungszeiten für verschiedene Log-Typen
- **Performance-Optimierung:** Angepasste Limits und Komprimierung

### Erweiterte Automatisierung
- **systemd-Timer:** Ersetzt Cron-Jobs durch moderne systemd-Timer
- **Health-Checks:** Automatische Überwachung und Neustart bei Problemen
- **Backup-Rotation:** Intelligente Aufbewahrung und Bereinigung

## 🎯 Design-Philosophie

### Modulare Einfachheit
Das Skript kombiniert die Einfachheit eines Ein-Datei-Ansatzes mit der Flexibilität modularer Komponenten. Das Hauptskript orchestriert das Setup, während spezialisierte Komponenten bei Bedarf von GitHub geladen werden. Dies macht das System sowohl einfach zu verwenden als auch leicht erweiterbar.

### Multi-Layer-Security
Anstatt sich auf eine einzige Sicherheitsmaßnahme zu verlassen, implementiert der Server-Baukasten mehrere Schutzschichten:

1. **Netzwerk-Ebene:** Tailscale VPN macht den Server unsichtbar
2. **Firewall-Ebene:** NFTables mit Default-Drop-Policy
3. **Geographische Ebene:** GeoIP-Blocking von Risiko-Ländern
4. **Anwendungs-Ebene:** CrowdSec IPS mit kollektiver Intelligenz
5. **System-Ebene:** Kernel-Härtung und AppArmor
6. **Überwachungs-Ebene:** AIDE und RKHunter für Integritätskontrolle

### Zero Trust-Prinzip
Der Server wird standardmäßig so konfiguriert, dass er von außen nicht erreichbar ist. Jede Verbindung muss explizit erlaubt werden, und der bevorzugte Zugangsweg ist über ein sicheres VPN.

### Fehlertoleranz & Rollback
Bei einem unerwarteten Fehler während der Installation bricht das Skript nicht einfach ab, sondern führt automatisch ein Rollback durch, um die ursprünglichen Konfigurationsdateien wiederherzustellen.

## 🚨 Notfall-Befehle

### Bei Aussperrung durch GeoIP-Blocking
```bash
# Über Rescue-Modus oder lokale Konsole:
sudo geoip-manager allow DEINE_IP_ADRESSE

# GeoIP komplett deaktivieren:
sudo nft delete rule inet filter input jump geoip_check

# Alle GeoIP-Blockierungen aufheben:
sudo nft flush set inet filter geoip_blocked_v4
sudo nft flush set inet filter geoip_blocked_v6
```

### Bei CrowdSec-Problemen
```bash
# CrowdSec-Ban für eigene IP aufheben:
sudo cscli decisions delete --ip DEINE_IP

# CrowdSec komplett deaktivieren:
sudo systemctl stop crowdsec crowdsec-firewall-bouncer
```

### Bei Firewall-Problemen
```bash
# Firewall komplett deaktivieren (nur im Notfall!):
sudo systemctl stop nftables

# Alle Firewall-Regeln löschen:
sudo nft flush ruleset
```

## 📊 Performance & Ressourcenverbrauch

### Typische Ressourcennutzung
- **RAM:** +50-100 MB (abhängig von aktivierten Features)
- **Festplatte:** +200-500 MB (inklusive Container-Images)
- **CPU:** Vernachlässigbar im Normalbetrieb
- **Netzwerk:** Minimaler Overhead durch VPN

### GeoIP-Listen Performance
- **Standard-Preset:** ~500.000 IP-Ranges (optimal für VPS)
- **Maximal-Preset:** ~2.000.000 IP-Ranges (kann auf schwachen Systemen langsam sein)
- **Update-Frequenz:** Wöchentlich (konfiguierbar)

### Automatisierte Wartung
- **Tägliche Backups:** 03:00 Uhr (mit Rotation)
- **Wöchentliche Updates:** Sonntag 02:00 Uhr
- **Security-Scans:** Sonntag 04:00 Uhr (RKHunter), Täglich 05:00 Uhr (AIDE)

## 🔧 Troubleshooting

### Häufige Probleme

#### 1. SSH-Verbindung nicht möglich
```bash
# Prüfe SSH-Service-Status
sudo systemctl status ssh

# Prüfe SSH-Port
sudo ss -tlnp | grep :22

# Prüfe Firewall-Regeln
sudo nft list ruleset | grep ssh
```

#### 2. GeoIP-Blocking funktioniert nicht
```bash
# Status prüfen
geoip-manager status

# Manuelles Update
geoip-manager update

# Test einer IP
geoip-manager test 8.8.8.8
```

#### 3. CrowdSec blockiert legitime IPs
```bash
# Aktuelle Entscheidungen anzeigen
sudo cscli decisions list

# Spezifische IP freigeben
sudo cscli decisions delete --ip X.X.X.X

# IP zur Whitelist hinzufügen
echo "X.X.X.X" >> /etc/crowdsec/parsers/s02-enrich/whitelists.yaml
```

#### 4. Container starten nicht
```bash
# Docker-Status prüfen
sudo systemctl status docker

# Container-Logs prüfen
docker logs portainer
docker logs watchtower

# Docker-Netzwerk prüfen
docker network ls
```

### Log-Analyse
```bash
# Alle Setup-Logs anzeigen
sudo journalctl -t server-baukasten

# Fehler in den letzten 24 Stunden
sudo journalctl --since "24 hours ago" --priority=err

# Live-Monitoring kritischer Services
sudo journalctl -f -u ssh -u nftables -u crowdsec
```

## 📞 Support & Community

### 🐛 Bug Reports & Feature Requests
- **GitHub Issues:** [Server-Baukasten Issues](https://github.com/TZERO78/Server-Baukasten/issues)
- **Fehlerberichte:** Bitte füge Log-Ausgaben und Systeminfo hinzu
- **Feature-Wünsche:** Beschreibe den Use Case und den erwarteten Nutzen

### 📖 Dokumentation & Guides
- **Wiki:** [Server-Baukasten Wiki](https://github.com/TZERO78/Server-Baukasten/wiki)
- **Erweiterte Guides:** Detaillierte Anleitungen für spezielle Setups
- **FAQ:** Häufig gestellte Fragen und deren Lösungen

### 🤝 Beitragen
Beiträge sind willkommen! Siehe [CONTRIBUTING.md](CONTRIBUTING.md) für Details.

- **Code-Beiträge:** Fork, Branch, Pull Request
- **Dokumentation:** Verbesserungen und Erweiterungen
- **Testing:** Teste neue Features und berichte Probleme
- **Übersetzungen:** Hilf bei der Internationalisierung

## 📄 Lizenz

Dieses Projekt steht unter der MIT-Lizenz - siehe [LICENSE](LICENSE) für Details.

## 🙏 Danksagungen

Dieses Projekt baut auf den Ideen und der Arbeit vieler anderer auf. Ein großer Dank geht an:

* [**CrowdSec**](https://crowdsec.net/) für ihre herausragende Arbeit im Bereich kollektiver Threat Intelligence
* [**IPDeny**](https://www.ipdeny.com/) für die kostenlose Bereitstellung der GeoIP-Datenbanken
* [**Tailscale**](https://tailscale.com/) für das revolutionäre VPN-Konzept
* Die gesamte **Linux-Community** für unzählige Best Practices und jahrzehntelanges geteiltes Wissen

Besonderer Dank für die Inspiration und die vielen Denkanstöße, die zu diesem Projekt geführt haben, gilt den YouTube-Kanälen:

* [**Christian's ion.it / Apfelcast**](https://www.youtube.com/@ionit-itservice)
* [**ct3003**](https://www.youtube.com/@ct3003)
* [**Raspberry Pi Cloud**](https://www.youtube.com/@RaspberryPiCloud)
* [**Geek Freaks**](https://www.youtube.com/@GeekFreaks)

### Mitwirkende
Besonderer Dank an alle, die zu diesem Projekt beigetragen haben:
- **Markus F. (TZERO78)** - Hauptentwickler und Projektinitiator
- **KI-Assistenten** - Unterstützung bei Code-Review und Optimierung
- **Beta-Tester** - Wertvolles Feedback aus der Community

## 🏆 Projektstatistiken

![GitHub stars](https://img.shields.io/github/stars/TZERO78/Server-Baukasten?style=social)
![GitHub forks](https://img.shields.io/github/forks/TZERO78/Server-Baukasten?style=social)
![GitHub issues](https://img.shields.io/github/issues/TZERO78/Server-Baukasten)
![GitHub last commit](https://img.shields.io/github/last-commit/TZERO78/Server-Baukasten)

---

⭐ **Star dieses Repository wenn es dir geholfen hat!** ⭐

**🚀 Transformiere deinen Server von einer offenen Tür zu einer uneinnehmbare Festung - in nur 20 Minuten!**
