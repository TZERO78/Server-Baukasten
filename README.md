# 🏗️ Server-Baukasten

**Vollautomatische Linux-Server-Härtung mit modularer Architektur**

> 🚀 **Ein Skript, um einen neuen Linux-Server in 20 Minuten in eine uneinnehmbare Festung zu verwandeln.**
>
> Das Hauptziel ist ein **von außen unsichtbarer Server**, der ausschließlich über ein sicheres VPN (Tailscale) erreichbar ist. Dadurch wird die Angriffsfläche gegen Null reduziert, noch bevor die Firewall überhaupt greift.

## ✨ Features

### 🧩 **Modulare Architektur (NEU)**
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
- **NFTables Firewall** mit Default-Drop-Policy
- **CrowdSec IPS** mit kollektiver Threat Intelligence
- **GeoIP-Blocking** zur intelligenten Abwehr von Angriffen aus Risiko-Ländern
- **AppArmor** Mandatory Access Control

### 🐳 **Moderner Container Stack (optional)**
- **Docker** mit gehärteter Konfiguration
- **Portainer** Web-Management-Interface
- **Watchtower** automatische Container-Updates

### 📊 **Proaktives Monitoring & Wartung**
- **AIDE** File Integrity Monitoring & **RKHunter** Rootkit Detection
- **Strukturierte Logs** via `journald` & automatische Security-Updates
- **Tägliche System-Backups** mit Rotation

## 🚀 Quick Start

Es gibt zwei Wege, das Skript zu nutzen: den empfohlenen automatischen Weg oder den interaktiven Modus.

### Empfohlener Weg (Automatisch via Konfigurationsdatei)

Dieser Weg ist ideal für wiederholbare Setups und die beste Methode.

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

**1. SSH-Zugang testen (KRITISCH!)**
Öffne ein **neues** Terminal (schließe das alte noch nicht!) und stelle sicher, dass du dich mit dem neuen Port und deinem Admin-Benutzer anmelden kannst.
```bash
ssh -p [DEIN_SSH_PORT] [DEIN_ADMIN_USER]@[SERVER_IP]
```

**2. SSH-Sicherheit maximieren (Public-Key-Verfahren)**
Falls du während des Setups keinen SSH-Schlüssel hinterlegt hast, solltest du es jetzt tun.
- Füge deinen öffentlichen SSH-Schlüssel zur Datei `~/.ssh/authorized_keys` hinzu
- Bearbeite die SSH-Konfiguration: `sudo nano /etc/ssh/sshd_config`
- Setze die Option `PasswordAuthentication no`
- Starte den SSH-Dienst neu: `sudo systemctl restart ssh`

**3. Root-Konto sperren**
Nachdem du den `sudo`-Zugang für deinen Admin-Benutzer getestet hast, sperre den direkten Login für den `root`-Benutzer.
```bash
sudo passwd -l root
```

**4. System neustarten**
Ein abschließender Neustart stellt sicher, dass alle Dienste korrekt starten und die Konfigurationen geladen werden.
```bash
sudo reboot
```

**5. GeoIP-Blocking aktivieren (nach dem Neustart)**
Nach dem Neustart sind die GeoIP-Listen in der Firewall leer. Führe diesen Befehl aus, um sie sofort zu befüllen und den Länderschutz zu aktivieren.
```bash
geoip-manager update
```

## 🎯 Design-Philosophie

**Modulare Einfachheit:**
Das Skript kombiniert die Einfachheit eines Ein-Datei-Ansatzes mit der Flexibilität modularer Komponenten. Das Hauptskript orchestriert das Setup, während spezialisierte Komponenten bei Bedarf von GitHub geladen werden. Dies macht das System sowohl einfach zu verwenden als auch leicht erweiterbar.

**🛡️ Integriertes Sicherheitsnetz:**
Bei einem unerwarteten Fehler während der Installation bricht das Skript nicht einfach ab, sondern führt automatisch ein Rollback durch, um die ursprünglichen Konfigurationsdateien wiederherzustellen.

## 🔧 System-Management nach dem Setup

Hier sind die wichtigsten Befehle, um den Zustand deines neuen Servers zu überprüfen.

### Services & Timer
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
```

### GeoIP-Blocking verwalten
Das System installiert automatisch ein Management-Tool für das GeoIP-Blocking:

| Befehl | Beschreibung |
|--------|-------------|
| `geoip-manager status` | Status und Konfiguration anzeigen |
| `geoip-manager update` | Manuelles Update der IP-Listen |
| `geoip-manager hits` | Blockierte/erlaubte Pakete anzeigen |
| `geoip-manager test <IP>` | IP-Adresse testen |
| `geoip-manager allow <IP>` | IP zur Whitelist hinzufügen |
| `geoip-manager logs` | Update-Logs anzeigen |
| `geoip-manager help` | Vollständige Hilfe |

### Logs
```bash
# Live-Logs des Baukasten-Skripts verfolgen
sudo journalctl -t server-baukasten -f

# Alle Security-Logs der letzten Stunde auf Fehler prüfen
sudo journalctl --since "1 hour ago" --priority=err
```

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

## 📄 Lizenz

Dieses Projekt steht unter der MIT-Lizenz - siehe [LICENSE](LICENSE) für Details.

## 🙏 Danksagungen

Dieses Projekt baut auf den Ideen und der Arbeit vieler anderer auf. Ein großer Dank geht an:

* [**CrowdSec**](https://crowdsec.net/) für ihre herausragende Arbeit im Bereich kollektiver Threat Intelligence
* [**IPDeny**](https://www.ipdeny.com/) für die kostenlose Bereitstellung der GeoIP-Datenbanken
* Die gesamte **Linux-Community** für unzählige Best Practices und jahrzehntelanges geteiltes Wissen

Besonderer Dank für die Inspiration und die vielen Denkanstöße, die zu diesem Projekt geführt haben, gilt den YouTube-Kanälen:

* [**Christian's ion.it / Apfelcast**](https://www.youtube.com/@ionit-itservice)
* [**ct3003**](https://www.youtube.com/@ct3003)
* [**Raspberry Pi Cloud**](https://www.youtube.com/@RaspberryPiCloud)
* [**Geek Freaks**](https://www.youtube.com/@GeekFreaks)

---
⭐ **Star dieses Repository wenn es dir geholfen hat!** ⭐