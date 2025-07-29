# 🏗️ Server-Baukasten

**Vollautomatische Linux-Server-Härtung**

> 🚀 **Ein Skript, um einen neuen Linux-Server in 20 Minuten in eine uneinnehmbare Festung zu verwandeln.**
>
> Das Hauptziel ist ein **von außen unsichtbarer Server**, der ausschließlich über ein sicheres VPN (Tailscale) erreichbar ist. Dadurch wird die Angriffsfläche gegen Null reduziert, noch bevor die Firewall überhaupt greift.

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
- **Strukturierte Logs** via `journald` & automatische Security-Updates
- **Tägliche System-Backups** mit Rotation

## 🚀 Quick Start

Es gibt zwei Wege, das Skript zu nutzen: den empfohlenen automatischen Weg oder den interaktiven Modus.

### Empfohlener Weg (Automatisch via Konfigurationsdatei)

Dieser Weg ist ideal für wiederholbare Setups und die beste Methode.

```bash
# 1. Skript und Standard-Konfiguration herunterladen
wget [https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh](https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh)
wget [https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/standard.conf](https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/standard.conf)
chmod +x serverbaukasten.sh

# 2. Konfiguration anpassen
# Kopiere die Vorlage und trage DEINE Werte ein (Passwörter, E-Mail etc.)
cp standard.conf mein-server.conf
nano mein-server.conf

# 3. Skript mit deiner Konfiguration ausführen
sudo ./serverbaukasten.sh -c mein-server.conf
```

### Alternativer Weg (Interaktiv)

Gut für die erste Einrichtung, wenn du dich durch die Optionen führen lassen möchtest.

```bash
# 1. Nur das Skript herunterladen
wget [https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh](https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh)
chmod +x serverbaukasten.sh

# 2. Skript starten und den Fragen folgen
sudo ./serverbaukasten.sh
```

## 🔐 Final Lockdown: Wichtigste Schritte nach der Installation

Das Skript hat die Festung gebaut, aber du schließt die Tore ab. Führe diese Schritte in der angegebenen Reihenfolge aus, um die maximale Sicherheit zu gewährleisten.

**1. SSH-Zugang testen (KRITISCH!)**
Öffne ein **neues** Terminal (schließe das alte noch nicht!) und stelle sicher, dass du dich mit dem neuen Port und deinem Admin-Benutzer anmelden kannst.
```bash
ssh -p [DEIN_SSH_PORT] [DEIN_ADMIN_USER]@[SERVER_IP]
```

**2. SSH-Sicherheit maximieren (Public-Key-Verfahren)**
Falls du während des Setups keinen SSH-Schlüssel hinterlegt hast, solltest du es jetzt tun.
- Füge deinen öffentlichen SSH-Schlüssel zur Datei `~/.ssh/authorized_keys` hinzu.
- Bearbeite die SSH-Konfiguration: `sudo nano /etc/ssh/sshd_config`.
- Setze die Option `PasswordAuthentication no`.
- Starte den SSH-Dienst neu: `sudo systemctl restart ssh`.

**3. Root-Konto sperren**
Nachdem du den `sudo`-Zugang für deinen Admin-Benutzer getestet hast, sperre den direkten Login für den `root`-Benutzer. Dies ist ein wichtiger Härtungsschritt.
```bash
sudo passwd -l root
```

**4. System neustarten**
Ein abschließender Neustart stellt sicher, dass alle Dienste korrekt starten und die Konfigurationen geladen werden.
```bash
sudo reboot
```

### GeoIP-Blocking verwalten (`geoip-manager`)

Das Skript installiert ein kleines, praktisches Werkzeug namens `geoip-manager`, um das GeoIP-Blocking einfach zu verwalten. Hier sind die wichtigsten Befehle:

| Befehl                        | Beschreibung                                                               |
| :---------------------------- | :------------------------------------------------------------------------- |
| `sudo geoip-manager status`   | Zeigt den Gesamtstatus, Konfiguration und Anzahl der geladenen IPs.        |
| `sudo geoip-manager update`   | Startet manuell ein sofortiges Update der IP-Listen von IPDeny.            |
| `sudo geoip-manager hits`     | Zeigt an, wie viele Pakete von den GeoIP-Regeln blockiert/erlaubt wurden.    |
| `sudo geoip-manager test <IP>`| Simuliert, wie die Firewall eine bestimmte IP-Adresse behandeln würde.       |
| `sudo geoip-manager allow <IP>`| Fügt eine IP-Adresse zur manuellen Ausnahmeliste (Whitelist) hinzu.        |
| `sudo geoip-manager logs`     | Zeigt die letzten Log-Einträge des wöchentlichen Update-Dienstes an.        |

**Beispiel-Ausgabe:**
```bash
$ sudo geoip-manager status
=== GeoIP-Blocking Status ===
Blockierte Länder: CN RU KP IR
Heimatland (geschützt): DE
...
Firewall-Integration: ✅ Aktiv und integriert
Heimatland IPs: 12589 (v4), 452 (v6)
Blockierte IPs: 15432 (v4), 876 (v6)

> **⚠️ Wichtiger Hinweis nach einem Server-Neustart**
>
> Nach einem `reboot` sind die GeoIP-Sets in der Firewall **zuerst leer**. Der automatische `systemd`-Timer füllt diese zwar bei seinem nächsten wöchentlichen Lauf, für sofortigen Schutz musst du sie aber einmalig manuell befüllen.
>
> Führe daher nach jedem Neustart diesen Befehl aus:
> ```bash
> sudo geoip-manager update
> ```


## 🎯 Design-Philosophie

**Einfachheit durch Ein-Datei-Ansatz:**
Dieses Skript wurde bewusst als eine einzige, in sich geschlossene Datei konzipiert. Anstatt viele einzelne Konfigurations- und Skriptdateien verwalten zu müssen, lädst du einfach nur die `serverbaukasten.sh` auf deinen neuen Server, machst sie ausführbar und startest sie. Das macht den gesamten Prozess – besonders für Einsteiger – extrem einfach und nachvollziehbar.

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

# GeoIP-Blocking-Status
sudo geoip-manager status

# CrowdSec-Statistiken
sudo cscli metrics
```

### Logs
```bash
# Live-Logs des Baukasten-Skripts verfolgen
sudo journalctl -t server-baukasten -f

# Alle Security-Logs der letzten Stunde auf Fehler prüfen
sudo journalctl --since "1 hour ago" --priority=err
```

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
* [**Geek Freaks**](https://www.google.com/search?q=https://www.youtube.com/%40ionit-itservice)

---
⭐ **Star dieses Repository wenn es dir geholfen hat!** ⭐
