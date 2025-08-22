# Server-Baukasten v3.0

**Pragmatisches Starter-Hardening für Home-Server & kleine VPS**

Ein einfaches Bash-Script, das einen frischen Debian/Ubuntu-Server in ~20 Minuten mit einer soliden Sicherheits-Basis ausstattet.

**Kernidee:** VPN-only (Tailscale) oder gehärteter Public-Mode. Alle nicht benötigten Ports werden per Drop-Policy blockiert. 

**Ziel:** Nicht Enterprise-Hardening, sondern ein praktischer Starter für Home- und VPS-User, um Angriffsfläche schnell zu minimieren.

### ❗ Wichtiger Sicherheitshinweis: Docker vs. Podman

Aktuell nutzt der Server-Baukasten in der Standard-Konfiguration (`SERVER_ROLE="1"`) **Docker**. Es ist ein bekanntes Problem, dass Docker standardmäßig versucht, die Firewall selbst zu verwalten. Dies kann in manchen Fällen die sorgfältig konfigurierten `nftables`-Regeln des Baukastens umgehen und unbeabsichtigt Ports öffnen.

**Meine Roadmap zur Lösung:**
Die nächste große Version des Server-Baukastens wird auf **Podman** umgestellt, eine moderne und sicherere Alternative, die sich perfekt in die System-Firewall integriert.

---
### **Empfohlene & sichere Methode für Container (Workaround)**

Bis zur Umstellung auf Podman empfehle ich für maximale Sicherheit folgenden Weg:

**Schritt 1: Konfiguration anpassen**
Setze in deiner `mein-server.conf`-Datei den `SERVER_ROLE` auf "Einfacher Server", um die Docker-Installation des Baukastens zu überspringen:
```bash
# Server-Typ
SERVER_ROLE="2"
```


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Debian](https://img.shields.io/badge/OS-Debian%2012-red.svg)](https://www.debian.org/)
[![Ubuntu](https://img.shields.io/badge/OS-Ubuntu%2022.04+-orange.svg)](https://ubuntu.com/)

## Warum Bash statt Ansible/Puppet?

**Bewusste Entscheidung für Einfachheit:**

- **Keine Dependencies:** Läuft sofort auf jedem Standard-Server
- **Vollständig transparent:** Jede Zeile Code ist nachvollziehbar  
- **Zielgruppe:** Home-User und VPS-Bastler, nicht Enterprise-Admins
- **Lerneffekt:** Du siehst genau, was konfiguriert wird
- **Portabilität:** Funktioniert überall wo Bash verfügbar ist

Ansible ist technisch "sauberer", aber für die Zielgruppe überdimensioniert. Dieses Script soll schnell und verständlich sein, nicht perfekt.

---

## Konzept & Philosophie

Der Server-Baukasten ist ein pragmatisches Starter-Tool mit drei Grundprinzipien:

**1. Solides Sicherheitsfundament**
Das Script implementiert mehrere Basisschutz-Schichten: NFTables-Firewall, CrowdSec IPS, GeoIP-Blocking und Kernel-Härtung. Es ist kein vollständiges Enterprise-System, sondern bietet eine sichere Ausgangsbasis für eigene Projekte.

**2. Einfachheit vor Perfektion**  
Bewusst als simples Bash-Script entwickelt - transparent, nachvollziehbar, ohne externe Dependencies. Du behältst die volle Kontrolle und verstehst jeden Schritt.

**3. Reproduzierbares Setup**
Server-Konfiguration über Config-File. Ermöglicht identische, gehärtete Server-Setups für Experimente oder Disaster Recovery.

**Was es NICHT ist:** Eine vollautomatische Enterprise-Lösung. Es schafft das sichere Fundament - für spezifische Services musst du selbst Hand anlegen.

### Zwei Sicherheitsmodelle

**Modell 1: VPN-Only (Empfohlen)**
- Server nur über Tailscale VPN erreichbar
- Alle öffentlichen Ports geschlossen
- Ideal für private Server und Entwicklungsumgebungen

**Modell 2: Gehärteter Public-Mode**
- Server kann öffentliche Dienste bereitstellen  
- Starkes Sicherheitsfundament durch moderne Tools
- Deutlich sicherer als Standard-Installationen

## Automatischer Download von Komponenten

Das Script lädt alle benötigten Komponenten automatisch von GitHub:
- Konfigurationsvorlagen für AIDE, RKHunter und andere Tools
- Management-Skripte wie geoip-manager und update-geoip-sets  
- Vorgefertigte Systemd-Units für Timer und Services

Du benötigst nur das Hauptskript und die Konfigurationsdatei - der Rest wird automatisch geladen.

## Wichtige Voraussetzungen

### Tailscale-Account erforderlich

**Für die VPN-Features benötigst du einen kostenlosen Tailscale-Account:**

1. **Registrierung:** [tailscale.com](https://tailscale.com) (kostenlos für bis zu 20 Geräte)
2. **Auth-Key generieren:** 
   - Bei Tailscale anmelden
   - "Settings" → "Keys" → "Generate auth key"
   - Key kopieren für die Konfigurationsdatei
3. **Warum Tailscale?** 
   - Reduziert die Angriffsfläche drastisch
   - Verschlüsselter, sicherer Zugang ohne offene Ports
   - Funktioniert auch hinter NAT/Firewall
   - **Verhindert viele Angriffe präventiv** - was nicht erreichbar ist, kann schwerer angegriffen werden

### System-Voraussetzungen

- **Server:** Frische Installation von Debian 12 oder Ubuntu 22.04+
- **Zugang:** Root-Rechte (temporär für Setup)
- **Internet:** Stabile Verbindung für Downloads
- **E-Mail:** SMTP-Server für Benachrichtigungen (optional)

## Haupt-Features

| Kategorie | Feature | Beschreibung |
| :--- | :--- | :--- |
| 👻 **Zugang (Zero Trust)** | Tailscale VPN | Macht den Server unsichtbar und bietet sicheren, verschlüsselten Zugang. |
| 🛡️ **Firewall & IPS** | NFTables Firewall | Moderne Firewall mit `policy drop` und dynamischer Regel-Generierung. |
| | CrowdSec IPS | Proaktive, KI-gestützte Abwehr von Angreifern durch Community-Daten. |
| | GeoIP-Blocking | Blockiert Angriffe aus vordefinierten Risiko-Ländern. Inklusive Management-Tool. |
| 🔍 **Monitoring** | AIDE & RKHunter | Überwachen die Datei-Integrität und suchen nach Rootkits. |
| | journald-Integration | Zentrale, strukturierte Protokollierung aller Sicherheitsereignisse. |
| ⚙️ **Hardening** | Kernel-Härtung | Optimiert den Linux-Kernel für Sicherheit und Performance. |
| | AppArmor Enforcement | Mandatory Access Control für zusätzliche Sicherheit. |
| | SSH-Härtung | Sichere SSH-Konfiguration mit optionaler Key-based Authentication. |
| 🐳 **Container (Optional)**| Docker Engine | Stellt eine gehärtete Docker-Umgebung bereit, die sauber mit `nftables` integriert ist. |
| | Management-Tools | Installiert optional Portainer (Web-UI) und Watchtower (Auto-Updates). |
| 🔄 **Automatisierung**| systemd-Timer | Alle wiederkehrenden Aufgaben (Updates, Scans) werden über moderne Timer gesteuert. |
| | Unattended-Upgrades | Hält das System mit Sicherheitspatches automatisch auf dem neuesten Stand. |
| 📧 **Benachrichtigungen** | E-Mail-Integration | Automatische Benachrichtigungen bei Sicherheitsereignissen via msmtp. |

## 🚀 Quick Start (Anfängerfreundlich)

### 1. Hauptskript herunterladen

```bash
# Mit wget (empfohlen)
wget https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh

# Oder mit curl
curl -O https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh

# Ausführbar machen
chmod +x serverbaukasten.sh
```

### 2. Konfiguration erstellen

```bash
# Konfigurationsvorlage herunterladen
wget https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/standard.conf

# Eigene Kopie erstellen
cp standard.conf mein-server.conf

# Mit deinem bevorzugten Editor bearbeiten (sudo für systemweite Configs)
sudo nano mein-server.conf
```

**Wichtige Werte in der Konfiguration:**
- `SERVER_HOSTNAME`: Name deines Servers
- `ADMIN_USER`: Dein Benutzername (nicht "root")
- `ADMIN_PASSWORD`: Starkes Passwort für deinen Benutzer
- `ROOT_PASSWORD`: Starkes Root-Passwort
- `NOTIFICATION_EMAIL`: Deine E-Mail für Benachrichtigungen
- `TAILSCALE_AUTH_KEY`: Auth-Key von tailscale.com (für VPN)

### 3. Installation starten

```bash
# Vollständige Installation
sudo ./serverbaukasten.sh -c mein-server.conf

# Schneller Testlauf (für Tests)
sudo ./serverbaukasten.sh -t -c mein-server.conf
```

### 4. Befehls-Optionen

| Option | Beschreibung |
|--------|-------------|
| `-c FILE` | Pfad zur Konfigurationsdatei (Pflicht) |
| `-t` | Test-Modus (überspringt langsame Schritte) |
| `-v` | Ausführliche Ausgaben |
| `-d` | Debug-Modus |
| `-h` | Hilfe anzeigen |

## 🔐 Final Lockdown: Wichtigste Schritte nach der Installation

Das Skript hat die Festung gebaut, aber du schließt die Tore ab:

### 1. SSH-Zugang testen (KRITISCH!)
Öffne ein **neues Terminal** und teste den Login, bevor du das alte schließt:

```bash
# Via normale Server-IP
ssh -p [DEIN_SSH_PORT] [DEIN_ADMIN_USER]@[SERVER_IP]

# Via Tailscale (empfohlen, falls VPN-Setup abgeschlossen)
ssh -p [DEIN_SSH_PORT] [DEIN_ADMIN_USER]@[TAILSCALE_IP]
```

### 2. SSH-Sicherheit maximieren
Falls du keinen SSH-Schlüssel hinterlegt hast:
```bash
# SSH-Key einrichten und Passwort-Login deaktivieren
# In /etc/ssh/sshd_config: PasswordAuthentication no
sudo systemctl restart ssh
```

### 3. Root-Konto sperren
Nachdem dein sudo-Zugang funktioniert:
```bash
sudo passwd -l root
```

### 4. System neustarten
```bash
sudo reboot
```

### 5. GeoIP-Blocking aktivieren
Nach dem Neustart:
```bash
sudo geoip-manager update
```

## 🔧 System-Management nach dem Setup

Dein Server ist jetzt so konzipiert, dass er wartungsarm läuft. Hier sind die wichtigsten Befehle:

| Aufgabe | Befehl |
|---------|---------|
| Status aller Timer anzeigen | `sudo systemctl list-timers` |
| Firewall-Regeln prüfen | `sudo nft list table inet filter` |
| CrowdSec-Statistiken | `sudo cscli metrics` |
| GeoIP-Status und -Management | `sudo geoip-manager status` |
| Setup-Logs ansehen | `sudo journalctl -t server-baukasten` |
| Docker-Container prüfen | `sudo docker ps -a` |
| Sicherheitslogs filtern | `sudo journalctl -t crowdsec -t aide-check -t rkhunter-check` |

## 📁 Projektstruktur

```
Server-Baukasten (nur diese 2 Dateien herunterladen):
├── serverbaukasten.sh          # Hauptskript
└── standard.conf               # Konfigurationsvorlage

Automatisch heruntergeladene Komponenten:
├── components/                 # Management-Tools
│   ├── geoip-manager          # GeoIP-Verwaltung
│   └── update-geoip-sets      # GeoIP-Updates
└── conf/                      # Systemkonfigurationen
    ├── aide.conf.template     # AIDE-Monitoring
    └── rkhunter.conf.template # Rootkit-Scanner
```

**Du brauchst nur 2 Dateien:** Das Hauptskript und die Konfiguration. Alle anderen Komponenten werden automatisch geladen!

## 🛡️ Sicherheitsarchitektur

Der Server-Baukasten implementiert eine mehrstufige Sicherheitsarchitektur, die unabhängig vom Zugangsmodell funktioniert:

```
Internet ←→ [NFTables Firewall] ←→ [CrowdSec IPS] ←→ [GeoIP Filter] ←→ [AppArmor] ←→ Server
                     ↓
             [Tailscale VPN - Optional]
                     ↓
            [AIDE/RKHunter Monitoring]
                     ↓
            [journald Logging]
```

### Sicherheitsschichten im Detail

**Layer 1: NFTables-Firewall**
- Default DROP Policy - nur explizit erlaubte Verbindungen
- Connection Tracking für Performance
- Automatische Regel-Generierung basierend auf Server-Konfiguration

**Layer 2: CrowdSec IPS**
- Community-basierte Bedrohungserkennung
- Automatisches Blocking von Angreifern
- Kollektive Intelligenz aus Millionen von Servern

**Layer 3: GeoIP-Blocking**
- Statistisch 60-85% weniger Angriffe (je nach Konfiguration)
- Schutz vor geografischen Bedrohungsquellen
- Automatischer Heimatland-Schutz

**Layer 4: AppArmor & Kernel-Härtung**
- Mandatory Access Control für Anwendungen
- DDoS-Schutz und Performance-Optimierung
- Härtung gegen bekannte Angriffsvektoren

**Layer 5: Monitoring & Logs**
- AIDE für Datei-Integritätsprüfung
- RKHunter für Rootkit-Erkennung
- Zentrale, strukturierte Protokollierung

### Für öffentliche Dienste optimiert

Auch wenn du später Webserver, APIs oder andere Services öffentlich bereitstellen möchtest, bietet dieses Fundament:

- **Erweiterbares Firewall-System** - neue Ports lassen sich sicher öffnen
- **Automatische Angriffserkennung** - verdächtige Aktivitäten werden sofort blockiert
- **Intelligente Filterung** - Reduzierung des "Rauschens" durch GeoIP-Blocking
- **Monitoring-Infrastruktur** - Überwachung auf Kompromittierung

**Das Ergebnis:** Ein gehärteter Server, der deutlich widerstandsfähiger ist als Standard-Installationen - mit oder ohne VPN-Schutz.

## 🔒 Sicherheitshinweise

### Automatische Bereinigung sensibler Daten

Die Konfigurationsdatei enthält kritische Informationen wie:
- Passwörter (Admin, Root, SMTP)
- Tailscale Auth-Keys
- E-Mail-Credentials

**Das Skript bietet am Ende automatisch an, diese Datei sicher zu löschen.**

```bash
# Am Ende des Setup-Prozesses erscheint:
"Soll die Konfigurationsdatei jetzt sicher gelöscht werden? (ja/nein, Standard: ja)"

# Empfehlung: Immer mit "ja" bestätigen!
```

### Manuelle Bereinigung

Falls du die Datei später manuell löschen möchtest:

```bash
# Sichere Löschung (überschreibt Daten mehrfach)
shred -n 3 -uz mein-server.conf

# Normale Löschung
rm mein-server.conf
```

### Warum ist das wichtig?

- Verhindert Zugriff auf Credentials bei Server-Kompromittierung
- Entspricht Security-Best-Practices
- Reduziert Angriffsfläche nach dem Setup

## 🔧 Erweiterte Konfiguration

### Wichtige Konfigurationswerte erklärt

```bash
# Basis-Setup
SERVER_HOSTNAME="mein-server"           # Name deines Servers
ADMIN_USER="admin"                      # Dein Benutzername (nicht "root"!)
ADMIN_PASSWORD="Sicheres-Passwort-123"  # Starkes Passwort
ROOT_PASSWORD="Root-Passwort-456"       # Root-Passwort (Fallback)
NOTIFICATION_EMAIL="admin@example.com"  # Deine E-Mail für Alerts

# VPN-Zugang (empfohlen)
ACCESS_MODEL="1"                        # 1=VPN-only, 2=öffentlich
TAILSCALE_AUTH_KEY="tskey-auth-..."     # Von tailscale.com

# Sicherheit
SSH_PORT="22"                           # SSH-Port (kann geändert werden)
SSH_PUBLIC_KEY="ssh-ed25519 AAA..."     # Dein öffentlicher SSH-Key

# GeoIP-Blocking
ENABLE_GEOIP_BLOCKING="ja"              # Aktiviert Länder-Blocking
HOME_COUNTRY="DE"                       # Dein Land (nie blockiert)
BLOCKED_COUNTRIES="CN RU KP IR"         # Risiko-Länder blockieren

# Docker (optional)
SERVER_ROLE="1"                         # 1=Docker-Host, 2=einfach
INSTALL_PORTAINER="ja"                  # Web-Interface für Docker
INSTALL_WATCHTOWER="ja"                 # Automatische Updates
```

### GeoIP-Länder-Codes

| Region | Häufige Codes |
|--------|--------------|
| **Deutschland** | DE, AT, CH |
| **Europa** | FR, IT, ES, NL, BE, SE, NO, DK, PL |
| **Weitere** | US, CA, AU, JP, SG, KR |
| **Oft blockiert** | CN, RU, KP, IR, BY, MM |

### SMTP-Beispiele

**Gmail:**
```bash
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USER="deine-email@gmail.com"
SMTP_PASSWORD="app-passwort"  # Nicht dein normales Passwort!
```

**Outlook:**
```bash
SMTP_HOST="smtp-mail.outlook.com"
SMTP_PORT="587"
SMTP_USER="deine-email@outlook.com"
SMTP_PASSWORD="dein-passwort"
```

## 📄 Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).

## 🙏 Danksagungen

Ein besonderer Dank für die Inspiration und die vielen Denkanstöße gilt den YouTube-Kanälen von Christian (ion.it/Apfelcast), ct3003, Raspberry Pi Cloud und Geek Freaks sowie der gesamten Linux- und Open-Source-Community.

## 🤝 Beitragen

**WICHTIG**: Da dieses Skript root-Rechte verwendet und kritische Systemkonfigurationen ändert, werden alle Änderungen sorgfältig geprüft.

### Vor einem Pull Request:
1. **Issue erstellen** - Beschreibe deine Idee/den Bugfix zuerst
2. **Diskussion abwarten** - Lass uns über den Ansatz sprechen
3. **Dann erst Code** - Fork und Pull Request nach Freigabe

### Akzeptierte Beiträge:
- Bugfixes und Sicherheitsverbesserungen
- Bessere Dokumentation und Beispiele
- Unterstützung für weitere Linux-Distributionen
- Performance-Optimierungen

### Nicht akzeptiert:
- Grundlegende Architektur-Änderungen ohne vorherige Diskussion
- Code ohne ausreichende Kommentierung
- Features die die Sicherheit verringern könnten

**Sicherheit hat oberste Priorität** - jeder Code-Beitrag wird eingehend geprüft bevor er ins Hauptprojekt übernommen wird.

## ⭐ Star dieses Repository wenn es dir geholfen hat!
