# **Server-Baukasten v5.0**

**Vollständig modulares Server-Hardening für Linux**

**Pragmatisches Starter-Hardening für Home-Server & kleine VPS**

Ein einfaches Bash-Skript, das einen frischen Debian/Ubuntu-Server in ~20 Minuten mit einer soliden, produktionstauglichen Sicherheits-Basis ausstattet.

**Kernidee:** VPN-only (Tailscale) oder gehärteter Public-Mode. Alle nicht benötigten Ports werden per Drop-Policy blockiert.

**Ziel:** Nicht Enterprise-Hardening, sondern ein praktischer Starter für Home- und VPS-User, um Angriffsfläche schnell und zuverlässig zu minimieren.

## **Warum Bash statt Ansible/Puppet?**

**Bewusste Entscheidung für Einfachheit:**

* **Keine Dependencies:** Läuft sofort auf jedem Standard-Server
* **Vollständig transparent:** Jede Zeile Code ist nachvollziehbar
* **Zielgruppe:** Home-User und VPS-Bastler, nicht Enterprise-Admins
* **Lerneffekt:** Du siehst genau, was konfiguriert wird
* **Portabilität:** Funktioniert überall wo Bash verfügbar ist

Ansible ist technisch "sauberer", aber für die Zielgruppe überdimensioniert. Dieses Script soll schnell und verständlich sein, nicht perfekt.

## **Konzept & Philosophie**

Der Server-Baukasten ist ein pragmatisches Starter-Tool mit drei Grundprinzipien:

**1. Solides Sicherheitsfundament**
Das Script implementiert mehrere Basisschutz-Schichten: NFTables-Firewall, CrowdSec IPS, GeoIP-Blocking und Kernel-Härtung. Es ist kein vollständiges Enterprise-System, sondern bietet eine sichere Ausgangsbasis für eigene Projekte.

**2. Einfachheit vor Perfektion**
Bewusst als simples Bash-Script entwickelt - transparent, nachvollziehbar, ohne externe Dependencies. Du behältst die volle Kontrolle und verstehst jeden Schritt.

**3. Reproduzierbares Setup**
Server-Konfiguration über Config-File. Ermöglicht identische, gehärtete Server-Setups für Experimente oder Disaster Recovery.

**Was es NICHT ist:** Eine vollautomatische Enterprise-Lösung. Es schafft das sichere Fundament - für spezifische Services musst du selbst Hand anlegen.

---

## 🆕 **Was ist neu in v5.0? (Breaking Changes!)**

### 🏗️ **Vollständig modulare Architektur**
- **NFTables komplett modular**: `/etc/nftables.d/` statt monolithische Konfiguration
- **Bibliotheken-System**: Funktionalitäten in separate `lib/*.sh` Dateien aufgeteilt
- **Module-Framework**: Jedes Setup-Feature als eigenständiges Modul in `modules/`
- **Automatischer Download**: `install.sh` lädt alle Komponenten direkt von GitHub

### 🐳 **Docker-Integration revolutioniert**
- **iptables-nft Backend**: Stabile Koexistenz zwischen Docker und NFTables
- **Systemd-Abhängigkeiten**: Docker startet garantiert nach der Firewall
- **Modulare Container-Regeln**: Separate NFTables-Datei für Docker-Traffic

### 🛡️ **CrowdSec Set-basierte Integration**
- **Keine Tabellen-Konflikte**: CrowdSec nutzt vordefinierte Sets statt eigene Tabellen
- **Modulare NFTables-Integration**: Separate CrowdSec-Konfigurationsdatei
- **Eigene systemd-Units**: Health-Checks und Neustart-Logik völlig neu entwickelt

### 🌍 **Erweiterte GeoIP-Verwaltung**
- **Management-Tool**: `geoip-manager` für einfache Verwaltung
- **Set-basierte Implementierung**: Bessere Performance durch NFTables-Sets
- **Konflikt-Auflösung**: Automatische Bereinigung von Heimatland aus Blocklist

### ⚙️ **Intelligente sudo-Verwaltung**
- **Temporäre Rechte**: NOPASSWD nur während des Setups, automatische Bereinigung
- **Atomare Operationen**: Sichere sudoers-Manipulation mit visudo-Validierung
- **Notfall-Cleanup**: Automatische Bereinigung bei Script-Abbruch

---

## 🔄 **Migration von v4.x zu v5.0**

⚠️ **BREAKING CHANGES** - v5.0 ist nicht kompatibel zu v4.x!

**Wichtigste Änderungen:**
- Neue modulare Projektstruktur
- NFTables-Konfiguration komplett überarbeitet
- Docker-Integration neu implementiert
- CrowdSec-Integration umgestellt auf Set-Modus

**Migration:** Führe ein komplettes Neu-Setup durch. Ein Update ist nicht möglich.

---

## 📁 **Projektstruktur v5.0**

```
Server-Baukasten v5.0/
├── install.sh                    # 🆕 Automatische Installation aller Komponenten
├── serverbaukasten.sh            # Hauptskript (Orchestrator)
├── standard.conf                 # Konfigurationsvorlage
├── LICENSE                       # MIT-Lizenz
├── README.md                     # Diese Dokumentation
├── lib/                          # 🆕 Kern-Bibliotheken (modular)
│   ├── core_helpers.sh           # Logging, sudo-Verwaltung, Validierung
│   ├── ui_helpers.sh             # Benutzeroberfläche & Zusammenfassung
│   ├── validation_helpers.sh     # Input-Validierung & Sicherheitschecks
│   ├── firewall_helpers.sh       # 🆕 Modulare NFTables-Generierung
│   ├── crowdsec_helpers.sh       # 🆕 CrowdSec-Installation & Set-Integration
│   └── geoip_helpers.sh          # 🆕 GeoIP-Management & Konfiguration
├── modules/                      # 🆕 Setup-Module (eigenständig)
│   ├── module_cleanup.sh         # System-Bereinigung
│   ├── module_base.sh            # Basis-System (Pakete, Benutzer, Docker)
│   ├── module_security.sh        # Multi-Layer Security-Architektur
│   ├── module_network.sh         # Tailscale VPN-Integration
│   ├── module_container.sh       # 🆕 Docker-Engine mit nft-Backend
│   ├── module_deploy_containers.sh # Management-Container
│   ├── module_kernel_hardening.sh  # Kernel-Parameter & sysctl
│   ├── module_system_update.sh     # Updates & systemd-Timer
│   ├── module_mail_setup.sh        # E-Mail-Benachrichtigungen
│   ├── module_journald_optimization.sh # Log-Optimierung
│   └── module_verify_setup.sh      # 🆕 Umfassende System-Verifikation
├── conf/                         # 🆕 Konfigurationsvorlagen für Services
│   ├── aide.conf.template        # AIDE Datei-Integritätsprüfung
│   └── rkhunter.conf.template     # RKHunter Rootkit-Scanner
└── components/                   # Automatisch heruntergeladene Tools
    ├── geoip-manager             # 🆕 GeoIP-Verwaltungstool
    └── update-geoip-sets         # 🆕 Automatische IP-Listen-Updates
```

**🆕 = Neu in v5.0 oder komplett überarbeitet**

---

## 🚀 **Installation & Quick Start**

### **Automatische Installation mit install.sh**
```bash
# Standard-Installation
curl -fsSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash
cd Server-Baukasten

# Installation mit Optionen (siehe install.sh für verfügbare Parameter)
curl -fsSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash -s -- [OPTIONEN]
```

**Verfügbare install.sh Optionen:**
```bash
# Zeige alle verfügbaren Parameter
curl -fsSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash -s -- --help
```

⚠️ **Warum nur install.sh?**
- v5.0 benötigt **alle Module und Bibliotheken** aus `lib/` und `modules/`
- Manuelle Installation ist **unvollständig** und führt zu Fehlern
- `install.sh` stellt sicher, dass die **komplette Struktur** korrekt geladen wird

### **Konfiguration anpassen**
```bash
# Eigene Kopie erstellen
cp standard.conf mein-server.conf

# Wichtigste Werte anpassen
nano mein-server.conf
```

### **Setup starten**
```bash
# Vollständige Installation
sudo ./serverbaukasten.sh -c mein-server.conf

# Schneller Test (überspringt langsame Operationen)
sudo ./serverbaukasten.sh -t -c mein-server.conf
```

---

## ⚙️ **Kommando-Optionen**

| Option | Beschreibung |
|:-------|:-------------|
| `-c FILE` | Pfad zur Konfigurationsdatei (**Pflicht**) |
| `-t` | **Test-Modus:** Überspringt zeitintensive Schritte (AIDE-Init, System-Updates) |
| `-v` | **Verbose:** Detaillierte Ausgaben während der Ausführung |
| `-d` | **Debug:** Maximale Ausgaben für Entwickler |
| `-h` | Zeigt ausführliche Hilfe an |

---

## 🛡️ **Sicherheitsarchitektur v5.0**

### **Layer 1: Modulare NFTables-Firewall**
```
/etc/nftables.conf              # Loader (lädt alle *.conf)
/etc/nftables.d/
├── 10-base-filter.conf         # Grundregeln (loopback, established)
├── 20-crowdsec.conf            # 🆕 CrowdSec-Sets & Chains
├── 30-geoip.conf              # 🆕 GeoIP-Blocking (set-basiert)
├── 40-tailscale.conf          # 🆕 VPN-Regeln
├── 50-docker.conf             # 🆕 Container-Forwarding
├── 60-services.conf           # SSH, ICMP, öffentliche Dienste
└── 90-nat.conf               # NAT für Tailscale Subnet-Routing
```

**Vorteile der modularen Struktur:**
- **Docker-kompatibel**: `iptables-nft` Backend verhindert Konflikte
- **Wartbar**: Einzelne Module können separat getestet/geladen werden
- **Erweiterbar**: Neue Dienste erhalten eigene Konfigurationsdateien
- **Debugfreundlich**: `nft -f /etc/nftables.d/30-geoip.conf` für Tests

### **Layer 2: CrowdSec IPS (Set-basiert)**
- **Community-Intelligence**: Globale Angriffsdaten von Millionen Servern
- **Set-Integration**: Nutzt vordefinierte NFTables-Sets (keine Tabellen-Konflikte)
- **Health-Checks**: Automatische Neustart-Logik bei API-Problemen
- **Performance**: Optimiert für VPS-Umgebungen

### **Layer 3: GeoIP-Blocking (Erweitert)**
- **Management-Tool**: `geoip-manager status|update|country add/remove`
- **Statistik-basiert**: 60-85% weniger Angriffe je nach Konfiguration
- **Heimatland-Schutz**: Automatische Konflikt-Auflösung
- **Set-Performance**: NFTables-Sets statt Einzelregeln

### **Layer 4: Tailscale VPN (Zero Trust)**
- **Unsichtbarer Server**: Komplette Abschottung vom öffentlichen Internet
- **Mesh-Netzwerk**: Sichere Verbindung zwischen allen Geräten
- **Subnet-Routing**: Server als Gateway für lokale Netze (IPv4)
- **IPv6-Kompatibilität**: Automatische Erkennung von VPS-IPv6-Limitationen
- **Auto-Updates**: Automatische Tailscale-Client-Updates

### **Layer 5: Integritäts-Monitoring**
- **AIDE**: Datei-Integritätsprüfung (täglich)
- **RKHunter**: Rootkit-Scanner (wöchentlich)
- **journald-optimiert**: Strukturierte Logs für alle Sicherheitsereignisse
- **systemd-Timer**: Moderne Automatisierung statt Cron

---

## 🐳 **Docker-Integration v5.0**

### **Revolutionierte Docker-Unterstützung**

**Problem in v4.x:** Docker und NFTables-Konflikte führten zu instabilen Setups.

**Lösung in v5.0:**
1. **iptables-nft Backend**: `update-alternatives --set iptables /usr/sbin/iptables-nft`
2. **Systemd-Abhängigkeiten**: Docker startet garantiert nach NFTables
3. **Modulare Container-Regeln**: Separate `/etc/nftables.d/50-docker.conf`
4. **Stabile Koexistenz**: Docker verwaltet seine Regeln, Baukasten die Sicherheit
5. **IPv6-VPS-Kompatibilität**: Automatische Erkennung von NAT66-Limitationen bei Standard-VPS

**Automatisch installierte Management-Tools:**
- **Portainer**: Web-Interface für Container-Management
- **Watchtower**: Automatische Container-Updates (täglich 04:00)

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

---

## 🌍 **GeoIP-Blocking v5.0**

### **Erweiterte Länder-Filterung**

**Management-Tool für GeoIP-Verwaltung:**
```bash
# Status & Statistiken anzeigen
sudo geoip-manager status

# Länder verwalten
sudo geoip-manager country add RU
sudo geoip-manager country remove CN
sudo geoip-manager country home DE

# Manuelle Updates
sudo geoip-manager update

# IP-Tests
sudo geoip-manager test 8.8.8.8

# Ausnahmen hinzufügen  
sudo geoip-manager allow 192.168.1.0/24
```

**Set-basierte Implementation:**
```bash
# Automatisch erstellte NFTables-Sets
geoip_blocked_v4     # Blockierte IPv4-Ranges
geoip_blocked_v6     # Blockierte IPv6-Ranges  
geoip_home_v4        # Geschütztes Heimatland IPv4
geoip_home_v6        # Geschütztes Heimatland IPv6
geoip_allowlist_v4   # Manuelle IPv4-Ausnahmen
geoip_allowlist_v6   # Manuelle IPv6-Ausnahmen
```

**Vorkonfigurierte Länder-Presets:**
- **Standard**: `CN RU KP IR` (~70% Angriffs-Reduktion)
- **Maximal**: `CN RU KP IR BY MM SY AF IQ LY` (~85% Angriffs-Reduktion)
- **Minimal**: `CN RU` (~60% Angriffs-Reduktion)

---

## 📧 **E-Mail-Integration**

### **Systemweite Benachrichtigungen**

**msmtp-basierte Lösung:**
- Ersetzt sendmail komplett
- Unterstützt STARTTLS, SMTP-Auth
- Gmail, Outlook, eigene Server
- Strukturierte journald-Logs

**Automatische Benachrichtigungen bei:**
- AIDE-Datei-Änderungen
- RKHunter-Warnungen  
- CrowdSec-Bedrohungen
- System-Update-Fehlern

**SMTP-Konfiguration (Gmail-Beispiel):**
```bash
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USER="deine-email@gmail.com"  
SMTP_PASSWORD="app-passwort"  # Nicht dein normales Passwort!
SMTP_TLS_STARTTLS="ja"
```

---

## ⏰ **Automatisierung v5.0**

### **Moderne systemd-Timer statt Cron**

| Timer | Zeitplan | Beschreibung |
|:------|:---------|:-------------|
| `aide-check.timer` | Täglich 05:00 | Datei-Integritätsprüfung |
| `rkhunter-check.timer` | Sonntags 04:00 | Rootkit-Scanner |
| `geoip-update.timer` | Sonntags 02:00 | GeoIP-Listen-Update |
| `unattended-upgrades-run.timer` | Täglich | Sicherheits-Updates |
| `crowdsec-healthcheck.timer` | Alle 5 Min | CrowdSec API-Überwachung |

**Timer-Verwaltung:**
```bash
# Alle Timer anzeigen
sudo systemctl list-timers

# Timer einzeln steuern
sudo systemctl start aide-check.timer
sudo systemctl status geoip-update.timer

# Logs anzeigen
sudo journalctl -u aide-check.service
```

---

## 🔧 **System-Management nach dem Setup**

### **Wichtigste Befehle**

| Aufgabe | Befehl |
|:--------|:-------|
| **GeoIP-Management** | `sudo geoip-manager status` |
| **Firewall-Status** | `sudo nft list ruleset \| head -20` |
| **CrowdSec-Statistiken** | `sudo cscli metrics` |
| **Docker-Container** | `sudo docker ps -a` |
| **Timer-Übersicht** | `sudo systemctl list-timers` |
| **Setup-Logs** | `sudo journalctl -t server-baukasten` |
| **Sicherheitslogs** | `sudo journalctl -t crowdsec -t aide-check` |

### **Troubleshooting**

**NFTables-Module einzeln testen:**
```bash
sudo nft -f /etc/nftables.d/30-geoip.conf
sudo nft -f /etc/nftables.d/40-tailscale.conf
```

**Docker-Probleme diagnostizieren:**
```bash
sudo systemctl status docker
sudo docker system info
sudo docker network ls
```

**CrowdSec-Status prüfen:**
```bash
sudo systemctl status crowdsec crowdsec-firewall-bouncer
sudo cscli machines list
sudo cscli decisions list
```

---

## 🔐 **Finale Sicherheitsschritte (UNBEDINGT BEFOLGEN!)**

Nach erfolgreichem Setup **in dieser exakten Reihenfolge**:

### **1. SSH-Zugang testen (KRITISCH!)**
```bash
# Neues Terminal öffnen und testen
ssh -p [SSH_PORT] [ADMIN_USER]@[SERVER_IP]

# Falls Tailscale aktiv
ssh -p [SSH_PORT] [ADMIN_USER]@[TAILSCALE_IP]
```

**💡 Profi-Tipp: Zusätzliche Sicherheitsebene (nur bei VPN-Modell)**
Wenn dein Zugang über Tailscale zuverlässig funktioniert, kannst du die Sicherheit maximieren:

* **Sperre den öffentlichen SSH-Port** (z.B. Port 22) direkt in der Firewall deines VPS-Providers (Hetzner Cloud, DigitalOcean etc.).
* Dein Server ist dann von außen **nicht mehr öffentlich erreichbar**, aber du kommst weiterhin über das Tailscale-VPN an ihn heran.
* Sollte Tailscale einmal Probleme machen, kannst du den Port bei deinem Provider mit einem Klick wieder freigeben.

**Provider-spezifische Anleitungen:**
- **Hetzner Cloud**: Console → Server → Firewalls → SSH-Port (22/tcp) entfernen
- **DigitalOcean**: Droplet → Networking → Firewalls → SSH-Rule löschen
- **AWS**: Security Groups → SSH-Regel (Port 22) entfernen
- **Vultr**: Server → Settings → Firewall → SSH-Port blockieren

### **2. SSH-Key einrichten (falls nicht geschehen)**
```bash
# SSH-Key erstellen (lokal)
ssh-keygen -t ed25519

# Key hochladen
ssh-copy-id -p [SSH_PORT] [ADMIN_USER]@[SERVER_IP]

# Passwort-Login deaktivieren
sudo nano /etc/ssh/sshd_config
# PasswordAuthentication no
sudo systemctl restart ssh
```

### **3. Root-Konto sperren**
```bash
sudo passwd -l root
```

### **4. System neustarten (KRITISCH!)**
```bash
sudo reboot
```

⚠️ **WICHTIG**: Der Neustart ist essentiell für:
- Aktivierung aller Kernel-Parameter
- Korrekte systemd-Service-Startreihenfolge
- Vollständige NFTables-Integration
- Docker-Daemon-Stabilität

### **5. Nach Neustart: GeoIP aktivieren (PFLICHT!)**
```bash
# Nach dem Neustart SSH-Verbindung neu aufbauen, dann:
sudo geoip-manager update
sudo geoip-manager status
```

⚠️ **WICHTIG**: Ohne `geoip-manager update` sind die GeoIP-Sets leer und das Blocking funktioniert nicht!

---

## 🎯 **Konfigurationsbeispiele**

### **VPS mit maximaler Sicherheit (Empfohlen)**
```bash
ACCESS_MODEL="1"                           # VPN-only
SERVER_ROLE="1"                           # Docker-Host
ENABLE_GEOIP_BLOCKING="ja"
HOME_COUNTRY="DE"
BLOCKED_COUNTRIES="CN RU KP IR BY MM SY AF IQ LY"  # Maximal-Blocking
ENABLE_SYSTEM_MAIL="ja"
INSTALL_PORTAINER="ja"
INSTALL_WATCHTOWER="ja"
```

### **Öffentlicher Webserver**
```bash
ACCESS_MODEL="2"                          # Öffentlich erreichbar  
SERVER_ROLE="1"                          # Docker für Services
ENABLE_GEOIP_BLOCKING="ja"
BLOCKED_COUNTRIES="CN RU KP IR"          # Standard-Blocking
SSH_PORT="2222"                          # Non-Standard Port
```

### **Minimaler Home-Server**
```bash
ACCESS_MODEL="1"                         # VPN-only
SERVER_ROLE="2"                         # Kein Docker
ENABLE_GEOIP_BLOCKING="nein"            # Kein GeoIP
ENABLE_SYSTEM_MAIL="nein"              # Keine E-Mails
```

---

## 📊 **Performance & Systemanforderungen**

### **Mindestanforderungen**
- **RAM**: 1GB (2GB für Docker-Host empfohlen)
- **Speicher**: 8GB für Basis, 20GB für Docker
- **Netzwerk**: Stabile Internetverbindung
- **OS**: Debian 12 oder Ubuntu 22.04+

### **Typical Resource Usage**
- **NFTables**: ~5MB RAM, minimal CPU
- **CrowdSec**: ~50MB RAM, niedrige CPU-Last
- **GeoIP-Sets**: ~10-50MB je nach Anzahl Länder
- **AIDE/RKHunter**: Hohe CPU/IO während Scans, sonst minimal

### **Optimierungen für VPS**
- journald-Speicher begrenzt (250MB)
- Log-Rotation optimiert (3 Wochen)
- Update-Timer mit RandomizedDelay
- CPU-Quotas für lange Prozesse

---

## 🆘 **Support & Community**

### **Debugging & Logs**
```bash
# Setup-Logs
sudo journalctl -t server-baukasten -f

# Alle Sicherheitslogs
sudo journalctl -t crowdsec -t aide-check -t rkhunter-check -f

# Specific Service Logs
sudo journalctl -u nftables -u docker -u tailscaled -f
```

### **Häufige Probleme**

**Docker startet nicht:**
```bash
# Dependency-Check
sudo systemctl status nftables
sudo systemctl restart docker
```

**GeoIP-Sets leer:**
```bash
sudo geoip-manager update
sudo nft list set inet filter geoip_blocked_v4
```

**CrowdSec-API nicht erreichbar:**
```bash
sudo systemctl restart crowdsec
sudo cscli metrics
```

**IPv6-NAT-Probleme auf Standard-VPS:**
```bash
# Häufig bei Hetzner, DigitalOcean, Vultr etc.
# Der Server-Baukasten erkennt dies automatisch und
# deaktiviert IPv6-NAT-Regeln bei fehlender Kernel-Unterstützung
sudo journalctl -t server-baukasten | grep -i ipv6
```

### **Repository & Issues**
- 🌐 **GitHub**: [TZERO78/Server-Baukasten](https://github.com/TZERO78/Server-Baukasten)
- 🐛 **Issues**: [GitHub Issues](https://github.com/TZERO78/Server-Baukasten/issues)
- 📖 **Wiki**: [Erweiterte Dokumentation](https://github.com/TZERO78/Server-Baukasten/wiki)
- 🔍 **Bekannte VPS-Limitationen**: [Issue #2 - IPv6-NAT Probleme](https://github.com/TZERO78/Server-Baukasten/issues/2)

---

## 📄 **Lizenz**

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).

**Copyright (c) 2025 Markus F. (TZERO78)**

---

## 🙏 **Danksagungen**

Besonderer Dank an:
- **Christian (ion.it/Apfelcast)** für Linux-Security-Inspiration
- **ct3003** für praktische Server-Tipps  
- **Dennis Schröder (Raspberry Pi Cloud/ipv64.net)** für seine Ideen und Aufklärung
- **Geek Freaks** für Docker-Best-Practices
- Die **Open-Source-Community** für CrowdSec, Tailscale & NFTables

---

## ⭐ **Star das Repository wenn es dir geholfen hat!**

**Teile es mit anderen, die sichere Server brauchen! 🚀**
