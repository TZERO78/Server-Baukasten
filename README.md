Server-Baukasten v4.0Pragmatisches Starter-Hardening für Home-Server & kleine VPSEin einfaches Bash-Skript, das einen frischen Debian/Ubuntu-Server in ~20 Minuten mit einer soliden, produktionstauglichen Sicherheits-Basis ausstattet.Kernidee: VPN-only (Tailscale) oder gehärteter Public-Mode. Alle nicht benötigten Ports werden per Drop-Policy blockiert.Ziel: Nicht Enterprise-Hardening, sondern ein praktischer Starter für Home- und VPS-User, um Angriffsfläche schnell und zuverlässig zu minimieren.Warum Bash statt Ansible/Puppet?Bewusste Entscheidung für Einfachheit:Keine Dependencies: Läuft sofort auf jedem Standard-ServerVollständig transparent: Jede Zeile Code ist nachvollziehbarZielgruppe: Home-User und VPS-Bastler, nicht Enterprise-AdminsLerneffekt: Du siehst genau, was konfiguriert wirdPortabilität: Funktioniert überall wo Bash verfügbar istAnsible ist technisch "sauberer", aber für die Zielgruppe überdimensioniert. Dieses Script soll schnell und verständlich sein, nicht perfekt.Konzept & PhilosophieDer Server-Baukasten ist ein pragmatisches Starter-Tool mit drei Grundprinzipien:1. Solides SicherheitsfundamentDas Script implementiert mehrere Basisschutz-Schichten: NFTables-Firewall, CrowdSec IPS, GeoIP-Blocking und Kernel-Härtung. Es ist kein vollständiges Enterprise-System, sondern bietet eine sichere Ausgangsbasis für eigene Projekte.2. Einfachheit vor PerfektionBewusst als simples Bash-Script entwickelt - transparent, nachvollziehbar, ohne externe Dependencies. Du behältst die volle Kontrolle und verstehst jeden Schritt.3. Reproduzierbares SetupServer-Konfiguration über Config-File. Ermöglicht identische, gehärtete Server-Setups für Experimente oder Disaster Recovery.Was es NICHT ist: Eine vollautomatische Enterprise-Lösung. Es schafft das sichere Fundament - für spezifische Services musst du selbst Hand anlegen.Zwei SicherheitsmodelleModell 1: VPN-Only (Empfohlen)Server nur über Tailscale VPN erreichbarAlle öffentlichen Ports geschlossenIdeal für private Server und EntwicklungsumgebungenModell 2: Gehärteter Public-ModeServer kann öffentliche Dienste bereitstellenStarkes Sicherheitsfundament durch moderne ToolsDeutlich sicherer als Standard-InstallationenAutomatischer Download von KomponentenDas Script lädt alle benötigten Komponenten automatisch von GitHub:Konfigurationsvorlagen für AIDE, RKHunter und andere ToolsManagement-Skripte wie geoip-manager und update-geoip-setsVorgefertigte Systemd-Units für Timer und ServicesDu benötigst nur das Hauptskript und die Konfigurationsdatei - der Rest wird automatisch geladen.Wichtige VoraussetzungenTailscale-Account erforderlichFür die VPN-Features benötigst du einen kostenlosen Tailscale-Account:Registrierung: tailscale.com (kostenlos für bis zu 20 Geräte)Authentifizierungsmethode wählen:Option A: Auth-Key (Empfohlen für Automatisierung):Bei Tailscale anmelden"Settings" → "Keys" → "Generate auth key"Den Key in die Konfigurationsdatei kopieren. Das Skript kann sich dann automatisch verbinden.Option B: Interaktiver Login (Wenn kein Auth-Key vorhanden):Lasse das TAILSCALE_AUTH_KEY-Feld in der Konfiguration leer.Das Skript wird dir während der Ausführung einen Login-Link anzeigen, den du im Browser öffnen musst.Warum Tailscale?Reduziert die Angriffsfläche drastischVerschlüsselter, sicherer Zugang ohne offene PortsFunktioniert auch hinter NAT/FirewallVerhindert viele Angriffe präventiv - was nicht erreichbar ist, kann schwerer angegriffen werdenSystem-VoraussetzungenServer: Frische Installation von Debian 12 oder Ubuntu 22.04+Zugang: Root-Rechte (temporär für Setup)Internet: Stabile Verbindung für DownloadsE-Mail: SMTP-Server für Benachrichtigungen (optional)Haupt-FeaturesKategorieFeatureBeschreibung👻 Zugang (Zero Trust)Tailscale VPNMacht den Server unsichtbar und bietet sicheren, verschlüsselten Zugang.🛡️ Firewall & IPSNFTables FirewallModerne, modulare Firewall mit policy drop und stabiler Docker-Integration.CrowdSec IPSProaktive, KI-gestützte Abwehr von Angreifern durch Community-Daten.GeoIP-BlockingBlockiert Angriffe aus vordefinierten Risiko-Ländern. Inklusive Management-Tool.🔍 MonitoringAIDE & RKHunterÜberwachen die Datei-Integrität und suchen nach Rootkits.journald-IntegrationZentrale, strukturierte Protokollierung aller Sicherheitsereignisse.⚙️ HardeningKernel-HärtungOptimiert den Linux-Kernel für Sicherheit und Performance.AppArmor EnforcementMandatory Access Control für zusätzliche Sicherheit.SSH-HärtungSichere SSH-Konfiguration mit optionaler Key-based Authentication.🐳 Container (Optional)Docker EngineStellt eine gehärtete Docker-Umgebung bereit, die sauber und stabil mit nftables koexistiert.Management-ToolsInstalliert optional Portainer (Web-UI) und Watchtower (Auto-Updates).🔄 Automatisierungsystemd-TimerAlle wiederkehrenden Aufgaben (Updates, Scans) werden über moderne Timer gesteuert.Unattended-UpgradesHält das System mit Sicherheitspatches automatisch auf dem neuesten Stand.📧 BenachrichtigungenE-Mail-IntegrationAutomatische Benachrichtigungen bei Sicherheitsereignissen via msmtp.🚀 Quick Start (Anfängerfreundlich)1. Hauptskript herunterladen# Mit wget (empfohlen)
wget https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh

# Oder mit curl
curl -O https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/serverbaukasten.sh

# Ausführbar machen
chmod +x serverbaukasten.sh
2. Konfiguration erstellen# Konfigurationsvorlage herunterladen
wget https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/standard.conf

# Eigene Kopie erstellen
cp standard.conf mein-server.conf

# Mit deinem bevorzugten Editor bearbeiten
nano mein-server.conf
Wichtige Werte in der Konfiguration:SERVER_HOSTNAME: Name deines ServersADMIN_USER: Dein Benutzername (nicht "root")ADMIN_PASSWORD: Starkes Passwort für deinen BenutzerROOT_PASSWORD: Starkes Root-PasswortNOTIFICATION_EMAIL: Deine E-Mail für BenachrichtigungenTAILSCALE_AUTH_KEY: Auth-Key von tailscale.com (empfohlen, für interaktiven Login leer lassen)3. Installation starten# Vollständige Installation
sudo ./serverbaukasten.sh -c mein-server.conf

# Schneller Testlauf (für Tests)
sudo ./serverbaukasten.sh -t -c mein-server.conf
4. Befehls-OptionenOptionBeschreibung-c FILEPfad zur Konfigurationsdatei (Pflicht)-tTest-Modus: Überspringt zeitintensive Schritte (System-Update, AIDE-Init, Tailscale-Setup).-vAusführliche Ausgaben-dDebug-Modus-hHilfe anzeigen🔐 Final Lockdown: Wichtigste Schritte nach der InstallationDas Skript hat die Festung gebaut, aber du schließt die Tore ab:1. SSH-Zugang testen (KRITISCH!)Öffne ein neues Terminal und teste den Login, bevor du das alte schließt:# Via normale Server-IP
ssh -p [DEIN_SSH_PORT] [DEIN_ADMIN_USER]@[SERVER_IP]

# Via Tailscale (empfohlen, falls VPN-Setup abgeschlossen)
ssh -p [DEIN_SSH_PORT] [DEIN_ADMIN_USER]@[TAILSCALE_IP]
💡 Profi-Tipp: Zusätzliche Sicherheitsebene (nur bei VPN-Modell)Wenn dein Zugang über Tailscale zuverlässig funktioniert, kannst du die Sicherheit maximieren:Sperre den öffentlichen SSH-Port (z.B. Port 22) direkt in der Firewall deines VPS-Providers (Hetzner Cloud, DigitalOcean etc.).Dein Server ist dann von außen nicht mehr öffentlich erreichbar, aber du kommst weiterhin über das Tailscale-VPN an ihn heran.Sollte Tailscale einmal Probleme machen, kannst du den Port bei deinem Provider mit einem Klick wieder freigeben.2. SSH-Sicherheit maximierenFalls du keinen SSH-Schlüssel hinterlegt hast:# SSH-Key einrichten und Passwort-Login deaktivieren
# In /etc/ssh/sshd_config: PasswordAuthentication no
sudo systemctl restart ssh
3. Root-Konto sperrenNachdem dein sudo-Zugang funktioniert:sudo passwd -l root
4. System neustartensudo reboot
5. GeoIP-Blocking aktivierenNach dem Neustart:sudo geoip-manager update
🔧 System-Management nach dem SetupDein Server ist jetzt so konzipiert, dass er wartungsarm läuft. Hier sind die wichtigsten Befehle:AufgabeBefehlStatus aller Timer anzeigensudo systemctl list-timersFirewall-Regeln prüfensudo nft list rulesetCrowdSec-Statistikensudo cscli metricsGeoIP-Status und -Managementsudo geoip-manager statusSetup-Logs ansehensudo journalctl -t server-baukastenDocker-Container prüfensudo docker ps -aSicherheitslogs filternsudo journalctl -t crowdsec -t aide-check -t rkhunter-check📁 ProjektstrukturServer-Baukasten (nur diese 2 Dateien herunterladen):
├── serverbaukasten.sh        # Hauptskript
└── standard.conf             # Konfigurationsvorlage

Automatisch heruntergeladene Komponenten:
├── components/               # Management-Tools
│   ├── geoip-manager         # GeoIP-Verwaltung
│   └── update-geoip-sets     # GeoIP-Updates
└── conf/                     # Systemkonfigurationen
    ├── aide.conf.template    # AIDE-Monitoring
    └── rkhunter.conf.template # Rootkit-Scanner
Du brauchst nur 2 Dateien: Das Hauptskript und die Konfiguration. Alle anderen Komponenten werden automatisch geladen!🛡️ SicherheitsarchitekturDer Server-Baukasten implementiert eine mehrstufige Sicherheitsarchitektur. Anstatt eines einzigen Datenstroms durchlaufen Anfragen und Systemprozesse mehrere, parallel wirkende Schutzebenen:1. Perimeter-Verteidigung (Traffic-Filter)Der gesamte Traffic aus dem Internet wird von der NFTables Firewall analysiert. In diese sind weitere Schutzmechanismen direkt integriert:CrowdSec IPS: Blockiert proaktiv die IP-Adressen bekannter Angreifer.GeoIP Filter: Weist Anfragen aus vordefinierten Hochrisiko-Ländern ab.2. Host-Sicherheit (System-Härtung)Unabhängig vom Netzwerkverkehr wird der Server selbst auf Betriebssystemebene geschützt:AppArmor: Schränkt die Rechte von laufenden Anwendungen ein (Mandatory Access Control).Kernel-Härtung: Sichert das System auf tiefster Ebene gegen bekannte Angriffsvektoren ab.3. Überwachung & Logging (System-Integrität)Das System wird kontinuierlich auf Anomalien überwacht:AIDE / RKHunter: Scannen das Dateisystem permanent auf unautorisierte Änderungen und Rootkits.journald: Protokolliert alle sicherheitsrelevanten Ereignisse zentral und strukturiert.4. Sicherer Zugang (Optional)Tailscale VPN: Bietet einen optionalen, verschlüsselten "Zero Trust"-Zugang, der den Server aus dem öffentlichen Internet unsichtbar macht. Auch dieser Zugangsweg wird durch die Firewall-Regeln geschützt.Sicherheitsschichten im DetailLayer 1: NFTables-FirewallModulare Architektur: Die Hauptkonfiguration (/etc/nftables.conf) lädt nur alle Regeldateien aus /etc/nftables.d/. Dies ist die Best Practice für eine saubere und erweiterbare Firewall.Stabile Docker-Koexistenz: Nutzt eine bewährte Hybrid-Lösung. Docker steuert die Firewall wie gewohnt über iptables, was durch das iptables-nft Backend ermöglicht wird. Die Baukasten-Regeln nutzen Hook-Prioritäten und eine modulare Struktur, um Konflikte zu vermeiden und einen stabilen, produktionssicheren Betrieb zu gewährleisten.Default DROP Policy: Standardmäßig werden alle eingehenden Verbindungen blockiert. Nur explizit freigegebene Dienste (wie SSH) sind erreichbar.Automatische Regel-Generierung: Das Skript erstellt die Regeln dynamisch basierend auf deiner Server-Konfiguration (z.B. für Tailscale).Layer 2: CrowdSec IPSCommunity-basierte BedrohungserkennungAutomatisches Blocking von AngreifernKollektive Intelligenz aus Millionen von ServernLayer 3: GeoIP-BlockingStatistisch 60-85% weniger Angriffe (je nach Konfiguration)Schutz vor geografischen BedrohungsquellenAutomatischer Heimatland-SchutzLayer 4: AppArmor & Kernel-HärtungMandatory Access Control für AnwendungenDDoS-Schutz und Performance-OptimierungHärtung gegen bekannte AngriffsvektorenLayer 5: Monitoring & LogsAIDE für Datei-IntegritätprüfungRKHunter für Rootkit-ErkennungZentrale, strukturierte ProtokollierungFür öffentliche Dienste optimiertAuch wenn du später Webserver, APIs oder andere Services öffentlich bereitstellen möchtest, bietet dieses Fundament:Erweiterbares Firewall-System - neue Ports lassen sich sicher öffnenAutomatische Angriffserkennung - verdächtige Aktivitäten werden sofort blockiertIntelligente Filterung - Reduzierung des "Rauschens" durch GeoIP-BlockingMonitoring-Infrastruktur - Überwachung auf KompromittierungDas Ergebnis: Ein gehärteter Server, der deutlich widerstandsfähiger ist als Standard-Installationen - mit oder ohne VPN-Schutz.🔒 SicherheitshinweiseAutomatische Bereinigung sensibler DatenDie Konfigurationsdatei enthält kritische Informationen wie:Passwörter (Admin, Root, SMTP)Tailscale Auth-KeysE-Mail-CredentialsDas Skript bietet am Ende automatisch an, diese Datei sicher zu löschen.# Am Ende des Setup-Prozesses erscheint:
"Soll die Konfigurationsdatei jetzt sicher gelöscht werden? (ja/nein, Standard: ja)"

# Empfehlung: Immer mit "ja" bestätigen!
Manuelle BereinigungFalls du die Datei später manuell löschen möchtest:# Sichere Löschung (überschreibt Daten mehrfach)
shred -n 3 -uz mein-server.conf

# Normale Löschung
rm mein-server.conf
Warum ist das wichtig?Verhindert Zugriff auf Credentials bei Server-KompromittierungEntspricht Security-Best-PracticesReduziert Angriffsfläche nach dem Setup🔧 Erweiterte KonfigurationWichtige Konfigurationswerte erklärt# Basis-Setup
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
GeoIP-Länder-CodesRegionHäufige CodesDeutschlandDE, AT, CHEuropaFR, IT, ES, NL, BE, SE, NO, DK, PLWeitereUS, CA, AU, JP, SG, KROft blockiertCN, RU, KP, IR, BY, MMSMTP-BeispieleGmail:SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USER="deine-email@gmail.com"
SMTP_PASSWORD="app-passwort"  # Nicht dein normales Passwort!
Outlook:SMTP_HOST="smtp-mail.outlook.com"
SMTP_PORT="587"
SMTP_USER="deine-email@outlook.com"
SMTP_PASSWORD="dein-passwort"
📄 LizenzDieses Projekt steht unter der MIT-Lizenz.🙏 DanksagungenEin besonderer Dank für die Inspiration und die vielen Denkanstöße gilt den YouTube-Kanälen von Christian (ion.it/Apfelcast), ct3003, Raspberry Pi Cloud und Geek Freaks sowie der gesamten Linux- und Open-Source-Community.🤝 BeitragenWICHTIG: Da dieses Skript root-Rechte verwendet und kritische Systemkonfigurationen ändert, werden alle Änderungen sorgfältig geprüft.Vor einem Pull Request:Issue erstellen - Beschreibe deine Idee/den Bugfix zuerstDiskussion abwarten - Lass uns über den Ansatz sprechenDann erst Code - Fork und Pull Request nach FreigabeAkzeptierte Beiträge:Bugfixes und SicherheitsverbesserungenBessere Dokumentation und BeispieleUnterstützung für weitere Linux-DistributionenPerformance-OptimierungenNicht akzeptiert:Grundlegende Architektur-Änderungen ohne vorherige DiskussionCode ohne ausreichende KommentierungFeatures die die Sicherheit verringern könntenSicherheit hat oberste Priorität - jeder Code-Beitrags wird eingehend geprüft bevor er ins Hauptprojekt übernommen wird.⭐ Star dieses Repository wenn es dir geholfen hat!
