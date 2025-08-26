#!/bin/bash
################################################################################
# SERVER BAUKASTEN
#
# @description: Ein Skript zur vollautomatischen Härtung von Linux-Servern.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Copyright (c) 2025 Markus F. (TZERO78)
#
# Dieses Skript steht unter der MIT-Lizenz.
# Eine Kopie der Lizenz finden Sie in der 'LICENSE'-Datei im Repository
# oder unter: https://opensource.org/licenses/MIT
# ==============================================================================
# Zweck: Richtet einen neuen Debian/Ubuntu-Server nach einem festen,
#        extrem sicheren und modernen Standard ein.
#
# USAGE:
#   Automatisch: sudo ./serverbaukasten.sh -c /pfad/zur/config.conf
#   Hilfe:      sudo ./serverbaukasten.sh -h
################################################################################

# --- Sicherheits-Präambel ---
# Stellt sicher, dass das Skript bei Fehlern sofort abbricht (set -e)
# und Fehler in einer Pipe-Kette weitergegeben werden (set -o pipefail).
set -e
set -o pipefail

readonly SCRIPT_VERSION="4.0.1"
readonly CROWDSEC_MAXRETRY_DEFAULT=5
readonly CROWDSEC_BANTIME_DEFAULT="48h" 
readonly SSH_PORT_DEFAULT=22
readonly NOTIFICATION_EMAIL_DEFAULT="admin@example.com"  # Generic für Community
readonly COMPONENTS_BASE_URL="https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/components"
readonly CONF_BASE_URL="https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/conf"

# Globale Verbose/Debug-Variablen
declare -g SCRIPT_VERBOSE=false
declare -g DEBUG=false
declare -g TEST_MODE=false

# --- Einfache Log-Funktionen für die Initialisierungsphase ---
# Diese werden später von core_helpers.sh überschrieben.
log_info() { echo -e "\033[0;36mℹ️  $*\033[0m"; }
log_ok() { echo -e "\033[0;32m✅ $*\033[0m"; }
log_error() { echo -e "\033[0;31m❌ $*\033[0m" >&2; exit 1; }

# Globale Variablen für den Skript-Zustand
declare -a BACKUP_FILES
CONFIG_FILE=""

##
##  Läd alle Bibliotheken aus dem './lib'-Verzeichnis.
##  Diese Bibliotheken enthalten Funktionen für Logging, UI, Validierung,
##  Konfigurationsmanagement und die einzelnen Setup-Module.
##  Jede Bibliothek sollte eigene log_* Aufrufe für Feedback enthalten.
##
load_libary() {
    log_info "Lade alle Helfer-Bibliotheken aus dem './lib'-Verzeichnis..."
    for file in ./lib/*.sh; do
        if [ -f "$file" ]; then
            source "$file"
            log_ok "  -> '$file' geladen."
        fi
    done
    log_ok "Alle Helfer-Bibliotheken wurden geladen."
}




################################################################################
#
#                                 HAUPTLOGIK
#
################################################################################

##
# Haupt-Einstiegspunkt des Skripts. Verarbeitet Argumente und startet das Setup.
##
main() {
    check_root

    # --- Argumente verarbeiten ---
    local TEST_MODE=false
    CONFIG_FILE=""
    
    # KORRIGIERT: -t für Test-Modus hinzugefügt
    while getopts ":c:thvd" opt; do
        case ${opt} in
            c) CONFIG_FILE=$OPTARG;;
            t) TEST_MODE=true;; # <-- DIESE ZEILE HAT GEFEHLT
            h) show_usage; exit 0;;
            v) SCRIPT_VERBOSE=true;;
            d) DEBUG=true; SCRIPT_VERBOSE=true;;
            \?) log_error "Ungültige Option: -$OPTARG"; show_usage; exit 1;;
            :) log_error "Option -$OPTARG benötigt ein Argument."; show_usage; exit 1;;
        esac
    done
    

    # --- KRITISCHE VORAB-PRÜFUNG: Konfigurationsdatei ---
    # 1. Prüfen, ob der Parameter -c überhaupt gesetzt wurde.
    if [ -z "$CONFIG_FILE" ]; then
        log_error "Fehler: Keine Konfigurationsdatei mit '-c' angegeben."
        show_usage
        exit 1
    fi

    # 2. Prüfen, ob die angegebene Datei existiert und lesbar ist.
    #    Dies geschieht VOR jeder anderen Aktion.
    if [ ! -r "$CONFIG_FILE" ]; then
        log_error "Fehler: Konfigurationsdatei nicht gefunden oder nicht lesbar: $CONFIG_FILE"
        exit 1
    fi

    export SCRIPT_VERBOSE DEBUG
    trap 'rollback' ERR

    log_info "🚀 Starte Server-Baukasten v$SCRIPT_VERSION..."
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS ist aktiviert. Zeitaufwändige Operationen werden übersprungen."
    fi
    if [ -n "$CONFIG_FILE" ]; then
        log_info "Verwende Konfigurationsdatei: $CONFIG_FILE"
    fi

    run_setup "$TEST_MODE"
    
    # Fehlerfalle nach erfolgreichem Setup deaktivieren
    trap - ERR
    
    # Sicherheits-Cleanup VOR der Zusammenfassung
    cleanup_sensitive_data "$TEST_MODE"

    show_summary
    
    if [ "$TEST_MODE" = true ]; then
        log_ok "Test-Setup erfolgreich abgeschlossen! ⚡"
    else
        log_ok "Server-Setup erfolgreich abgeschlossen! 🎉"
    fi
}

##
# Führt die einzelnen Setup-Module in einer logisch korrekten Reihenfolge aus.
# @param bool $1 Test-Modus (true/false).
##
run_setup() {
    local TEST_MODE="$1"
    
    # --- Phase 1: Vorbereitung ---
    log_info "Phase 1/5: Vorbereitung..."
    pre_flight_checks
    load_config_from_file "$CONFIG_FILE" 
    module_cleanup


    # --- Phase 2: System-Fundament ---
    log_info "Phase 2/5: System-Fundament (OS, Pakete, Kernel)..."
    detect_os
    module_fix_apt_sources
    module_base
    module_system_update "$TEST_MODE"
    # WICHTIG: Kernel-Härtung VOR den Diensten, die davon abhängen (z.B. IP-Forwarding für Docker)
    module_kernel_hardening

   # --- Phase 3: Sicherheits-Architektur ---
    log_info "Phase 3/5: Sicherheits-Architektur (Firewall, IPS, Monitoring)..."
    # Die Sicherheit wird bewusst am Ende konfiguriert, wenn alle Dienste laufen und ihre Ports bekannt sind
    module_security "$TEST_MODE"
    

    # --- Phase 4: Kern-Dienste (Netzwerk & Container) ---
    log_info "Phase 4/5: Kern-Dienste (Netzwerk & Container)..."
    module_network "$TEST_MODE" 
    if [ "$SERVER_ROLE" = "1" ]; then
        module_container # Docker Daemon
        module_deploy_containers # Portainer, Watchtower
    fi
 
    # --- Phase 5: Abschluss-Arbeiten ---
    log_info "Phase 5/5: Abschluss-Arbeiten (Mail, Logs, Backup, Verifikation)..."
    module_mail_setup
    module_journald_optimization
    module_verify_setup
    cleanup_admin_sudo_rights
}

# ===============================================================================
#                    AIDE & RKHUNTER JOURNALD-INTEGRATION
# ===============================================================================

##
# Konfiguriert AIDE durch Herunterladen des Templates und Erstellen der systemd-Units.
##
configure_aide() {
    log_info "Konfiguriere AIDE (System-Integritäts-Monitoring)..."
    
    # --- Schritt 1: Deaktiviere Standard-Timer ---
    systemctl disable --now dailyaidecheck.timer >/dev/null 2>&1 || true

    # --- Schritt 2: Verzeichnisse erstellen ---
    mkdir -p /etc/aide /var/lib/aide /var/log/aide
    chown root:root /etc/aide /var/lib/aide
    chmod 750 /etc/aide /var/lib/aide
    chown root:adm /var/log/aide
    chmod 750 /var/log/aide
   
    # --- Schritt 3: Lade Konfigurations-Template herunter ---
    download_and_process_template "aide.conf.template" "/etc/aide/aide.conf" "640" "root:root"

    # AIDE-spezifisches Log-Directory (nur als Backup)
    mkdir -p /var/log/aide
    chown root:adm /var/log/aide
    chmod 750 /var/log/aide

    # 3. Systemd Service 
    cat > /etc/systemd/system/aide-check.service << 'EOF'
[Unit]
Description=AIDE File Integrity Check
Documentation=man:aide(1)
After=multi-user.target

[Service]
Type=oneshot
User=root

# KORRIGIERT: Check if database exists, if not create it
ExecStartPre=/bin/bash -c 'if [ ! -f /var/lib/aide/aide.db ]; then /usr/bin/aide --config /etc/aide/aide.conf --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db; fi'

# KORRIGIERT: Run the integrity check with structured output
ExecStart=/usr/bin/aide --config /etc/aide/aide.conf --check

# journald-optimized output
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aide-check

# Structured logging environment
Environment="SYSTEMD_LOG_LEVEL=info"
Environment="SYSTEMD_LOG_TARGET=journal"

# Performance optimization (VPS-friendly)
TimeoutStartSec=45min
CPUQuota=40%
Nice=19
IOSchedulingClass=2
IOSchedulingPriority=7

# Security hardening
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/aide /var/log/aide /tmp

# Exit codes: AIDE-specific handling
# 0 = No changes, 1 = New files, 2 = Removed files, 3 = Changed files
# 4 = Changed and new files, 5 = Changed and removed, 6 = New and removed
# 7 = All types of changes, 14 = Error writing database
SuccessExitStatus=0 1 2 3 4 5 6 7

[Install]
# IMPORTANT: Don't enable service directly - only via timer!
WantedBy=
EOF

    # 4. Systemd Timer
    cat > /etc/systemd/system/aide-check.timer << 'EOF'
[Unit]
Description=Run AIDE integrity check daily
Documentation=man:systemd.timer(5)
Requires=aide-check.service

[Timer]
# Daily at 5:00 AM (low system load time)
OnCalendar=*-*-* 05:00:00

# Randomize up to 30 minutes (spread server load)
RandomizedDelaySec=1800

# Run even if system was down
Persistent=true

# Explicit service reference
Unit=aide-check.service

[Install]
WantedBy=timers.target
EOF

   # 5. journald-Konfiguration neu laden und systemd-Units aktivieren
    run_with_spinner "Lade systemd-Konfiguration neu..." "systemctl restart systemd-journald && systemctl daemon-reload"
    
    # --- Schritt 6: Aktiviere den neuen Timer (für zukünftige Starts) ---
    systemctl daemon-reload
    if ! run_with_spinner "Aktiviere AIDE-Timer für zukünftige Starts..." "systemctl enable aide-check.timer"; then
        log_warn "AIDE-Timer konnte nicht für den Systemstart aktiviert werden."
    fi
    
    log_ok "AIDE-Konfiguration abgeschlossen und Timer für nächsten Boot vorgemerkt."
    log_info "  📜 Logs abrufen mit: journalctl -u aide-check.service"
    log_info "  📊 Timer-Status prüfen mit: systemctl list-timers aide-check.timer"
}

##
# Konfiguriert RKHunter (Rootkit-Scanner) für die Ausführung via systemd-Timer
# und leitet die Ausgabe direkt an das journald-Log um.
##
configure_rkhunter() {
    log_info "Konfiguriere RKHunter..."
    
    # --- Schritt 1: Lade Konfigurations-Template herunter ---
    download_and_process_template "rkhunter.conf.template" "/etc/rkhunter.conf" "640" "root:root"
    
    # RKHunter-spezifische journald-Konfiguration
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/rkhunter-logging.conf << 'EOF'
# RKHunter-optimierte journald-Konfiguration
[Journal]
# RKHunter-Logs persistent speichern (wichtig für Security-Audit)
Storage=persistent

# Längere Aufbewahrung für Security-Logs
MaxRetentionSec=16week

# Komprimierung für RKHunter-Reports
Compress=yes

# Security-Logs haben Priorität - größere Limits
SystemMaxUse=350M
SystemMaxFileSize=40M

# Rate-Limiting für RKHunter-Scans anpassen
RateLimitIntervalSec=120s
RateLimitBurst=30000
EOF

    # 3. Mail nur wenn aktiviert
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ] && [ -n "${NOTIFICATION_EMAIL:-}" ]; then
        echo "MAIL-ON-WARNING=\"$NOTIFICATION_EMAIL\"" >> /etc/rkhunter.conf
        echo "MAIL_CMD=mail -s \"[rkhunter] \$(hostname)\"" >> /etc/rkhunter.conf
        log_info "Mail aktiviert für $NOTIFICATION_EMAIL"
    fi
    
    # 4. Datenbank initialisieren
    log_info "Initialisiere RKHunter-Pfade und Datenbank..."
    
    # Stelle sicher, dass alle benötigten Verzeichnisse existieren
    mkdir -p /var/lib/rkhunter/tmp
    mkdir -p /var/lib/rkhunter/db
    chown root:root /var/lib/rkhunter/tmp /var/lib/rkhunter/db
    chmod 755 /var/lib/rkhunter/tmp /var/lib/rkhunter/db
    
    # Prüfe ob kritische Pfade existieren
    local missing_paths=()
    [ ! -d /usr/share/rkhunter/scripts ] && missing_paths+=("SCRIPTDIR")
    [ ! -d /usr/share/rkhunter ] && missing_paths+=("INSTALLDIR")
    
    if [ ${#missing_paths[@]} -gt 0 ]; then
        log_error "Kritische RKHunter-Pfade fehlen: ${missing_paths[*]}"
        log_warn "RKHunter-Paket ist beschädigt oder nicht vollständig installiert"
        log_info "Lösung: sudo apt-get remove --purge rkhunter && sudo apt-get install rkhunter"
        log_warn "Überspringe RKHunter-Konfiguration..."
        return 0
    fi
    
    rkhunter --update --quiet || true
    rkhunter --propupd --quiet || true
    
    # 5. Systemd Service (journald-optimiert)
    cat > /etc/systemd/system/rkhunter-check.service << 'EOF'
[Unit]
Description=RKHunter Security Check (Rootkit Detection)
Documentation=man:rkhunter(8)
After=multi-user.target

[Service]
Type=oneshot
User=root

# Update signatures if needed
ExecStartPre=-/usr/bin/rkhunter --update --quiet

# Main security scan with structured output
ExecStart=/usr/bin/rkhunter --check --cronjob --report-warnings-only

# journald-optimized output
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rkhunter-check

# Structured logging environment
Environment="SYSTEMD_LOG_LEVEL=info"
Environment="SYSTEMD_LOG_TARGET=journal"

# Performance settings (VPS-optimized)
TimeoutStartSec=20min
CPUQuota=25%
Nice=19

# Security hardening
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rkhunter /var/log /tmp

# RKHunter-specific exit codes as success
# 0 = OK, 1 = Warnings found, 2 = Errors (but scan completed)
SuccessExitStatus=0 1 2

[Install]
# IMPORTANT: Don't enable service directly - only via timer!
WantedBy=
EOF

    # 6. Systemd Timer
    cat > /etc/systemd/system/rkhunter-check.timer << 'EOF'
[Unit]
Description=Run RKHunter security check weekly
Documentation=man:systemd.timer(5)
Requires=rkhunter-check.service

[Timer]
# Weekly on Sunday at 4:00 AM (low system load)
OnCalendar=Sun *-*-* 04:00:00

# Randomize up to 30 minutes (spread server load)
RandomizedDelaySec=1800

# Run even if system was down
Persistent=true

# Explicit service reference
Unit=rkhunter-check.service

[Install]
WantedBy=timers.target
EOF

    # 7. journald-Konfiguration neu laden und aktivieren
    systemctl restart systemd-journald
    systemctl daemon-reload
    systemctl enable --now rkhunter-check.timer
    
    log_ok "RKHunter konfiguriert (wöchentlich sonntags 4:00-4:30 Uhr, journald-optimiert)"
    log_info "Logs: journalctl -u rkhunter-check.service"
    log_info "Security-Filter: journalctl -t rkhunter-check"
    log_info "Timer-Status: systemctl list-timers rkhunter-check.timer"
}


##
# MODUL: Konfiguriert die zentrale Log-Verwaltung via journald.
##


##
# MODUL: Überprüft den Status aller kritischen und wichtigen Services.
##



##
# Zeigt eine praxisorientierte Zusammenfassung mit den wichtigsten Informationen
# und den nächsten Schritten für den Administrator an.
##
show_summary() {
    local server_ip
    server_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "Unbekannt")
    
    echo -e "${GREEN}🎉 Server-Setup erfolgreich abgeschlossen! 🎉${NC}\n"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ZUGANGS-INFORMATIONEN (kritisch für nächste Schritte)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "ZUGANGS-INFORMATIONEN" "GREEN"
    print_summary_entry "Server" "${SERVER_HOSTNAME:-$(hostname)} ($server_ip)"
    print_summary_entry "SSH-Befehl" "ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$server_ip"
    print_summary_entry "Admin-User" "${ADMIN_USER:-admin} (sudo-Berechtigung)"
    
    # SSH-Key-Status (wichtig für Sicherheit)
    if [ -n "${SSH_PUBLIC_KEY:-}" ]; then
        print_summary_entry "SSH-Key" "✅ Konfiguriert"
        print_ssh_host_keys
        print_summary_tip "SSH-Key ist aktiv - Passwort-Login kann deaktiviert werden"
    else
        print_summary_entry "SSH-Key" "❌ Nicht konfiguriert"
        print_summary_warning "SSH-Key nach erstem Login einrichten!"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TAILSCALE VPN (falls konfiguriert - wichtig für sicheren Zugang)
    # ═══════════════════════════════════════════════════════════════════════════
    if [ "${ACCESS_MODEL:-}" = "1" ] && command -v tailscale >/dev/null 2>&1; then
        print_summary_header "TAILSCALE VPN-ZUGANG" "PURPLE"
        local tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "")
        local tailscale_status=$(tailscale status --json 2>/dev/null | grep -o '"Online":[^,]*' | cut -d: -f2 || echo "false")
        
        if [ -n "$tailscale_ip" ] && [ "$tailscale_status" = "true" ]; then
            print_summary_entry "VPN-Status" "✅ Verbunden"
            print_summary_entry "VPN-IP" "$tailscale_ip"
            print_summary_entry "SSH via VPN" "ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$tailscale_ip"
            print_summary_tip "VPN ist aktiv - sicherster Zugangsweg!"
        else
            print_summary_entry "VPN-Status" "⚠️ Nicht verbunden"
            print_summary_warning "Tailscale-Autorisierung abschließen!"
            print_summary_tip "Befehl: sudo tailscale up"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # DOCKER-INFORMATIONEN (falls installiert - wichtig für Container-Verwaltung)
    # ═══════════════════════════════════════════════════════════════════════════
    if [ "${SERVER_ROLE:-}" = "1" ] || systemctl is-active --quiet docker 2>/dev/null; then
        print_summary_header "DOCKER-CONTAINER" "CYAN"
        
        if systemctl is-active --quiet docker; then
            print_summary_entry "Docker-Status" "✅ Aktiv"
            
            # Docker-Netzwerk-Info (wichtig für Container-Konfiguration)
            local docker_network=$(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || echo "Standard")
            print_summary_entry "Docker-Netz" "$docker_network"
            
            # Portainer (wichtig für Web-Management)
            if [ "${INSTALL_PORTAINER:-}" = "ja" ]; then
                local portainer_ip="${PORTAINER_FINAL_IP:-127.0.0.1}"
                local portainer_status="❌ Nicht erreichbar"
                
                if docker ps --filter name=portainer --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
                    portainer_status="✅ Läuft"
                fi
                
                print_summary_entry "Portainer" "$portainer_status"
                print_summary_entry "Portainer-URL" "https://$portainer_ip:9443"
                
                if [ "$portainer_ip" = "127.0.0.1" ]; then
                    print_summary_tip "SSH-Tunnel: ssh -L 9443:localhost:9443 ${ADMIN_USER:-admin}@$server_ip"
                fi
            fi
            
            # Watchtower (Auto-Updates)
            if [ "${INSTALL_WATCHTOWER:-}" = "ja" ] && docker ps --filter name=watchtower --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
                print_summary_entry "Auto-Updates" "✅ Watchtower aktiv (täglich 04:00)"
            fi
            
        else
            print_summary_entry "Docker-Status" "❌ Problem"
            print_summary_warning "Docker-Service prüfen: systemctl status docker"
        fi
    fi
    # ═══════════════════════════════════════════════════════════════════════════
    # AUTOMATISCHE WARTUNG (systemd-Timer - komplett automatisch)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "AUTOMATISCHE WARTUNG (SYSTEMD-TIMER)" "YELLOW"

    # Finde alle Timer
    local all_timers=$(systemctl list-unit-files --type=timer 2>/dev/null | grep "\.timer" | awk '{print $1}' | sort)

    local active_count=0
    local total_count=0

    # Durchlaufe alle gefundenen Timer
    while read -r timer_name; do
        if [ -n "$timer_name" ]; then
            ((total_count++))
            
            # Timer-Name formatieren (ohne .timer, Bindestriche zu Leerzeichen)
            local display_name=$(echo "$timer_name" | sed 's/\.timer$//' | sed 's/-/ /g')
            
            if systemctl is-active --quiet "$timer_name" 2>/dev/null; then
                ((active_count++))
                local next_run=$(systemctl list-timers "$timer_name" --no-pager 2>/dev/null | grep "$timer_name" | awk '{print $1, $2}' | head -1 || echo "Unbekannt")
                print_summary_entry "$display_name" "✅ Aktiv (Nächster: $next_run)"
            else
                print_summary_entry "$display_name" "❌ Inaktiv"
            fi
        fi
    done <<< "$all_timers"

    if [ "${ENABLE_GEOIP_BLOCKING:-}" = "ja" ]; then
        print_summary_header "GEOIP BLOCKING" "YELLOW"
        print_summary_entry "Status & Statistiken" "geoip-manager status"
        print_summary_entry "Manuelles Update" "geoip-manager update"
        print_summary_entry "Logs anzeigen" "geoip-manager logs"
        print_summary_tip "Blockierte Länder: ${BLOCKED_COUNTRIES:-Keine}"
        print_summary_tip "Geschütztes Heimatland: ${HOME_COUNTRY:-Keines}"
    fi

    # Zusammenfassung
    print_summary_entry "Timer Status" "$active_count von $total_count aktiv"
    print_summary_tip "Alle Timer: systemctl list-timers"

    # ═══════════════════════════════════════════════════════════════════════════
    # SOFORT-AKTIONEN (Was jetzt gemacht werden muss)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "SOFORT-AKTIONEN (IN DIESER REIHENFOLGE)" "RED"
    
    echo -e "    ${RED}1. SSH-ZUGANG TESTEN (KRITISCH!)${NC}"
    echo -e "       ${CYAN}ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$server_ip${NC}"
    if [ -n "$tailscale_ip" ]; then
        echo -e "       ${PURPLE}Oder via VPN: ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$tailscale_ip${NC}"
    fi
    echo ""
    
    echo -e "    ${RED}2. SSH-SICHERHEIT MAXIMIEREN${NC}"
    if [ -z "${SSH_PUBLIC_KEY:-}" ]; then
        echo -e "       ${YELLOW}• SSH-Key einrichten (empfohlen!)${NC}"
        echo -e "       ${YELLOW}• Dann PasswordAuthentication no setzen${NC}"
    else
        print_summary_tip "SSH-Key bereits konfiguriert"
    fi
    echo ""
    
    echo -e "    ${RED}3. ROOT-ZUGANG SPERREN${NC}"
    echo -e "       ${CYAN}sudo passwd -l root${NC}"
    echo ""
    
    echo -e "    ${RED}4. SYSTEM NEUSTARTEN${NC}"
    echo -e "       ${CYAN}sudo reboot${NC}"
    echo ""
    
    # ═══════════════════════════════════════════════════════════════════════════
    # VERIFIKATIONS-BEFEHLE (für Kontrolle nach Neustart)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "VERIFIKATION NACH NEUSTART" "BLUE"
    echo -e "    ${BLUE}Firewall:${NC} sudo nft list ruleset | head -20"
    echo -e "    ${BLUE}Services:${NC} systemctl status ssh nftables"
    if command -v crowdsec >/dev/null 2>&1; then
        echo -e "    ${BLUE}IPS:${NC} systemctl status crowdsec"
    fi
    echo -e "    ${BLUE}Updates:${NC} systemctl list-timers"
    echo -e "    ${BLUE}Logs:${NC} journalctl -f"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # WICHTIGE DATEIEN & BEFEHLE (für spätere Verwaltung)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "WICHTIGE DATEIEN & BEFEHLE" "PURPLE"
    print_summary_entry "Setup-Log" "$LOG_FILE"
    print_summary_entry "SSH-Config" "/etc/ssh/sshd_config"
    print_summary_entry "Firewall-Config" "/etc/nftables.conf"
    
    if [ "${ENABLE_GEOIP_BLOCKING:-}" = "ja" ]; then
        print_summary_entry "GeoIP-Management" "geoip-manager status"
    fi
    
    if systemctl is-active --quiet docker 2>/dev/null; then
        print_summary_entry "Docker-Container" "docker ps -a"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FOOTER mit kritischen Hinweisen
    # ═══════════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${RED}⚠️  KRITISCH: Teste SSH-Zugang BEVOR du das Terminal schließt!${NC}"
    echo -e "${YELLOW}💡 Bei Problemen: Rescue-Mode des VPS-Providers nutzen${NC}"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}   🚀 Server bereit für Finalisierung! Folge den Sofort-Aktionen oben.        ${NC}"
    echo -e "${BLUE}   📊 Setup-Details: $LOG_FILE${NC}"
    echo -e "${BLUE}   ⏰ Setup abgeschlossen: $(date '+%d.%m.%Y %H:%M')${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
}

#################################################################################
#                             INITIALISIERUNG
#           CrobdSec Stack und Bouncer-Installation fuer NFTables
################################################################################
##
# Installiert den CrowdSec Agenten und den Firewall Bouncer.
##
install_crowdsec_stack() {
    log_info "⚙️  Installiere und konfiguriere den CrowdSec-Stack..."

    # --- 1. CrowdSec Repository hinzufügen (falls nötig) ---
    if [ ! -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then
        log_info "  -> Füge CrowdSec APT-Repository hinzu..."
        local install_script="/tmp/crowdsec-install.sh"
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh -o "$install_script"
        
        if grep -q "packagecloud" "$install_script"; then
            run_with_spinner "Richte APT-Repository ein und aktualisiere..." "bash '$install_script' && apt-get update -qq"
        else
            log_error "Das heruntergeladene CrowdSec-Installationsskript scheint ungültig zu sein."
            rm -f "$install_script"
            return 1
        fi
        rm -f "$install_script"
    fi

    # --- 2. CrowdSec Agent sauber installieren ---
    log_info "  -> Installiere CrowdSec Agenten (ggf. Re-Installation)..."
    local install_cmd="apt-get remove --purge -y crowdsec >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"
    if ! run_with_spinner "Installiere 'crowdsec' Paket..." "$install_cmd"; then
        log_error "Installation des CrowdSec Agenten ist fehlgeschlagen."
        return 1
    fi

    # --- 3. systemd-Verhalten anpassen ---
    log_info "  -> Konfiguriere CrowdSec für netzwerkabhängigen Start..."
    mkdir -p /etc/systemd/system/crowdsec.service.d
    cat > /etc/systemd/system/crowdsec.service.d/override.conf <<EOF
[Unit]
After=network.target
[Service]
Restart=on-failure
RestartSec=30s
EOF

    # --- 4. Firewall Bouncer installieren ---
    # Die Funktion install_bouncer sollte ihr eigenes, sauberes Logging haben.
    install_bouncer

    # --- 5. Services aktivieren und Start verifizieren ---
    log_info "  -> Aktiviere CrowdSec-Dienste und warte auf den Start..."
    systemctl daemon-reload
    systemctl enable --now crowdsec >/dev/null 2>&1

    # Ein Befehl, der 30s lang versucht, die API zu erreichen
    local wait_cmd="
        for i in {1..30}; do
            if systemctl is-active --quiet crowdsec && cscli metrics &>/dev/null; then exit 0; fi
            sleep 1
        done
        exit 1"
    
    if run_with_spinner "Warte auf CrowdSec-API..." "bash -c \"$wait_cmd\""; then
        log_ok "CrowdSec-Agent ist erfolgreich gestartet und API ist erreichbar."
        return 0
    else
        log_error "CrowdSec-Agent konnte nicht gestartet werden oder die API antwortet nicht."
        return 1
    fi
}
##
# Installiert und konfiguriert den CrowdSec Firewall Bouncer für NFTables.
# KORRIGIERTE VERSION - Kombiniert bewährte Teile der alten mit neuen Verbesserungen
##
install_bouncer() {
    log_info "🐾 Installiere CrowdSec-Bouncer (NFTables-Integration)..."

    # --- 1. Voraussetzungen prüfen (wie in neuer Version) ---
    log_info "  -> Prüfe Voraussetzungen (CrowdSec-Service & API)..."
    if ! systemctl is-active --quiet crowdsec; then
        log_error "Voraussetzung nicht erfüllt: CrowdSec-Service läuft nicht."
        return 1
    fi
    if ! cscli metrics >/dev/null 2>&1; then
        log_error "Voraussetzung nicht erfüllt: CrowdSec API ist nicht erreichbar."
        return 1
    fi
    log_ok "Voraussetzungen erfüllt: CrowdSec-Service und API sind erreichbar."

    # --- 2. Bouncer-Paket sauber installieren (wie in alter Version) ---
    local pkg="crowdsec-firewall-bouncer"
    local dir="/etc/crowdsec/bouncers"
    local base_yml="$dir/crowdsec-firewall-bouncer.yaml"
    local local_yml="$dir/crowdsec-firewall-bouncer.yaml.local"
    local keyfile="$dir/.api_key"  # BEWÄHRT: Separater Keyfile wie in alter Version
    
    local install_cmd="apt-get remove --purge -y '$pkg' >/dev/null 2>&1 || true; rm -rf '$dir'; DEBIAN_FRONTEND=noninteractive apt-get install -y '$pkg'"
    if ! run_with_spinner "Installiere Bouncer-Paket (ggf. Re-Installation)..." "$install_cmd"; then
        log_error "Installation des Bouncer-Pakets ist fehlgeschlagen."
        return 1
    fi
    if [ ! -f "$local_yml" ]; then
        log_error "Bouncer-Konfigurationsdatei wurde nicht erstellt."
        return 1
    fi

    # --- 3. Konfiguriere für NFTables-Modus (bewährte alte Logik) ---
    log_info "  -> Konfiguriere NFTables-Modus..."
    cp "$base_yml" "$local_yml"
    
    if grep -q '${BACKEND}' "$local_yml" 2>/dev/null; then
        sed -i 's/mode: ${BACKEND}/mode: nftables/' "$local_yml"
        log_info "     🔧 Template-Modus → nftables"
    else
        if command -v yq &>/dev/null; then
            yq -i -y '.mode = "nftables"' "$local_yml"
        else
            if grep -q '^mode:' "$local_yml"; then
                sed -i 's/^mode:.*/mode: nftables/' "$local_yml"
            else
                sed -i '1i mode: nftables' "$local_yml"
            fi
        fi
        log_info "     🔧 NFTables-Modus direkt gesetzt"
    fi
    
    # Logging-Level optimieren
    sed -i 's/debug: .*/debug: false/' "$local_yml" 2>/dev/null || true
    sed -i 's/log_level: .*/log_level: info/' "$local_yml" 2>/dev/null || true
    
    # --- 4. API-Schlüssel generieren (bewährte alte Methode) ---
    log_info "  -> Generiere und konfiguriere API-Schlüssel..."
    
    if [ ! -s "$keyfile" ]; then
        install -o root -g root -m600 /dev/null "$keyfile"
        if ! cscli bouncers add firewall-bouncer -o raw >"$keyfile"; then
            log_error "API-Key-Generierung fehlgeschlagen!"
            return 1
        fi
    fi
    
    local api_key
    api_key=$(cat "$keyfile" 2>/dev/null | tr -d '\n\r')
    if [ -n "$api_key" ]; then
        if grep -q '${API_KEY}' "$local_yml" 2>/dev/null; then
            sed -i "s|\${API_KEY}|$api_key|g" "$local_yml"
        else
            if command -v yq &>/dev/null; then
                yq -i -y ".api_key = \"$api_key\"" "$local_yml"
            else
                if grep -q 'api_key:' "$local_yml"; then
                    sed -i "s/api_key:.*/api_key: $api_key/" "$local_yml"
                else
                    echo "api_key: $api_key" >> "$local_yml"
                fi
            fi
        fi
        log_info "     🔑 API-Key konfiguriert"
    else
        log_error "API-Key ist leer!"
        return 1
    fi
    log_ok "API-Schlüssel erfolgreich in Konfiguration eingetragen."

    # --- 5. systemd-Integration (KORRIGIERT - alte bewährte Methode) ---
    log_info "  -> Konfiguriere systemd-Integration..."
    local override_dir="/etc/systemd/system/crowdsec-firewall-bouncer.service.d"
    
    # Bereinige alte Override-Files (verhindert Konflikte)
    if [ -d "$override_dir" ]; then
        log_info "     -> Bereinige alte Override-Konfigurationen..."
        rm -rf "$override_dir"
    fi
    mkdir -p "$override_dir"

    # KORRIGIERT: Verwende bewährte systemd-Konfiguration aus alter Version
    cat > "$override_dir/override.conf" <<EOF
[Unit]
After=multi-user.target crowdsec.service
Requires=crowdsec.service

[Service]
# Verwende lokale Konfiguration (WICHTIG: ExecStart muss zurückgesetzt werden!)
ExecStartPre=
ExecStart=
ExecStartPre=/bin/bash -c 'until cscli metrics >/dev/null 2>&1; do sleep 2; done'
ExecStartPre=/usr/bin/crowdsec-firewall-bouncer -c $local_yml -t
ExecStart=/usr/bin/crowdsec-firewall-bouncer -c $local_yml

# Auto-Recovery bei Problemen
Restart=on-failure
RestartSec=15s

[Install]
# Separate Boot-Phase - startet NACH multi-user.target
WantedBy=default.target
EOF

    # --- 6. Health-Check-System (alte bewährte Version) ---
    log_info "  -> Installiere Health-Check-System..."
    install -m755 /dev/null /usr/local/bin/crowdsec-healthcheck
    cat > /usr/local/bin/crowdsec-healthcheck <<'EOF'
#!/bin/bash
# CrowdSec Health-Check: Restart bei API-Problemen
if ! cscli metrics >/dev/null 2>&1; then
    logger -t "crowdsec-healthcheck" -p daemon.warn "CrowdSec API nicht erreichbar - starte Services neu..."
    systemctl restart crowdsec crowdsec-firewall-bouncer
fi
EOF
    
    # Health-Check als systemd-Service
    cat > /etc/systemd/system/crowdsec-healthcheck.service <<'EOF'
[Unit]
Description=CrowdSec Health-Check
After=crowdsec.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/crowdsec-healthcheck
User=root
EOF

    # Health-Check-Timer (alle 5 Minuten) - KORRIGIERT: OnUnitInactiveSec statt OnUnitActiveSec
    cat > /etc/systemd/system/crowdsec-healthcheck.timer <<'EOF'
[Unit]
Description=CrowdSec Health-Check (alle 5 Min)
Requires=crowdsec-healthcheck.service

[Timer]
OnBootSec=5min
OnUnitInactiveSec=5min
Unit=crowdsec-healthcheck.service

[Install]
WantedBy=timers.target
EOF

    # --- 7. Services aktivieren und starten (mit Verifikation) ---
    systemctl daemon-reload
    if run_with_spinner "Aktiviere Bouncer und Health-Check..." "systemctl enable --now crowdsec-firewall-bouncer crowdsec-healthcheck.timer"; then
        # Finale Verifikation (aus alter Version)
        log_info "  -> Prüfe Bouncer-Installation..."
        local verification_passed=true
        
        # Service-Status prüfen
        if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
            log_warn "Bouncer-Service startet noch..."
            sleep 3
            if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
                verification_passed=false
            fi
        fi
        
        # NFTables-Modus prüfen
        if command -v yq &>/dev/null; then
            if ! yq '.mode' "$local_yml" | grep -q "nftables"; then
                log_error "NFTables-Modus nicht gesetzt!"
                verification_passed=false
            fi
        fi
        
        # API-Key prüfen
        if [ ! -s "$keyfile" ]; then
            log_error "API-Key fehlt!"
            verification_passed=false
        fi

        # Ergebnis ausgeben
        if [ "$verification_passed" = true ]; then
            log_ok "CrowdSec-Bouncer erfolgreich installiert und mit NFTables integriert."
            log_info "  -> Der Health-Check läuft jetzt automatisch alle 5 Minuten."
            return 0
        else
            log_error "Bouncer-Installation unvollständig!"
            return 1
        fi
    else
        log_error "Bouncer-Installation ist unvollständig! Services konnten nicht gestartet werden."
        return 1
    fi
}

##
# Passt die CrowdSec SSH-Policy an die Benutzereingaben an.
##
tune_crowdsec_ssh_policy() {
    log_info "  -> Passe CrowdSec SSH-Policy an (Ban-Dauer: ${CROWDSEC_BANTIME})..."
    
    # Nur eine lokale Profildatei erstellen, wenn die Ban-Dauer vom Standard abweicht.
    # HINWEIS: Der MaxRetry-Wert wird von den CrowdSec-Szenarien selbst gehandhabt,
    #          wir passen hier gezielt nur die Dauer der Verbannung an.
    if [ "$CROWDSEC_BANTIME" != "4h" ]; then
        mkdir -p /etc/crowdsec/profiles.d/
        
        local custom_profile="/etc/crowdsec/profiles.d/99-custom-ssh-duration.yaml"
        cat > "$custom_profile" <<EOF
name: custom_ssh_ban_duration
description: "Override default ssh ban duration"
filters:
  - "decision.scenario starts_with 'crowdsecurity/sshd-'"
decisions:
  - type: ban
    duration: "$CROWDSEC_BANTIME"
on_success: break
EOF
        log_ok "Custom SSH-Profile mit Ban-Dauer '$CROWDSEC_BANTIME' erstellt."
    else
        log_info "Standard CrowdSec SSH-Ban-Dauer ('4h') wird verwendet."
    fi
}

# ===============================================================================
#  GeoIP Konfigurationsdateien sicher erstellen
# ===============================================================================
create_geoip_config_files() {
    log_info "  -> Erstelle GeoIP-Konfigurationsdateien mit sicheren Rechten..."
    
    # Blockierte Länder
    echo "$BLOCKED_COUNTRIES" > /etc/geoip-countries.conf
    chown root:root /etc/geoip-countries.conf
    chmod 640 /etc/geoip-countries.conf

    # Heimatland
    echo "$HOME_COUNTRY" > /etc/geoip-home-country.conf
    chown root:root /etc/geoip-home-country.conf
    chmod 640 /etc/geoip-home-country.conf
    
    # Manuelle Allowlist (leer anlegen, falls nicht vorhanden)
    touch /etc/geoip-allowlist.conf
    chown root:root /etc/geoip-allowlist.conf
    chmod 640 /etc/geoip-allowlist.conf
    
    log_ok "GeoIP-Konfigurationsdateien sicher erstellt (Rechte: 640)."
}
# ===============================================================================
#  GEOP-IP-SYSTEMD-TIMER ERSTELLEN (wöchentliches Update)
# ===============================================================================
create_geoip_systemd_timer() {
    log_info "  -> Erstelle systemd-Timer für wöchentliches GeoIP-Update..."
    
    # systemd-Service
    cat > /etc/systemd/system/geoip-update.service << 'EOF'
[Unit]
Description=Update GeoIP block lists (Set-based)
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-geoip-sets
User=root
EOF
    
    # systemd-Timer mit wöchentlichem Zeitplan
    cat > /etc/systemd/system/geoip-update.timer << 'EOF'
[Unit]
Description=Run GeoIP update weekly

[Timer]
# Wöchentlich - guter Kompromiss
OnCalendar=Sun *-*-* 02:00:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    log_ok "GeoIP-Update-Timer konfiguriert (wöchentlich sonntags)."
}

# ===============================================================================
#  GeoIP-Blocking installieren 
# ===============================================================================
configure_geoip_system() {
    log_info "🚀 Installiere GeoIP-Blocking (nutzt vordefinierte Sets)..."
    
    # 1. Konfigs erstellen
    create_geoip_config_files
    create_geoip_systemd_timer
    
    # 2. Sets müssen nicht mehr erstellt werden, da sie in nftables.conf stehen.
    log_info "  -> Sets sind bereits in nftables.conf definiert."
    
    # 3. Chain leeren und mit sauberen, Set-basierten Regeln befüllen
    log_info "  -> Fülle Chain 'geoip_check' mit 6 Kernregeln (inkl. Countern)..."
    
    nft flush chain inet filter geoip_check
    
    nft add rule inet filter geoip_check ip saddr @geoip_allowlist_v4 counter accept comment \"Manual-Allow-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_allowlist_v6 counter accept comment \"Manual-Allow-v6\"
    nft add rule inet filter geoip_check ip saddr @geoip_home_v4 counter accept comment \"GeoIP-Allow-Home-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_home_v6 counter accept comment \"GeoIP-Allow-Home-v6\"
    nft add rule inet filter geoip_check ip saddr @geoip_blocked_v4 counter drop comment \"GeoIP-Block-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_blocked_v6 counter drop comment \"GeoIP-Block-v6\"
    

    
    # 4. Timer aktivieren und erstes Update sofort ausführen
    log_info "  -> Starte GeoIP-Timer und führe initiales Update aus..."
    
    # VERWENDE run_with_spinner für besseres Feedback
    run_with_spinner "Aktiviere GeoIP-Update-Timer..." "systemctl daemon-reload && systemctl enable --now geoip-update.timer"
    
    # Führe das Update-Skript direkt aus, um die Sets sofort zu befüllen
    if run_with_spinner "Führe initiales GeoIP-Update aus..." "/usr/local/bin/update-geoip-sets"; then
        log_ok "Erstes GeoIP-Update erfolgreich. Die Sets sind jetzt befüllt."
    else
        log_warn "Erstes GeoIP-Update fehlgeschlagen. Sets sind noch leer. Timer wird es erneut versuchen."
    fi
    
    log_ok "GeoIP-Blocking (Set-basiert) erfolgreich installiert und aktiviert."
}

##
## Zeigt die Hilfe-Informationen für das Skript an.
##
show_usage() {
    print_section_header "HELP" "SERVER-BAUKASTEN v$SCRIPT_VERSION" "🏗️"
    echo -e "${BLUE}    Ein umfassendes Bash-Skript zur automatisierten Härtung und Konfiguration   ${NC}"
    echo -e "${BLUE}         von neuen Debian 12 / Ubuntu 22.04+ Servern nach höchsten Standards.     ${NC}"
    echo ""
    
    # Verwendung
    print_summary_header "VERWENDUNG" "GREEN"
    print_summary_entry "Standard-Ausführung" "sudo ./serverbaukasten.sh -c config.conf"
    print_summary_entry "Schneller Testlauf" "sudo ./serverbaukasten.sh -t -c config.conf"
    
    # Optionen
    print_summary_header "OPTIONEN" "CYAN"
    print_summary_entry "-c FILE" "Pfad zur Konfigurationsdatei (Pflicht)."
    print_summary_entry "-t" "Test-Modus (überspringt langsame Operationen)."
    print_summary_entry "-v" "Verbose-Modus (detaillierte Ausgaben)."
    print_summary_entry "-d" "Debug-Modus (maximale Ausgaben)."
    print_summary_entry "-h" "Zeigt diese Hilfe an."

    # Haupt-Features
    print_summary_header "HAUPT-FEATURES" "PURPLE"
    print_summary_entry "Sicherheits-Basis" "NFTables, CrowdSec, AIDE, RKHunter, Kernel-Härtung"
    print_summary_entry "Unsichtbarer Zugang" "Vollständige Integration von Tailscale VPN"
    print_summary_entry "Automatisierung" "Updates & Wartung via moderner systemd-Timer"
    print_summary_entry "Container-Ready" "Gehärtete Docker-Installation (optional)"
    
    # Wichtigste Schritte nach dem Setup
    print_summary_header "WICHTIGSTE SCHRITTE NACH DEM SETUP" "YELLOW"
    echo -e "  ${PURPLE}1.${NC} SSH-Zugang in einem **neuen Terminal** testen."
    echo -e "  ${PURPLE}2.${NC} Passwort-Login deaktivieren (falls SSH-Key genutzt)."
    echo -e "  ${PURPLE}3.${NC} Root-Konto sperren: ${CYAN}sudo passwd -l root${NC}"
    echo -e "  ${PURPLE}4.${NC} Server neustarten: ${CYAN}sudo reboot${NC}"
    echo -e "  ${PURPLE}5.${NC} GeoIP-Listen laden: ${CYAN}sudo geoip-manager update${NC}"
    
    # Footer
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}   🌐 Vollständige Doku: https://github.com/TZERO78/Server-Baukasten            ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
}
main "$@"
