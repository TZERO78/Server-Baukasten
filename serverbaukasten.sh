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

main "$@"
