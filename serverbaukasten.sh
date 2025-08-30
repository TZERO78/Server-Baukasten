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
set -e
set -o pipefail

# ═══════════════════════════════════════════════════════════════════════════
# GLOBALE SCRIPT-VARIABLEN & ZUSTÄNDE
# ═══════════════════════════════════════════════════════════════════════════
declare -g SCRIPT_VERBOSE=false
declare -g DEBUG=false
declare -g TEST_MODE=false
declare -g CONFIG_FILE=""
declare -a BACKUP_FILES

# --- Einfache Log-Funktionen für die Initialisierungsphase ---
# Diese werden später von core_helpers.sh überschrieben.
log_info() { echo -e "\033[0;36mℹ️  $*\033[0m"; }
log_ok() { echo -e "\033[0;32m✅ $*\033[0m"; }
log_warn() { echo -e "\033[1;33m⚠️  $*\033[0m"; }
log_error() { echo -e "\033[0;31m❌ $*\033[0m" >&2; exit 1; }
log_debug() {
    # Mache nichts, wenn der DEBUG-Modus nicht aktiv ist
    [ "${DEBUG:-false}" = "true" ] || return 0
    # Gib die Debug-Nachricht (nach stderr) aus, um die normale Ausgabe nicht zu stören
    echo -e "\033[0;90m⚙️  [DEBUG] $*\033[0m" >&2
}

##
# Prüft, ob das Skript als root ausgeführt wird.
##
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Dieses Skript muss als 'root' ausgeführt werden."
        exit 1
    fi
}

##
# Lädt alle Helfer-Bibliotheken aus dem ./lib Verzeichnis.
# Bricht bei ersten Fehler sofort ab.
##
load_libraries() {
    local lib_dir="./lib"
    log_info "📚 Lade Helfer-Bibliotheken..."

    if [ ! -d "$lib_dir" ]; then
        log_error "Bibliotheks-Verzeichnis '$lib_dir' nicht gefunden. Abbruch."
        return 1
    fi

    local lib_files=("$lib_dir"/*.sh)
    local total_files=${#lib_files[@]}
    
    log_debug "Gefunden: $total_files Bibliotheksdateien."

    local file_count=0
    for lib_file in "${lib_files[@]}"; do
        [ -f "$lib_file" ] || continue

        local filename
        filename=$(basename "$lib_file")

        if ! source "$lib_file"; then
            log_error "Kritischer Fehler beim Laden der Bibliothek '$filename'. Abbruch."
            return 1
        fi
    
        log_debug "✅ '$filename' erfolgreich geladen."
        
        # GEÄNDERT: Zähler "klassisch" mit 'let' hochzählen
        let file_count=file_count+1
        
        log_debug "Fortschritt: $file_count / $total_files"
    done

    log_info "🎉 $file_count Bibliotheken erfolgreich geladen."
}
##
# Lädt alle Setup-Module aus dem ./modules Verzeichnis.
# Bricht bei ersten Fehler sofort ab.
##
load_modules() {
    log_info "🔧 Lade Setup-Module..."

    # Die Konstante MODULES_DIR wird in constants.sh definiert
    if [ ! -d "$MODULES_DIR" ]; then
        log_warn "Module-Verzeichnis '$MODULES_DIR' nicht gefunden - überspringe."
        return 0 # Das ist kein kritischer Fehler
    fi

    local module_files=("$MODULES_DIR"/*.sh)
    local total_files=${#module_files[@]}
    log_debug "Gefunden: $total_files Setup-Module."

    local count=0
    for module_file in "${module_files[@]}"; do
        [ -f "$module_file" ] || continue

        local filename
        filename=$(basename "$module_file")

        # Robuste Fehlerbehandlung: Kein Verstecken von Fehlern mehr
        if ! source "$module_file"; then
            log_error "Kritischer Fehler beim Laden des Moduls '$filename'. Abbruch."
            return 1 # Signalisiert einen Fehler -> set -e greift
        fi

        log_debug "✅ Modul '$filename' erfolgreich geladen."
        
        # Der "klassische" Zähler, der bei dir zuverlässig funktioniert
        let count=count+1
    done

    log_ok "🎉 $count Setup-Module erfolgreich geladen."
}

################################################################################
#                                 HAUPTLOGIK
################################################################################

##
# Haupt-Einstiegspunkt des Skripts.
##
main() {
    check_root
    

    
    # --- Argumente verarbeiten ---
    local local_test_mode=false
    
    while getopts ":c:thvd" opt; do
        case ${opt} in
            c) CONFIG_FILE=$OPTARG;;
            t) local_test_mode=true;;
            h) show_usage; exit 0;;
            v) SCRIPT_VERBOSE=true;;
            d) DEBUG=true; SCRIPT_VERBOSE=true;;
            \?) log_error "Ungültige Option: -$OPTARG"; show_usage; exit 1;;
            :) log_error "Option -$OPTARG benötigt ein Argument."; show_usage; exit 1;;
        esac
    done
       
    # Setze globale TEST_MODE Variable
    TEST_MODE=$local_test_mode
    
    # --- Konfigurationsdatei-Prüfung ---
    if [ -z "$CONFIG_FILE" ]; then
        log_error "Fehler: Keine Konfigurationsdatei mit '-c' angegeben."
        show_usage
        exit 1
    fi

    if [ ! -r "$CONFIG_FILE" ]; then
        log_error "Fehler: Konfigurationsdatei nicht gefunden oder nicht lesbar: $CONFIG_FILE"
        exit 1
    fi

    export SCRIPT_VERBOSE DEBUG TEST_MODE
    trap 'rollback' ERR

    log_info "🚀 Starte $SCRIPT_NAME v$SCRIPT_VERSION..."
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS ist aktiviert. Zeitaufwändige Operationen werden übersprungen."
    fi
    log_info "Verwende Konfigurationsdatei: $CONFIG_FILE"

    load_libraries  # Lädt constants.sh automatisch mit!
    load_modules  

    run_setup "$TEST_MODE"
    
    trap - ERR
    cleanup_sensitive_data "$TEST_MODE"
    show_summary
    
    if [ "$TEST_MODE" = true ]; then
        log_ok "Test-Setup erfolgreich abgeschlossen! ⚡"
    else
        log_ok "Server-Setup erfolgreich abgeschlossen! 🎉"
    fi
}

##
# Führt die Setup-Module in der korrekten Reihenfolge aus.
##
run_setup() {
    local TEST_MODE="$1"
    
    log_info "Phase 1/5: Vorbereitung..."
    pre_flight_checks
    load_config_from_file "$CONFIG_FILE" 
    module_cleanup

    log_info "Phase 2/5: System-Fundament (OS, Pakete, Kernel)..."
    detect_os
    module_fix_apt_sources
    module_base
    module_system_update "$TEST_MODE"
    module_kernel_hardening

    log_info "Phase 3/5: Sicherheits-Architektur (Firewall, IPS, Monitoring)..."
    module_security "$TEST_MODE"
    
    log_info "Phase 4/5: Kern-Dienste (Netzwerk & Container)..."
    module_network "$TEST_MODE" 
    if [ "$SERVER_ROLE" = "1" ]; then
        module_container
        module_deploy_containers
    fi
 
    log_info "Phase 5/5: Abschluss-Arbeiten (Mail, Logs, Backup, Verifikation)..."
    module_mail_setup
    module_journald_optimization
    module_verify_setup
    cleanup_admin_sudo_rights
}

main "$@"