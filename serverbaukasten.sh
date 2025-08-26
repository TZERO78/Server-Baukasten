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

# --- Einfache Log-Funktionen für die Initialisierungsphase ---
# Diese werden später von core_helpers.sh überschrieben.
log_info() { echo -e "\033[0;36mℹ️  $*\033[0m"; }
log_ok() { echo -e "\033[0;32m✅ $*\033[0m"; }
log_warn() { echo -e "\033[1;33m⚠️  $*\033[0m"; }
log_error() { echo -e "\033[0;31m❌ $*\033[0m" >&2; exit 1; }

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
# Lädt alle Helfer-Bibliotheken aus dem konfigurierten Verzeichnis.
##
load_libraries() {
    local lib_dir="./lib"
    log_info "📚 Lade Helfer-Bibliotheken aus '$lib_dir'..."
    
    local count=0
    local failed=0
    
    if [ ! -d "$lib_dir" ]; then
        log_warn "Verzeichnis '$lib_dir' nicht gefunden - überspringe Bibliotheken."
        return 0
    fi
    
    for file in "$lib_dir"/*.sh; do
        [ ! -f "$file" ] && continue
        
        if source "$file" 2>/dev/null; then
            log_ok "  -> '$(basename "$file")' geladen"
            ((count++))
        else
            log_error "  -> '$(basename "$file")' FEHLER beim Laden!"
            ((failed++))
        fi
    done
    
    if [ $failed -gt 0 ]; then
        log_error "$failed Bibliothek(en) konnten nicht geladen werden!"
        exit 1
    fi
    
    log_ok "$count Helfer-Bibliotheken erfolgreich geladen."
}

##
# Lädt alle Setup-Module aus dem konfigurierten Verzeichnis.
##
load_modules() {
    # Jetzt können wir die Konstanten verwenden!
    log_info "🔧 Lade Setup-Module aus '$MODULES_DIR'..."
    
    local count=0
    local failed=0
    
    if [ ! -d "$MODULES_DIR" ]; then
        log_warn "Verzeichnis '$MODULES_DIR' nicht gefunden - überspringe Module."
        return 0
    fi
    
    for file in "$MODULES_DIR"/*.sh; do
        [ ! -f "$file" ] && continue
        
        if source "$file" 2>/dev/null; then
            log_ok "  -> '$(basename "$file")' geladen"
            ((count++))
        else
            log_error "  -> '$(basename "$file")' FEHLER beim Laden!"
            ((failed++))
        fi
    done
    
    if [ $failed -gt 0 ]; then
        log_error "$failed Modul(e) konnten nicht geladen werden!"
        exit 1
    fi
    
    log_ok "$count Setup-Module erfolgreich geladen."
}

################################################################################
#                                 HAUPTLOGIK
################################################################################

##
# Haupt-Einstiegspunkt des Skripts.
##
main() {
    check_root
    
    load_libraries  # Lädt constants.sh automatisch mit!
    load_modules   
    
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