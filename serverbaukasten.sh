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

set -e
set -o pipefail
shopt -s nullglob  # Verhindert Glob-Expansion-Fehler bei leeren Verzeichnissen

# ═══════════════════════════════════════════════════════════════════════════
# GLOBALE SCRIPT-VARIABLEN & ZUSTÄNDE
# ═══════════════════════════════════════════════════════════════════════════
declare -g SCRIPT_VERBOSE=false
declare -g DEBUG=false
declare -g TEST_MODE=false
declare -g CONFIG_FILE=""
declare -a BACKUP_FILES
declare -g PRIMARY_INTERFACE=""
declare -g TAILSCALE_INTERFACE=""
declare -g DOCKER_INTERFACE=""
##
# Früher Error-Handler vor Library-Load (Stub-Version)
##
early_error_handler() {
    echo -e "\033[0;31m❌ Kritischer Fehler während der Initialisierung!\033[0m" >&2
    echo -e "\033[0;33m⚠️  Rollback-Funktionen noch nicht verfügbar.\033[0m" >&2
    exit 1
}

# ═══════════════════════════════════════════════════════════════════════════
# FRÜHE HELFER-FUNKTIONEN (vor Bibliotheks-Load)
# ═══════════════════════════════════════════════════════════════════════════

# Einfache Log-Funktionen für die Initialisierungsphase
# Diese werden später von core_helpers.sh überschrieben
log_info() { echo -e "\033[0;36mℹ️  $*\033[0m"; }
log_ok() { echo -e "\033[0;32m✅ $*\033[0m"; }
log_warn() { echo -e "\033[1;33m⚠️  $*\033[0m"; }
log_error() { echo -e "\033[0;31m❌ $*\033[0m" >&2; exit 1; }
log_debug() {
    [ "${DEBUG:-false}" = "true" ] || return 0
    echo -e "\033[0;90m⚙️  [DEBUG] $*\033[0m" >&2
}

##
# Prüft, ob das Skript als root ausgeführt wird.
##
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Dieses Skript muss als 'root' ausgeführt werden."
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# ARGUMENT-PARSING UND VALIDIERUNG
# ═══════════════════════════════════════════════════════════════════════════

##
# Verarbeitet die Kommandozeilen-Argumente.
##
parse_command_arguments() {
    while getopts ":c:thvd" opt; do
        case ${opt} in
            c) CONFIG_FILE="$OPTARG";;
            t) TEST_MODE=true;;
            h) show_usage; exit 0;;
            v) SCRIPT_VERBOSE=true;;
            d) DEBUG=true; SCRIPT_VERBOSE=true;;
            \?) log_error "Ungültige Option: -$OPTARG";;
            :) log_error "Option -$OPTARG benötigt ein Argument.";;
        esac
    done
}

##
# Validiert die erforderlichen Argumente.
##
validate_required_arguments() {
    if [ -z "$CONFIG_FILE" ]; then
        log_error "Fehler: Keine Konfigurationsdatei mit '-c' angegeben."
    fi

    if [ ! -r "$CONFIG_FILE" ]; then
        log_error "Fehler: Konfigurationsdatei nicht gefunden oder nicht lesbar: $CONFIG_FILE"
    fi
    
    log_debug "Verwende Konfigurationsdatei: $CONFIG_FILE"
}

# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM-ZUSTAND UND ABHÄNGIGKEITEN
# ═══════════════════════════════════════════════════════════════════════════

##
# Erkennt das primäre Interface nur wenn in Config als "auto" definiert.
##
detect_primary_interface_if_needed() {
    # Nur ermitteln, wenn in Config explizit als "auto" gesetzt
    if [ "${PRIMARY_INTERFACE:-auto}" = "auto" ]; then
        log_debug "PRIMARY_INTERFACE=auto erkannt - ermittle automatisch..."
        
        local detected_interface=""
        if command -v ip &>/dev/null; then
            detected_interface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -n1)
        fi
        if [ -z "$detected_interface" ]; then
            detected_interface=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1)
        fi
        if [ -z "$detected_interface" ]; then
            detected_interface=$(ls /sys/class/net/ | grep -E '^(eth|ens|enp)' | head -n1)
        fi
        
        PRIMARY_INTERFACE="${detected_interface:-eth0}"
        export PRIMARY_INTERFACE
        log_debug "Automatisch ermitteltes Interface: $PRIMARY_INTERFACE"
    else
        log_debug "PRIMARY_INTERFACE aus Config: ${PRIMARY_INTERFACE}"
        export PRIMARY_INTERFACE
    fi
}

##
# Lädt alle Helfer-Bibliotheken aus dem ./lib Verzeichnis.
##
load_libraries() {
    local lib_dir="./lib"
    log_info "Lade Helfer-Bibliotheken..."

    if [ ! -d "$lib_dir" ]; then
        log_error "Bibliotheks-Verzeichnis '$lib_dir' nicht gefunden."
    fi

    local file_count=0
    # nullglob sorgt dafür, dass bei leeren Verzeichnissen der Glob leer bleibt
    for lib_file in "$lib_dir"/*.sh; do
        local filename
        filename=$(basename "$lib_file")

        if ! source "$lib_file"; then
            log_error "Kritischer Fehler beim Laden der Bibliothek '$filename'."
        fi
    
        log_debug "'$filename' erfolgreich geladen."
        let file_count=file_count+1
    done

    log_debug "$file_count Bibliotheken erfolgreich geladen."
}

##
# Lädt alle Setup-Module aus dem ./modules Verzeichnis.
##
load_modules() {
    log_info "Lade Setup-Module..."
    local modules_dir="./modules"

    if [ ! -d "$modules_dir" ]; then
        log_warn "Module-Verzeichnis '$modules_dir' nicht gefunden - überspringe."
        return 0
    fi

    local count=0
    # nullglob sorgt dafür, dass bei leeren Verzeichnissen der Glob leer bleibt
    for module_file in "$modules_dir"/*.sh; do
        local filename
        filename=$(basename "$module_file")

        if ! source "$module_file"; then
            log_error "Kritischer Fehler beim Laden des Moduls '$filename'."
        fi

        log_debug "Modul '$filename' erfolgreich geladen."
        let count=count+1
    done

    log_debug "$count Setup-Module erfolgreich geladen."
}

# ═══════════════════════════════════════════════════════════════════════════
# SETUP-AUSFÜHRUNG
# ═══════════════════════════════════════════════════════════════════════════

##
# Führt die einzelnen Setup-Module in der korrekten Reihenfolge aus.
# KORRIGIERT v4.3: Zweistufiges Firewall-Setup für NFTables/Docker/CrowdSec-Kompatibilität
# @param bool $1 Test-Modus (true/false).
##
run_setup() {
    local TEST_MODE="$1"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1: VORBEREITUNG & SYSTEM-GRUNDLAGEN
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "Phase 1/5: Vorbereitung & System-Grundlagen..."
    
    pre_flight_checks
    load_config_from_file "$CONFIG_FILE"
    
    # Interface-Detection NACH Config-Load (für NAT-Regeln später)
    detect_primary_interface_if_needed
    
    # Systembereinigung für sauberen Ausgangszustand
    module_cleanup

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2: SYSTEM-FUNDAMENT (OS, Pakete, Kernel)
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "Phase 2/5: System-Fundament (OS, Pakete, Kernel)..."
    
    detect_os
    module_fix_apt_sources
    module_base
    module_system_update "$TEST_MODE"
    
    # WICHTIG: Kernel-Härtung VOR Firewall (IP-Forwarding für Docker/VPN)
    module_kernel_hardening

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3: BASIS-SICHERHEIT (Firewall + IPS + Monitoring)
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "Phase 3/5: Basis-Sicherheit (SSH, BASIS-Firewall, CrowdSec)..."
    
    # KORRIGIERT: module_security macht jetzt ALLES auf einmal:
    # - SSH-Härtung & AppArmor
    # - iptables-nft Backend
    # - BASIS-Firewall (ohne VPN/Docker)
    # - CrowdSec IPS
    # - AIDE & RKHunter (falls nicht Test-Modus)
    module_security "$TEST_MODE"

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 4: DIENSTE & DYNAMISCHE FIREWALL-ERWEITERUNG
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "Phase 4/5: Dienste installieren & Firewall dynamisch erweitern..."
    
    # STUFE 1: Netzwerk-Dienste (Tailscale VPN)
    # -> Ruft activate_tailscale_rules() auf und erweitert die Firewall
    module_network "$TEST_MODE"
    
    # STUFE 2: Container-Dienste (Docker Engine + Management)
    if [ "${SERVER_ROLE:-2}" = "1" ]; then
        # -> Ruft activate_docker_rules() auf und erweitert die Firewall
        module_container
        module_deploy_containers
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 5: ABSCHLUSS & FINALISIERUNG
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "Phase 5/5: Abschluss-Arbeiten (Mail, Logs, Verifikation)..."
    
    # System-Services (Mail, Logging)
    module_mail_setup
    module_journald_optimization
    
    # Finale Verifikation aller Komponenten
    module_verify_setup
    
    # Sicherheits-Cleanup (sudo-Rechte normalisieren)
    cleanup_admin_sudo_rights
}

##
# Führt Cleanup-Aktionen und Finalisierung durch.
##
cleanup_and_finalize() {
    trap - ERR
    cleanup_sensitive_data "$TEST_MODE"
    show_summary
    
    if [ "$TEST_MODE" = true ]; then
        log_ok "Test-Setup erfolgreich abgeschlossen!"
    else
        log_ok "Server-Setup erfolgreich abgeschlossen!"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# HAUPT-FUNKTION
# ═══════════════════════════════════════════════════════════════════════════

##
# Haupt-Einstiegspunkt des Skripts.
##
main() {
    # 1. Basis-Validierung
    check_root
    
    # 2. Früher Error-Handler (Stub-Version vor Library-Load)
    trap 'early_error_handler' ERR
    
    # 3. Argumente parsen und validieren
    parse_command_arguments "$@"
    validate_required_arguments
    
    # 4. Globale Variablen exportieren
    export SCRIPT_VERBOSE DEBUG TEST_MODE CONFIG_FILE
    
    # 5. Abhängigkeiten laden
    load_libraries
    load_modules
    
    # 6. Jetzt erst den echten Error-Handler setzen (rollback existiert jetzt)
    trap 'rollback' ERR
    
    # 7. Begrüßung (nach Library-Load für erweiterte Funktionen)
    log_info "Starte Server-Baukasten v4.0.1..."
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS ist aktiviert. Zeitaufwändige Operationen werden übersprungen."
    fi
    log_info "Verwende Konfigurationsdatei: $CONFIG_FILE"
    
    # 8. Hauptlogik ausführen
    run_setup
    
    # 9. Cleanup und Abschluss
    cleanup_and_finalize
}

main "$@"
