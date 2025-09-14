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
declare -g LOG_FILE="/var/log/server-baukasten.log"
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

##
# Fehler-Handler für kritische Fehler während der Setup-Ausführung.
# Führt bei Bedarf einen Rollback durch.
# @param int $1 Exit-Code des fehlgeschlagenen Befehls.
# @param int $2 Zeilennummer des fehlgeschlagenen Befehls.
# @param string $3 Der fehlgeschlagene Befehl.
##
handle_error() {
    local exit_code=$1
    local line_number=$2 
    local failed_command=$3
    
    # Permanente Debug-Ausgabe
    echo "DEBUG: ERR-Trap ausgelöst!"
    echo "  Exit-Code: $exit_code"
    echo "  Zeile: $line_number"  
    echo "  Befehl: '$failed_command'"
    
    case "$failed_command" in
        *'(('*'))'*|*'$((*))'*)
            log_debug "Harmlose arithmetische Operation ignoriert: $failed_command"
            return 0
            ;;
        *"systemctl"*|*"apt"*|*"curl"*|*"wget"*|*"cp "*|*"mv "*|*"rm "*|*"mkdir"*)
            log_error "Kritischer Systemfehler in Zeile $line_number: $failed_command"
            rollback  # ✅ WIEDER HINZUGEFÜGT
            ;;
        *)
            if [ $exit_code -gt 1 ]; then
                log_error "Schwerwiegender Fehler in Zeile $line_number: $failed_command" 
                rollback  # ✅ WIEDER HINZUGEFÜGT
            else
                log_debug "Exit-Code 1 ignoriert für: $failed_command"
            fi
            ;;
    esac
}

##
# Führt einen Setup-Schritt kontrolliert aus und prüft dessen Erfolg.
# Sorgt für einheitliches Logging und löst bei Fehlern den globalen
# Error-Handler kontrolliert aus.
#
# @param string $1 Name des Schritts (für das Logging)
# @param string $@ Der auszuführende Befehl und seine Argumente
##
execute_step() {
    local step_name="$1"
    shift # Entfernt den Namen des Schritts aus der Argumentenliste
    local command_to_run=("$@")

    log_info "➡️  Schritt wird ausgeführt: ${BLUE}${step_name}${NC}"

    # Wir führen den Befehl aus und fangen den Fehlerfall direkt ab.
    # Das 'if' verhindert, dass 'set -e' das Skript sofort beendet.
    if "${command_to_run[@]}"; then
        log_ok "✅ Schritt erfolgreich abgeschlossen: ${step_name}"
        echo # Eine Leerzeile für bessere Lesbarkeit
        return 0
    else
        local exit_code=$?
        # Wir geben eine klare, übergeordnete Fehlermeldung aus...
        echo -e "\033[0;31m❌ Kritischer Fehler im Schritt: '${step_name}' (Exit-Code: $exit_code)\033[0m" >&2
        
        # ...und beenden das Skript dann mit einem Fehlercode.
        # Dies löst unseren globalen 'trap' und die 'handle_error'-Funktion aus,
        # die dann den Rollback durchführen kann.
        exit 1
    fi
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

##
# Zeigt den Begrüßungs-Header an.
##
show_startup_header() {
    local current_date=$(date '+%d.%m.%Y %H:%M:%S')
    
    echo
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo "                           🏗️  SERVER-BAUKASTEN v$SCRIPT_VERSION"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo "  Vollautomatische Linux-Server-Härtung nach modernen Sicherheitsstandards"
    echo
    echo "  📅 Gestartet am: $current_date"
    echo "  🖥️  System: $(uname -n) ($(uname -m))"
    echo "  🐧 Kernel: $(uname -r)"
    echo "  👤 Benutzer: $(whoami)"
    echo
    if [ "$TEST_MODE" = true ]; then
        echo "  ⚡ MODUS: TEST (Schnell-Setup ohne zeitaufwändige Operationen)"
    else
        echo "  🚀 MODUS: PRODUKTIV (Vollständige Installation)"
    fi
    echo "  📋 Config: $CONFIG_FILE"
    echo
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo
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
# Führt die einzelnen Setup-Module in einer kontrollierten Reihenfolge aus.
# Jeder Schritt wird einzeln überwacht und sein Erfolg protokolliert.
##
run_setup() {
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1: VORBEREITUNG & SYSTEM-GRUNDLAGEN
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "Phase 1/5: Vorbereitung & System-Grundlagen..."
    
    execute_step "System für Installation vorbereiten" module_prepare_install
    execute_step "Konfigurationsdatei laden" load_config_from_file "$CONFIG_FILE"
    execute_step "Primäres Netzwerk-Interface ermitteln" detect_primary_interface_if_needed
    execute_step "Initiales System bereinigen" module_cleanup

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2: SYSTEM-FUNDAMENT (OS, Pakete, Kernel)
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "Phase 2/5: System-Fundament (OS, Pakete, Kernel)..."
    
    execute_step "Betriebssystem erkennen" detect_os
    execute_step "Basissystem einrichten" module_base
    execute_step "Benötigte Dienste installieren" module_install_services
    execute_step "System-Updates durchführen" module_system_update "$TEST_MODE"
    execute_step "Kernel-Härtung anwenden" module_kernel_hardening

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3: BASIS-SICHERHEIT (Firewall + IPS + Monitoring)
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "Phase 3/5: Basis-Sicherheit (SSH, BASIS-Firewall, CrowdSec)..."
    
    execute_step "Basis-Sicherheit anwenden (SSH, Firewall, IPS)" module_security "$TEST_MODE"
    execute_step "GeoIP-Blocking-System konfigurieren" module_geoip
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 4: DIENSTE & DYNAMISCHE FIREWALL-ERWEITERUNG
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "Phase 4/5: Dienste installieren & Firewall dynamisch erweitern..."
    
    # STUFE 1: Netzwerk-Dienste (VPN, Tailscale, Dynamic DNS)
    execute_step "Netzwerk-Dienste (VPN, etc.) einrichten" module_network "$TEST_MODE"
    
    # STUFE 2: Container-Dienste (Docker Engine + Management)
    if [ "${SERVER_ROLE:-2}" = "1" ]; then
        execute_step "Container-Engine (Docker) installieren" module_container
        execute_step "Management-Container (Portainer, Watchtower) bereitstellen" module_deploy_containers
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 5: ABSCHLUSS & FINALISIERUNG
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "Phase 5/5: Abschluss-Arbeiten (Mail, Logs, Verifikation)..."
    
    execute_step "System-Mail (msmtp) einrichten" module_mail_setup
    execute_step "System-Protokoll (journald) optimieren" module_journald_optimization
    execute_step "Finale Verifikation aller Komponenten" module_verify_setup
    execute_step "Admin-Rechte normalisieren" cleanup_admin_sudo_rights
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

    # 6. Zeige Header 
    show_startup_header 
    
    # 7. Jetzt erst den echten Error-Handler setzen (rollback existiert jetzt)
 	trap 'handle_error $? $LINENO $BASH_COMMAND' ERR
    
    # 8. Begrüßung (nach Library-Load für erweiterte Funktionen)
    log_info "Starte Server-Baukasten v$SCRIPT_VERSION..."
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS ist aktiviert. Zeitaufwändige Operationen werden übersprungen."
    fi
    log_info "Verwende Konfigurationsdatei: $CONFIG_FILE"
    
    # 10. Hauptlogik ausführen
    run_setup
    
    # 11. Cleanup und Abschluss
    cleanup_and_finalize
}

main "$@"
