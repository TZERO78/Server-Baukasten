#!/bin/bash
################################################################################
# KOMPONENTEN-INSTALLER v1.0 (SCHLANK)
#
# @description: Einfacher Installer für Server-Baukasten Komponenten
# @author:      Markus F. (TZERO78)
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# Verwendung:
#   sudo ./components/install-components.sh [komponente]
#   curl -sSL https://raw.../components/install-components.sh | sudo bash
################################################################################

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# KOMPONENTEN-KONFIGURATION (1 Script = 1 Komponente)
# ═══════════════════════════════════════════════════════════════════════════

# Verfügbare Komponenten definieren
declare -A COMPONENTS=(
    # Format: [name]="script|dependencies|description"
    ["geoip-manager"]="geoip-manager|nftables curl|GeoIP-Management-Tool"
    ["geoip-updater"]="update-geoip-sets|nftables curl|GeoIP-Listen-Updater"
    
    # Später einfach hinzufügen:
    # ["system-backup"]="system-backup.sh|systemd|System-Backup mit Rotation"
    # ["crowdsec-installer"]="crowdsec-installer.sh|systemd curl|CrowdSec-Installation"
    # ["docker-setup"]="docker-setup.sh|systemd|Docker-Konfiguration"
)

# Standard-Komponente (wenn keine angegeben)
readonly DEFAULT_COMPONENT="geoip-manager"

# ═══════════════════════════════════════════════════════════════════════════
# BASIS-KONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

readonly INSTALL_DIR="/usr/local/bin"
readonly BASE_URL="https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/components"

# Farben
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; 
CYAN='\033[0;36m'; BLUE='\033[0;34m'; NC='\033[0m'

# ═══════════════════════════════════════════════════════════════════════════
# HILFSFUNKTIONEN
# ═══════════════════════════════════════════════════════════════════════════

log_info() { echo -e "${CYAN}ℹ️  $*${NC}"; }
log_ok() { echo -e "${GREEN}✅ $*${NC}"; }
log_error() { echo -e "${RED}❌ $*${NC}" >&2; }

print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# Root-Check
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Muss als root ausgeführt werden!"
        log_info "Verwendung: sudo $0"
        exit 1
    fi
}

# Netzwerk-Check
check_network() {
    if ! curl -s --connect-timeout 5 https://github.com >/dev/null; then
        log_error "Keine Internetverbindung!"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# KOMPONENTEN-MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════

##
# Prüft, ob eine Komponente existiert.
##
component_exists() {
    local component="$1"
    [ -n "${COMPONENTS[$component]:-}" ]
}

##
# Parst Komponenten-Definition.
##
parse_component() {
    local component="$1"
    local definition="${COMPONENTS[$component]}"
    
    # Parse Format: "script|deps|description"
    IFS='|' read -r script deps description <<< "$definition"
    echo "$script|$deps|$description"
}

##
# Prüft Abhängigkeiten einer Komponente.
##
check_dependencies() {
    local deps="$1"
    
    if [ -z "$deps" ] || [ "$deps" = "none" ]; then
        return 0
    fi
    
    local missing=()
    for dep in $deps; do
        case "$dep" in
            "nftables") command -v nft >/dev/null || missing+=("nftables") ;;
            "systemd") command -v systemctl >/dev/null || missing+=("systemd") ;;
            *) command -v "$dep" >/dev/null || missing+=("$dep") ;;
        esac
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Fehlende Abhängigkeiten: ${missing[*]}"
        log_info "Installiere mit: apt-get install ${missing[*]}"
        return 1
    fi
    
    return 0
}

##
# Installiert eine Komponente.
##
install_component() {
    local component="$1"
    
    # Prüfe ob Komponente existiert
    if ! component_exists "$component"; then
        log_error "Unbekannte Komponente: $component"
        log_info "Verfügbare Komponenten: sudo $0 --list"
        return 1
    fi
    
    # Parse Komponenten-Definition
    local component_data
    component_data=$(parse_component "$component")
    IFS='|' read -r script deps description <<< "$component_data"
    
    print_header "INSTALLIERE: $description"
    
    # Abhängigkeiten prüfen
    log_info "Prüfe Abhängigkeiten: $deps"
    if ! check_dependencies "$deps"; then
        return 1
    fi
    log_ok "Abhängigkeiten erfüllt"
    
    # Script installieren
    log_info "Installiere Script: $script"
    echo -n "  📥 Download... "
    
    if curl -fsSL "$BASE_URL/$script" -o "$INSTALL_DIR/$script" 2>/dev/null; then
        chmod +x "$INSTALL_DIR/$script"
        echo -e "${GREEN}✓${NC}"
        log_ok "$description erfolgreich installiert!"
        show_usage_for_component "$component" "$script"
        return 0
    else
        echo -e "${RED}✗${NC}"
        log_error "Download fehlgeschlagen: $BASE_URL/$script"
        return 1
    fi
}

##
# Zeigt Verwendungs-Hinweise für eine Komponente.
##
show_usage_for_component() {
    local component="$1"
    local script="$2"
    
    echo
    case "$component" in
        "geoip-manager")
            log_info "📋 Verwendung: geoip-manager status"
            log_info "📋 Hilfe: geoip-manager help"
            ;;
        "geoip-updater")
            log_info "📋 Verwendung: update-geoip-sets"
            log_info "📋 Hinweis: Benötigt GeoIP-Konfigurationsdateien"
            ;;
        "system-backup")
            log_info "📋 Verwendung: system-backup.sh"
            ;;
        "crowdsec-installer")
            log_info "📋 Verwendung: crowdsec-installer.sh"
            ;;
        "docker-setup")
            log_info "📋 Verwendung: docker-setup.sh"
            ;;
        *)
            log_info "📋 Installiert: $script nach $INSTALL_DIR/"
            ;;
    esac
    
    echo
    log_info "💡 Für komplettes Setup: Server-Baukasten verwenden"
}

# ═══════════════════════════════════════════════════════════════════════════
# UI-FUNKTIONEN
# ═══════════════════════════════════════════════════════════════════════════

##
# Listet alle verfügbaren Komponenten auf.
##
list_components() {
    print_header "VERFÜGBARE KOMPONENTEN"
    
    echo "Installierbare Komponenten:"
    echo
    
    for component in "${!COMPONENTS[@]}"; do
        local component_data
        component_data=$(parse_component "$component")
        IFS='|' read -r script deps description <<< "$component_data"
        
        echo -e "  ${YELLOW}$component${NC} - $description"
        echo -e "    Script: ${CYAN}$script${NC}"
        [ "$deps" != "none" ] && [ -n "$deps" ] && echo -e "    Benötigt: $deps"
        echo
    done
}

##
# Zeigt die Hilfe an.
##
show_help() {
    cat << EOF
${BLUE}Server-Baukasten Komponenten-Installer${NC}

${CYAN}VERWENDUNG:${NC}
  sudo $0 [komponente]

${CYAN}VERFÜGBARE KOMPONENTEN:${NC}
$(for comp in "${!COMPONENTS[@]}"; do
    IFS='|' read -r script deps desc <<< "${COMPONENTS[$comp]}"
    echo "  $comp - $desc"
done | sort)

${CYAN}BEISPIELE:${NC}
  sudo $0                     # Standard-Komponente ($DEFAULT_COMPONENT)
  sudo $0 geoip-manager       # GeoIP-Management-Tool
  sudo $0 geoip-updater       # GeoIP-Listen-Updater
  sudo $0 --list              # Alle Komponenten anzeigen

${CYAN}REMOTE-INSTALLATION:${NC}
  # Standard-Komponente
  curl -sSL https://raw.../components/install-components.sh | sudo bash
  
  # Spezifische Komponente
  curl -sSL https://raw.../components/install-components.sh | sudo bash -s geoip-updater

${CYAN}MEHRERE KOMPONENTEN:${NC}
  sudo $0 geoip-manager
  sudo $0 geoip-updater

EOF
}

# ═══════════════════════════════════════════════════════════════════════════
# HAUPTFUNKTION
# ═══════════════════════════════════════════════════════════════════════════

main() {
    local component="${1:-$DEFAULT_COMPONENT}"
    
    # Argument-Parsing
    case "$component" in
        "--help"|"-h")
            show_help
            exit 0
            ;;
        "--list"|"-l")
            list_components
            exit 0
            ;;
        "")
            component="$DEFAULT_COMPONENT"
            ;;
    esac
    
    # System-Checks
    check_root
    check_network
    
    # Installation
    if install_component "$component"; then
        log_ok "Installation erfolgreich abgeschlossen! 🎉"
        exit 0
    else
        log_error "Installation fehlgeschlagen!"
        exit 1
    fi
}

# Script starten
main "$@"