#!/bin/bash
################################################################################
# SERVER-BAUKASTEN INSTALLER
#
# @description: Lädt den Server-Baukasten von GitHub herunter und bereitet
#               die Installation vor.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Verwendung:
#   curl -sSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash
#   curl -sSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash -s -- -b develop
################################################################################

set -e
set -o pipefail

# ═══════════════════════════════════════════════════════════════════════════
# KONSTANTEN & VARIABLEN
# ═══════════════════════════════════════════════════════════════════════════
readonly REPO_URL="https://github.com/TZERO78/Server-Baukasten"
readonly DEFAULT_BRANCH="main"
readonly DEFAULT_INSTALL_DIR="./server-baukasten"

# Version aus GitHub VERSION-Datei laden
_get_installer_version() {
    local version
    version=$(curl -sSL "https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/VERSION" 2>/dev/null || echo "")
    [ -n "$version" ] && echo "$version" || echo "latest"
}
readonly VERSION=$(_get_installer_version)

# Globale Variablen (können durch Parameter überschrieben werden)
BRANCH="$DEFAULT_BRANCH"
INSTALL_DIR="$DEFAULT_INSTALL_DIR"

# Farben für Output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING-FUNKTIONEN
# ═══════════════════════════════════════════════════════════════════════════
log_info() { echo -e "${CYAN}ℹ️  $*${NC}"; }
log_ok() { echo -e "${GREEN}✅ $*${NC}"; }
log_warn() { echo -e "${YELLOW}⚠️  $*${NC}"; }
log_error() { echo -e "${RED}❌ $*${NC}" >&2; }

# ═══════════════════════════════════════════════════════════════════════════
# UI-FUNKTIONEN
# ═══════════════════════════════════════════════════════════════════════════

##
# Zeigt den Header mit Projektinfo an.
##
show_header() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}           🏗️  SERVER-BAUKASTEN INSTALLER v$VERSION           ${NC}"
    echo -e "${BLUE}                                                                ${NC}"
    echo -e "${BLUE}    Automatische Härtung für Debian/Ubuntu Server              ${NC}"
    echo -e "${BLUE}    Repository: $REPO_URL            ${NC}"
    echo -e "${BLUE}    Branch/Tag: $BRANCH                              ${NC}"
    echo -e "${BLUE}    Ziel: $INSTALL_DIR                           ${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo
}

##
# Zeigt die Hilfe an.
##
show_help() {
    echo -e "${BLUE}SERVER-BAUKASTEN INSTALLER v$VERSION${NC}"
    echo
    echo -e "${CYAN}VERWENDUNG:${NC}"
    echo "  $0 [OPTIONEN]"
    echo
    echo -e "${CYAN}OPTIONEN:${NC}"
    echo "  -b, --branch BRANCH    Branch/Tag zum Herunterladen (Standard: $DEFAULT_BRANCH)"
    echo "  -d, --dir VERZEICHNIS  Zielverzeichnis (Standard: $DEFAULT_INSTALL_DIR)"
    echo "  -h, --help             Diese Hilfe anzeigen"
    echo
    echo -e "${CYAN}BEISPIELE:${NC}"
    echo "  $0                              # Lädt main-Branch herunter"
    echo "  $0 -b develop                   # Lädt develop-Branch herunter"
    echo "  $0 -b v4.0.1                    # Lädt spezifischen Tag herunter"
    echo "  $0 -b feature/new-module        # Lädt Feature-Branch herunter"
    echo "  $0 -d ./mein-baukasten          # Anderes Zielverzeichnis"
    echo
    echo -e "${CYAN}ONE-LINER INSTALLATION:${NC}"
    echo "  curl -sSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash"
    echo "  curl -sSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash -s -- -b develop"
    echo
}

##
# Zeigt die nächsten Schritte an.
##
show_next_steps() {
    echo
    log_ok "🎉 Installation erfolgreich abgeschlossen!"
    echo
    echo -e "${BLUE}═══ NÄCHSTE SCHRITTE ═══${NC}"
    echo -e "${CYAN}1. Konfiguration anpassen:${NC}"
    echo "   cd $INSTALL_DIR"
    echo "   nano meine-config.conf"
    echo
    echo -e "${CYAN}2. Server-Setup starten:${NC}"
    echo "   sudo ./serverbaukasten.sh -c meine-config.conf"
    echo
    echo -e "${CYAN}3. Für Tests (schneller):${NC}"
    echo "   sudo ./serverbaukasten.sh -t -c meine-config.conf"
    echo
    echo -e "${YELLOW}📖 Dokumentation: cat README.md${NC}"
    echo -e "${YELLOW}🔧 Hilfe: ./serverbaukasten.sh -h${NC}"
    
    # Zeige Verzeichnisinhalt
    if [ -d "$INSTALL_DIR" ]; then
        echo
        echo -e "${BLUE}═══ HERUNTERGELADENE DATEIEN ═══${NC}"
        echo -e "${CYAN}Hauptdateien:${NC}"
        ls -la "$INSTALL_DIR"/*.sh "$INSTALL_DIR"/*.conf "$INSTALL_DIR"/*.md 2>/dev/null | sed 's/^/   /' || true
        echo -e "${CYAN}Verzeichnisse:${NC}"
        ls -la "$INSTALL_DIR" | grep "^d" | awk '{print "   " $9}' || true
    fi
    echo
}

# ═══════════════════════════════════════════════════════════════════════════
# ARGUMENT-PARSING
# ═══════════════════════════════════════════════════════════════════════════

##
# Verarbeitet Kommandozeilen-Argumente.
##
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -b|--branch)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    BRANCH="$2"
                    shift 2
                else
                    log_error "Option '$1' benötigt einen Branch-Namen."
                    exit 1
                fi
                ;;
            -d|--dir)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    INSTALL_DIR="$2"
                    shift 2
                else
                    log_error "Option '$1' benötigt einen Verzeichnisnamen."
                    exit 1
                fi
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unbekannte Option: $1"
                echo
                show_help
                exit 1
                ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM-CHECKS
# ═══════════════════════════════════════════════════════════════════════════

##
# Prüft Voraussetzungen und installiert fehlende Tools.
##
check_prerequisites() {
    log_info "Prüfe Voraussetzungen..."
    
    local missing_tools=()
    
    # Prüfe kritische Tools
    for tool in curl tar; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    # Installiere fehlende Tools (falls root)
    if [ ${#missing_tools[@]} -gt 0 ]; then
        if [ "$EUID" -eq 0 ]; then
            log_info "Installiere fehlende Tools: ${missing_tools[*]}"
            apt-get update -qq
            apt-get install -y "${missing_tools[@]}"
        else
            log_error "Fehlende Tools: ${missing_tools[*]}"
            log_error "Bitte installiere sie mit: sudo apt-get install ${missing_tools[*]}"
            exit 1
        fi
    fi
    
    log_ok "Alle Voraussetzungen erfüllt."
}

# ═══════════════════════════════════════════════════════════════════════════
# DOWNLOAD-FUNKTIONEN
# ═══════════════════════════════════════════════════════════════════════════

##
# Bestimmt die richtige Archive-URL basierend auf Branch/Tag.
##
get_archive_url() {
    if [[ "$BRANCH" =~ ^v[0-9] ]] || [[ "$BRANCH" =~ ^[0-9] ]]; then
        # Tag-Format erkannt
        echo "https://github.com/TZERO78/Server-Baukasten/archive/refs/tags/${BRANCH}.tar.gz"
    else
        # Branch-Format
        echo "https://github.com/TZERO78/Server-Baukasten/archive/refs/heads/${BRANCH}.tar.gz"
    fi
}

##
# Lädt das komplette Repository als tar.gz Archiv herunter.
##
download_repository() {
    local archive_url
    archive_url=$(get_archive_url)
    
    if [[ "$BRANCH" =~ ^v[0-9] ]] || [[ "$BRANCH" =~ ^[0-9] ]]; then
        log_info "Lade Tag '$BRANCH' von GitHub herunter..."
    else
        log_info "Lade Branch '$BRANCH' von GitHub herunter..."
    fi
    
    # Zielverzeichnis vorbereiten
    prepare_target_directory
    
    # Download durchführen
    local temp_dir
    temp_dir=$(mktemp -d)
    trap "rm -rf '$temp_dir'" EXIT
    
    log_info "  -> Lade tar.gz Archiv herunter..."
    if ! curl -sSL "$archive_url" -o "$temp_dir/repository.tar.gz"; then
        log_error "Download des Archivs fehlgeschlagen!"
        log_error "Prüfe ob Branch/Tag '$BRANCH' existiert: $REPO_URL/tree/$BRANCH"
        exit 1
    fi
    
    # Entpacken und installieren
    extract_and_install "$temp_dir"
    
    log_ok "Repository ($BRANCH) erfolgreich heruntergeladen!"
    show_download_summary
}

##
# Bereitet das Zielverzeichnis vor.
##
prepare_target_directory() {
    if [ -d "$INSTALL_DIR" ]; then
        log_warn "Verzeichnis '$INSTALL_DIR' existiert bereits."
        read -p "Überschreiben? (j/n): " -r
        if [[ ! $REPLY =~ ^[Jj]$ ]]; then
            log_error "Installation abgebrochen."
            exit 1
        fi
        rm -rf "$INSTALL_DIR"
    fi
    
    mkdir -p "$INSTALL_DIR"
}

##
# Entpackt das Archiv und installiert die Dateien.
##
extract_and_install() {
    local temp_dir="$1"
    
    log_info "  -> Entpacke Archiv..."
    if ! tar -xzf "$temp_dir/repository.tar.gz" -C "$temp_dir"; then
        log_error "Entpacken des Archivs fehlgeschlagen!"
        exit 1
    fi
    
    # Finde den entpackten Ordner (GitHub Format: "Server-Baukasten-BRANCH")
    local extracted_dir
    extracted_dir=$(find "$temp_dir" -maxdepth 1 -type d -name "*Server-Baukasten*" | head -1)
    
    if [ -z "$extracted_dir" ] || [ ! -d "$extracted_dir" ]; then
        log_error "Entpackter Ordner nicht gefunden!"
        exit 1
    fi
    
    # Verschiebe Inhalt ins Zielverzeichnis
    mv "$extracted_dir"/* "$INSTALL_DIR/"
    mv "$extracted_dir"/.* "$INSTALL_DIR/" 2>/dev/null || true
    
    # Setze korrekte Berechtigungen
    set_file_permissions
}

##
# Setzt die korrekten Dateiberechtigungen.
##
set_file_permissions() {
    log_info "  -> Setze Dateiberechtigungen..."
    
    # Hauptskript: Ausführbar + sichere Rechte
    if [ -f "$INSTALL_DIR/serverbaukasten.sh" ]; then
        chmod 750 "$INSTALL_DIR/serverbaukasten.sh"
        log_ok "     ✅ serverbaukasten.sh (750 - owner/group ausführbar)"
    else
        log_warn "     ⚠️  Hauptskript 'serverbaukasten.sh' nicht gefunden!"
    fi
    
    # Install-Script falls vorhanden
    if [ -f "$INSTALL_DIR/install.sh" ]; then
        chmod 750 "$INSTALL_DIR/install.sh"
        log_ok "     ✅ install.sh (750)"
    fi
    
    # Components: Ausführbar für alle Tools
    if [ -d "$INSTALL_DIR/components" ]; then
        local component_count=0
        for component in "$INSTALL_DIR/components"/*; do
            [ -f "$component" ] || continue
            chmod 750 "$component"
            component_count=$((component_count + 1))
        done
        log_ok "     ✅ $component_count Components ausführbar (750)"
    fi
    
    # Lib-Dateien: Nur lesbar
    if [ -d "$INSTALL_DIR/lib" ]; then
        chmod 644 "$INSTALL_DIR/lib"/*.sh 2>/dev/null || true
        log_ok "     ✅ lib/*.sh (644 - nur lesbar)"
    fi
    
    # Module: Nur lesbar (werden nur gesourct)
    if [ -d "$INSTALL_DIR/modules" ]; then
        chmod 644 "$INSTALL_DIR/modules"/*.sh 2>/dev/null || true
        log_ok "     ✅ modules/*.sh (644 - nur lesbar)"
    fi
    
    # Config-Dateien: Sicher lesbar
    if [ -f "$INSTALL_DIR/standard.conf" ]; then
        chmod 644 "$INSTALL_DIR/standard.conf"
    fi
    if [ -f "$INSTALL_DIR/meine-config.conf" ]; then
        chmod 600 "$INSTALL_DIR/meine-config.conf"
        log_ok "     ✅ meine-config.conf (600 - nur owner lesbar)"
    fi
    
    # Templates und sonstige Dateien
    if [ -d "$INSTALL_DIR/conf" ]; then
        chmod 644 "$INSTALL_DIR/conf"/* 2>/dev/null || true
    fi
    
    # README und Dokumentation
    chmod 644 "$INSTALL_DIR"/*.md "$INSTALL_DIR"/LICENSE 2>/dev/null || true
    
    log_info "     📋 Berechtigungsschema:"
    log_info "        • Scripts (750): Nur owner+group ausführbar"
    log_info "        • Libs/Modules (644): Alle lesbar, nicht ausführbar"
    log_info "        • Config (600/644): Sichere Zugriffsrechte"
}

##
# Zeigt eine Zusammenfassung des Downloads.
##
show_download_summary() {
    log_info "  📁 Heruntergeladene Struktur:"
    if command -v tree >/dev/null 2>&1; then
        tree -L 2 "$INSTALL_DIR" | head -15
    else
        find "$INSTALL_DIR" -maxdepth 2 -type f | head -10 | sed 's/^/     /'
        local file_count
        file_count=$(find "$INSTALL_DIR" -type f | wc -l)
        echo "     ... ($file_count Dateien insgesamt)"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# KONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

##
# Bereitet die Konfiguration vor.
##
prepare_config() {
    log_info "Bereite Konfiguration vor..."
    
    cd "$INSTALL_DIR"
    
    # Erstelle lokale Konfiguration
    if [ ! -f "meine-config.conf" ]; then
        if [ -f "standard.conf" ]; then
            cp standard.conf meine-config.conf
            log_ok "Konfigurationsvorlage als 'meine-config.conf' erstellt."
        else
            log_warn "standard.conf nicht gefunden - erstelle leere meine-config.conf"
            touch meine-config.conf
        fi
        
        echo
        log_warn "WICHTIG: Bearbeite die Datei 'meine-config.conf' bevor du das Setup startest!"
        echo -e "${YELLOW}Mindestens diese Werte ändern:${NC}"
        echo "  • SERVER_HOSTNAME"
        echo "  • ADMIN_USER" 
        echo "  • ADMIN_PASSWORD"
        echo "  • ROOT_PASSWORD"
        echo "  • NOTIFICATION_EMAIL"
        echo
    fi
    
    cd - >/dev/null
}

# ═══════════════════════════════════════════════════════════════════════════
# HAUPTFUNKTION
# ═══════════════════════════════════════════════════════════════════════════

##
# Hauptfunktion des Installers.
##
main() {
    # Verarbeite Argumente zuerst
    parse_arguments "$@"
    
    show_header
    
    # Root-Warnung
    if [ "$EUID" -eq 0 ]; then
        log_warn "Installer läuft als root - das ist für den Download nicht nötig."
        log_info "Nur das eigentliche Setup muss als root laufen."
        echo
    fi
    
    # Installation durchführen
    check_prerequisites
    download_repository
    prepare_config
    show_next_steps
}

# ═══════════════════════════════════════════════════════════════════════════
# FEHLERBEHANDLUNG & START
# ═══════════════════════════════════════════════════════════════════════════

# Fehlerbehandlung
trap 'log_error "Installation fehlgeschlagen! Prüfe deine Internetverbindung."; exit 1' ERR

# Script starten
main "$@"
