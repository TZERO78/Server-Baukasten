#!/bin/bash
################################################################################
#
# GLOBALE KONSTANTEN FÜR DEN SERVER-BAUKASTEN
#
# @description: Zentrale Konfiguration aller unveränderlichen Werte
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

# ═══════════════════════════════════════════════════════════════════════════
# SCRIPT-INFORMATIONEN
# ═══════════════════════════════════════════════════════════════════════════
readonly SCRIPT_VERSION="4.0.1"
readonly SCRIPT_NAME="Server-Baukasten"
readonly SCRIPT_AUTHOR="Markus F. (TZERO78)"

# ═══════════════════════════════════════════════════════════════════════════
# STANDARD-WERTE FÜR KONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
readonly CROWDSEC_MAXRETRY_DEFAULT=5
readonly CROWDSEC_BANTIME_DEFAULT="48h"
readonly SSH_PORT_DEFAULT=22
readonly NOTIFICATION_EMAIL_DEFAULT="admin@example.com"

# ═══════════════════════════════════════════════════════════════════════════
# REPOSITORY-URLS (GITHUB)
# ═══════════════════════════════════════════════════════════════════════════
readonly COMPONENTS_BASE_URL="https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/components"
readonly CONF_BASE_URL="https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/conf"

# ═══════════════════════════════════════════════════════════════════════════
# PROJEKT-PFADE (RELATIV)
# ═══════════════════════════════════════════════════════════════════════════
readonly LIB_DIR="./lib"
readonly MODULES_DIR="./modules"

# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM-PFADE (ABSOLUT)
# ═══════════════════════════════════════════════════════════════════════════
readonly BACKUP_DIR="/var/backups/server-baukasten"
readonly LOG_DIR="/var/log/server-baukasten"
readonly CONFIG_DIR="/etc/server-baukasten"

# ═══════════════════════════════════════════════════════════════════════════
# UNTERSTÜTZTE BETRIEBSSYSTEME
# ═══════════════════════════════════════════════════════════════════════════
readonly SUPPORTED_OS=("debian:12" "ubuntu:22.04" "ubuntu:24.04")


# ═══════════════════════════════════════════════════════════════════════════
# HILFSFUNKTIONEN
# ═══════════════════════════════════════════════════════════════════════════

##
# Zeigt Script-Informationen an.
##
show_script_info() {
    echo "$SCRIPT_NAME v$SCRIPT_VERSION by $SCRIPT_AUTHOR"
}

##
# Zeigt die Konstanten-Version (für Debugging).
##
show_constants_version() {
    log_debug "Konstanten geladen: $SCRIPT_NAME v$SCRIPT_VERSION"
}

# Beim Laden der Datei automatisch ausführen
if [ "${DEBUG:-false}" = "true" ]; then
    show_constants_version
fi