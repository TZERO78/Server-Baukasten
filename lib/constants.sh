#!/bin/bash
################################################################################
# GLOBALE KONSTANTEN FÜR DEN SERVER-BAUKASTEN
# Zentrale Konfiguration aller unveränderlichen Werte
################################################################################

set -Eeuo pipefail

# --- Logging-Fallbacks (nur wenn log_helper nicht geladen ist) ---
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { [ "${DEBUG:-false}" = "true" ] && echo -e "🐞  $*" >&2 || true; }
fi

# --- Script-/Projektpfade robust aus Skriptstandort ableiten ---
# Ermittle das Hauptprojekt-Verzeichnis (eine Ebene über lib/)
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && cd .. && pwd -P)"

# ════════════════════════════════════════════════════════════════
# SCRIPT-INFORMATIONEN
# ════════════════════════════════════════════════════════════════
# Version aus VERSION-Datei laden (Single Source of Truth)
if [ -f "${SCRIPT_DIR}/VERSION" ]; then
    SCRIPT_VERSION=$(cat "${SCRIPT_DIR}/VERSION" | tr -d '\n\r ')
else
    SCRIPT_VERSION="unknown"
fi
readonly SCRIPT_VERSION
readonly SCRIPT_NAME="Server-Baukasten"
readonly SCRIPT_AUTHOR="Markus F. (TZERO78)"

# ════════════════════════════════════════════════════════════════
# STANDARD-WERTE FÜR KONFIGURATION
# ════════════════════════════════════════════════════════════════
readonly CROWDSEC_MAXRETRY_DEFAULT=5
readonly CROWDSEC_BANTIME_DEFAULT="48h"
readonly SSH_PORT_DEFAULT=22
readonly NOTIFICATION_EMAIL_DEFAULT="admin@example.com"

# ════════════════════════════════════════════════════════════════
# REPOSITORY-URLS (GITHUB)
# ════════════════════════════════════════════════════════════════
readonly COMPONENTS_BASE_URL="https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/components"
readonly CONF_BASE_URL="https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/conf"

# Wenn Child-Prozesse sie brauchen:
# export COMPONENTS_BASE_URL CONF_BASE_URL

# ════════════════════════════════════════════════════════════════
# PROJEKT-PFADE (RELATIV ZUM SKRIPT)
# ════════════════════════════════════════════════════════════════
readonly LIB_DIR="${SCRIPT_DIR}/lib"
readonly MODULES_DIR="${SCRIPT_DIR}/modules"
readonly COMP_DIR="${SCRIPT_DIR}/components"
readonly TEMPLATE_DIR="${SCRIPT_DIR}/conf"

# ════════════════════════════════════════════════════════════════
# SYSTEM-PFADE (ABSOLUT)
# ════════════════════════════════════════════════════════════════
readonly BACKUP_DIR="/var/backups/server-baukasten"
readonly LOG_DIR="/var/log/server-baukasten"
readonly CONFIG_DIR="/etc/server-baukasten"

# ════════════════════════════════════════════════════════════════
# UNTERSTÜTZTE BETRIEBSSYSTEME
# ════════════════════════════════════════════════════════════════
readonly SUPPORTED_OS=("debian:12" "ubuntu:22.04" "ubuntu:24.04")

# ════════════════════════════════════════════════════════════════
# HILFSFUNKTIONEN
# ════════════════════════════════════════════════════════════════
show_script_info() {
  echo "${SCRIPT_NAME} v${SCRIPT_VERSION} by ${SCRIPT_AUTHOR}"
}

show_constants_version() {
  log_debug "Konstanten geladen: ${SCRIPT_NAME} v${SCRIPT_VERSION}"
}

# Optional: Verzeichnisse anlegen, wenn gebraucht
ensure_project_dirs() {
  install -d -m 0750 "$BACKUP_DIR" "$LOG_DIR" "$CONFIG_DIR"
}

# Automatik nur im Debug-Fall
if [ "${DEBUG:-false}" = "true" ]; then
  show_constants_version
fi
