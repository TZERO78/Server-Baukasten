#!/bin/bash
################################################################################
#
# LOG HELPER
#
# @description: Logging-Funktionen mit Symbolen und Journal-Integration
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

# --- Basics ---
set -Eeuo pipefail

# =============================================================================
# Farben (nur auf TTY; NO_COLOR respektieren)
# =============================================================================
_use_color=false
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then _use_color=true; fi
if $_use_color; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  PURPLE='\033[0;35m'
  CYAN='\033[0;36m'
  NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; PURPLE=''; CYAN=''; NC=''
fi

# =============================================================================
# Konfiguration
# =============================================================================
# LOG_LEVEL: DEBUG | INFO | WARN | ERROR
LOG_LEVEL="${LOG_LEVEL:-INFO}"
# Tag für syslog/logger
LOG_TAG="${LOG_TAG:-server-baukasten}"

_level_to_num() {
  case "$1" in
    DEBUG) echo 10 ;;
    INFO)  echo 20 ;;
    WARN)  echo 30 ;;
    ERROR) echo 40 ;;
    *)     echo 20 ;;
  esac
}

_allow() { [ "$( _level_to_num "$1" )" -ge "$( _level_to_num "$LOG_LEVEL" )" ]; }

_log_syslog() {
  local pri="$1"; shift
  command -v logger >/dev/null 2>&1 && logger -t "$LOG_TAG" -p "daemon.${pri}" -- "$@"
}

# =============================================================================
# Logging-Funktionen
# =============================================================================
log_info() {
  _allow INFO || return 0
  printf "%b\n" "${CYAN}ℹ️  $*${NC}"
  _log_syslog info "INFO: $*"
}

log_ok() {
  _allow INFO || return 0
  printf "%b\n" "${GREEN}✅ $*${NC}"
  _log_syslog notice "SUCCESS: $*"
}

log_warn() {
  _allow WARN || return 0
  printf "%b\n" "${YELLOW}⚠️  $*${NC}"
  _log_syslog warning "WARN: $*"
}

log_error() {
  printf "%b\n" "${RED}❌ $*${NC}" >&2
  _log_syslog err "ERROR: $*"
}

# beendet sofort mit RC (Default 1)
log_error_exit() {
  local rc="${1:-1}"; shift || true
  log_error "$*"
  exit "$rc"
}

# Debug-Logging nur wenn DEBUG=true und Level erlaubt
log_debug() {
  [ "${DEBUG:-false}" = "true" ] || return 0
  _allow DEBUG || return 0
  printf "%b\n" "${PURPLE}🐞  $*${NC}" >&2
  _log_syslog debug "DEBUG: $*"
}