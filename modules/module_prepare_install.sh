#!/bin/bash
################################################################################
# MODULE: MODULE_PREPARE_INSTALL
#
# Phase 1: Vorbereitung & System-Grundlagen (idempotent)
# - Wartet auf APT/DPKG-Locks
# - Repariert APT-Quellen (Provider-aware) via apt_repair_helpers.sh
# - Aktualisiert Paketlisten (mit Retries)
# - Installiert fehlende Basis-Tools
# - Enthält lokale run_with_spinner-Implementierung
#
# Dieses Modul ist sicher mehrfach auszuführen (idempotent).
################################################################################

set -Eeuo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Fallback-Logs (falls log_helper noch nicht geladen ist)
# ──────────────────────────────────────────────────────────────────────────────
if ! command -v log_info >/dev/null 2>&1; then
  log_info()  { echo -e "ℹ️  $*"; }
  log_ok()    { echo -e "✅ $*"; }
  log_warn()  { echo -e "⚠️  $*"; }
  log_error() { echo -e "❌ $*" >&2; }
  log_debug() { [ "${DEBUG:-false}" = "true" ] && echo -e "🐞  $*" >&2 || true; }
fi

# Sanfte Info-Funktion: darf NIE fehlschlagen (damit set -e nicht triggert)
if ! command -v explain >/dev/null 2>&1; then
  explain() { [ $# -gt 0 ] && log_info "$*" || true; return 0; }
fi

## Verzeichnisse sicherstellen, die apt erwartet
ensure_apt_paths() {
  # Diese Verzeichnisse werden von apt & Repo-Installern erwartet
  mkdir -p /etc/apt/sources.list.d /etc/apt/keyrings /etc/apt/preferences.d
  chmod 755 /etc/apt /etc/apt/sources.list.d /etc/apt/preferences.d
  # keyrings darf 755 sein, einzelne *.gpg darin 644
  chmod 755 /etc/apt/keyrings 2>/dev/null || true
}

# ──────────────────────────────────────────────────────────────────────────────
# Modul-Einstiegspunkt
# ──────────────────────────────────────────────────────────────────────────────
# Phase 1: Vorbereitung & System-Grundlagen (nur Orchestrierung)
module_prepare_install() {
  log_info "Phase 1: Vorbereitung & System-Grundlagen (Prepare)"
  log_info "Vorbereitungen: Grundpakete & dpkg/apt entsperren"

  # --- Host/OS-Info (nur Debug) ---------------------------------------------
  if [ -r /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    log_debug "System: host=$(hostname -f 2>/dev/null || hostname), kernel=$(uname -r), arch=$(uname -m)"
    log_debug "OS: ID=${ID:-?} VERSION_ID=${VERSION_ID:-?} CODENAME=${VERSION_CODENAME:-?}"
  fi

  explain "Wir stellen sicher, dass apt/dpkg frei sind und Basis-Tools vorhanden sind."
  
  # --- APT-Backup-Verzeichnis sicherstellen --------------------------------
  cleanup_apt_backup_files	
  
  # --- APT/DPKG-Locks abwarten ----------------------------------------------
  if type -t apt_wait_for_locks >/dev/null 2>&1; then
    apt_wait_for_locks
  else
    log_debug "apt_wait_for_locks nicht verfügbar – einfacher Fallback (dpkg --configure -a)"
    dpkg --configure -a >/dev/null 2>&1 || true
  fi

  # --- APT-Quellen prüfen/reparieren (Delegation) ----------------------------
  # Kein Idempotenz- oder Sanitize-Code hier; alles macht apt_repair_helpers.sh
  if type -t fix_apt_sources_if_needed >/dev/null 2>&1; then
    # Nur Hinweis-Log; die eigentlichen Details loggt der Helper.
    if [ -d /etc/apt/mirrors ] || [ "${VPS_PROVIDER:-}" = "ionos" ]; then
      log_warn "  -> IONOS/Problem-Provider erkannt – repariere APT-Quellen…"
    else
      log_info "  -> Prüfe APT-Quellen (Reparatur bei Bedarf)…"
    fi
    if ! fix_apt_sources_if_needed; then
      log_error "Reparatur der APT-Quellen fehlgeschlagen."
      exit 1
    fi
  else
    log_debug "apt_repair_helpers nicht geladen – überspringe APT-Reparatur."
  fi

  # --- Paketlisten aktualisieren (robuste 3×-Retry) --------------------------
  local tries=0
  while :; do
    tries=$((tries+1))
    log_debug "apt-get update (Versuch ${tries}/3)"
    if run_with_spinner "Paketlisten aktualisieren (Versuch ${tries}/3)" \
         "apt-get -o DPkg::Lock::Timeout=60 update"; then
      log_ok "Paketlisten aktualisiert."
      break
    fi
    if [ $tries -ge 3 ]; then
      log_error "apt-get update schlug 3× fehl – Abbruch."
      exit 1
    fi
    log_warn "apt-get update fehlgeschlagen – erneuter Versuch in 5s…"
    sleep 5
    if type -t apt_wait_for_locks >/dev/null 2>&1; then apt_wait_for_locks; fi
  done

  # --- Minimal nötige Basis-Tools nachziehen --------------------------------
  # (Nur das, was wir in dieser frühen Phase brauchen; alles Weitere später
  #  im module_install_services – so vermeiden wir Konflikte & Redundanzen.)
  local to_install=()
  command -v curl      >/dev/null 2>&1 || to_install+=(curl)
  command -v wget      >/dev/null 2>&1 || to_install+=(wget)
  command -v gpg       >/dev/null 2>&1 || to_install+=(gnupg)
  command -v ip        >/dev/null 2>&1 || to_install+=(iproute2)
  command -v envsubst  >/dev/null 2>&1 || to_install+=(gettext-base)
  command -v logger    >/dev/null 2>&1 || to_install+=(bsdutils)
  dpkg -s ca-certificates >/dev/null 2>&1 || to_install+=(ca-certificates)

  if [ ${#to_install[@]} -gt 0 ]; then
    log_info "Installiere Basis-Tools: ${to_install[*]}"
    if ! run_with_spinner "Installiere Basis-Tools…" \
         "DEBIAN_FRONTEND=noninteractive apt-get install -y ${to_install[*]}"; then
      log_error "Installation der Basis-Tools fehlgeschlagen."
      exit 1
    fi
    log_ok "Basis-Tools installiert."
  else
    log_ok "Alle Basis-Tools bereits vorhanden."
  fi

  # APT-Pfade sicherstellen (für Repo-Installer etc.)
  ensure_apt_paths
  log_debug "APT-Pfade sichergestellt."

  # --- Locks final räumen ----------------------------------------------------
  if type -t apt_wait_for_locks >/dev/null 2>&1; then apt_wait_for_locks; fi
  log_ok "Phase 1 abgeschlossen."
}