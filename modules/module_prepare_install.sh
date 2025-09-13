#!/bin/bash
################################################################################
# MODULE: 00_PREPARE_INSTALL (Server-Baukasten)
# System konfliktfrei vorbereiten: Provider-/Repo-Fixes, alte Firewalls/Timer,
# fail2ban → CrowdSec, iptables-Minimalflush. Wizard/Autofix/Dry-Run.
# MIT © Markus F. (TZERO78) & KI-Assistenten
################################################################################
set -Eeuo pipefail
set -x # Debugging

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

# Helfer
# shellcheck source=/dev/null
source "$ROOT_DIR/lib/idempotent_helpers.sh"
[ -f "$ROOT_DIR/lib/apt_repair_helpers.sh" ] && source "$ROOT_DIR/lib/apt_repair_helpers.sh"

# Fallback-Logs (falls globaler Logger noch nicht geladen)
if ! command -v log_info >/dev/null 2>&1; then
  log_info()  { echo -e "\033[0;36mℹ️  $*\033[0m"; }
  log_ok()    { echo -e "\033[0;32m✅ $*\033[0m"; }
  log_warn()  { echo -e "\033[1;33m⚠️  $*\033[0m"; }
  log_error() { echo -e "\033[0;31m❌ $*\033[0m" >&2; }
fi
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { [ "${DEBUG:-false}" = "true" ] && echo -e "\033[0;90m🐞  $*\033[0m" >&2 || true; }
fi

# ── Interaktivität ────────────────────────────────────────────────────────────
yn_default_yes() {
  local prompt="$1" ans
  if [ "${PREPARE_WIZARD:-no}" = "yes" ] && [ -t 0 ]; then
    read -r -p "$prompt [J/n] " ans || true
    case "${ans,,}" in n|nein|no) return 1;; *) return 0;; esac
  fi
  [ "${PREPARE_DRYRUN:-no}" = "yes" ] && return 1 || return 0
}

explain() { [ "${EXPLAIN:-no}" = "yes" ] && echo -e "\033[0;36m   ➜ $*\033[0m"; }

# ── Schritte ──────────────────────────────────────────────────────────────────
step_prereqs() {
  log_info "Vorbereitungen: Grundpakete & dpkg/apt entsperren"
  log_debug "System: Hostname=$(hostname -f 2>/dev/null || hostname), Kernel=$(uname -r), Arch=$(uname -m)"
  if [ -r /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    log_debug "OS: ID=${ID:-?} VERSION_ID=${VERSION_ID:-?} CODENAME=${VERSION_CODENAME:-?}"
  fi
  explain "Wir stellen sicher, dass apt/dpkg frei sind und Basis-Tools vorhanden sind."
  ensure_dpkg_unlocked
  ensure_packages_present ca-certificates curl wget gnupg iproute2 gettext-base bsdutils lsb-release
}

step_provider_and_apt() {
  log_info "Provider/Repos: Erkennen & APT-Quellen prüfen"
  explain "Manche VPS-Images bringen kaputte Mirrors oder Provider-Sonderwege mit."

  local provider="generic"
  if type -t detect_vps_provider >/dev/null 2>&1; then
    provider=$(detect_vps_provider)
    export VPS_PROVIDER="$provider"
    log_debug "VPS-Provider erkannt: $provider"
  else
    log_debug "VPS-Provider-Helper nicht verfügbar"
  fi

  # IONOS & /etc/apt/mirrors → immer fixen (ohne Rückfrage)
  if [ "$provider" = "ionos" ] || [ -d /etc/apt/mirrors ]; then
    log_warn "IONOS/Problem-Provider – repariere APT-Quellen zwingend"
    type -t fix_apt_sources_if_needed >/dev/null 2>&1 && fix_apt_sources_if_needed || true
    return
  fi

  if type -t fix_apt_sources_if_needed >/dev/null 2>&1; then
    yn_default_yes "APT-Quellen prüfen/reparieren?" \
      && fix_apt_sources_if_needed \
      || log_info "Übersprungen: APT-Quellenprüfung"
  else
    log_debug "APT-Helper nicht verfügbar – überspringe Repo-Fixes"
  fi
}

step_disable_legacy_firewalls() {
  log_info "Firewalls: UFW/firewalld entschärfen"
  explain "Damit unsere nftables-Regeln später konsistent sind, schalten wir alte Layer ab."

  if command -v ufw >/dev/null 2>&1; then
    if yn_default_yes "UFW deaktivieren (empfohlen)?"; then
      ensure_ufw_disabled
      [ "${PREPARE_PURGE_LEGACY:-no}" = "yes" ] && ensure_packages_absent ufw
    else
      log_info "UFW bleibt aktiv (kann Konflikte verursachen)"
    fi
  fi

  if command -v firewall-cmd >/dev/null 2>&1 || pkg_installed firewalld; then
    if yn_default_yes "firewalld deaktivieren (empfohlen)?"; then
      ensure_unit_stopped_disabled_masked firewalld.service
      [ "${PREPARE_PURGE_LEGACY:-no}" = "yes" ] && ensure_packages_absent firewalld
    else
      log_info "firewalld bleibt aktiv (kann Konflikte verursachen)"
    fi
  fi
}

step_minimal_iptables_flush() {
  log_info "Netzfilter: Minimalen iptables-Flush durchführen"
  explain "Entlädt alte iptables-Regeln, ohne nftables zu berühren."
  iptables_minimal_flush
}

step_disable_legacy_scheduling() {
  log_info "Timer: cron/anacron/atd & unattended-upgrades eindampfen"
  explain "Wir nutzen systemd-Timer – alte cron/atd Jobs sind nicht nötig."

  if yn_default_yes "cron/anacron/atd deaktivieren (empfohlen)?"; then
    ensure_unit_stopped_disabled_masked cron.service crond.service anacron.timer anacron.service atd.service
    [ "${PREPARE_PURGE_LEGACY:-no}" = "yes" ] && ensure_packages_absent cron anacron at
  else
    log_info "cron/anacron/atd bleiben aktiv"
  fi

  if pkg_installed unattended-upgrades; then
    if yn_default_yes "unattended-upgrades deaktivieren (empfohlen)?"; then
      ensure_unit_stopped_disabled_masked unattended-upgrades.service unattended-upgrades.timer apt-daily.timer apt-daily-upgrade.timer
      [ "${PREPARE_PURGE_LEGACY:-no}" = "yes" ] && ensure_packages_absent unattended-upgrades
    else
      log_info "unattended-upgrades bleibt aktiv (kann apt-Locks erzeugen)"
    fi
  fi
}

step_replace_fail2ban_with_crowdsec_hint() {
  log_info "IPS: fail2ban zugunsten von CrowdSec zurückfahren"
  explain "CrowdSec übernimmt die Rolle von fail2ban effizienter – doppelt braucht es das nicht."
  if pkg_installed fail2ban; then
    if yn_default_yes "fail2ban deaktivieren (empfohlen)?"; then
      ensure_unit_stopped_disabled_masked fail2ban.service fail2ban.socket
      [ "${PREPARE_PURGE_LEGACY:-no}" = "yes" ] && ensure_packages_absent fail2ban
    else
      log_info "fail2ban bleibt aktiv (später ggf. Konflikte prüfen)"
    fi
  else
    log_debug "fail2ban nicht installiert"
  fi
}

# ── Top-Level ─────────────────────────────────────────────────────────────────
module_prepare_install() {
  log_info "Phase 1: Vorbereitung & System-Grundlagen (Prepare)"
  step_prereqs
  step_provider_and_apt
  step_disable_legacy_firewalls
  step_minimal_iptables_flush
  step_disable_legacy_scheduling
  step_replace_fail2ban_with_crowdsec_hint
  log_ok "Prepare-Phase abgeschlossen. System ist bereit für das Setup."
}

# Direkter Aufruf (manuelles Testen)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  : "${PREPARE_WIZARD:=no}"
  : "${PREPARE_AUTOFIX:=yes}"
  : "${PREPARE_DRYRUN:=no}"
  module_prepare_install
fi
