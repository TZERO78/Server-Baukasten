#!/bin/bash
################################################################################
# MODUL: Core- und Admin-Services installieren
#
# @description: Installiert essentielle System-, Admin- und Security-Pakete
#               release-agnostisch (Debian/Ubuntu) und idempotent.
#               Außerdem: optional msmtp-Integration & yq (Go-Version).
# @author:      Server-Baukasten (TZERO78)
# @license:     MIT
# @version:     1.0.0
################################################################################

set -Eeuo pipefail

module_install_services() {
  log_info "🧩 MODUL: Core- und Admin-Services installieren"

  # Sicherstellen, dass Helper verfügbar sind
  if ! command -v install_packages_safe >/dev/null 2>&1; then
    log_warn "install_packages_safe nicht verfügbar – lade Fallback-Helfer."
    # Versuche Helper zu laden, falls noch nicht
    if [ -f "./lib/idempotent_helpers.sh" ]; then
      # shellcheck disable=SC1091
      source "./lib/idempotent_helpers.sh"
    fi
  fi

  # Einmal Update (leise), mit lock-Wartefunktion falls vorhanden
  if command -v apt_update_quick >/dev/null 2>&1; then
    run_with_spinner "Paketlisten aktualisieren..." "apt_update_quick"
  else
    run_with_spinner "Paketlisten aktualisieren..." "apt-get update -qq"
  fi

  # Falls install_packages_safe weiterhin fehlt: Minimal-Fallback (nicht ideal, aber funktionsfähig)
  if ! command -v install_packages_safe >/dev/null 2>&1; then
    log_warn "install_packages_safe nicht verfügbar – nutze einfachen Fallback."
    export DEBIAN_FRONTEND=noninteractive
    apt-get -y --no-install-recommends install \
      ca-certificates openssl curl wget gnupg gpg gpg-agent sudo nano vim screen \
      tcpdump file psmisc apparmor || true
  else
    # Paketgruppen (release-agnostisch; Alternativen werden in den Helfern gelöst)
    local pkgs_core=(
      ca-certificates openssl curl wget gnupg gpg gpg-agent sudo nano vim screen
      file psmisc
    )
    local pkgs_admin=(
      htop tree unzip git rsync tmux net-tools bind9-dnsutils tcpdump jq lsof
    )
    local pkgs_security=(
      apparmor aide rkhunter apparmor-utils
    )
    # Optional: GeoIP-Tools (wenn aktiviert)
    local pkgs_geoip=()
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
      pkgs_geoip+=(ipset geoip-database geoip-bin)
    fi
    # Optional: Mail-Stack
    local pkgs_mail=()
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ]; then
      pkgs_mail+=(msmtp msmtp-mta mailutils)
    fi

    install_packages_safe "${pkgs_core[@]}"
    install_packages_safe "${pkgs_admin[@]}"
    install_packages_safe "${pkgs_security[@]}"

    [ ${#pkgs_geoip[@]} -gt 0 ] && install_packages_safe "${pkgs_geoip[@]}"
    [ ${#pkgs_mail[@]}  -gt 0 ] && install_packages_safe "${pkgs_mail[@]}"

    # apparmor-profiles-extra nur, wenn im Release verfügbar
    if apt_pkg_available apparmor-profiles-extra; then
      install_packages_safe apparmor-profiles-extra
      log_ok "AppArmor-Profile-Extras installiert."
    else
      log_info "AppArmor-Profile-Extras im Release nicht verfügbar – übersprungen."
    fi
  fi

  # ────────────────────────────────────────────────────────────────────────────
  # yq (Go-Version) installieren, falls nicht vorhanden
  # ────────────────────────────────────────────────────────────────────────────
  log_info "  -> Installiere yq (Go-Version)…"
  if ! command -v yq >/dev/null 2>&1; then
    # Architektur auf GitHub-Bezeichner mappen
    local arch; arch="$(dpkg --print-architecture)"
    case "$arch" in
      amd64|arm64|ppc64el|s390x|armhf) : ;;
      *) arch="amd64" ;;  # Fallback
    esac
    run_with_spinner "Lade yq ($arch)..." \
      "wget -q https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${arch} -O /usr/local/bin/yq && chmod +x /usr/local/bin/yq"
    if command -v yq >/dev/null 2>&1; then
      log_ok "yq installiert."
    else
      log_warn "yq-Installation fehlgeschlagen (optional)."
    fi
  else
    log_info "yq bereits installiert: $(yq --version 2>/dev/null || echo vorhanden)"
  fi

  # ────────────────────────────────────────────────────────────────────────────
  # Mail: msmtp als sendmail-Alternative konfigurieren (nur wenn installiert)
  # ────────────────────────────────────────────────────────────────────────────
  log_info "  -> Konfiguriere Mail (msmtp als sendmail-Alternative)…"
  if command -v msmtp >/dev/null 2>&1; then
    update-alternatives --install /usr/sbin/sendmail sendmail /usr/bin/msmtp 25
    update-alternatives --set     sendmail /usr/bin/msmtp
    log_ok "msmtp als systemweite sendmail-Alternative konfiguriert."
  else
    log_warn "msmtp nicht installiert – Mail-Alternative übersprungen."
  fi

  log_ok "Modul Install-Services erfolgreich abgeschlossen."
}
