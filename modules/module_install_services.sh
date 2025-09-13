#!/bin/bash
################################################################################
#
# MODUL: INSTALL SERVICES
#
# @description: Installiert Kern-/Admin-/Security-Pakete idempotent & robust,
#               richtet optional Mail (msmtp) ein, installiert yq (Go-Version).
#               Docker & GeoIP-spezifisches bleiben in eigenen Modulen.
# @license:     MIT
#
################################################################################

set -Eeuo pipefail

# Erwartet: idempotent_helpers.sh geladen (install_packages_safe, map_package_name, ...)
# Fallback: weiche Warnungen, falls die Helper fehlen
_have_install_safe() { type -t install_packages_safe >/dev/null 2>&1; }

module_install_services() {
    log_info "🧩 MODUL: Core- und Admin-Services installieren"

    # Immer frisch updaten (billig & idempotent)
    run_with_spinner "Paketlisten aktualisieren..." "apt-get update -qq"

    # --- Paketlisten definieren -----------------------------------------------------
    # System/Core
    local BASE_PACKAGES=(
        ca-certificates curl wget gnupg gpg gpg-agent openssl
        software-properties-common      # wird ggf. gewarnt, falls nicht verfügbar
        apt-transport-https             # wird via Mapping auf 'apt' gesetzt
    )

    # Admin-Tools
    local ADMIN_PACKAGES=(
        sudo nano vim htop tree unzip git rsync screen tmux
        net-tools bind9-dnsutils tcpdump jq lsof file psmisc
    )

    # Security
    local SECURITY_PACKAGES=(
        apparmor apparmor-utils          # utils wird ggf. auf 'apparmor' gemappt
        aide rkhunter libipc-system-simple-perl
    )

    # Optional: GeoIP
    local GEOIP_PACKAGES=()
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        GEOIP_PACKAGES=( ipset geoip-database geoip-bin )
        log_debug "GeoIP aktiviert – zusätzliche Pakete: ${GEOIP_PACKAGES[*]}"
    fi

    # Optional: Mail
    local MAIL_PACKAGES=()
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ]; then
        MAIL_PACKAGES=( msmtp msmtp-mta mailutils )
        log_debug "Mail aktiviert – zusätzliche Pakete: ${MAIL_PACKAGES[*]}"
    fi

    # --- Installation robust durchführen -------------------------------------------
    if _have_install_safe; then
        log_debug "Verwende install_packages_safe (idempotent & mapping-aware)."
        install_packages_safe "${BASE_PACKAGES[@]}"
        install_packages_safe "${ADMIN_PACKAGES[@]}"
        install_packages_safe "${SECURITY_PACKAGES[@]}"
        [ ${#GEOIP_PACKAGES[@]} -gt 0 ] && install_packages_safe "${GEOIP_PACKAGES[@]}"
        [ ${#MAIL_PACKAGES[@]} -gt 0 ] && install_packages_safe "${MAIL_PACKAGES[@]}"
    else
        # Minimaler Fallback (nicht so robust wie der Helper)
        log_warn "install_packages_safe nicht verfügbar – nutze einfachen Fallback."
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
          "${BASE_PACKAGES[@]}" "${ADMIN_PACKAGES[@]}" "${SECURITY_PACKAGES[@]}" \
          "${GEOIP_PACKAGES[@]}" "${MAIL_PACKAGES[@]}" || true
    fi

    # --- AppArmor-Extras (best effort) ---------------------------------------------
    # Nicht fatal, falls nicht verfügbar
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apparmor-profiles-extra 2>/dev/null; then
        log_warn "AppArmor-Profile-Extras nicht verfügbar – übersprungen."
    else
        log_ok "AppArmor-Profile-Extras installiert."
    fi

    # --- yq (Go-Version) installieren (idempotent) ---------------------------------
    log_info "  -> Installiere yq (Go-Version)..."
    if [ -x /usr/local/bin/yq ]; then
        log_info "     yq bereits vorhanden – überspringe Download."
    else
        local arch; arch="$(dpkg --print-architecture)"
        local yq_asset="yq_linux_amd64"
        case "$arch" in
            amd64) yq_asset="yq_linux_amd64" ;;
            arm64) yq_asset="yq_linux_arm64" ;;
            armhf) yq_asset="yq_linux_arm" ;;
            i386)  yq_asset="yq_linux_386" ;;
        esac
        if run_with_spinner "Lade yq (${arch})..." \
            "wget -q https://github.com/mikefarah/yq/releases/latest/download/${yq_asset} -O /usr/local/bin/yq && chmod +x /usr/local/bin/yq"; then
            log_ok "yq installiert."
        else
            log_warn "yq-Installation fehlgeschlagen (nicht kritisch)."
        fi
    fi

    # --- Mail-System konfigurieren (falls aktiviert) -------------------------------
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ]; then
        log_info "  -> Konfiguriere Mail (msmtp als sendmail-Alternative)..."
        if command -v msmtp >/dev/null 2>&1; then
            update-alternatives --install /usr/sbin/sendmail sendmail /usr/bin/msmtp 25
            update-alternatives --set sendmail /usr/bin/msmtp
            log_ok "msmtp als systemweite sendmail-Alternative konfiguriert."
        else
            log_warn "msmtp nicht installiert – Mail-Konfiguration übersprungen."
        fi
    else
        log_info "  -> Mail-System-Konfiguration übersprungen (deaktiviert)."
    fi

    log_ok "Modul Install-Services erfolgreich abgeschlossen."
}
