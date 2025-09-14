#!/bin/bash
################################################################################
# MODUL: Core- und Admin-Services installieren
# @description:
#   - Installiert Standard-Tools (Core/Admin) sowie optionale Security/Apps
#   - yq (Go-Version) nur bei Bedarf und mit Version-Check
#   - msmtp Installation (Konfiguration erfolgt in module_mail)
# @license: MIT
################################################################################

module_install_services() {
  log_info "🧩 MODUL: Core- und Admin-Services installieren"

  # 0) Paketlisten aktualisieren (kurzer Retry über Helper, falls vorhanden)
  if type -t apt_update_retry >/dev/null 2>&1; then
    run_with_spinner "Paketlisten aktualisieren" "apt_update_retry" \
      || { log_error "apt-get update fehlgeschlagen"; return 1; }
  else
    run_with_spinner "Paketlisten aktualisieren" "apt-get -o DPkg::Lock::Timeout=60 update" \
      || { log_error "apt-get update fehlgeschlagen"; return 1; }
  fi

  # 1) Paketsets – bewusst schlank & distro-neutral
  local core_pkgs=(
    ca-certificates curl wget gnupg gpg gpg-agent openssl
    sudo nano vim screen tcpdump file psmisc apparmor
  )
  local admin_pkgs=(htop tree unzip git rsync net-tools jq lsof)
  local security_pkgs=(aide rkhunter apparmor-utils libipc-system-simple-perl)

  # Optional: DNS-Tools (nur auf Wunsch)
  if [ "${INSTALL_DNS_TOOLS:-nein}" = "ja" ]; then
    admin_pkgs+=(bind9-dnsutils)
  fi

  # Optional: GeoIP-Tools (nur auf Wunsch)
  if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
    admin_pkgs+=(ipset geoip-database geoip-bin)
  fi

  # 2) Installation robust (bevorzugt über Helper)
  local all_pkgs=("${core_pkgs[@]}" "${admin_pkgs[@]}" "${security_pkgs[@]}")
  if type -t install_packages_safe >/dev/null 2>&1; then
    if ! install_packages_safe "${all_pkgs[@]}"; then
      log_warn "Gesamtinstallation schlug fehl – versuche blockweise…"
      install_packages_safe "${core_pkgs[@]}"     || log_warn "Core-Pakete nicht vollständig"
      install_packages_safe "${admin_pkgs[@]}"    || log_warn "Admin-Pakete nicht vollständig"
      install_packages_safe "${security_pkgs[@]}" || log_warn "Security-Pakete nicht vollständig"
    fi
  else
    log_warn "install_packages_safe nicht verfügbar – nutze direkten Fallback."
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${all_pkgs[@]}" || true
  fi

  # 3) AppArmor-Extras (nur falls im Repo vorhanden)
  if apt-cache show apparmor-profiles-extra >/dev/null 2>&1; then
    run_with_spinner "AppArmor-Profile-Extras installieren" \
      "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apparmor-profiles-extra" \
      && log_ok "AppArmor-Profile-Extras installiert." \
      || log_warn "AppArmor-Profile-Extras nicht verfügbar."
  else
    log_debug "apparmor-profiles-extra nicht in Repos – überspringe."
  fi

  # 4) yq (Go) – installieren, wenn fehlt ODER Version kaputt
  if ! command -v yq >/dev/null 2>&1 || ! yq --version >/dev/null 2>&1; then
    log_info "  -> Installiere yq (Go-Version)…"
    local arch=""
    case "$(dpkg --print-architecture)" in
      amd64) arch="amd64" ;;
      arm64) arch="arm64" ;;
      armhf) arch="arm" ;;
      *)     log_warn "Unbekannte Architektur für yq – überspringe."; arch="";;
    esac
    if [ -n "$arch" ]; then
      run_with_spinner "Lade yq (${arch})" \
        "wget -q https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${arch} -O /usr/local/bin/yq && chmod +x /usr/local/bin/yq" \
        && log_ok "yq installiert." \
        || log_warn "yq-Installation fehlgeschlagen."
    fi
  else
    log_debug "yq bereits ok: $(yq --version 2>/dev/null || echo '?')"
  fi

  # 5) Mail (msmtp) – nur Installation, Konfiguration erfolgt in module_mail
  if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ]; then
    log_info "  -> Installiere msmtp (Konfiguration erfolgt später)..."
    
    # msmtp installieren falls nicht vorhanden
    if ! dpkg -s msmtp >/dev/null 2>&1; then
      run_with_spinner "Installiere msmtp" "apt-get install -y msmtp msmtp-mta" \
        && log_ok "msmtp erfolgreich installiert." \
        || { log_error "msmtp-Installation fehlgeschlagen."; return 1; }
    else
      log_debug "msmtp bereits installiert."
    fi
  else
    log_debug "ENABLE_SYSTEM_MAIL!=ja – msmtp-Installation übersprungen."
  fi

  log_ok "Modul Install-Services erfolgreich abgeschlossen."
}