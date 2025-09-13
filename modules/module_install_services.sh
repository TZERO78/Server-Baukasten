#!/bin/bash
################################################################################
# MODUL: Core- und Admin-Services installieren
# @description:
#   - Installiert Standard-Tools (Core/Admin) sowie optionale Security/Apps
#   - yq (Go-Version) nur bei Bedarf und mit Version-Check
#   - msmtp-Konfiguration nur bei gültigen SMTP-Variablen
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

  # 5) Mail (msmtp) – nur wenn gewünscht, installiert und Variablen valide
  if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ]; then
    if dpkg -s msmtp >/dev/null 2>&1; then
      # Minimalprüfung: ohne HOST kein Sinn – überspringen statt Fehler
      if [ -z "${SMTP_HOST:-}" ]; then
        log_warn "SMTP_HOST nicht gesetzt – überspringe Mail-Konfiguration."
      else
        # Wenn AUTH=ja, müssen USER/PASSWORD da sein
        local need_auth="nein"
        [ "${SMTP_AUTH:-ja}" = "ja" ] && need_auth="ja"
        if [ "$need_auth" = "ja" ] && { [ -z "${SMTP_USER:-}" ] || [ -z "${SMTP_PASSWORD:-}" ]; }; then
          log_warn "SMTP_AUTH=ja aber SMTP_USER/PASSWORD fehlen – überspringe Mail-Konfiguration."
        else
          log_debug "msmtp-Setup: host=${SMTP_HOST} port=${SMTP_PORT:-25} auth=${SMTP_AUTH:-ja} starttls=${SMTP_TLS_STARTTLS:-ja}"

          update-alternatives --install /usr/sbin/sendmail sendmail /usr/bin/msmtp 25
          update-alternatives --set sendmail /usr/bin/msmtp

          # ja/nein → on/off
          local tls_onoff="on"
          [ "${SMTP_TLS_STARTTLS:-ja}" = "nein" ] && tls_onoff="off"
          local auth_onoff="on"
          [ "${SMTP_AUTH:-ja}" = "nein" ] && auth_onoff="off"

          # Idempotent schreiben (mit ensure_* falls vorhanden)
          if type -t ensure_file >/dev/null 2>&1; then
            ensure_file "/etc/msmtprc" 0600 "root:root"
          else
            install -m 0600 -o root -g root /dev/null /etc/msmtprc
          fi

          cat >/etc/msmtprc <<EOF
defaults
auth           ${auth_onoff}
tls            ${tls_onoff}
tls_starttls   ${tls_onoff}
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

account        default
host           ${SMTP_HOST}
port           ${SMTP_PORT:-25}
from           ${SMTP_FROM:-root@$(hostname -f 2>/dev/null || hostname)}
$( [ "$auth_onoff" = "on" ] && printf 'user           %s\npassword       %s\n' "${SMTP_USER:-}" "${SMTP_PASSWORD:-}" )
EOF

          if type -t ensure_mode_owner >/dev/null 2>&1; then
            ensure_mode_owner "/etc/msmtprc" 0600 "root:root"
          else
            chmod 600 /etc/msmtprc; chown root:root /etc/msmtprc
          fi

          log_ok "msmtp als sendmail konfiguriert."
        fi
      fi
    else
      log_warn "msmtp nicht installiert – Mail-Konfiguration übersprungen."
    fi
  else
    log_debug "ENABLE_SYSTEM_MAIL!=ja – msmtp-Konfiguration übersprungen."
  fi

  log_ok "Modul Install-Services erfolgreich abgeschlossen."
}
