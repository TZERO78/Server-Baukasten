#!/bin/bash
################################################################################
#
# MODUL: INSTALL SERVICES (Core & Admin)
#
# @description: Installiert Basis- und Admin-Tools idempotent, setzt APT-Guard
#               (Default-Release), konfiguriert optional Mail (msmtp) und yq.
# @author:      Server-Baukasten (TZERO78) & KI
# @license:     MIT
# @version:     1.2.0
#
################################################################################

# Dieses Modul erwartet:
# - OS_ID und OS_VERSION_CODENAME (via detect_os in core_helpers)
# - idempotent_helpers (ensure_default_release, missing_packages, install_packages_safe)
# - run_with_spinner (optional)

collect_base_packages() {
  # Namensreferenz: Ergebnis in Array des Aufrufers schreiben
  local -n out="$1"

  # Core / Krypto / Tools
  out=(ca-certificates curl wget gnupg openssl sudo nano vim screen tcpdump file psmisc)

  # Admin-CLI
  out+=(htop tree unzip git rsync net-tools jq lsof)

  # DNS-Tools: Debian (bind9-dnsutils), Ubuntu (dnsutils)
  case "${OS_ID:-debian}" in
    debian) out+=(bind9-dnsutils) ;;
    ubuntu) out+=(dnsutils) ;;
    *)      out+=(dnsutils) ;;
  esac

  # AppArmor & optionale Zusatzprofile
  out+=(apparmor apparmor-profiles-extra)

  # GeoIP (nur falls aktiv – Hinweis: Für nftables brauchst du ipset nicht zwingend)
  if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
    out+=(geoip-database geoip-bin)
  fi

  # Mailstack (optional)
  if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ]; then
    out+=(msmtp msmtp-mta mailutils)
  fi
}

# Architektur → yq-Binary Name
_yq_asset_from_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64) echo "yq_linux_amd64" ;;
    aarch64|arm64) echo "yq_linux_arm64" ;;
    armv7l) echo "yq_linux_arm" ;;
    *) echo "" ;;
  esac
}

module_install_services() {
  log_info "🧩 MODUL: Core- und Admin-Services installieren"

  # 0) OS-Infos loggen
  log_debug "OS: ID=${OS_ID:-?} CODENAME=${OS_VERSION_CODENAME:-?}"

  # 1) APT Default-Release fixieren (verhindert Suite-Mischungen)
  if command -v ensure_default_release >/dev/null 2>&1; then
    ensure_default_release "${OS_VERSION_CODENAME:-}"
  fi

  # 2) Paketliste sammeln (je OS)
  local want=()
  collect_base_packages want
  log_debug "Paketwunsch-Liste (${#want[@]}): ${want[*]}"

  # 3) Fehlende Pakete ermitteln (wenn Helper verfügbar)
  if command -v missing_packages >/dev/null 2>&1; then
    mapfile -t want < <(missing_packages "${want[@]}")
    log_debug "Fehlende Pakete nach Filter (${#want[@]}): ${want[*]:-—}"
  fi

  # 4) Installieren (nur wenn nötig)
  if [ ${#want[@]} -eq 0 ]; then
    log_ok "Alle gewünschten Pakete sind bereits installiert."
  else
    if command -v install_packages_safe >/dev/null 2>&1; then
      install_packages_safe "${want[@]}"
    else
      # Fallback – sollte in der Praxis nie genutzt werden, wird aber zur Sicherheit bereitgestellt
      log_warn "install_packages_safe nicht verfügbar – nutze einfachen Fallback."
      local APT_OPTS="-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --no-install-recommends"
      _run "Paketlisten aktualisieren..." "apt-get update -qq"
      _run "Installiere ${#want[@]} Pakete…" "DEBIAN_FRONTEND=noninteractive apt-get install $APT_OPTS ${want[*]}"
    fi
  fi

  # 5) Mail (msmtp) als sendmail-Alternative setzen – nur wenn installiert
  if dpkg -s msmtp >/dev/null 2>&1; then
    log_info "→ Konfiguriere Mail (msmtp als sendmail-Alternative)…"
    update-alternatives --install /usr/sbin/sendmail sendmail /usr/bin/msmtp 25
    update-alternatives --set sendmail /usr/bin/msmtp
    log_ok "msmtp als systemweite sendmail-Alternative konfiguriert."
  else
    log_debug "msmtp nicht installiert – Mail-Alternatives übersprungen."
  fi

  # 6) yq (Go-Version) – idempotent und arch-aware
  if ! command -v yq >/dev/null 2>&1; then
    log_info "→ Installiere yq (Go-Version)…"
    local asset; asset="$(_yq_asset_from_arch)"
    if [ -z "$asset" ]; then
      log_warn "Unbekannte Architektur ($(uname -m)) – yq-Installation übersprungen."
    else
      if _run "Lade yq ($(uname -m))…" \
         "curl -fsSL https://github.com/mikefarah/yq/releases/latest/download/${asset} -o /usr/local/bin/yq && chmod +x /usr/local/bin/yq"; then
        log_ok "yq installiert."
      else
        log_warn "yq-Installation fehlgeschlagen."
      fi
    fi
  else
    log_debug "yq bereits vorhanden: $(command -v yq)"
  fi

  log_ok "Modul Install-Services erfolgreich abgeschlossen."
}
