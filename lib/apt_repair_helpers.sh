#!/bin/bash
################################################################################
#
# APT-REPAIR & PROVIDER-DETECTION HELPER
#
# @description: Provider-spezifische APT-Probleme erkennen & beheben – idempotent
# @author:      Server-Baukasten (TZERO78) & KI-Assistenten
# @version:     1.3.0
# @license:     MIT
#
################################################################################

set -Eeuo pipefail

# --- Logging Fallbacks (immer auf STDERR!) ------------------------------------
if ! command -v log_info >/dev/null 2>&1; then
  log_info()  { printf "ℹ️  %s\n" "$*" >&2; }
  log_ok()    { printf "✅ %s\n" "$*" >&2; }
  log_warn()  { printf "⚠️  %s\n" "$*" >&2; }
  log_error() { printf "❌ %s\n" "$*" >&2; }
fi
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { [ "${DEBUG:-false}" = "true" ] && printf "🐞  %s\n" "$*" >&2 || true; }
fi

# --- Mini-Helpers --------------------------------------------------------------
_has() { command -v "$1" >/dev/null 2>&1; }
_have_proxy() { [ -n "${HTTP_PROXY:-}${http_proxy:-}${HTTPS_PROXY:-}${https_proxy:-}${NO_PROXY:-}${no_proxy:-}" ]; }

# HTTP-Getter mit kurzem Timeout; IMDS ohne Proxy
_http_get() {
  local url="$1"; shift || true
  local no_proxy=false
  case "$url" in
    http://169.254.169.254/*|http://metadata.google.internal/*) no_proxy=true ;;
  esac
  if _has curl; then
    if $no_proxy; then
      curl -fsS --connect-timeout 1 -m 1 --noproxy '*' "$@" "$url"
    else
      curl -fsS --connect-timeout 1 -m 1 "$@" "$url"
    fi
  elif _has wget; then
    if $no_proxy; then
      wget -qO- --timeout=1 --no-proxy "$url" 2>/dev/null
    else
      wget -qO- --timeout=1 "$url" 2>/dev/null
    fi
  else
    return 1
  fi
}

# Auf APT/DPKG-Locks warten (nicht löschen!)
apt_wait_for_locks() {
  local i
  for i in {1..30}; do
    if command -v fuser >/dev/null 2>&1 && {
         fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 ||
         fuser /var/lib/apt/lists/lock >/dev/null 2>&1 ||
         fuser /var/cache/apt/archives/lock >/dev/null 2>&1 ; } then
      log_debug "    - Warte auf APT-Locks... ($i/30)"
      sleep 2
    else
      return 0
    fi
  done
  log_warn "    - APT-Locks hängen – versuche 'dpkg --configure -a'"
  dpkg --configure -a || true
}

# APT-Update mit sinnvollen Defaults (APT 3); optional ForceIPv4 via Env
_apt_update() {
  local opts=(-o "DPkg::Lock::Timeout=60" -o "Acquire::Retries=3" -o "Acquire::http::No-Cache=true")
  if [ "${APT_FORCE_IPV4:-false}" = "true" ]; then
    opts+=(-o "Acquire::ForceIPv4=true")
  fi
  apt-get "${opts[@]}" update
}

# Datei-Sanitizer: CRLF/BOM weg, nur gültige deb/deb-src Zeilen durchlassen
sanitize_sources_file() {
  local file="$1"
  [ -f "$file" ] || return 0

  local tmp; tmp="$(mktemp)"
  cp -a "$file" "$tmp"

  sed -i 's/\r$//' "$tmp" || true      # CRLF -> LF
  sed -i 's/\x1a$//' "$tmp" || true    # DOS EOF ^Z
  sed -i '1s/^\xEF\xBB\xBF//' "$tmp" || true # BOM

  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/                                { print; next }
    /^[[:space:]]*deb(-src)?([[:space:]]|\[)/                             { print; next }
    { print "# (commented by Server-Baukasten) " $0 }
  ' "$tmp" > "$tmp.norm" && mv -f "$tmp.norm" "$tmp"

  # whitespace normalisieren in deb/deb-src
  awk '{ if($1 ~ /^deb(-src)?$/) { $1=$1; gsub(/[\t ]+/," "); } print }' "$tmp" > "$tmp.norm" && mv -f "$tmp.norm" "$tmp"

  if ! cmp -s "$file" "$tmp"; then
    log_debug "    - Sanitize: korrigiere $(basename "$file")"
    cp -f "$tmp" "$file"
  fi
  rm -f "$tmp"
}

# ------------------------------------------------------------------------------
# Provider Detection
# ------------------------------------------------------------------------------
detect_vps_provider() {
  local provider="generic"
  log_debug "  -> Starte VPS-Provider-Detection..."

  if   grep -qi "ionos\|1und1\|1and1" /etc/resolv.conf 2>/dev/null || [ -d /etc/apt/mirrors ]; then
    provider="ionos";       log_info "  -> IONOS/1&1 VPS erkannt"
  elif grep -qi "hetzner\|your-server\.de" /etc/resolv.conf 2>/dev/null || grep -qi "hetzner" /etc/hostname 2>/dev/null || [ -f /etc/hetzner ]; then
    provider="hetzner";     log_info "  -> Hetzner VPS erkannt"
  elif _http_get http://169.254.169.254/metadata/v1/id | grep -Eq '^[0-9]+$'; then
    provider="digitalocean";log_info "  -> DigitalOcean Droplet erkannt"
  elif grep -qi "ovh\|kimsufi\|soyoustart" /etc/resolv.conf 2>/dev/null || [ -f /etc/ovh-release ]; then
    provider="ovh";         log_info "  -> OVH/Kimsufi/SoYouStart VPS erkannt"
  elif grep -qi "contabo" /etc/resolv.conf 2>/dev/null || hostname -f 2>/dev/null | grep -qi "contabo"; then
    provider="contabo";     log_info "  -> Contabo VPS erkannt"
  elif [ -f /etc/scw-release ] || grep -qi "scaleway" /etc/resolv.conf 2>/dev/null; then
    provider="scaleway";    log_info "  -> Scaleway VPS erkannt"
  elif grep -qi "linode" /etc/resolv.conf 2>/dev/null || [ -f /etc/linode ]; then
    provider="linode";      log_info "  -> Linode VPS erkannt"
  elif { if _has curl; then
           TOK=$(_http_get -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token 2>/dev/null || true)
           _http_get -H "X-aws-ec2-metadata-token: ${TOK:-}" http://169.254.169.254/latest/meta-data/ 2>/dev/null || true
         else
           _http_get http://169.254.169.254/latest/meta-data/ 2>/dev/null || true
         fi; } | grep -q "ami-id"; then
    provider="aws";         log_info "  -> AWS EC2 Instance erkannt"
  elif _http_get http://169.254.169.254/v1.json 2>/dev/null | grep -q "instanceid"; then
    provider="vultr";       log_info "  -> Vultr VPS erkannt"
  elif _http_get -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id 2>/dev/null; then
    provider="gcp";         log_info "  -> Google Cloud Platform erkannt"
  elif _http_get -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | grep -q "azEnvironment"; then
    provider="azure";       log_info "  -> Microsoft Azure erkannt"
  else
    log_debug "  -> Kein spezifischer Provider erkannt (generic)"
  fi

  printf '%s\n' "$provider"
}

# ------------------------------------------------------------------------------
# Provider-spezifische APT-Fixes
# ------------------------------------------------------------------------------
apply_provider_apt_fixes() {
  local provider="${1:-generic}"
  log_debug "  -> Wende Provider-APT-Fixes an für: $provider"

  case "$provider" in
    ionos)
      [ -d /etc/apt/mirrors ] && rm -f /etc/apt/mirrors/*.list 2>/dev/null && log_debug "    - IONOS Mirror-Listen entfernt"
      rm -f /etc/apt/apt.conf.d/99ionos* 2>/dev/null || true
      ;;
    hetzner)
      rm -f /etc/apt/sources.list.d/hetzner* 2>/dev/null || true
      sed -i '/mirror\.hetzner\.de/d' /etc/apt/sources.list 2>/dev/null || true
      log_debug "    - Hetzner-Mirror entfernt"
      ;;
    ovh)
      sed -i 's|http://.*\.ovh\.net/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list 2>/dev/null || true
      rm -f /etc/apt/sources.list.d/ovh* 2>/dev/null || true
      ;;
    contabo|netcup)
      rm -f /etc/apt/apt.conf.d/*${provider}* 2>/dev/null || true
      ;;
    aws|gcp|azure)
      sed -i 's|http://.*\.ec2\.archive\.ubuntu\.com|https://archive.ubuntu.com|g' /etc/apt/sources.list 2>/dev/null || true
      sed -i 's|http://.*\.amazonaws\.com/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list 2>/dev/null || true
      ;;
    digitalocean)
      sed -i 's|http://mirrors.digitalocean.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' /etc/apt/sources.list 2>/dev/null || true
      sed -i 's|http://mirrors.digitalocean.com/debian|https://deb.debian.org/debian|g'      /etc/apt/sources.list 2>/dev/null || true
      ;;
    linode)
      sed -i 's|http://mirrors.linode.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' /etc/apt/sources.list 2>/dev/null || true
      sed -i 's|http://mirrors.linode.com/debian|https://deb.debian.org/debian|g'      /etc/apt/sources.list 2>/dev/null || true
      ;;
    scaleway)
      sed -i 's|http://mirrors.scaleway.com/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list 2>/dev/null || true
      ;;
  esac

  apply_general_apt_cleanup
}

# ------------------------------------------------------------------------------
# Allgemeine APT-Bereinigung
# ------------------------------------------------------------------------------
apply_general_apt_cleanup() {
  log_debug "  -> Führe allgemeine APT-Bereinigungen durch..."
  apt_wait_for_locks

  sed -i '/^deb cdrom:/d' /etc/apt/sources.list 2>/dev/null || true
  sed -i '/^#.*mirror\./d' /etc/apt/sources.list 2>/dev/null || true

  # Sanitize Hauptdatei & vorhandene .list Dateien
  sanitize_sources_file "/etc/apt/sources.list"
  if [ -d /etc/apt/sources.list.d ]; then
    find /etc/apt/sources.list.d -maxdepth 1 -type f -name '*.list' -print0 2>/dev/null | while IFS= read -r -d '' f; do
      sanitize_sources_file "$f"
    done
  fi

  if ! _have_proxy; then
    log_debug "    - Kein Proxy (HTTP/HTTPS) erkannt; APT-Proxy-Configs bleiben unangetastet"
  fi
}

# ------------------------------------------------------------------------------
# OS-Erkennung
# ------------------------------------------------------------------------------
detect_os_version() {
  local os_id="unknown" os_version="unknown" os_codename="unknown"

  if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    os_id="${ID:-unknown}"
    os_version="${VERSION_ID:-unknown}"
    os_codename="${VERSION_CODENAME:-unknown}"
  fi

  # Fallback für Debian
  if [ "$os_codename" = "unknown" ] && [ -f /etc/debian_version ]; then
    local deb_version; deb_version=$(cat /etc/debian_version)
    case "${deb_version%%.*}" in
      13) os_codename="trixie" ;;
      12) os_codename="bookworm" ;;
      11) os_codename="bullseye" ;;
      10) os_codename="buster" ;;
       9) os_codename="stretch" ;;
      *)  os_codename="stable" ;;
    esac
  fi

  printf '%s %s %s\n' "$os_id" "$os_version" "$os_codename"
}

# ------------------------------------------------------------------------------
# sources.list Generatoren (nur Kommentare + gültige deb-Zeilen)
# ------------------------------------------------------------------------------
generate_debian_sources() {
  local codename="${1:-stable}" protocol="${2:-https}"
  local provider_tag
  provider_tag="$(printf '%s' "${VPS_PROVIDER:-unknown}" | awk '{print $1}')"
  cat << EOF
# Debian ${codename}
# Generated-UTC: $(date -u +'%Y-%m-%dT%H:%M:%SZ')
# Provider: ${provider_tag}

deb ${protocol}://deb.debian.org/debian ${codename} main contrib non-free non-free-firmware
deb ${protocol}://deb.debian.org/debian ${codename}-updates main contrib non-free non-free-firmware
deb ${protocol}://security.debian.org/debian-security ${codename}-security main contrib non-free non-free-firmware

# Backports (optional)
#deb ${protocol}://deb.debian.org/debian ${codename}-backports main contrib non-free non-free-firmware
EOF
}

generate_ubuntu_sources() {
  local codename="${1:-focal}" protocol="${2:-https}"
  local provider_tag
  provider_tag="$(printf '%s' "${VPS_PROVIDER:-unknown}" | awk '{print $1}')"
  cat << EOF
# Ubuntu ${codename}
# Generated-UTC: $(date -u +'%Y-%m-%dT%H:%M:%SZ')
# Provider: ${provider_tag}

deb ${protocol}://archive.ubuntu.com/ubuntu ${codename} main restricted universe multiverse
deb ${protocol}://archive.ubuntu.com/ubuntu ${codename}-updates main restricted universe multiverse
deb ${protocol}://security.ubuntu.com/ubuntu ${codename}-security main restricted universe multiverse

# Backports (optional)
#deb ${protocol}://archive.ubuntu.com/ubuntu ${codename}-backports main restricted universe multiverse
# Partner (optional)
#deb ${protocol}://archive.canonical.com/ubuntu ${codename} partner
EOF
}

# ------------------------------------------------------------------------------
# Hauptfunktion
# ------------------------------------------------------------------------------
fix_apt_sources_if_needed() {
  log_info "  -> Prüfe und repariere APT-Quellen..."

  local provider; provider=$(detect_vps_provider)
  export VPS_PROVIDER="$provider"
  apply_provider_apt_fixes "$provider"

  read -r os_id os_version os_codename <<< "$(detect_os_version)"
  log_debug "    - OS: $os_id $os_version ($os_codename)"

  # Vorprüfung & Sanitize
  [ -f /etc/apt/sources.list ] && sanitize_sources_file "/etc/apt/sources.list"

  local needs_fix=false
  if [ ! -f /etc/apt/sources.list ] || ! grep -qE "^deb\\s+" /etc/apt/sources.list 2>/dev/null; then
    needs_fix=true; log_warn "  -> APT-Quellen fehlen oder sind ungültig"
  fi
  if ! apt-cache policy 2>/dev/null | grep -qE "o=(Debian|Ubuntu)"; then
    needs_fix=true; log_warn "  -> Keine offiziellen Repositories verfügbar"
  fi

  if [ "$needs_fix" = true ]; then
    local TS tmp backup_sl backup_sld
    TS="$(date +%Y%m%d_%H%M%S)"

    # Backups idempotent
    if [ -f /etc/apt/sources.list ] && [ ! -f /etc/apt/sources.list.backup."$TS" ]; then
      cp -a /etc/apt/sources.list "/etc/apt/sources.list.backup.$TS"
      backup_sl="/etc/apt/sources.list.backup.$TS"
    fi
    if [ -d /etc/apt/sources.list.d ]; then
      local park_dir="/etc/apt/sources.list.d.disabled-$TS"
      if [ ! -d "$park_dir" ]; then
        mv /etc/apt/sources.list.d "$park_dir"
        mkdir -p /etc/apt/sources.list.d
        backup_sld="$park_dir"
        log_warn "  -> sources.list.d nach $(basename "$park_dir") verschoben"
      fi
    fi

    tmp=$(mktemp)
    case "$os_id" in
      debian) generate_debian_sources "$os_codename" "https" > "$tmp" ;;
      ubuntu) generate_ubuntu_sources "$os_codename" "https" > "$tmp" ;;
      *)      log_error "  -> OS '$os_id' nicht unterstützt"; return 1 ;;
    esac

    if [ ! -f /etc/apt/sources.list ] || ! cmp -s "$tmp" /etc/apt/sources.list; then
      mv -f "$tmp" /etc/apt/sources.list
    else
      rm -f "$tmp"
    fi

    apt_wait_for_locks

    # Erster Update-Versuch (HTTPS)
    if ! _apt_update; then
      # TLS/CA Bootstrap-Fallback
      if grep -qiE 'certificate|tls|ssl' /var/log/apt/term.log 2>/dev/null || true; then
        log_warn "  -> TLS/CA-Problem vermutet – temporär auf HTTP wechseln zum Bootstrap"

        # temporär HTTP
        case "$os_id" in
          debian) generate_debian_sources "$os_codename" "http"  > /etc/apt/sources.list ;;
          ubuntu) generate_ubuntu_sources "$os_codename" "http"  > /etc/apt/sources.list ;;
        esac
        if _apt_update && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates; then
          log_ok "  -> CA-Zertifikate installiert – zurück zu HTTPS"
          case "$os_id" in
            debian) generate_debian_sources "$os_codename" "https" > /etc/apt/sources.list ;;
            ubuntu) generate_ubuntu_sources "$os_codename" "https" > /etc/apt/sources.list ;;
          esac
          _apt_update || true
        else
          log_error "❌ Bootstrap mit HTTP/ca-certificates fehlgeschlagen"
          # Rollback der Park-Verzeichnisse
          if [ -n "${backup_sld:-}" ] && [ -d "$backup_sld" ]; then
            rm -rf /etc/apt/sources.list.d
            mv "$backup_sld" /etc/apt/sources.list.d
          fi
          if [ -n "${backup_sl:-}" ] && [ -f "$backup_sl" ]; then
            cp -f "$backup_sl" /etc/apt/sources.list
          fi
          return 1
        fi
      else
        log_warn "  -> Update fehlgeschlagen – versuche Sanitize & zweiten Versuch"
        sanitize_sources_file "/etc/apt/sources.list"
        _apt_update || { log_error "❌ Reparatur der APT-Quellen fehlgeschlagen (zweiter Versuch)"; return 1; }
      fi
    fi

    log_ok "✅ APT-Quellen repariert"
  else
    log_ok "  -> APT-Quellen sind funktionsfähig"
  fi

  return 0
}
