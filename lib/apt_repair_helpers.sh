#!/bin/bash
################################################################################
# APT-REPAIR HELPER (nur APT, keine Datei-Helper)
# @description: Provider erkennen, Quellen reparieren, Updates/Locks, Pakete.
# @license:     MIT
# @version:     2.0.0
################################################################################
set -Eeuo pipefail

# Logging-Fallbacks
if ! command -v log_info  >/dev/null 2>&1; then log_info()  { printf "ℹ️  %s\n" "$*" >&2; }; fi
if ! command -v log_ok    >/dev/null 2>&1; then log_ok()    { printf "✅ %s\n" "$*" >&2; }; fi
if ! command -v log_warn  >/dev/null 2>&1; then log_warn()  { printf "⚠️  %s\n" "$*" >&2; }; fi
if ! command -v log_error >/dev/null 2>&1; then log_error() { printf "❌ %s\n" "$*" >&2; }; fi
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { [ "${DEBUG:-false}" = "true" ] && printf "🐞  %s\n" "$*" >&2 || true; }
fi

_has() { command -v "$1" >/dev/null 2>&1; }

# HTTP (für Cloud-Metadata, kurze Timeouts)
_http_get() {
  local url="$1"; shift || true
  local no_proxy=false
  case "$url" in
    http://169.254.169.254/*|http://metadata.google.internal/*) no_proxy=true ;;
  esac
  if _has curl; then
    if $no_proxy; then curl -fsS --connect-timeout 1 -m 1 --noproxy '*' "$@" "$url"
    else               curl -fsS --connect-timeout 1 -m 1 "$@" "$url"; fi
  elif _has wget; then
    if $no_proxy; then wget -qO- --timeout=1 --no-proxy "$url" 2>/dev/null
    else               wget -qO- --timeout=1 "$url" 2>/dev/null; fi
  else
    return 1
  fi
}

_have_proxy() { [ -n "${HTTP_PROXY:-}${http_proxy:-}${HTTPS_PROXY:-}${https_proxy:-}${NO_PROXY:-}${no_proxy:-}" ]; }

# Locks abwarten statt löschen
apt_wait_for_locks() {
  for i in {1..30}; do
    if command -v fuser >/dev/null 2>&1 && {
         fuser /var/lib/dpkg/lock-frontend  >/dev/null 2>&1 ||
         fuser /var/lib/apt/lists/lock      >/dev/null 2>&1 ||
         fuser /var/cache/apt/archives/lock >/dev/null 2>&1 ; } then
      log_debug "    - Warte auf APT-Locks… ($i/30)"; sleep 2
    else
      return 0
    fi
  done
  log_warn "    - APT-Locks hängen – versuche 'dpkg --configure -a'"
  dpkg --configure -a || true
}

# sources.list sanitisieren (CRLF/BOM; nur deb/deb-src bleiben aktiv)
sanitize_sources_file() {
  local file="$1"
  [ -f "$file" ] || return 0

  local tmp; tmp="$(mktemp)"
  cp -a "$file" "$tmp"

  sed -i 's/\r$//' "$tmp" || true         # CRLF→LF
  sed -i 's/\x1a$//' "$tmp" || true       # DOS EOF ^Z
  sed -i '1s/^\xEF\xBB\xBF//' "$tmp" || true  # BOM

  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/                         { print; next }
    /^[[:space:]]*deb(-src)?([[:space:]]|\[)/                     { print; next }
    { print "# (commented by Server-Baukasten) " $0 }
  ' "$tmp" > "$tmp.norm" && mv -f "$tmp.norm" "$tmp"

  awk '{ if($1 ~ /^deb(-src)?$/) { $1=$1; gsub(/[\t ]+/," "); } print }' "$tmp" > "$tmp.norm" && mv -f "$tmp.norm" "$tmp"

  if ! cmp -s "$file" "$tmp"; then
    log_debug "    - Sanitize: korrigiere $(basename "$file")"
    cp -f "$tmp" "$file"
  fi
  rm -f "$tmp"
}

# Provider erkennen
detect_vps_provider() {
  local provider="generic"
  log_debug "  -> Provider-Detection…"

  if grep -qi "ionos\|1und1\|1and1" /etc/resolv.conf 2>/dev/null || [ -d /etc/apt/mirrors ]; then
    provider="ionos";      log_info "  -> IONOS/1&1 erkannt"
  elif grep -qi "hetzner\|your-server\\.de" /etc/resolv.conf 2>/dev/null || grep -qi "hetzner" /etc/hostname 2>/dev/null || [ -f /etc/hetzner ]; then
    provider="hetzner";    log_info "  -> Hetzner erkannt"
  elif _http_get http://169.254.169.254/metadata/v1/id | grep -Eq '^[0-9]+$'; then
    provider="digitalocean"; log_info "  -> DigitalOcean erkannt"
  elif grep -qi "ovh\|kimsufi\|soyoustart" /etc/resolv.conf 2>/dev/null || [ -f /etc/ovh-release ]; then
    provider="ovh";        log_info "  -> OVH/SoYouStart/Kimsufi erkannt"
  elif grep -qi "contabo" /etc/resolv.conf 2>/dev/null || hostname -f 2>/dev/null | grep -qi "contabo"; then
    provider="contabo";    log_info "  -> Contabo erkannt"
  elif [ -f /etc/scw-release ] || grep -qi "scaleway" /etc/resolv.conf 2>/dev/null; then
    provider="scaleway";   log_info "  -> Scaleway erkannt"
  elif grep -qi "linode" /etc/resolv.conf 2>/dev/null || [ -f /etc/linode ]; then
    provider="linode";     log_info "  -> Linode erkannt"
  elif { if _has curl; then
            TOK=$(_http_get -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token 2>/dev/null || true);
            _http_get -H "X-aws-ec2-metadata-token: ${TOK:-}" http://169.254.169.254/latest/meta-data/ 2>/dev/null || true;
         else
            _http_get http://169.254.169.254/latest/meta-data/ 2>/dev/null || true; fi; } | grep -q "ami-id"; then
    provider="aws";        log_info "  -> AWS EC2 erkannt"
  elif _http_get -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id 2>/dev/null; then
    provider="gcp";        log_info "  -> Google Cloud erkannt"
  elif _http_get -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | grep -q "azEnvironment"; then
    provider="azure";      log_info "  -> Microsoft Azure erkannt"
  else
    log_debug "  -> kein spezifischer Provider (generic)"
  fi

  printf '%s\n' "$provider"
}

# Provider-spezifische APT-Fixes
apply_provider_apt_fixes() {
  local provider="${1:-generic}"
  log_debug "  -> Provider-Fixes: $provider"

  case "$provider" in
    ionos)
      [ -d /etc/apt/mirrors ] && rm -f /etc/apt/mirrors/*.list 2>/dev/null && log_debug "    - IONOS mirror-list bereinigt"
      rm -f /etc/apt/apt.conf.d/99ionos* 2>/dev/null || true
      ;;
    hetzner)
      rm -f /etc/apt/sources.list.d/hetzner* 2>/dev/null || true
      sed -i '/mirror\.hetzner\.de/d' /etc/apt/sources.list 2>/dev/null || true
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
  esac

  apply_general_apt_cleanup
}

# Allgemeine APT-Bereinigung
apply_general_apt_cleanup() {
  log_debug "  -> Allgemeine APT-Bereinigung…"
  apt_wait_for_locks
  sed -i '/^deb cdrom:/d' /etc/apt/sources.list 2>/dev/null || true
  sed -i '/^#.*mirror\./d' /etc/apt/sources.list 2>/dev/null || true
  sanitize_sources_file "/etc/apt/sources.list"
  if ! _have_proxy; then
    log_debug "    - kein Proxy erkannt – apt.conf Proxy bleibt unberührt"
  fi
}

# OS-Erkennung
detect_os_version() {
  local os_id="unknown" os_version="unknown" os_codename="unknown"
  if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    os_id="${ID:-unknown}"; os_version="${VERSION_ID:-unknown}"; os_codename="${VERSION_CODENAME:-unknown}"
  fi
  if [ "$os_codename" = "unknown" ] && [ -f /etc/debian_version ]; then
    case "$(cut -d. -f1 < /etc/debian_version)" in
      13) os_codename="trixie" ;; 12) os_codename="bookworm" ;;
      11) os_codename="bullseye" ;; 10) os_codename="buster" ;;
       9) os_codename="stretch" ;; *)  os_codename="stable" ;;
    esac
  fi
  printf '%s %s %s\n' "$os_id" "$os_version" "$os_codename"
}

# Sources-Generatoren
generate_debian_sources() {
  local codename="${1:-stable}" protocol="${2:-https}"
  local provider_tag; provider_tag="$(printf '%s' "${VPS_PROVIDER:-unknown}" | awk '{print $1}')"
  cat << EOF
# Debian $codename - Official Repositories
# Generated by Server-Baukasten on $(date -u +'%Y-%m-%dT%H:%M:%SZ')
# Provider: ${provider_tag}

deb ${protocol}://deb.debian.org/debian ${codename} main contrib non-free non-free-firmware
deb ${protocol}://deb.debian.org/debian ${codename}-updates main contrib non-free non-free-firmware
deb ${protocol}://security.debian.org/debian-security ${codename}-security main contrib non-free non-free-firmware

# Backports (optional, uncomment if needed)
#deb ${protocol}://deb.debian.org/debian ${codename}-backports main contrib non-free non-free-firmware
EOF
}

generate_ubuntu_sources() {
  local codename="${1:-focal}" protocol="${2:-https}"
  local provider_tag; provider_tag="$(printf '%s' "${VPS_PROVIDER:-unknown}" | awk '{print $1}')"
  cat << EOF
# Ubuntu ${codename} - Official Repositories
# Generated by Server-Baukasten on $(date -u +'%Y-%m-%dT%H:%M:%SZ')
# Provider: ${provider_tag}

deb ${protocol}://archive.ubuntu.com/ubuntu ${codename} main restricted universe multiverse
deb ${protocol}://archive.ubuntu.com/ubuntu ${codename}-updates main restricted universe multiverse
deb ${protocol}://security.ubuntu.com/ubuntu ${codename}-security main restricted universe multiverse

# Backports (optional, uncomment if needed)
#deb ${protocol}://archive.ubuntu.com/ubuntu ${codename}-backports main restricted universe multiverse
EOF
}

# Ungültiges APT::Default-Release entfernen, wenn nicht verfügbar
apt_clear_invalid_default_release() {
  local codename="${1:-}"
  if [ -n "$codename" ] && ! apt-cache policy 2>/dev/null | grep -q "a=${codename}"; then
    log_warn "  -> Entferne ungültiges APT::Default-Release (kein '${codename}' in den Quellen)"
    [ -f /etc/apt/apt.conf ] && sed -i -E '/APT::Default-Release/d' /etc/apt/apt.conf || true
    if [ -d /etc/apt/apt.conf.d ]; then
      grep -Rl --null 'APT::Default-Release' /etc/apt/apt.conf.d 2>/dev/null | xargs -0 -r sed -i -E '/APT::Default-Release/d'
    fi
  fi
}

# apt-get update mit kurzem Retry
apt_update_retry() {
  local tries=0
  while :; do
    tries=$((tries+1))
    log_debug "apt-get update (Try ${tries}/2)"
    if apt-get -o DPkg::Lock::Timeout=60 update; then
      return 0
    fi
    [ $tries -ge 2 ] && return 1
    log_warn "  -> Update fehlgeschlagen – sanitize & retry…"
    sanitize_sources_file "/etc/apt/sources.list"
    apt_wait_for_locks
  done
}

# Pakete robust installieren (Bulk → Einzelpakete), inkl. Default-Release-Fix
install_packages_safe() {
  local pkgs=("$@")
  [ ${#pkgs[@]} -gt 0 ] || { log_debug "install_packages_safe: keine Pakete"; return 0; }

  local todo=() p
  for p in "${pkgs[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || todo+=("$p"); done
  if [ ${#todo[@]} -eq 0 ]; then
    log_ok "Alle gewünschten Pakete sind bereits installiert: —"
    return 0
  fi

  apt_wait_for_locks
  local _id _ver _code; read -r _id _ver _code <<<"$(detect_os_version)"
  apt_clear_invalid_default_release "$_code"

  log_info "Installiere ${#todo[@]} Pakete…"
  if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${todo[@]}"; then
    log_ok "Pakete installiert."
    return 0
  fi

  log_warn "Gesamte Installation fehlgeschlagen – versuche Einzelpakete…"
  local failed=()
  for p in "${todo[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 && continue
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$p" || failed+=("$p")
  done

  if [ ${#failed[@]} -gt 0 ]; then
    log_error "Folgende Pakete ließen sich nicht installieren: ${failed[*]}"
    return 1
  fi
  log_ok "Pakete installiert (Einzelmodus)."
}

# Haupt-Reparatur
fix_apt_sources_if_needed() {
  log_info "  -> Prüfe und repariere APT-Quellen…"

  local provider; provider="$(detect_vps_provider)"; export VPS_PROVIDER="$provider"
  apply_provider_apt_fixes "$provider"

  local os_id os_ver os_code; read -r os_id os_ver os_code <<<"$(detect_os_version)"
  log_debug "    - OS: $os_id $os_ver ($os_code)"

  [ -f /etc/apt/sources.list ] && sanitize_sources_file "/etc/apt/sources.list"

  local needs=false
  if [ ! -f /etc/apt/sources.list ] || ! grep -qE "^deb\\s+" /etc/apt/sources.list 2>/dev/null; then
    needs=true; log_warn "  -> APT-Quellen fehlen oder sind ungültig"
  fi
  if ! apt-cache policy 2>/dev/null | grep -qE "o=(Debian|Ubuntu)"; then
    needs=true; log_warn "  -> Keine offiziellen Repositories verfügbar"
  fi

  if [ "$needs" = true ]; then
    local TS; TS="$(date +%Y%m%d_%H%M%S)"
    [ -f /etc/apt/sources.list ] && cp -a /etc/apt/sources.list "/etc/apt/sources.list.backup.$TS"

    local parked=""
    if [ -d /etc/apt/sources.list.d ]; then
      local park="/etc/apt/sources.list.d.disabled-$TS"
      mv /etc/apt/sources.list.d "$park"; mkdir -p /etc/apt/sources.list.d
      parked="$park"; log_warn "  -> sources.list.d geparkt: $(basename "$park")"
    fi

    local tmp; tmp="$(mktemp)"
    case "$os_id" in
      debian) generate_debian_sources "$os_code" "https" > "$tmp" ;;
      ubuntu) generate_ubuntu_sources "$os_code" "https" > "$tmp" ;;
      *) log_error "  -> OS '$os_id' nicht unterstützt"; return 1 ;;
    esac
    mv -f "$tmp" /etc/apt/sources.list

    apt_wait_for_locks
    apt_clear_invalid_default_release "$os_code"

    if ! apt_update_retry; then
      log_warn "  -> Update fehlgeschlagen – zweiter Versuch (sanitize)"
      sanitize_sources_file "/etc/apt/sources.list"
      if ! apt_update_retry; then
        log_error "❌ Reparatur der APT-Quellen fehlgeschlagen"
        if [ -n "$parked" ] && [ -d "$parked" ]; then
          rm -rf /etc/apt/sources.list.d
          mv "$parked" /etc/apt/sources.list.d
        fi
        return 1
      fi
    fi

    log_ok "✅ APT-Quellen repariert"
  else
    log_ok "  -> APT-Quellen sind funktionsfähig"
  fi
}

# Optionaler Modul-Wrapper (wenn du es als eigenes Modul führst)
module_fix_apt_sources() {
  log_info "MODUL 1: APT-Quellen prüfen/reparieren"
  if fix_apt_sources_if_needed; then
    log_ok "APT-Quellen korrekt."
  else
    log_error "APT-Quellen konnten nicht repariert werden."
    return 1
  fi
}
