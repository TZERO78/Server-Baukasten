#!/bin/bash
################################################################################
# APT-REPAIR HELPER (Universal & Vereinfacht)
# @description: Löst Mixed-Release-Probleme bei ALLEN VPS-Providern universal
# @license:     MIT
# @version:     3.0.0
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

# Provider-Detection (vollständig beibehalten, nur stderr-fixes)
detect_vps_provider() {
  local provider="generic"
  log_debug "  -> Provider-Detection…" >&2

  if grep -qi "ionos\|1und1\|1and1" /etc/resolv.conf 2>/dev/null || [ -d /etc/apt/mirrors ]; then
    provider="ionos";      log_info "  -> IONOS/1&1 erkannt" >&2
  elif grep -qi "hetzner\|your-server\\.de" /etc/resolv.conf 2>/dev/null || grep -qi "hetzner" /etc/hostname 2>/dev/null || [ -f /etc/hetzner ]; then
    provider="hetzner";    log_info "  -> Hetzner erkannt" >&2
  elif _http_get http://169.254.169.254/metadata/v1/id | grep -Eq '^[0-9]+$'; then
    provider="digitalocean"; log_info "  -> DigitalOcean erkannt" >&2
  elif grep -qi "ovh\|kimsufi\|soyoustart" /etc/resolv.conf 2>/dev/null || [ -f /etc/ovh-release ]; then
    provider="ovh";        log_info "  -> OVH/SoYouStart/Kimsufi erkannt" >&2
  elif grep -qi "contabo" /etc/resolv.conf 2>/dev/null || hostname -f 2>/dev/null | grep -qi "contabo"; then
    provider="contabo";    log_info "  -> Contabo erkannt" >&2
  elif [ -f /etc/scw-release ] || grep -qi "scaleway" /etc/resolv.conf 2>/dev/null; then
    provider="scaleway";   log_info "  -> Scaleway erkannt" >&2
  elif grep -qi "linode" /etc/resolv.conf 2>/dev/null || [ -f /etc/linode ]; then
    provider="linode";     log_info "  -> Linode erkannt" >&2
  elif { if _has curl; then
            TOK=$(_http_get -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token 2>/dev/null || true);
            _http_get -H "X-aws-ec2-metadata-token: ${TOK:-}" http://169.254.169.254/latest/meta-data/ 2>/dev/null || true;
         else
            _http_get http://169.254.169.254/latest/meta-data/ 2>/dev/null || true; fi; } | grep -q "ami-id"; then
    provider="aws";        log_info "  -> AWS EC2 erkannt" >&2
  elif _http_get http://169.254.169.254/v1.json 2>/dev/null | grep -q "instanceid"; then
    provider="vultr";      log_info "  -> Vultr erkannt" >&2
  elif grep -qi "netcup" /etc/resolv.conf 2>/dev/null || hostname -f 2>/dev/null | grep -qi "netcup"; then
    provider="netcup";     log_info "  -> Netcup erkannt" >&2
  elif _http_get -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id 2>/dev/null; then
    provider="gcp";        log_info "  -> Google Cloud erkannt" >&2
  elif _http_get -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | grep -q "azEnvironment"; then
    provider="azure";      log_info "  -> Microsoft Azure erkannt" >&2
  else
    log_debug "  -> kein spezifischer Provider (generic)" >&2
  fi

  printf '%s\n' "$provider"
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

  if ! cmp -s "$file" "$tmp"; then
    log_debug "    - Sanitize: korrigiere $(basename "$file")"
    cp -f "$tmp" "$file"
  fi
  rm -f "$tmp"
}

# EINZIGER sources.list Generator (universell für alle Provider)
generate_clean_sources() {
  local os_id="$1" codename="$2" provider="${3:-generic}"
  
  cat << EOF
# ${os_id^} $codename - Official Repositories (Universal Fix)
# Generated by Server-Baukasten on $(date -u +'%Y-%m-%dT%H:%M:%SZ')
# Provider: ${provider}
# Fixed: Mixed-Release-Problem universal gelöst

EOF

  case "$os_id" in
    debian)
      cat << EOF
deb https://deb.debian.org/debian $codename main contrib non-free non-free-firmware
deb https://deb.debian.org/debian $codename-updates main contrib non-free non-free-firmware
deb https://security.debian.org/debian-security $codename-security main contrib non-free non-free-firmware

# Backports (optional, uncomment if needed)
#deb https://deb.debian.org/debian $codename-backports main contrib non-free non-free-firmware
EOF
      ;;
    ubuntu)
      cat << EOF
deb https://archive.ubuntu.com/ubuntu $codename main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu $codename-updates main restricted universe multiverse
deb https://security.ubuntu.com/ubuntu $codename-security main restricted universe multiverse

# Backports (optional, uncomment if needed)
#deb https://archive.ubuntu.com/ubuntu $codename-backports main restricted universe multiverse
EOF
      ;;
    *)
      log_error "OS '$os_id' wird nicht unterstützt"
      return 1
      ;;
  esac
}

# Ungültiges APT::Default-Release entfernen
clear_invalid_default_release() {
  local codename="${1:-}"
  if [ -n "$codename" ] && ! apt-cache policy 2>/dev/null | grep -q "a=${codename}"; then
    log_warn "  -> Entferne ungültiges APT::Default-Release (kein '${codename}' in den Quellen)"
    [ -f /etc/apt/apt.conf ] && sed -i -E '/APT::Default-Release/d' /etc/apt/apt.conf || true
    if [ -d /etc/apt/apt.conf.d ]; then
      grep -Rl --null 'APT::Default-Release' /etc/apt/apt.conf.d 2>/dev/null | xargs -0 -r sed -i -E '/APT::Default-Release/d'
    fi
  fi
}

# apt-get update mit Retry
apt_update_with_retry() {
  local tries=0
  while :; do
    tries=$((tries+1))
    log_debug "apt-get update (Try ${tries}/2)"
    if apt-get -o DPkg::Lock::Timeout=60 update; then
      return 0
    fi
    [ $tries -ge 2 ] && return 1
    log_warn "  -> Update fehlgeschlagen – sanitize sources.list & retry…"
    sanitize_sources_file "/etc/apt/sources.list"
    apt_wait_for_locks
  done
}

# UNIVERSAL APT-REPARATUR (für alle Provider)
fix_apt_sources_universal() {
  log_info "  -> Universal APT-Reparatur (löst Mixed-Release-Probleme aller Provider)"

  # 1. Provider erkennen (für Logging)
  local provider; provider="$(detect_vps_provider)"; export VPS_PROVIDER="$provider"
  local os_id os_ver os_code; read -r os_id os_ver os_code <<<"$(detect_os_version)"
  log_debug "    - OS: $os_id $os_ver ($os_code), Provider: $provider"

  # 2. Backup erstellen
  local TS; TS="$(date +%Y%m%d_%H%M%S)"
  [ -f /etc/apt/sources.list ] && cp -a /etc/apt/sources.list "/etc/apt/sources.list.backup.$TS"

  # 3. sources.list.d temporär parken (bei Problemen)
  local parked=""
  if [ -d /etc/apt/sources.list.d ] && [ -n "$(find /etc/apt/sources.list.d -name '*.list' -type f 2>/dev/null)" ]; then
    local park="/etc/apt/sources.list.d.disabled-$TS"
    mv /etc/apt/sources.list.d "$park"; mkdir -p /etc/apt/sources.list.d
    parked="$park"; log_warn "  -> sources.list.d temporär geparkt: $(basename "$park")"
  fi

  # 4. Universal: Saubere sources.list erzwingen (für ALLE Provider gleich)
  log_info "  -> Erstelle universell saubere sources.list…"
  generate_clean_sources "$os_id" "$os_code" "$provider" > /etc/apt/sources.list

  # 5. Mixed-Release-Probleme universal lösen
  apt_wait_for_locks
  clear_invalid_default_release "$os_code"

  # 6. Update testen
  if ! apt_update_with_retry; then
    log_error "❌ Universal APT-Reparatur fehlgeschlagen"
    # Rollback bei totalem Versagen
    if [ -n "$parked" ] && [ -d "$parked" ]; then
      rm -rf /etc/apt/sources.list.d
      mv "$parked" /etc/apt/sources.list.d
      log_warn "  -> sources.list.d wiederhergestellt"
    fi
    return 1
  fi

  log_ok "✅ Universal APT-Reparatur erfolgreich (Provider: $provider)"
}

# Robuste Paket-Installation mit Mixed-Release-Behandlung
install_packages_safe() {
  local pkgs=("$@")
  [ ${#pkgs[@]} -gt 0 ] || { log_debug "install_packages_safe: keine Pakete"; return 0; }

  local todo=() p
  for p in "${pkgs[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || todo+=("$p"); done
  if [ ${#todo[@]} -eq 0 ]; then
    log_ok "Alle gewünschten Pakete sind bereits installiert."
    return 0
  fi

  # Bei Mixed-Release-Problemen: zuerst Default-Release clearen
  apt_wait_for_locks
  local _id _ver _code; read -r _id _ver _code <<<"$(detect_os_version)"
  clear_invalid_default_release "$_code"

  log_info "Installiere ${#todo[@]} Pakete…"
  # Versuche Installation mit Downgrades (löst Mixed-Release-Konflikte)
  if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --allow-downgrades "${todo[@]}"; then
    log_ok "Pakete installiert."
    return 0
  fi

  # Fallback: Einzelpakete
  log_warn "Gesamte Installation fehlgeschlagen – versuche Einzelpakete…"
  local failed=()
  for p in "${todo[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 && continue
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --allow-downgrades "$p" || failed+=("$p")
  done

  if [ ${#failed[@]} -gt 0 ]; then
    log_error "Folgende Pakete ließen sich nicht installieren: ${failed[*]}"
    return 1
  fi
  log_ok "Pakete installiert (Einzelmodus)."
}

# Hauptfunktion (Wrapper für Rückwärtskompatibilität)
fix_apt_sources_if_needed() {
  fix_apt_sources_universal
}

# Modul-Wrapper
module_fix_apt_sources() {
  log_info "MODUL: Universal APT-Reparatur"
  if fix_apt_sources_universal; then
    log_ok "APT-System universell repariert."
  else
    log_error "Universal APT-Reparatur fehlgeschlagen."
    return 1
  fi
}