#!/bin/bash
################################################################################
# APT-REPAIR HELPER (Universal - Fixed für Mixed-Release-Detection)
# @description: Intelligente Mixed-Release-Erkennung und universelle Reparatur
# @license:     MIT
# @version:     3.2.0
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

# HTTP für Cloud-Metadata
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

# Locks abwarten
apt_wait_for_locks() {
  for i in {1..30}; do
    if command -v fuser >/dev/null 2>&1 && {
         fuser /var/lib/dpkg/lock-frontend  >/dev/null 2>&1 ||
         fuser /var/lib/apt/lists/lock      >/dev/null 2>&1 ||
         fuser /var/cache/apt/archives/lock >/dev/null 2>&1 ; } then
      log_debug "    - Warte auf APT-Locks… ($i/30)"
      sleep 2
    else
      return 0
    fi
  done
  log_warn "    - APT-Locks hängen – versuche 'dpkg --configure -a'"
  dpkg --configure -a || true
}

# Provider-Detection (Top 5)
detect_vps_provider() {
  local provider="generic"
  log_debug "  -> Provider-Detection (Top 5)…" >&2

  # 1. IONOS (größter deutscher Provider)
  if grep -qi "ionos\|1und1\|1and1" /etc/resolv.conf 2>/dev/null || [ -d /etc/apt/mirrors ]; then
    provider="ionos"; log_info "  -> IONOS/1&1 erkannt" >&2
  
  # 2. Hetzner
  elif grep -qi "hetzner\|your-server\\.de" /etc/resolv.conf 2>/dev/null || grep -qi "hetzner" /etc/hostname 2>/dev/null; then
    provider="hetzner"; log_info "  -> Hetzner erkannt" >&2
  
  # 3. AWS EC2
  elif { if _has curl; then
            TOK=$(_http_get -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token 2>/dev/null || true);
            _http_get -H "X-aws-ec2-metadata-token: ${TOK:-}" http://169.254.169.254/latest/meta-data/ 2>/dev/null || true;
         else
            _http_get http://169.254.169.254/latest/meta-data/ 2>/dev/null || true; fi; } | grep -q "ami-id"; then
    provider="aws"; log_info "  -> AWS EC2 erkannt" >&2
  
  # 4. DigitalOcean
  elif _http_get http://169.254.169.254/metadata/v1/id | grep -Eq '^[0-9]+$'; then
    provider="digitalocean"; log_info "  -> DigitalOcean erkannt" >&2
  
  # 5. OVH
  elif grep -qi "ovh\|kimsufi\|soyoustart" /etc/resolv.conf 2>/dev/null || [ -f /etc/ovh-release ]; then
    provider="ovh"; log_info "  -> OVH erkannt" >&2
  
  else
    log_debug "  -> Generic Provider (nicht in Top 5)" >&2
  fi

  printf '%s\n' "$provider"
}

# INTELLIGENTE OS-Erkennung (verhindert Mixed-Release-Probleme)
detect_actual_os_version() {
  local os_id="unknown" os_version="unknown" os_codename="unknown"
  
  # 1. /etc/os-release (kann lügen bei Mixed-Release)
  if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    os_id="${ID:-unknown}"
    os_version="${VERSION_ID:-unknown}"
    os_codename="${VERSION_CODENAME:-unknown}"
  fi
  
  # 2. KRITISCH: Erkennung des tatsächlichen Systems basierend auf installierten Paketen
  if [ "$os_id" = "debian" ]; then
    # Prüfe welche Debian-Version WIRKLICH installiert ist
    local actual_suite="unknown"
    
    # Perl-Version als Indikator
    local perl_version=""
    if dpkg -s perl-base >/dev/null 2>&1; then
      perl_version=$(dpkg-query -W -f='${Version}' perl-base 2>/dev/null || true)
    fi
    
    # Python-Version als Indikator  
    local python_version=""
    if dpkg -s python3 >/dev/null 2>&1; then
      python_version=$(dpkg-query -W -f='${Version}' python3 2>/dev/null || true)
    fi
    
    # libc-Version als Indikator
    local libc_version=""
    if dpkg -s libc6 >/dev/null 2>&1; then
      libc_version=$(dpkg-query -W -f='${Version}' libc6 2>/dev/null || true)
    fi
    
    log_debug "    - Installierte Versionen: perl-base=$perl_version, python3=$python_version, libc6=$libc_version"
    
    # Bestimme tatsächliche Suite basierend auf Paket-Versionen
    if [[ "$perl_version" =~ ^5\.40 ]] || [[ "$python_version" =~ ^3\.13 ]] || [[ "$libc_version" =~ ^2\.4[0-9] ]]; then
      actual_suite="trixie"
      log_warn "    - Mixed-Release erkannt: System ist TRIXIE (nicht $os_codename)"
    elif [[ "$perl_version" =~ ^5\.36 ]] || [[ "$python_version" =~ ^3\.11 ]] || [[ "$libc_version" =~ ^2\.3[6-9] ]]; then
      actual_suite="bookworm"  
      log_debug "    - System ist BOOKWORM"
    else
      # Fallback auf /etc/debian_version
      if [ -f /etc/debian_version ]; then
        case "$(cut -d. -f1 < /etc/debian_version)" in
          13) actual_suite="trixie" ;;
          12) actual_suite="bookworm" ;;
          11) actual_suite="bullseye" ;;
          10) actual_suite="buster" ;;
          *)  actual_suite="$os_codename" ;;
        esac
      fi
    fi
    
    # Überschreibe Codename mit tatsächlicher Suite
    if [ "$actual_suite" != "unknown" ] && [ "$actual_suite" != "$os_codename" ]; then
      log_warn "    - Korrigiere Suite: $os_codename → $actual_suite"
      os_codename="$actual_suite"
    fi
  fi
  
  printf '%s %s %s\n' "$os_id" "$os_version" "$os_codename"
}

# sources.list sanitisieren
sanitize_sources_file() {
  local file="$1"
  [ -f "$file" ] || return 0

  local tmp; tmp="$(mktemp)"
  cp -a "$file" "$tmp"

  sed -i 's/\r$//' "$tmp" || true
  sed -i 's/\x1a$//' "$tmp" || true
  sed -i '1s/^\xEF\xBB\xBF//' "$tmp" || true

  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/                          { print; next }
    /^[[:space:]]*deb(-src)?([[:space:]]|\[)/                       { print; next }
    { print "# (commented by Server-Baukasten) " $0 }
  ' "$tmp" > "$tmp.norm" && mv -f "$tmp.norm" "$tmp"

  if ! cmp -s "$file" "$tmp"; then
    log_debug "    - Sanitize: korrigiere $(basename "$file")"
    cp -f "$tmp" "$file"
  fi
  rm -f "$tmp"
}

# Security-Pfad intelligenter wählen
_debian_security_line() {
  case "$1" in
    stretch|buster) echo "deb https://security.debian.org/debian-security $1/updates main contrib non-free non-free-firmware" ;;
    *)              echo "deb https://security.debian.org/debian-security $1-security main contrib non-free non-free-firmware" ;;
  esac
}

# UNIVERSELLER sources.list Generator
generate_clean_sources() {
  local os_id="$1" codename="$2" provider="${3:-generic}"

  cat << EOF
# ${os_id^} $codename - Official Repositories (Universal Fix)
# Generated by Server-Baukasten on $(date -u +'%Y-%m-%dT%H:%M:%SZ')
# Provider: ${provider}
# Fixed: Mixed-Release-Problem intelligent erkannt und gelöst

EOF

  case "$os_id" in
    debian)
      cat << EOF
deb https://deb.debian.org/debian $codename main contrib non-free non-free-firmware
deb https://deb.debian.org/debian $codename-updates main contrib non-free non-free-firmware
$(_debian_security_line "$codename")

# Backports (optional, uncomment if needed)
#deb https://deb.debian.org/debian $codename-backports main contrib non-free non-free-firmware
EOF
      ;;
    ubuntu)
      cat << EOF
deb https://archive.ubuntu.com/ubuntu $codename main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu $codename-updates main restricted universe multiverse
deb https://security.ubuntu.com/ubuntu $codename-security main restricted universe multiverse
EOF
      ;;
    *)
      log_error "OS '$os_id' wird nicht unterstützt"
      return 1
      ;;
  esac
}

# APT-Config bereinigen
clear_invalid_default_release() {
  local codename="${1:-}"
  [ -n "$codename" ] || return 0
  if ! apt-cache policy 2>/dev/null | grep -q "a=${codename}\b"; then
    log_warn "  -> Entferne ungültiges APT::Default-Release"
    [ -f /etc/apt/apt.conf ] && sed -i -E '/^[[:space:]]*APT::Default-Release/d' /etc/apt/apt.conf || true
    if [ -d /etc/apt/apt.conf.d ]; then
      grep -Rl --null '^[[:space:]]*APT::Default-Release' /etc/apt/apt.conf.d 2>/dev/null | xargs -0 -r sed -i -E '/^[[:space:]]*APT::Default-Release/d'
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
    log_warn "  -> Update fehlgeschlagen – sanitize & retry…"
    sanitize_sources_file "/etc/apt/sources.list"
    apt_wait_for_locks
  done
}

# UNIVERSAL APT-REPARATUR (mit intelligenter Mixed-Release-Erkennung)
fix_apt_sources_universal() {
  log_info "  -> Universal APT-Reparatur (intelligente Mixed-Release-Erkennung)"

  # 1. Provider erkennen (für Logging)
  local provider; provider="$(detect_vps_provider)"; export VPS_PROVIDER="$provider"
  
  # 2. INTELLIGENTE OS-Erkennung (prüft installierte Pakete)
  local os_id os_ver os_code; read -r os_id os_ver os_code <<<"$(detect_actual_os_version)"
  log_info "    - Erkanntes System: $os_id $os_ver ($os_code), Provider: $provider"

  # 3. Backup
  local TS; TS="$(date +%Y%m%d_%H%M%S)"
  [ -f /etc/apt/sources.list ] && cp -a /etc/apt/sources.list "/etc/apt/sources.list.backup.$TS"

  # 4. sources.list.d parken
  local parked=""
  if [ -d /etc/apt/sources.list.d ] && [ -n "$(find /etc/apt/sources.list.d -name '*.list' -type f 2>/dev/null)" ]; then
    local park="/etc/apt/sources.list.d.disabled-$TS"
    mv /etc/apt/sources.list.d "$park"; mkdir -p /etc/apt/sources.list.d
    parked="$park"; log_warn "  -> sources.list.d geparkt: $(basename "$park")"
  fi

  # 5. UNIVERSELLE sources.list erzwingen (basiert auf TATSÄCHLICHER Suite)
  log_info "  -> Erstelle korrekte sources.list für $os_code…"
  generate_clean_sources "$os_id" "$os_code" "$provider" > /etc/apt/sources.list

  # 6. APT-Config säubern
  clear_invalid_default_release "$os_code"
  
  # 7. Update testen
  apt_wait_for_locks
  if ! apt_update_with_retry; then
    log_error "❌ Universal APT-Reparatur fehlgeschlagen"
    if [ -n "$parked" ] && [ -d "$parked" ]; then
      rm -rf /etc/apt/sources.list.d
      mv "$parked" /etc/apt/sources.list.d
    fi
    return 1
  fi

  log_ok "✅ Universal APT-Reparatur erfolgreich (System: $os_code, Provider: $provider)"
}

# Direkte Einzelpaket-Installation (kein Bulk-Versuch)
install_packages_safe() {
  local pkgs=("$@")
  [ ${#pkgs[@]} -gt 0 ] || { log_debug "install_packages_safe: keine Pakete"; return 0; }

  local todo=() p
  for p in "${pkgs[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || todo+=("$p"); done
  if [ ${#todo[@]} -eq 0 ]; then
    log_ok "Alle gewünschten Pakete sind bereits installiert."
    return 0
  fi

  apt_wait_for_locks
  local _id _ver _code; read -r _id _ver _code <<<"$(detect_actual_os_version)"
  
  log_info "Installiere ${#todo[@]} Pakete (einzeln)..."
  
  local installed=() failed=()
  for pkg in "${todo[@]}"; do
    # Skip falls zwischenzeitlich als Dependency installiert
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      log_debug "  ✓ $pkg bereits installiert (Dependency)"
      installed+=("$pkg")
      continue
    fi
    
    log_debug "  → $pkg..."
    if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --allow-downgrades "$pkg" 2>/dev/null; then
      installed+=("$pkg")
    else
      failed+=("$pkg")
      log_warn "  ✗ $pkg fehlgeschlagen"
    fi
  done

  # Ergebnis-Report
  if [ ${#installed[@]} -gt 0 ]; then
    log_ok "Installiert: ${installed[*]}"
  fi
  if [ ${#failed[@]} -gt 0 ]; then
    log_error "Fehlgeschlagen: ${failed[*]}"
    return 1
  fi
  log_ok "Alle Pakete erfolgreich installiert."
}

# Wrapper für Rückwärtskompatibilität
fix_apt_sources_if_needed() { fix_apt_sources_universal; }

module_fix_apt_sources() {
  log_info "MODUL: Universal APT-Reparatur"
  if fix_apt_sources_universal; then
    log_ok "APT-System universell repariert."
  else
    log_error "Universal APT-Reparatur fehlgeschlagen."
    return 1
  fi
}