#!/bin/bash
################################################################################
#
# APT-REPAIR & PROVIDER-DETECTION HELPER
#
# @description: Provider-spezifische APT-Probleme erkennen & beheben – idempotent
# @author:      Server-Baukasten (TZERO78) & KI-Assistenten
# @version:     1.2.0
# @license:     MIT
#
################################################################################

# --- Basics -------------------------------------------------------------------
set -Eeuo pipefail

# Fallback-Logs, immer auf STDERR (wichtig für Command Substitution!) -----------
if ! command -v log_info >/dev/null 2>&1; then
  log_info()  { printf "ℹ️  %s\n" "$*" >&2; }
  log_ok()    { printf "✅ %s\n" "$*" >&2; }
  log_warn()  { printf "⚠️  %s\n" "$*" >&2; }
  log_error() { printf "❌ %s\n" "$*" >&2; }
fi
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { [ "${DEBUG:-false}" = "true" ] && printf "🐞  %s\n" "$*" >&2 || true; }
fi

# Kleine Helfer ----------------------------------------------------------------
_has() { command -v "$1" >/dev/null 2>&1; }

# HTTP-Getter (curl/wget) mit kurzem Timeout.
# Für Cloud-Metadata (169.254.169.254, metadata.google.internal) werden Proxies explizit umgangen.
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

_have_proxy() { [ -n "${HTTP_PROXY:-}${http_proxy:-}${HTTPS_PROXY:-}${https_proxy:-}${NO_PROXY:-}${no_proxy:-}" ]; }

# Auf APT/DPKG-Locks warten (statt sie zu löschen)
apt_wait_for_locks() {
  local i
  for i in {1..30}; do
    if command -v fuser >/dev/null 2>&1 && {
         fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 ||
         fuser /var/lib/apt/lists/lock >/dev/null 2>&1 ||
         fuser /var/cache/apt/archives/lock >/dev/null 2>&1 ; } then
      log_debug "    - Warte auf APT-Locks... ($i/30)"; sleep 2
    else
      return 0
    fi
  done
  log_warn "    - APT-Locks hängen lange – versuche 'dpkg --configure -a'"
  dpkg --configure -a || true
}

# Datei-Sanitizer: CRLF/BOM entfernen & nur gültige Zeilen behalten ------------
sanitize_sources_file() {
  local file="$1"
  [ -f "$file" ] || return 0

  local tmp; tmp="$(mktemp)"
  cp -a "$file" "$tmp"

  # CRLF -> LF, DOS-EOF (^Z) weg, BOM weg
  sed -i 's/\r$//' "$tmp" || true
  sed -i 's/\x1a$//' "$tmp" || true
  sed -i '1s/^\xEF\xBB\xBF//' "$tmp" || true

  # Nicht-deb-Zeilen zu Kommentaren machen, gültige deb/deb-src durchlassen
  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/                              { print; next }
    /^[[:space:]]*deb(-src)?([[:space:]]|\[)/                           { print; next }
    { print "# (commented by Server-Baukasten) " $0 }
  ' "$tmp" > "$tmp.norm" && mv -f "$tmp.norm" "$tmp"

  # Mehrfache Leerzeichen normalisieren (nur in deb-Zeilen)
  awk '{ if($1 ~ /^deb(-src)?$/) { $1=$1; gsub(/[\t ]+/," "); } print }' "$tmp" > "$tmp.norm" && mv -f "$tmp.norm" "$tmp"

  # Nur ersetzen, wenn sich der Inhalt ändert (idempotent)
  if ! cmp -s "$file" "$tmp"; then
    log_debug "    - Sanitize: korrigiere ungültige Zeilen in $(basename "$file")"
    cp -f "$tmp" "$file"
  fi
  rm -f "$tmp"
}

# ----------------------------------------------------------------------------
# Provider Detection
# ----------------------------------------------------------------------------
# Erkennt VPS-Provider anhand verschiedener Merkmale – gibt NUR den Namen aus!
detect_vps_provider() {
  local provider="generic"

  log_debug "  -> Starte VPS-Provider-Detection..."

  # IONOS (1&1)
  if grep -qi "ionos\|1und1\|1and1" /etc/resolv.conf 2>/dev/null || [ -d /etc/apt/mirrors ]; then
    provider="ionos"; log_info "  -> IONOS/1&1 VPS erkannt"
    log_debug "    - Mirror-Verzeichnis: $([ -d /etc/apt/mirrors ] && echo 'vorhanden' || echo 'nicht vorhanden')"

  # Hetzner
  elif grep -qi "hetzner\|your-server\\.de" /etc/resolv.conf 2>/dev/null || \
       grep -qi "hetzner" /etc/hostname 2>/dev/null || [ -f /etc/hetzner ]; then
    provider="hetzner"; log_info "  -> Hetzner VPS erkannt"

  # DigitalOcean (IMDS v1: numerische Droplet-ID)
  elif _http_get http://169.254.169.254/metadata/v1/id | grep -Eq '^[0-9]+$'; then
    provider="digitalocean"; log_info "  -> DigitalOcean Droplet erkannt (IMDS)"

  # OVH/OVHcloud
  elif grep -qi "ovh\|kimsufi\|soyoustart" /etc/resolv.conf 2>/dev/null || [ -f /etc/ovh-release ]; then
    provider="ovh"; log_info "  -> OVH/Kimsufi/SoYouStart VPS erkannt"

  # Contabo
  elif grep -qi "contabo" /etc/resolv.conf 2>/dev/null || hostname -f 2>/dev/null | grep -qi "contabo"; then
    provider="contabo"; log_info "  -> Contabo VPS erkannt"

  # Scaleway
  elif [ -f /etc/scw-release ] || grep -qi "scaleway" /etc/resolv.conf 2>/dev/null; then
    provider="scaleway"; log_info "  -> Scaleway VPS erkannt"

  # Linode
  elif grep -qi "linode" /etc/resolv.conf 2>/dev/null || [ -f /etc/linode ]; then
    provider="linode"; log_info "  -> Linode VPS erkannt"

  # AWS EC2 (IMDSv2-Token; Fallback IMDSv1)
  elif { if _has curl; then 
            TOK=$(_http_get -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token 2>/dev/null || true); 
            _http_get -H "X-aws-ec2-metadata-token: ${TOK:-}" http://169.254.169.254/latest/meta-data/ 2>/dev/null || true; 
         else 
            _http_get http://169.254.169.254/latest/meta-data/ 2>/dev/null || true; fi; } | grep -q "ami-id"; then
    provider="aws"; log_info "  -> AWS EC2 Instance erkannt"

  # Vultr
  elif _http_get http://169.254.169.254/v1.json 2>/dev/null | grep -q "instanceid"; then
    provider="vultr"; log_info "  -> Vultr VPS erkannt"

  # Netcup
  elif grep -qi "netcup" /etc/resolv.conf 2>/dev/null || hostname -f 2>/dev/null | grep -qi "netcup"; then
    provider="netcup"; log_info "  -> Netcup VPS erkannt"

  # Google Cloud (IMDS)
  elif _http_get -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id 2>/dev/null; then
    provider="gcp"; log_info "  -> Google Cloud Platform erkannt"

  # Azure (IMDS)
  elif _http_get -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | grep -q "azEnvironment"; then
    provider="azure"; log_info "  -> Microsoft Azure erkannt"
  else
    log_debug "  -> Kein spezifischer Provider erkannt, nutze generic"
  fi

  printf '%s\n' "$provider"
}

# ----------------------------------------------------------------------------
# Provider-spezifische APT-Fixes
# ----------------------------------------------------------------------------
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
      sed -i 's|http://.*\\.ovh\\.net/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list 2>/dev/null || true
      rm -f /etc/apt/sources.list.d/ovh* 2>/dev/null || true
      ;;

    contabo|netcup)
      rm -f /etc/apt/apt.conf.d/*${provider}* 2>/dev/null || true
      ;;

    aws|gcp|azure)
      sed -i 's|http://.*\\.ec2\\.archive\\.ubuntu\\.com|https://archive.ubuntu.com|g' /etc/apt/sources.list 2>/dev/null || true
      sed -i 's|http://.*\\.amazonaws\\.com/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list 2>/dev/null || true
      ;;
  esac

  apply_general_apt_cleanup
}

# ----------------------------------------------------------------------------
# Allgemeine APT-Bereinigung
# ----------------------------------------------------------------------------
apply_general_apt_cleanup() {
  log_debug "  -> Führe allgemeine APT-Bereinigungen durch..."

  apt_wait_for_locks

  # CD/DVD Quellen entfernen
  sed -i '/^deb cdrom:/d' /etc/apt/sources.list 2>/dev/null || true

  # Veraltete Mirror-Kommentare entfernen
  sed -i '/^#.*mirror\./d' /etc/apt/sources.list 2>/dev/null || true

  # Optional: Sanitizer laufen lassen
  sanitize_sources_file "/etc/apt/sources.list"

  # Proxy-Configs nicht blind löschen – nur Hinweis loggen
  if ! _have_proxy; then
    log_debug "    - Kein Proxy (HTTP/HTTPS) erkannt; APT-Proxy-Configs bleiben unangetastet"
  fi
}

# ----------------------------------------------------------------------------
# OS-Erkennung
# ----------------------------------------------------------------------------
detect_os_version() {
  local os_id="unknown" os_version="unknown" os_codename="unknown"

  if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    os_id="${ID:-unknown}"; os_version="${VERSION_ID:-unknown}"; os_codename="${VERSION_CODENAME:-unknown}"
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

# ----------------------------------------------------------------------------
# sources.list Generatoren (nur Kommentare + gültige deb-Zeilen)
# ----------------------------------------------------------------------------
generate_debian_sources() {
  local codename="${1:-stable}" protocol="${2:-https}"
  local provider_tag
  provider_tag="$(printf '%s' "${VPS_PROVIDER:-unknown}" | awk '{print $1}')"
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
  local provider_tag
  provider_tag="$(printf '%s' "${VPS_PROVIDER:-unknown}" | awk '{print $1}')"
  cat << EOF
# Ubuntu $codename - Official Repositories
# Generated by Server-Baukasten on $(date -u +'%Y-%m-%dT%H:%M:%SZ')
# Provider: ${provider_tag}

deb ${protocol}://archive.ubuntu.com/ubuntu ${codename} main restricted universe multiverse
deb ${protocol}://archive.ubuntu.com/ubuntu ${codename}-updates main restricted universe multiverse
deb ${protocol}://security.ubuntu.com/ubuntu ${codename}-security main restricted universe multiverse

# Backports (optional, uncomment if needed)
#deb ${protocol}://archive.ubuntu.com/ubuntu ${codename}-backports main restricted universe multiverse
# Partner repository (optional)
#deb ${protocol}://archive.canonical.com/ubuntu ${codename} partner
EOF
}

# ----------------------------------------------------------------------------
# Hauptfunktion
# ----------------------------------------------------------------------------
fix_apt_sources_if_needed() {
  log_info "  -> Prüfe und repariere APT-Quellen..."

  # Provider erkennen und Fixes anwenden
  local provider; provider=$(detect_vps_provider)
  export VPS_PROVIDER="$provider"
  apply_provider_apt_fixes "$provider"

  # OS erkennen
  read -r os_id os_version os_codename <<< "$(detect_os_version)"
  log_debug "    - OS: $os_id $os_version ($os_codename)"

  # Vorprüfung: sources.list sanitisieren, falls vorhanden (idempotent)
  [ -f /etc/apt/sources.list ] && sanitize_sources_file "/etc/apt/sources.list"

  # Prüfungen
  local needs_fix=false
  if [ ! -f /etc/apt/sources.list ] || ! grep -qE "^deb\\s+" /etc/apt/sources.list 2>/dev/null; then
    needs_fix=true; log_warn "  -> APT-Quellen fehlen oder sind ungültig"
  fi
  if ! apt-cache policy 2>/dev/null | grep -qE "o=(Debian|Ubuntu)"; then
    needs_fix=true; log_warn "  -> Keine offiziellen Repositories verfügbar"
  fi

  # Reparatur wenn nötig
  if [ "$needs_fix" = true ]; then
    local TS tmp backup_sl backup_sld new_content
    TS="$(date +%Y%m%d_%H%M%S)"

    # Backups (idempotent: vorhandene Backups nicht überschreiben)
    if [ -f /etc/apt/sources.list ] && [ ! -f /etc/apt/sources.list.backup."$TS" ]; then
      cp -a /etc/apt/sources.list "/etc/apt/sources.list.backup.$TS"
      backup_sl="/etc/apt/sources.list.backup.$TS"
    fi
    if [ -d /etc/apt/sources.list.d ]; then
      # nur parken, nicht löschen – verschieben statt tar (leichter rückgängig)
      local park_dir="/etc/apt/sources.list.d.disabled-$TS"
      if [ ! -d "$park_dir" ]; then
        mv /etc/apt/sources.list.d "$park_dir"
        mkdir -p /etc/apt/sources.list.d
        backup_sld="$park_dir"
        log_warn "  -> sources.list.d nach $(basename "$park_dir") verschoben"
      fi
    fi

    # Neue sources erzeugen (atomar)
    tmp=$(mktemp)
    case "$os_id" in
      debian) generate_debian_sources "$os_codename" "https" > "$tmp" ;;
      ubuntu) generate_ubuntu_sources "$os_codename" "https" > "$tmp" ;;
      *)      log_error "  -> OS '$os_id' nicht unterstützt"; return 1 ;;
    esac

    # Nur schreiben, wenn sich der Inhalt unterscheidet
    if [ ! -f /etc/apt/sources.list ] || ! cmp -s "$tmp" /etc/apt/sources.list; then
      mv -f "$tmp" /etc/apt/sources.list
    else
      rm -f "$tmp"
    fi

    apt_wait_for_locks

    # APT selbst warten lassen (zusätzlich zur Polling-Wartefunktion)
    if ! apt-get -o DPkg::Lock::Timeout=60 update; then
      log_warn "  -> Update fehlgeschlagen – versuche Sanitize & zweiten Versuch"
      sanitize_sources_file "/etc/apt/sources.list"
      if ! apt-get -o DPkg::Lock::Timeout=60 update; then
        log_error "❌ Reparatur der APT-Quellen fehlgeschlagen (zweiter Versuch)"
        # Rollback der geparkten Verzeichnisse (best effort)
        if [ -n "${backup_sld:-}" ] && [ -d "$backup_sld" ]; then
          rm -rf /etc/apt/sources.list.d
          mv "$backup_sld" /etc/apt/sources.list.d
        fi
        # ggf. altes sources.list-Backup zurückspielen
        if [ -n "${backup_sl:-}" ] && [ -f "$backup_sl" ]; then
          cp -f "$backup_sl" /etc/apt/sources.list
        fi
        return 1
      fi
    fi

    log_ok "✅ APT-Quellen repariert"
  else
    log_ok "  -> APT-Quellen sind funktionsfähig"
  fi

  return 0
}
