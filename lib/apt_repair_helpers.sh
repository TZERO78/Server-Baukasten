#!/bin/bash
################################################################################
# APT-REPAIR HELPER (Universal & robust, Debian/Ubuntu)
#  - Fix für Mixed-Release-Setups (z.B. Trixie<->Bookworm)
#  - Korrekte Erkennung via 'n=<codename>' (nicht nur 'a=<archive>')
#  - Setzt APT::Default-Release als Regex passend zu vorhandenen Archiven
#  - Installiert Pakete EINZELN (robust) mit --allow-downgrades
#  - Keine Provider-Sonderlogik mehr, nur Debug-Logging
# @license: MIT
# @version: 3.1.0
################################################################################
set -Eeuo pipefail

# ---------------------------- Logging Fallbacks -------------------------------
if ! command -v log_info  >/dev/null 2>&1; then log_info()  { printf "ℹ️  %s\n" "$*" >&2; }; fi
if ! command -v log_ok    >/dev/null 2>&1; then log_ok()    { printf "✅ %s\n" "$*" >&2; }; fi
if ! command -v log_warn  >/dev/null 2>&1; then log_warn()  { printf "⚠️  %s\n" "$*" >&2; }; fi
if ! command -v log_error >/dev/null 2>&1; then log_error() { printf "❌ %s\n" "$*" >&2; }; fi
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { [ "${DEBUG:-false}" = "true" ] && printf "🐞  %s\n" "$*" >&2 || true; }
fi

_has() { command -v "$1" >/dev/null 2>&1; }

# ----------------------------- Lock Handling ---------------------------------
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

# ----------------------- Alte APT-Backup-Dateien löschen ---------------------
cleanup_apt_backup_files() {
  local d="/etc/apt/apt.conf.d"
  [ -d "$d" ] || return 0
  # lösche nur Dateien mit unserer .bak.<timestamp> Signatur
  find "$d" -maxdepth 1 -type f -name '*.bak.*' -print0 \
    | while IFS= read -r -d '' f; do
        log_warn "  -> Entferne APT-Backup: $(basename "$f")"
        rm -f -- "$f"
      done
}

# ----------------------------- Sanitizer -------------------------------------
sanitize_sources_file() {
  local file="$1"
  [ -f "$file" ] || return 0

  local tmp; tmp="$(mktemp)"
  cp -a "$file" "$tmp"

  # CRLF/BOM/DOS-EOF bereinigen
  sed -i 's/\r$//' "$tmp" || true
  sed -i 's/\x1a$//' "$tmp" || true
  sed -i '1s/^\xEF\xBB\xBF//' "$tmp" || true

  # Nur deb/deb-src unkommentiert lassen
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

# ------------------------ OS/Codename Erkennung ------------------------------
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
       9) os_codename="stretch" ;; *)  os_codename="stable"  ;;
    esac
  fi
  printf '%s %s %s\n' "$os_id" "$os_version" "$os_codename"
}

# Liest aus apt-cache policy die vorhandenen Release-Felder (o=, a=, n=)
# und gibt die für 'n=<codename>' passenden 'a='-Archive (unique, sortiert) aus.
get_archives_for_codename() {
  local codename="$1"
  apt-cache policy 2>/dev/null | awk -v codename="$codename" '
    index($0, "release ") {
      a=""; n="";
      line=$0
      pos=index(line,"release ")
      if (pos>0) line=substr(line, pos+8)       # nach "release "
      # Kommas zu Leerzeichen (ohne 3rd-arg gsub: über $0 umleiten)
      old0=$0; $0=line; gsub(",", " "); line=$0; $0=old0
      nf=split(line, f, /[[:space:]]+/)
      for (i=1; i<=nf; i++) {
        if (f[i] ~ /^a=/) a=substr(f[i],3)
        else if (f[i] ~ /^n=/) n=substr(f[i],3)
      }
      if (n==codename && a!="") print a
    }
  ' | sort -u
}


# Prüft, ob der Codename in den Sourcen vorhanden ist (über n=)
codename_present_in_sources() {
  local codename="$1"
  apt-cache policy 2>/dev/null | grep -q "n=${codename}[, ]"
}

# ---------------------------- sources.list Gen -------------------------------
generate_clean_sources() {
  local os_id="$1" codename="$2"
  cat << EOF
# ${os_id^} $codename - Official Repositories (Universal Clean)
# Generated by Server-Baukasten on $(date -u +'%Y-%m-%dT%H:%M:%SZ')

EOF

  case "$os_id" in
    debian)
      cat << EOF
deb https://deb.debian.org/debian $codename main contrib non-free non-free-firmware
deb https://deb.debian.org/debian $codename-updates main contrib non-free non-free-firmware
deb https://security.debian.org/debian-security $codename-security main contrib non-free non-free-firmware
# Backports (optional):
#deb https://deb.debian.org/debian $codename-backports main contrib non-free non-free-firmware
EOF
      ;;
    ubuntu)
      cat << EOF
deb https://archive.ubuntu.com/ubuntu $codename main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu $codename-updates main restricted universe multiverse
deb https://security.ubuntu.com/ubuntu $codename-security main restricted universe multiverse
# Backports (optional):
#deb https://archive.ubuntu.com/ubuntu $codename-backports main restricted universe multiverse
EOF
      ;;
    *)
      log_error "OS '$os_id' wird nicht unterstützt"; return 1 ;;
  esac
}

# ------------------- Default-Release (Regex, robust) -------------------------
# Setzt APT::Default-Release (Regex), basierend auf den tatsächlich
# vorhandenen Archiven (a=...) für den gewünschten Codename (n=...).
ensure_default_release_regex() {
  local codename="$1" conf="/etc/apt/apt.conf.d/00-default-release"

  # 1) Primär aus policy (a= … für n=<codename>)
  local archives; archives="$(get_archives_for_codename "$codename" || true)"

  # 2) Wenn leer: heuristisch aus apt-cache policy ableiten
  if [ -z "$archives" ]; then
    # Versuche a= direkt neben n=<codename> mit sed rauszuziehen
    local guess
    guess="$(apt-cache policy 2>/dev/null \
      | sed -n "/n=${codename}[, ]/ s/.*a=\([^, ]*\).*/\1/p" \
      | sort -u)"
    if [ -n "$guess" ]; then
      archives="$(printf '%s\n%s\n%s\n' "$guess" "${guess}-updates" "${guess}-security")"
    fi
  fi

  # 3) Als letzte Rückfallebene: nur Codename selbst
  [ -n "$archives" ] || archives="$codename"

  # 4) Patternliste ohne Leerzeilen/CRs & ohne trailing '|'
  local patlist
  patlist="$(
    printf '%s' "$archives" | tr -d '\r' | sed '/^[[:space:]]*$/d' | paste -sd'|' -
  )"

  # Alte Einträge weg, neuen schreiben
  grep -Rl --null 'APT::Default-Release' /etc/apt 2>/dev/null \
    | xargs -0 -r sed -i -E '/APT::Default-Release/d'
  printf 'APT::Default-Release "/^(%s)$/";\n' "$patlist" > "$conf"

  log_info  "  -> Default-Release gesetzt auf Regex: /^(${patlist})$/"
  log_debug "    - geschrieben nach: $conf"
}

# --------------------------- Update mit Retry --------------------------------
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

# -------------------------- Universal Repair ---------------------------------
fix_apt_sources_universal() {
  log_info "  -> Starte UNIVERSAL APT-Reparatur"

  local os_id os_ver os_code; read -r os_id os_ver os_code <<<"$(detect_os_version)"
  log_debug "    - OS: $os_id $os_ver (codename=$os_code)"

  # Backup & sources.list.d parken (nur wenn .list-Dateien vorhanden)
  local TS; TS="$(date +%Y%m%d_%H%M%S)"
  [ -f /etc/apt/sources.list ] && cp -a /etc/apt/sources.list "/etc/apt/sources.list.backup.$TS"

  local parked=""
  if [ -d /etc/apt/sources.list.d ] && find /etc/apt/sources.list.d -type f -name '*.list' | grep -q .; then
    local park="/etc/apt/sources.list.d.disabled-$TS"
    mv /etc/apt/sources.list.d "$park"; mkdir -p /etc/apt/sources.list.d
    parked="$park"; log_warn "  -> sources.list.d temporär geparkt: $(basename "$park")"
  fi

  # Saubere sources.list für den erkannten Codename schreiben
  log_info "  -> Schreibe saubere sources.list für: $os_code"
  generate_clean_sources "$os_id" "$os_code" > /etc/apt/sources.list
  sanitize_sources_file "/etc/apt/sources.list"

  apt_wait_for_locks

  # Default-Release: Regex passend zu vorhandenen a=… für n=<codename>
  ensure_default_release_regex "$os_code"

  # Update testen
  if ! apt_update_with_retry; then
    log_error "❌ APT-Reparatur fehlgeschlagen (update)"
    # Rollback der geparkten Verzeichnisse
    if [ -n "$parked" ] && [ -d "$parked" ]; then
      rm -rf /etc/apt/sources.list.d
      mv "$parked" /etc/apt/sources.list.d
      log_warn "  -> sources.list.d wiederhergestellt"
    fi
    return 1
  fi

  # Finaler Check: ist n=<codename> nun sichtbar?
  if codename_present_in_sources "$os_code"; then
    log_ok "✅ Universal APT-Reparatur erfolgreich; n=$os_code in den Quellen vorhanden."
  else
    log_warn "⚠️  n=$os_code ist noch nicht sichtbar – Quellen prüfen!"
  fi
}

# ---------------------- Einzelpaket-Installation -----------------------------
# true nur bei exakt "install ok installed"
_is_installed() {
  dpkg-query -W -f='${Status}\n' "$1" 2>/dev/null | grep -qx 'install ok installed'
}

install_packages_safe() {
  local pkgs=("$@")
  [ ${#pkgs[@]} -gt 0 ] || { log_debug "install_packages_safe: nix zu tun"; return 0; }

  # fehlende Pakete sammeln
  local missing=() p
  for p in "${pkgs[@]}"; do
    _is_installed "$p" || missing+=("$p")
  done
  [ ${#missing[@]} -gt 0 ] || { log_ok "Alle gewünschten Pakete sind bereits installiert."; return 0; }

  # Release/Locks wie gehabt
  local _id _ver _code; read -r _id _ver _code <<<"$(detect_os_version)"
  ensure_default_release_regex "$_code"
  apt_wait_for_locks

  log_info "Installiere Pakete: ${missing[*]}"
  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --allow-downgrades "${missing[@]}"; then
    log_error "Paketinstallation fehlgeschlagen: ${missing[*]}"
    return 1
  fi

  log_ok "Pakete installiert."
}



# ---------------------------- Öffentliche Wrapper ----------------------------
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
