#!/bin/bash
################################################################################
# IDEMPOTENT HELPERS
#
# @description: Release-agnostische Helfer für Paket-, Service- und Datei-Tasks,
#               mit sanften Fallbacks und ohne Hardcoding von Codenames.
# @author:      Server-Baukasten (TZERO78) & KI-Assistenten
# @license:     MIT
# @version:     1.0.0
################################################################################

set -Eeuo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Logging-Fallbacks (falls kein log_helper geladen ist)
# ──────────────────────────────────────────────────────────────────────────────
if ! command -v log_info >/dev/null 2>&1; then
  log_info()  { printf '%b\n' "ℹ️  $*"; }
  log_ok()    { printf '%b\n' "✅ $*"; }
  log_warn()  { printf '%b\n' "⚠️  $*"; }
  log_error() { printf '%b\n' "❌ $*" >&2; }
fi
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { [ "${DEBUG:-false}" = "true" ] && printf '%b\n' "🐞  $*" >&2 || true; }
fi

# ──────────────────────────────────────────────────────────────────────────────
# Kleine Utils
# ──────────────────────────────────────────────────────────────────────────────
_has() { command -v "$1" >/dev/null 2>&1; }

# Minimaler Spinner-Fallback (nur wenn run_with_spinner fehlt)
if ! command -v run_with_spinner >/dev/null 2>&1; then
  run_with_spinner() {
    # $1: Titel, $2: Kommando
    local title="$1" cmd="$2"
    log_info "$title"
    if eval "$cmd"; then
      log_ok "$title: Erfolg!"
      return 0
    else
      log_error "$title: Fehlgeschlagen!"
      return 1
    fi
  }
fi

# ──────────────────────────────────────────────────────────────────────────────
# OS/Codename ermitteln (release-agnostisch)
# ──────────────────────────────────────────────────────────────────────────────
os_release() {
  local id="unknown" codename="unknown"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID:-$id}"
    codename="${VERSION_CODENAME:-$codename}"
  fi
  printf '%s %s\n' "$id" "$codename"
}

# ──────────────────────────────────────────────────────────────────────────────
# APT/DPKG Locks warten (nur wenn apt_repair_helpers nicht geladen)
# ──────────────────────────────────────────────────────────────────────────────
apt_wait_for_locks_local() {
  local tries=30
  while (( tries-- > 0 )); do
    if command -v fuser >/dev/null 2>&1 && {
         fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 ||
         fuser /var/lib/apt/lists/lock >/dev/null 2>&1 ||
         fuser /var/cache/apt/archives/lock >/dev/null 2>&1 ; } ; then
      log_debug "    - Warte auf APT-Locks… ($((30-tries))/30)"
      sleep 2
    else
      return 0
    fi
  done
  log_warn "APT-Locks hängen ungewöhnlich lang – versuche 'dpkg --configure -a'."
  dpkg --configure -a || true
}

apt_wait_for_locks_wrapper() {
  if command -v apt_wait_for_locks >/dev/null 2>&1; then
    apt_wait_for_locks
  else
    apt_wait_for_locks_local
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# APT: Paketverfügbarkeit / Alternativen / Installation
# ──────────────────────────────────────────────────────────────────────────────

# Prüfen, ob ein Paket im aktuellen Release eine Candidate-Version hat
apt_pkg_available() {
  apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/ {print $2}' | grep -vq '(none)'
}

# Bekannte Umbenennungen/Alternativen ohne Release-Hardcodes
# – nur wenn Hauptname nicht verfügbar ist
pkg_alternatives() {
  case "$1" in
    # dns tools
    bind9-dnsutils) echo "dnsutils" ;;
    # https transport (alt)
    apt-transport-https) echo "apt" ;;
    # apparmor-utils ist teils im metapaket aufgegangen
    apparmor-utils) echo "apparmor" ;;
    # geoip-bin teils ersetzt/entfallen → lassen wir leer (wird ggf. geskippt)
    # tmux Versionskonflikte behebt apt selbst, keine Alt nötig
    *) : ;;
  esac
}

# Ermittelt die erste installierbare Wahl aus Hauptpaket + Alternativen
pkg_resolve_one() {
  local name="$1"; shift || true
  if apt_pkg_available "$name"; then
    echo "$name"; return 0
  fi
  local alt
  for alt in "$@"; do
    if apt_pkg_available "$alt"; then
      echo "$alt"; return 0
    fi
  done
  return 1
}

# Führt ein apt-get update (leise) aus, wenn sinnvoll.
apt_update_quick() {
  apt_wait_for_locks_wrapper
  apt-get -o DPkg::Lock::Timeout=60 update -qq
}

# Idempotente Installation: wählt dynamisch Alternativen & skipt nicht verfügbare
install_packages_safe() {
  local id codename; read -r id codename < <(os_release)

  # Falls Default-Release gesetzt wurde, respektieren
  local apt_def_rel_opt=()
  if [ -f /etc/apt/apt.conf.d/90defaultrelease ]; then
    apt_def_rel_opt=(-o "APT::Default-Release=$codename")
  fi

  local wants=("$@") n alts choice
  local resolved=() skipped=()

  # Vorher einmal schnell update (schadet nicht)
  apt_update_quick || true

  for n in "${wants[@]}"; do
    # Bereits installiert?
    if dpkg -s "$n" >/dev/null 2>&1; then
      log_debug "✓ $n bereits installiert"
      continue
    fi
    # Alternativen ermitteln
    read -r -a alts <<<"$(pkg_alternatives "$n")"
    if choice="$(pkg_resolve_one "$n" "${alts[@]}")"; then
      # Doppelungen vermeiden
      if [[ ! " ${resolved[*]} " =~ " ${choice} " ]]; then
        resolved+=("$choice")
      fi
    else
      log_warn "Paket im Release nicht verfügbar: $n"
      skipped+=("$n")
    fi
  done

  if [ ${#resolved[@]} -eq 0 ]; then
    log_ok "Alle gewünschten Pakete sind bereits installiert oder entfallen: ${skipped[*]:-—}"
    return 0
  fi

  export DEBIAN_FRONTEND=noninteractive
  run_with_spinner "Installiere ${#resolved[@]} Pakete…" \
    apt-get "${apt_def_rel_opt[@]}" -o Dpkg::Options::=--force-confdef \
                                   -o Dpkg::Options::=--force-confold \
                                   --no-install-recommends -y install "${resolved[@]}"
}

# Idempotente Entfernung (purge) einer Paketliste.
purge_packages_safe() {
  local to_purge=() p
  for p in "$@"; do
    dpkg -s "$p" >/dev/null 2>&1 && to_purge+=("$p")
  done
  [ ${#to_purge[@]} -eq 0 ] && { log_info "Keine Pakete zu purgen."; return 0; }
  run_with_spinner "Entferne Pakete (purge)..." \
    "apt-get -y --purge autoremove ${to_purge[*]} && apt-get -y autoclean"
}

# ──────────────────────────────────────────────────────────────────────────────
# systemd: Idempotente Service-Operationen
# ──────────────────────────────────────────────────────────────────────────────
systemctl_enable_now_safe() {
  local unit="$1"
  systemctl is-enabled "$unit" >/dev/null 2>&1 || systemctl enable "$unit"
  systemctl is-active  "$unit" >/dev/null 2>&1 || systemctl start  "$unit"
}

systemctl_disable_mask_safe() {
  local unit="$1"
  systemctl is-active "$unit"  >/dev/null 2>&1 && systemctl stop  "$unit"
  systemctl is-enabled "$unit" >/dev/null 2>&1 && systemctl disable "$unit"
  systemctl is-enabled "$unit" >/dev/null 2>&1 || systemctl mask "$unit" || true
}

# ──────────────────────────────────────────────────────────────────────────────
# Dateien/Symlinks: Idempotente Helfer
# ──────────────────────────────────────────────────────────────────────────────
write_file_if_changed() {
  # $1: Zieldatei, $2: Inhalt (String)
  local dest="$1" content="$2"
  local tmp; tmp="$(mktemp)"
  printf '%s' "$content" > "$tmp"

  # Optional: Backup registrieren, wenn Funktion existiert
  if command -v backup_and_register >/dev/null 2>&1; then
    backup_and_register "$dest"
  fi

  if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
    log_debug "Unverändert: $dest"
    rm -f "$tmp"
    return 0
  fi
  install -m 0644 -o root -g root "$tmp" "$dest"
  rm -f "$tmp"
  log_ok "Aktualisiert: $dest"
}

ensure_line_in_file() {
  # $1: Datei, $2: Regex (ohne Delimiter), $3: Zeile (ganzer Text)
  local file="$1" pattern="$2" line="$3"
  touch "$file"
  grep -Eq "$pattern" "$file" && { log_debug "Zeile bereits vorhanden in $file"; return 0; }
  if command -v backup_and_register >/dev/null 2>&1; then
    backup_and_register "$file"
  fi
  printf '%s\n' "$line" >> "$file"
  log_ok "Zeile ergänzt in $file"
}

ensure_symlink() {
  # $1: Linkpfad, $2: Ziel
  local link="$1" target="$2"
  if [ -L "$link" ] && [ "$(readlink -f "$link")" = "$(readlink -f "$target")" ]; then
    log_debug "Symlink ok: $link -> $target"
    return 0
  fi
  rm -f "$link"
  ln -s "$target" "$link"
  log_ok "Symlink gesetzt: $link -> $target"
}
# Ende ─────────────────────────────────────────────────────────────────────────