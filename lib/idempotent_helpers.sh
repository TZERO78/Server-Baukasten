#!/bin/bash
################################################################################
#
# IDEMPOTENT HELPERS
#
# @description: Kleine, robuste Bausteine für wiederholbare (idempotente)
#               Datei-/System- und APT-Operationen.
# @author:      Server-Baukasten (TZERO78) & KI
# @license:     MIT
# @version:     1.2.0
#
################################################################################

set -Eeuo pipefail

# --- Logging-Fallbacks --------------------------------------------------------
if ! command -v log_info >/dev/null 2>&1; then
  log_info()  { printf 'ℹ️  %s\n' "$*"; }
  log_ok()    { printf '✅ %s\n' "$*"; }
  log_warn()  { printf '⚠️  %s\n' "$*"; }
  log_error() { printf '❌ %s\n' "$*" >&2; }
fi
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { [ "${DEBUG:-false}" = "true" ] && printf '🐞  %s\n' "$*" >&2 || true; }
fi

# --- Mini-Utils ---------------------------------------------------------------
_has() { command -v "$1" >/dev/null 2>&1; }

# Nutze vorhandenen Spinner, sonst direkt ausführen
_run() {
  local title="$1"; shift
  local cmd="$*"
  if command -v run_with_spinner >/dev/null 2>&1; then
    run_with_spinner "$title" "$cmd"
  else
    log_info "$title"
    eval "$cmd"
  fi
}

# Warte auf APT/DPKG-Locks (falls Funktion aus apt_repair_helpers vorhanden ist)
_apt_wait() {
  if command -v apt_wait_for_locks >/dev/null 2>&1; then
    apt_wait_for_locks
  fi
}

# ------------------------------------------------------------------------------
# Dateisystem – idempotente Helfer
# ------------------------------------------------------------------------------

# Stellt sicher, dass ein Verzeichnis existiert (Owner/Mode optional).
ensure_dir() {
  local path="$1" owner="${2:-root:root}" mode="${3:-0755}"
  if [ ! -d "$path" ]; then
    log_debug "ensure_dir: Erstelle Verzeichnis $path (owner=$owner mode=$mode)"
    install -o "${owner%:*}" -g "${owner#*:}" -m "$mode" -d "$path"
  else
    log_debug "ensure_dir: Verzeichnis existiert bereits: $path"
    # Owner/Mode ggf. korrigieren
    chown "$owner" "$path"
    chmod "$mode" "$path"
  fi
}

# Stellt sicher, dass eine Datei existiert (Owner/Mode optional).
ensure_file() {
  local path="$1" owner="${2:-root:root}" mode="${3:-0644}"
  if [ ! -f "$path" ]; then
    log_debug "ensure_file: Erstelle Datei $path (owner=$owner mode=$mode)"
    install -o "${owner%:*}" -g "${owner#*:}" -m "$mode" /dev/null "$path"
  else
    log_debug "ensure_file: Datei existiert bereits: $path"
    chown "$owner" "$path"
    chmod "$mode" "$path"
  fi
}

# Fügt eine *exakte* Zeile hinzu, falls noch nicht vorhanden.
ensure_line() {
  local line="$1" file="$2"
  ensure_file "$file"
  if ! grep -qxF -- "$line" "$file" 2>/dev/null; then
    log_debug "ensure_line: Füge Zeile hinzu in $file: $line"
    printf '%s\n' "$line" >> "$file"
  else
    log_debug "ensure_line: Zeile bereits vorhanden in $file"
  fi
}

# Ersetzt/erzwingt KEY<sep>VALUE in einfacher KEY=VALUE-Datei.
# - legt Parent-Verzeichnis & Datei an (falls nötig)
# - sichert die Datei, wenn backup_and_register() existiert
# - escaped korrekt (Regex + Replacement), inkl. Sonderzeichen in SEP und VALUE
# - ersetzt vorhandenen Eintrag (am Zeilenanfang, ggf. mit Whitespaces) oder hängt an
ensure_kv() {
  local file="$1" key="$2" val="$3" sep="${4:-=}"

  # Guard
  if [ -z "${file:-}" ] || [ -z "${key:-}" ]; then
    log_error "ensure_kv: fehlende Parameter (file/key)"; return 1
  fi

  # Datei & Parent-Dir sicherstellen
  if command -v ensure_dir >/dev/null 2>&1; then
    ensure_dir "$(dirname "$file")"
  else
    mkdir -p -- "$(dirname "$file")"
  fi
  if command -v ensure_file >/dev/null 2>&1; then
    ensure_file "$file"
  else
    [ -f "$file" ] || install -m 0644 /dev/null "$file"
  fi

  # Optionales Backup registrieren
  if command -v backup_and_register >/dev/null 2>&1; then
    backup_and_register "$file"
  fi

  # Key/Separator für REGEX escapen
  # (WICHTIG: schließende eckige Klammer zuerst in der sed-Char-Class)
  local escaped_key escaped_sep
  escaped_key="$(printf '%s' "$key" | sed -e 's/[][\.^$*+?{}|()]/\\&/g')"
  escaped_sep="$(printf '%s' "$sep" | sed -e 's/[][\.^$*+?{}|()]/\\&/g')"

  # Replacement-Anteil (& und \ müssen escaped werden)
  local key_rep sep_rep val_rep
  key_rep="$(printf '%s' "$key" | sed -e 's/[&\\]/\\&/g')"
  sep_rep="$(printf '%s' "$sep" | sed -e 's/[&\\]/\\&/g')"
  val_rep="$(printf '%s' "$val" | sed -e 's/[&\\]/\\&/g')"

  # Existiert ein (nicht-kommentierter) Key bereits?
  if grep -qE "^[[:space:]]*${escaped_key}[[:space:]]*${escaped_sep}" "$file"; then
    log_debug "ensure_kv: Ersetze '${key}${sep}…' in $file"
    # ersetze die *erste* passende Zeile (Anfang der Zeile, evtl. Whitespaces vor KEY)
    sed -i -E "s|^[[:space:]]*${escaped_key}[[:space:]]*${escaped_sep}.*|${key_rep}${sep_rep}${val_rep}|" "$file"
  else
    log_debug "ensure_kv: Füge '${key}${sep}${val}' ans Ende von $file an"
    printf '%s%s%s\n' "$key" "$sep" "$val" >> "$file"
  fi
}


# ------------------------------------------------------------------------------
# APT – idempotente Helfer
# ------------------------------------------------------------------------------

# Setzt APT Default-Release, z. B. "trixie", um Suite-Mischungen zu vermeiden.
ensure_default_release() {
  local codename="$1"
  local conf="/etc/apt/apt.conf.d/00default-release"
  [ -n "$codename" ] || { log_warn "ensure_default_release: Kein Codename übergeben – überspringe."; return 0; }

  if [ -f "$conf" ] && grep -q "APT::Default-Release \"$codename\";" "$conf"; then
    log_debug "ensure_default_release: Bereits gesetzt auf '$codename'."
    return 0
  fi

  log_debug "ensure_default_release: Setze Default-Release auf '$codename'."
  printf 'APT::Default-Release "%s";\n' "$codename" > "$conf"
}

# Prüft per dpkg -s, ob ein Paket installiert ist.
is_installed() {
  dpkg -s "$1" >/dev/null 2>&1
}

# Filtert eine Paketliste und gibt nur die *fehlenden* Pakete auf STDOUT aus.
missing_packages() {
  local p
  for p in "$@"; do
    if ! is_installed "$p"; then
      echo "$p"
    fi
  done
}

# Apt-Update leise (mit Lock-Wait)
apt_update_quiet() {
  _apt_wait
  _run "Paketlisten aktualisieren..." "apt-get update -qq"
}

# Installiert Pakete robust und idempotent (Update + Install + Fallback pro Paket).
install_packages_safe() {
  local pkgs=("$@")
  [ ${#pkgs[@]} -gt 0 ] || { log_info "Keine Pakete angefordert – überspringe Installation."; return 0; }

  log_debug "install_packages_safe: Anforderung ${#pkgs[@]} Pakete: ${pkgs[*]}"

  apt_update_quiet

  _apt_wait
  local APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  if DEBIAN_FRONTEND=noninteractive apt-get install "${APT_OPTS[@]}" --no-install-recommends "${pkgs[@]}"; then
    log_ok "Pakete installiert: ${pkgs[*]}"
    return 0
  fi

  log_warn "Gesamte Installation fehlgeschlagen – versuche Einzelpakete zur Eingrenzung…"
  local failed=() ok=()
  for p in "${pkgs[@]}"; do
    _apt_wait
    if DEBIAN_FRONTEND=noninteractive apt-get install "${APT_OPTS[@]}" --no-install-recommends "$p"; then
      ok+=("$p")
    else
      failed+=("$p")
    fi
  done

  if [ ${#failed[@]} -gt 0 ]; then
    log_error "Folgende Pakete ließen sich nicht installieren: ${failed[*]}"
    log_debug "Erfolgreich installiert: ${ok[*]:-keine}"
    return 1
  fi

  log_ok "Alle Pakete erfolgreich installiert (Einzelläufe)."
  return 0
}
