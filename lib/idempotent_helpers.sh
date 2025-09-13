#!/bin/bash
################################################################################
# IDEMPOTENT FILE HELPERS
# @description: Sichere, idempotente Datei-Helfer (KEINE APT-Logik).
# @license:     MIT
# @version:     1.0.0
################################################################################
set -Eeuo pipefail

# Fallback-Logs (wenn globales Logging nicht geladen ist)
if ! command -v log_info  >/dev/null 2>&1; then log_info()  { printf "ℹ️  %s\n" "$*" >&2; }; fi
if ! command -v log_ok    >/dev/null 2>&1; then log_ok()    { printf "✅ %s\n" "$*" >&2; }; fi
if ! command -v log_warn  >/dev/null 2>&1; then log_warn()  { printf "⚠️  %s\n" "$*" >&2; }; fi
if ! command -v log_error >/dev/null 2>&1; then log_error() { printf "❌ %s\n" "$*" >&2; }; fi
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { [ "${DEBUG:-false}" = "true" ] && printf "🐞  %s\n" "$*" >&2 || true; }
fi

# Optionaler Rollback-Hook: registriert Backups falls vorhanden
_backup_if_possible() {
  local f="$1"
  if command -v backup_and_register >/dev/null 2>&1; then
    backup_and_register "$f"
  elif [ -f "$f" ] && [ ! -f "${f}.bak" ]; then
    cp -a "$f" "${f}.bak"
    log_debug "    - Lokales Backup angelegt: ${f}.bak"
  fi
}

# Verzeichnis sicherstellen (idempotent)
ensure_dir() {
  local dir="$1" mode="${2:-0755}" owner="${3:-root:root}"
  if [ ! -d "$dir" ]; then
    install -d -m "$mode" -o "${owner%:*}" -g "${owner#*:}" "$dir"
    log_debug "    - Verzeichnis angelegt: $dir ($mode $owner)"
  fi
}

# Datei sicherstellen (idempotent)
ensure_file() {
  local file="$1" mode="${2:-0644}" owner="${3:-root:root}"
  if [ ! -f "$file" ]; then
    ensure_dir "$(dirname "$file")"
    install -m "$mode" -o "${owner%:*}" -g "${owner#*:}" /dev/null "$file"
    log_debug "    - Datei angelegt: $file ($mode $owner)"
  fi
}

# Zeile exakt hinzufügen, falls nicht vorhanden (idempotent)
ensure_line() {
  local file="$1" line="$2"
  ensure_file "$file"
  _backup_if_possible "$file"
  if ! grep -Fxq -- "$line" "$file"; then
    printf '%s\n' "$line" >> "$file"
    log_debug "    - Zeile ergänzt: $(basename "$file"): $line"
  fi
}

# Key=Value (oder KEY: VALUE …) setzen/ersetzen (idempotent, robuster Key-Regex)
# sep default "="; unterstützt auch ":" u.a.
ensure_kv() {
  local file="$1" key="$2" val="$3" sep="${4:-=}"
  ensure_file "$file"
  _backup_if_possible "$file"

  # Key-Pattern für sed/grep vollständig escapen (inkl. '-')
  local esc_key
  esc_key=$(printf '%s' "$key" | sed -E 's/[][(){}.^$*+?|\\/-]/\\&/g')

  if grep -qE "^[[:space:]]*${esc_key}[[:space:]]*${sep}" "$file"; then
    sed -i -E "s|^[[:space:]]*${esc_key}[[:space:]]*${sep}.*|${key}${sep}${val}|" "$file"
    log_debug "    - KV ersetzt: ${key}${sep}${val} in $(basename "$file")"
  else
    printf '%s%s%s\n' "$key" "$sep" "$val" >> "$file"
    log_debug "    - KV ergänzt: ${key}${sep}${val} in $(basename "$file")"
  fi
}

# Block zwischen Markern atomar ersetzen/hinzufügen (idempotent)
# Marker sind reine Textlinien, z.B. "# BEGIN BAUKASTEN" / "# END BAUKASTEN"
ensure_block() {
  local file="$1" begin_marker="$2" end_marker="$3" content="$4"
  ensure_file "$file"
  _backup_if_possible "$file"

  local esc_begin esc_end tmp
  esc_begin=$(printf '%s' "$begin_marker" | sed -E 's/[][(){}.^$*+?|\\/-]/\\&/g')
  esc_end=$(printf '%s' "$end_marker"   | sed -E 's/[][(){}.^$*+?|\\/-]/\\&/g')

  tmp="$(mktemp)"
  if grep -qF "$begin_marker" "$file" && grep -qF "$end_marker" "$file"; then
    # ersetzen
    awk -v b="$begin_marker" -v e="$end_marker" -v c="$content" '
      BEGIN{inblk=0}
      $0==b {print b; print c; skip=1; inblk=1; next}
      $0==e && inblk==1 {print e; inblk=0; skip=0; next}
      skip!=1 {print $0}
    ' "$file" > "$tmp"
  else
    # anhängen
    cat "$file" > "$tmp"
    printf '%s\n%s\n%s\n' "$begin_marker" "$content" "$end_marker" >> "$tmp"
  fi

  if ! cmp -s "$file" "$tmp"; then
    mv -f "$tmp" "$file"
    log_debug "    - Block aktualisiert in $(basename "$file")"
  else
    rm -f "$tmp"
  fi
}

# Zeilen entfernen, die auf Regex matchen (vorsichtig, idempotent)
delete_lines_matching() {
  local file="$1" pattern="$2"
  [ -f "$file" ] || return 0
  _backup_if_possible "$file"
  local tmp; tmp="$(mktemp)"
  grep -Ev -- "$pattern" "$file" > "$tmp" || true
  if ! cmp -s "$file" "$tmp"; then
    mv -f "$tmp" "$file"
    log_debug "    - Zeilen entfernt in $(basename "$file") (pattern: $pattern)"
  else
    rm -f "$tmp"
  fi
}

# Dateirechte/Owner sicherstellen (idempotent)
ensure_mode_owner() {
  local path="$1" mode="${2:-}" owner="${3:-}"
  [ -e "$path" ] || return 0
  if [ -n "$mode" ];  then chmod "$mode" "$path";  fi
  if [ -n "$owner" ]; then chown "$owner" "$path"; fi
  log_debug "    - Rechte/Owner gesetzt: $path ${mode:+($mode)} ${owner:+$owner}"
}
