#!/bin/bash
################################################################################
#
# CONFIG HELPER
#
# @description: Sicheres Laden & Validieren der serverbaukasten.conf
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
# @license:     MIT
# @version:     1.1.2
#
################################################################################

# --- Basics -------------------------------------------------------------------
set -Eeuo pipefail

# Import der Validatoren -------------------------------------------------------
# Erwartet: validation_helpers.sh im selben Verzeichnis
source "$(dirname "${BASH_SOURCE[0]}")/validation_helpers.sh"

# Log-Fallbacks (wenn kein externer log_helper geladen ist) --------------------
if ! command -v log_info >/dev/null 2>&1; then
  log_info()  { echo -e "ℹ️  $*"; }
  log_ok()    { echo -e "✅ $*"; }
  log_warn()  { echo -e "⚠️  $*"; }
  log_error() { echo -e "❌ $*" >&2; }
fi
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { echo -e "🐞  $*" >&2; }
fi

# ==============================================================================
# SECRETS-LADER ( *_FILE )
# ==============================================================================
##
# Lädt Secret aus <VAR>_FILE, falls gesetzt. Sicher für set -u.
# Nutzt eval nur nach strikter Namensprüfung (A-Z0-9_). Keine Ausgabe der Werte.
#
# Example: resolve_secret SMTP_PASSWORD  -> liest SMTP_PASSWORD_FILE
##
resolve_secret() {
  local var="$1"
  local file_var="${1}_FILE"
  local path=""

  # Nur saubere VAR-Namen erlauben
  [[ "$file_var" =~ ^[A-Z0-9_]+$ ]] || return 0
  # Indirekte Expansion robust mit eval (kein :- bei ${!...} erlaubt)
  eval "path=\${$file_var-}"
  [ -z "$path" ] && return 0

  umask 077
  if [ -r "$path" ]; then
    local s
    IFS= read -r s <"$path" || { log_error "Kann Secret nicht lesen: $path"; return 1; }
    printf -v "$var" '%s' "$s"
    export "$var"
  else
    log_error "Secret-Datei nicht lesbar: $path"; return 1
  fi
}

# Heuristik: Variablennamen, die wie Secrets klingen (für Log-Maskierung)
is_secret_var() { [[ "$1" =~ (PASSWORD|AUTH_KEY|SECRET|TOKEN)$ ]]; }

# ==============================================================================
# KONFIGURATIONSFUNKTIONEN
# ==============================================================================

##
# Normalisiert eine Konfigurationsdatei (CRLF->LF, DOS-EOF, UTF-8 BOM)
# -> gibt NUR den Pfad der temp-Datei auf STDOUT aus; Logs gehen auf STDERR
# @param string $1 Pfad zur Konfigurationsdatei
# @return string Pfad zur normalisierten temporären Datei
##
normalize_config() {
  local src="$1"
  local tmp

  [ -f "$src" ] || { log_error "Konfigurationsdatei nicht gefunden: $src" >&2; exit 1; }

  tmp="$(mktemp)" || { log_error "Konnte temporäre Datei nicht erstellen" >&2; exit 1; }

  log_info "⚙️  Normalisiere Konfigurationsdatei..." >&2

  cp "$src" "$tmp" || { log_error "Fehler beim Kopieren der Config" >&2; rm -f "$tmp"; exit 1; }

  # Windows-Zeilenumbrüche erkennen & bereinigen
  if file "$tmp" 2>/dev/null | grep -q "CRLF\|with CR" || \
     od -c "$tmp" 2>/dev/null | head -1 | grep -q '\\r'; then
    log_warn "⚠️  Windows-Zeilenumbrüche (CRLF) erkannt – bereinige..." >&2
    sed -i 's/\r$//' "$tmp"           # CRLF -> LF
    sed -i 's/\x1a$//' "$tmp"         # DOS EOF (^Z) entfernen
    log_ok "✅ Zeilenumbrüche bereinigt" >&2
  fi

  # UTF-8 BOM entfernen (falls vorhanden)
  sed -i '1s/^\xEF\xBB\xBF//' "$tmp"

  echo "$tmp"
}

##
# Lädt Konfiguration sicher (ohne Code-Execution-Risiken)
# @param string $1 Pfad zur normalisierten Konfigurationsdatei
##
source_config_safely() {
  local file="$1"

  log_info "🔒 Lade Konfiguration sicher..."

  # Syntax-Check vor dem Laden
  if ! bash -n "$file" 2>/dev/null; then
    log_error "Syntax-Fehler in Konfigurationsdatei: $file"
    log_info "  Tipp: Prüfe die Datei mit 'bash -n $file'"
    exit 1
  fi

  # Nur erlaubte Zeilen: KEY=VALUE, Kommentare, Leerzeilen
  if grep -nEv '^(#|$|[A-Z0-9_]+\s*=)' "$file" | grep -q .; then
    log_error "Ungültige Zeilen in Config gefunden (nur KEY=VALUE, # und Leerzeilen erlaubt)"
    grep -nEv '^(#|$|[A-Z0-9_]+\s*=)' "$file" | head -3
    exit 1
  fi

  # Verdächtige Zeichen prüfen (nur Zuweisungen; Kommentare/Leerzeilen ignorieren)
  if awk '
    BEGIN{bad=0}
    /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
    /^[A-Z0-9_]+[[:space:]]*=/ {
      line=$0
      sub(/^[A-Z0-9_]+[[:space:]]*=[[:space:]]*/, "", $0)
      if ($0 ~ /`|\$\(|<\(|>\(|[;&|<>]/) { print NR ":" line; bad=1 }
      next
    }
    END{exit bad}
  ' "$file"; then
    log_error "Verdächtige Zeichen in Config gefunden (potentielle Command Injection)"
    exit 1
  fi

  # Sicher laden via source
  # shellcheck source=/dev/null
  source "$file"

  log_ok "✅ Konfiguration sicher geladen"
}

##
# Prüft, ob eine Bedingung erfüllt ist ('' | KEY=VAL | KEY!=VAL)
##
cond_met() {
  case "$1" in
    "") return 0 ;;
    *"!="*) local k="${1%%!=*}" v="${1#*!=}"; [ "${!k:-}" != "$v" ] ;;
    *=*)     local k="${1%%=*}"  v="${1#*=}";  [ "${!k:-}"  = "$v" ] ;;
    *) return 1 ;;
  esac
}

##
# Validiert alle Konfigurationsvariablen nach definierten Regeln
##
validate_config() {
  local errors=0

  log_info "🔍 Validiere Konfigurationsvariablen..."

  # Validierungsregeln: "VARIABLE|VALIDATOR|FEHLERMELDUNG|BEDINGUNG"
  local validations=(
    # Grundkonfiguration
    "SERVER_HOSTNAME|is_valid_hostname|Ungültiger Hostname.|"
    "ADMIN_USER|is_valid_username|Ungültiger Benutzername (nur a-z, 0-9, _, -).|"
    "ADMIN_PASSWORD|:|Admin-Passwort darf nicht leer sein.|"
    "ROOT_PASSWORD|:|Root-Passwort darf nicht leer sein.|"
    "NOTIFICATION_EMAIL|is_valid_email|Ungültiges E-Mail-Format.|"
    "ACCESS_MODEL|is_choice_1_2|Zugriffsmodell muss 1 (VPN) oder 2 (Öffentlich) sein.|"
    "SSH_PORT|is_valid_port|SSH-Port muss zwischen 1025 und 65535 liegen.|"
    "SERVER_ROLE|is_choice_1_2|Server-Rolle muss 1 (Docker) oder 2 (Einfach) sein.|"
    "TIMEZONE|is_valid_timezone|Zeitzone ist ungültig.|"
    "LOCALE|:|Locale darf nicht leer sein.|"
    "UPGRADE_EXTENDED|is_yes_no|UPGRADE_EXTENDED muss 'ja' oder 'nein' sein.|"

    # CrowdSec
    "CROWDSEC_MAXRETRY|is_numeric|CROWDSEC_MAXRETRY muss eine Zahl sein.|"
    "CROWDSEC_BANTIME|:|CROWDSEC_BANTIME darf nicht leer sein.|"

    # Mail (nur wenn aktiviert)
    "ENABLE_SYSTEM_MAIL|is_yes_no|ENABLE_SYSTEM_MAIL muss 'ja' oder 'nein' sein.|"
    "SMTP_HOST|is_valid_hostname|SMTP_HOST ist ein ungültiger Hostname.|WHEN ENABLE_SYSTEM_MAIL=ja"
    "SMTP_PORT|is_numeric|SMTP_PORT muss eine Zahl sein.|WHEN ENABLE_SYSTEM_MAIL=ja"
    "SMTP_FROM|is_valid_email|SMTP_FROM ist keine gültige E-Mail.|WHEN ENABLE_SYSTEM_MAIL=ja"
    "SMTP_AUTH|is_yes_no|SMTP_AUTH muss 'ja' oder 'nein' sein.|WHEN ENABLE_SYSTEM_MAIL=ja"
    "SMTP_TLS_STARTTLS|is_yes_no|SMTP_TLS_STARTTLS muss 'ja' oder 'nein' sein.|WHEN ENABLE_SYSTEM_MAIL=ja"
    "SMTP_USER|:|SMTP_USER darf nicht leer sein.|WHEN SMTP_AUTH=ja"
    "SMTP_PASSWORD|:|SMTP_PASSWORD darf nicht leer sein.|WHEN SMTP_AUTH=ja"

    # Docker (nur bei SERVER_ROLE=1)
    "DOCKER_IPV4_CIDR|is_valid_ipv4_cidr|Ungültiges Docker IPv4 CIDR-Format.|WHEN SERVER_ROLE=1"
    "DOCKER_IPV6_CIDR|is_valid_ipv6_cidr|Ungültiges Docker IPv6 CIDR-Format.|WHEN SERVER_ROLE=1"
    "INSTALL_PORTAINER|is_yes_no|INSTALL_PORTAINER muss 'ja' oder 'nein' sein.|WHEN SERVER_ROLE=1"
    "INSTALL_WATCHTOWER|is_yes_no|INSTALL_WATCHTOWER muss 'ja' oder 'nein' sein.|WHEN SERVER_ROLE=1"

    # GeoIP-Blocking
    "ENABLE_GEOIP_BLOCKING|is_yes_no|ENABLE_GEOIP_BLOCKING muss 'ja' oder 'nein' sein.|"
    "BLOCKED_COUNTRIES|is_valid_country_list|BLOCKED_COUNTRIES enthält ungültige Ländercodes.|WHEN ENABLE_GEOIP_BLOCKING=ja"
    "HOME_COUNTRY|is_valid_country_code|HOME_COUNTRY ist kein gültiger Ländercode.|WHEN ENABLE_GEOIP_BLOCKING=ja"
  )

  # Validierungsschleife
  local rule var validator msg cond val shown
  for rule in "${validations[@]}"; do
    IFS='|' read -r var validator msg cond <<< "$rule"
    if cond_met "${cond#WHEN }"; then
      val="${!var:-}"
      if [ -z "$val" ]; then
        log_error "Fehlende Variable: '$var'"
        ((errors++))
        continue
      fi
      if [ "$validator" != ":" ] && ! "$validator" "$val"; then
        shown="$val"; is_secret_var "$var" && shown="***redacted***"
        log_error "$msg (Wert war: '$shown')"
        ((errors++))
      fi
    fi
  done

  # Spezielle Logik: GeoIP Heimatland-Konflikt
  if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ] && echo "$BLOCKED_COUNTRIES" | grep -wq "$HOME_COUNTRY"; then
    log_warn "⚠️  KONFLIKT: Heimatland ($HOME_COUNTRY) wurde in der Blocklist gefunden!"
    BLOCKED_COUNTRIES=$(echo "$BLOCKED_COUNTRIES" | sed "s/\b$HOME_COUNTRY\b//g" | tr -s ' ' | sed 's/^ *//; s/ *$//')
    log_ok "✅ Heimatland wurde automatisch aus der Blocklist entfernt"
    log_info "     Bereinigte Blocklist: $BLOCKED_COUNTRIES"
  fi

  # Optionale Variablen mit Defaults setzen
  SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"
  TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
  PORTAINER_IP="${PORTAINER_IP:-}"

  if (( errors > 0 )); then
    log_error "❌ $errors Validierungsfehler gefunden – Setup abgebrochen!"
    exit 1
  fi
  log_ok "✅ Alle Validierungen bestanden – Setup kann beginnen!"
}

##
# Hauptfunktion: lädt & validiert Konfiguration
# @param string $1 Pfad zur Konfigurationsdatei
##
load_config_from_file() {
  local config_file="$1"
  local temp_config

  log_info "⚙️  Lade Konfiguration aus Datei: $config_file"

  # Schritt 1: Normalisierung → stdout: Pfad, stderr: Logs
  log_debug "Schritt 1/4: Normalisierung"
  temp_config=$(normalize_config "$config_file")
  [ -f "$temp_config" ] || { log_error "Interner Fehler: tmp-Datei fehlt: '$temp_config'"; exit 1; }

  # Schritt 2: Sicheres Laden
  log_debug "Schritt 2/4: Sicheres Laden"
  source_config_safely "$temp_config"

  # Schritt 3: Defaults & Secrets & Kanonisierung vor Validate
  # Defaults
  ENABLE_SYSTEM_MAIL="${ENABLE_SYSTEM_MAIL:-nein}"
  UPGRADE_EXTENDED="${UPGRADE_EXTENDED:-nein}"
  INSTALL_PORTAINER="${INSTALL_PORTAINER:-nein}"
  INSTALL_WATCHTOWER="${INSTALL_WATCHTOWER:-nein}"

  # Secrets aus *_FILE (no-op, wenn *_FILE nicht gesetzt)
  resolve_secret TAILSCALE_AUTH_KEY
  resolve_secret SMTP_PASSWORD

  # Kanonisierung
  HOME_COUNTRY="${HOME_COUNTRY^^}"  # upper-case
  if [ -n "${BLOCKED_COUNTRIES:-}" ]; then
    BLOCKED_COUNTRIES="$(tr ' ' '\n' <<<"$BLOCKED_COUNTRIES" | awk 'NF{print toupper($0)}' | paste -sd' ' -)"
  fi

  # Schritt 4: Validierung
  log_debug "Schritt 3/4: Validierung"
  validate_config

  # Schritt 5: Cleanup
	log_debug "Schritt 4/4: Cleanup (sicheres Löschen der temporären Datei: $temp_config)"
	if [ -f "$temp_config" ]; then
		shred -u "$temp_config" 2>/dev/null || rm -f "$temp_config"
	fi

  log_ok "🎉 Konfiguration erfolgreich geladen und validiert!"
}

# Ende ------------------------------------------------------------------------
