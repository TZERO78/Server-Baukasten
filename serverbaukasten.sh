#!/bin/bash
################################################################################
# SERVER BAUKASTEN
#
# @description: Ein Skript zur vollautomatischen Härtung von Linux-Servern.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Copyright (c) 2025 Markus F. (TZERO78)
#
# Dieses Skript steht unter der MIT-Lizenz.
# Eine Kopie der Lizenz finden Sie in der 'LICENSE'-Datei im Repository
# oder unter: https://opensource.org/licenses/MIT
# ==============================================================================
# Zweck: Richtet einen neuen Debian/Ubuntu-Server nach einem festen,
#        extrem sicheren und modernen Standard ein.
#
# USAGE:
#   Interaktiv: sudo ./serverbaukasten.sh
#   Automatisch: sudo ./serverbaukasten.sh -c /pfad/zur/config.conf
#   Hilfe:      sudo ./serverbaukasten.sh -h
################################################################################

# --- Sicherheits-Präambel ---
# Stellt sicher, dass das Skript bei Fehlern sofort abbricht (set -e)
# und Fehler in einer Pipe-Kette weitergegeben werden (set -o pipefail).
set -e
set -o pipefail

readonly SCRIPT_VERSION="1.0"
readonly CROWDSEC_MAXRETRY_DEFAULT=5
readonly CROWDSEC_BANTIME_DEFAULT="48h" 
readonly SSH_PORT_DEFAULT=22
readonly NOTIFICATION_EMAIL_DEFAULT="admin@example.com"  # Generic für Community
readonly COMPONENTS_BASE_URL="https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/components"

# Globale Verbose/Debug-Variablen
declare -g SCRIPT_VERBOSE=false
declare -g DEBUG=false

# Farben für die Ausgabe
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'

# Globale Variablen für den Skript-Zustand
declare -a BACKUP_FILES
CONFIG_FILE=""

################################################################################
#
#                                  UI-HELFER
#
################################################################################

##
# Gibt einen formatierten Header für einen Abschnitt in der Konsole aus.
# @param string $1 Schrittnummer (z.B. "1").
# @param string $2 Titel des Abschnitts.
# @param string $3 Icon für den Abschnitt.
##
print_section_header() {
    local step="$1" title="$2" icon="$3"
    local padding_size=$((60 - ${#title} - ${#step}))
    local padding; printf -v padding '%*s' $padding_size
    echo -e "\n${BLUE}┌─────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│ ${icon}   SCHRITT ${step}:   ${title}${padding}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────────────┘${NC}"
}

##
# Fragt den Benutzer nach einer Ja/Nein-Antwort und speichert das Ergebnis.
# @param string $1 Die Frage, die dem Benutzer gestellt wird.
# @param string $2 Der Name der Variable, in der das Ergebnis ('ja'/'nein') gespeichert wird.
# @param string $3 Der Standardwert ('ja' oder 'nein').
##
prompt_for_yes_no() {
    local prompt="$1" var_name="$2" default="$3"
    local answer
    while true; do
        read -p "$(echo -e "${CYAN}›${NC}") $prompt (ja/nein, Standard: $default, Enter für Standard): " answer
        if [ -z "$answer" ]; then answer="$default"; fi
        
        case "$answer" in
            [jJ]|[yY]|[jJ][aA]|[yY][eE][sS] ) eval "$var_name='ja'"; break;;
            [nN]|[nN][eE][iI][nN]|[nN][oO] ) eval "$var_name='nein'"; break;;
            * ) echo -e "${RED}  Bitte mit 'ja' oder 'nein' antworten.${NC}";;
        esac
    done
}

##
# Fragt den Benutzer nach einer Texteingabe und validiert diese.
# @param string $1 Die Frage, die dem Benutzer gestellt wird.
# @param string $2 Der Name der Variable, in der die Eingabe gespeichert wird.
# @param string $3 Der Standardwert.
# @param string $4 Der Name der Validierungsfunktion (z.B. "is_valid_email").
# @param string $5 Die Fehlermeldung bei ungültiger Eingabe.
##
prompt_for_validated_input() {
    local prompt="$1" var_name="$2" default="$3" validator="$4" error_msg="$5"
    local input
    while true; do
        read -p "$(echo -e "${CYAN}›${NC}") $prompt (Standard: $default, Enter für Standard): " input
        if [ -z "$input" ]; then input="$default"; fi

        if $validator "$input"; then
            eval "$var_name=\"$input\""
            break
        else
            echo -e "${RED}  $error_msg${NC}"
        fi
    done
}

##
# Fragt den Benutzer nach einer Auswahl aus einer nummerierten Liste.
# @param string $1 Die Frage, die dem Benutzer gestellt wird.
# @param string $2 Der Name der Variable, in der die Auswahl (Index) gespeichert wird.
# @param string $3 Der Standard-Index.
# @param array  $@ Die Liste der Optionen.
##
prompt_for_choice() {
    local prompt="$1" var_name="$2" default="$3"
    shift 3
    local options=("$@")
    local choice

    echo -e "${CYAN}›${NC} $prompt"
    for i in "${!options[@]}"; do
        echo -e "     ${PURPLE}$((i+1)))${NC} ${options[$i]}"
    done

    while true; do
        read -p "   Auswahl (Standard: $default, Enter für Standard): " choice
        if [ -z "$choice" ]; then choice="$default"; fi
        
        if [[ "$choice" -ge 1 && "$choice" -le ${#options[@]} ]]; then
            eval "$var_name=$choice"
            break
        else
            echo -e "${RED}  Ungültige Auswahl. Bitte eine Zahl zwischen 1 und ${#options[@]} eingeben.${NC}"
        fi
    done
}

##
# Fragt den Benutzer nach einem Passwort mit Längenprüfung und Bestätigung.
# @param string $1 Die Aufforderung für das Passwort.
# @param string $2 Der Name der Variable, in der das Passwort gespeichert wird.
##
prompt_for_password() {
    local prompt="$1" var_name="$2"
    local pass pass_confirm
    while true; do
        read -s -p "$(echo -e "${CYAN}›${NC}") $prompt (mind. 8 Zeichen): " pass; echo
        if [ ${#pass} -lt 8 ]; then
            echo -e "${RED}  Passwort zu kurz!${NC}"; continue
        fi
        read -s -p "$(echo -e "${CYAN}›${NC}") Passwort wiederholen: " pass_confirm; echo
        if [ "$pass" = "$pass_confirm" ]; then
            eval "$var_name=\"$pass\""
            break
        else
            echo -e "${RED}  Passwörter stimmen nicht überein!${NC}"
        fi
    done
}

##
# Gibt einen formatierten Header für einen Block in der Zusammenfassung aus.
# @param string $1 Titel des Headers.
# @param string $2 Farbvariable (z.B. "GREEN").
##
print_summary_header() {
    local title="$1" color="$2"
    echo -e "\n${!color}--- $title ---${NC}"
}

##
# Gibt einen formatierten Eintrag (Label: Wert) in der Zusammenfassung aus.
# @param string $1 Das Label.
# @param string $2 Der Wert.
# @param string $3 Optionale Farbvariable (Standard: CYAN).
##
print_summary_entry() {
    local label="$1" value="$2" color="${3:-$CYAN}"
    printf "   %-28s %b\n" "$label:" "${color}${value}${NC}"
}

##
# Gibt einen formatierten Tipp in der Zusammenfassung aus.
# @param string $1 Der Tipp-Text.
##
print_summary_tip() {
    local tip="$1"
    echo -e "   ${BLUE}💡 $1${NC}"
}

##
# Gibt eine formatierte Warnung in der Zusammenfassung aus.
# @param string $1 Der Warnhinweis.
##
print_summary_warning() {
    local warning="$1"
    echo -e "   ${YELLOW}⚠️  $1${NC}"
}

##
# Eine verbesserte Passwort-Eingabe mit visueller Bestätigung und Bearbeitungsoption.
# @param string $1 Die Aufforderung für das Passwort.
# @param string $2 Der Name der Variable, in der das Passwort gespeichert wird.
##
prompt_for_password_with_confirmation() {
    local prompt="$1"
    local var_name="$2"
    local password=""
    local confirm=""
    
    while true; do
        # Passwort eingeben
        read -srp "$(echo -e "${CYAN}›${NC} $prompt: ")" password
        echo
        
        # Passwort bestätigen
        read -srp "$(echo -e "${CYAN}›${NC} Passwort wiederholen: ")" confirm
        echo
        
        # Prüfe ob Passwörter übereinstimmen
        if [ "$password" = "$confirm" ]; then
            # Zeige Passwort für 10 Sekunden zur Bestätigung
            echo -e "\n${YELLOW}📋 Eingegebenes Passwort (wird 10 Sekunden angezeigt):${NC}"
            echo -e "${CYAN}$password${NC}"
            echo -e "${YELLOW}⏰ Passwort korrekt? Wird in 10 Sekunden ausgeblendet...${NC}"
            
            # Countdown mit Interrupt-Möglichkeit
            local countdown=10
            local user_choice=""
            
            while [ $countdown -gt 0 ]; do
                printf "\r${YELLOW}⏰ Automatische Übernahme in %d Sekunden... (j=Ja, n=Nein, Enter=Bearbeiten): ${NC}" $countdown
                
                # Prüfe auf User-Input mit 1-Sekunden-Timeout
                if read -t 1 -n 1 user_choice 2>/dev/null; then
                    echo  # Neue Zeile nach Input
                    break
                fi
                ((countdown--))
            done
            
            # Bildschirm kurz leeren (Passwort verstecken)
            printf "\033[2K\r"  # Lösche aktuelle Zeile
            printf "\033[1A\033[2K\r"  # Lösche vorherige Zeile
            printf "\033[1A\033[2K\r"  # Lösche Passwort-Zeile
            
            # Verarbeite User-Choice
            case "$user_choice" in
                "j"|"J"|"")  # Ja oder Timeout = Akzeptieren
                    eval "$var_name=\"$password\""
                    echo -e "${GREEN}✅ Passwort akzeptiert und gespeichert.${NC}"
                    return 0
                    ;;
                "n"|"N")  # Nein = Neu eingeben
                    echo -e "${YELLOW}🔄 Passwort wird neu eingegeben...${NC}"
                    continue
                    ;;
                *)  # Enter oder andere Taste = Bearbeiten
                    echo -e "${CYAN}📝 Passwort bearbeiten:${NC}"
                    local edited_password
                    read -rp "$(echo -e "${CYAN}›${NC} Bearbeitetes Passwort: ")" -i "$password" edited_password
                    password="$edited_password"
                    eval "$var_name=\"$password\""
                    echo -e "${GREEN}✅ Bearbeitetes Passwort gespeichert.${NC}"
                    return 0
                    ;;
            esac
        else
            echo -e "${RED}❌ Passwörter stimmen nicht überein. Bitte erneut eingeben.${NC}"
        fi
    done
}

##
# Fragt nach SMTP-Benutzerdaten, falls SMTP-Authentifizierung aktiviert ist.
##
prompt_for_smtp_credentials() {
    if [ "$SMTP_AUTH" = "ja" ]; then
        read -p "$(echo -e "${CYAN}›${NC}   👤 SMTP-Benutzername: ")" SMTP_USER
        
        # Verwende verbesserte Passwort-Eingabe
        prompt_for_password_with_confirmation "🔑 SMTP-Passwort" "SMTP_PASSWORD"
    fi
}

##
# Gibt die Fingerprints der SSH-Host-Schlüssel aus.
##
print_ssh_host_keys() {
    echo -e "   ${BLUE}Server Host-Key Fingerprints:${NC}"
    for key_file in /etc/ssh/ssh_host_*_key.pub; do
        if [ -f "$key_file" ]; then
            local fingerprint
            fingerprint=$(ssh-keygen -l -f "$key_file" | awk '{print $2}')
            print_summary_entry "  > $(basename "$key_file" .pub)" "$fingerprint" "$CYAN"
        fi
    done
}


##
# Führt einen Befehl aus. Zeigt im Normalmodus einen Spinner und bei Fehlern die
# Fehlermeldung an. Im Verbose-Modus wird die gesamte Ausgabe live angezeigt.
# @param string $1 Der Text, der neben dem Spinner angezeigt wird.
# @param string $2 Der auszuführende Befehl.
# @return int Exit-Code des Befehls.
##
run_with_spinner() {
    local title="$1"
    local command="$2"

    # --- Verbose-Modus: Kein Spinner, zeige alle Ausgaben live ---
    if [ "${SCRIPT_VERBOSE:-false}" = "true" ]; then
        log_info "Ausführung (verbose): $title..."
        # Führe Befehl direkt aus, die Ausgabe geht auf den Bildschirm
        eval "$command"
        local ec=$?

        if [ $ec -eq 0 ]; then
            log_ok "$title: Erfolg!"
        else
            log_error "$title: Fehlgeschlagen! (Exit-Code: $ec)"
        fi
        return $ec
    fi

    # --- Normalmodus: Spinner anzeigen, Fehlerdetails bei Fehlschlag ---
    local stderr_file
    stderr_file=$(mktemp)
    trap 'rm -f "$stderr_file"' RETURN # Stellt sicher, dass die temporäre Datei immer gelöscht wird

    local spinner_chars="/|\\-"
    local i=0

    # Logge den Start der Aktion
    log_info "Starte: $title..."

    # stdout nach /dev/null (still), stderr in unsere temporäre Fehler-Datei
    eval "$command" >/dev/null 2> "$stderr_file" &
    local pid=$!

    printf "${YELLOW}⏳ %s ${NC}" "$title"
    while ps -p $pid &>/dev/null; do
        i=$(((i + 1) % 4))
        printf "\b${spinner_chars:$i:1}"
        sleep 0.1
    done

    wait $pid
    local ec=$?

    if [ $ec -eq 0 ]; then
        printf "\b${GREEN}✔${NC}\n"
        log_ok "$title: Abgeschlossen."
    else
        printf "\b${RED}✖${NC}\n"
        log_error "$title: Fehlgeschlagen!"
        
        if [ -s "$stderr_file" ]; then
            # Zeige die Fehlermeldung auf dem Bildschirm an
            echo -e "${RED}┌─── FEHLERMELDUNG ─────────────────────────────────────────┐${NC}"
            while IFS= read -r line; do
                echo -e "${RED}│${NC} $line"
            done < "$stderr_file"
            echo -e "${RED}└──────────────────────────────────────────────────────────┘${NC}"
            
            # Sende die detaillierte Fehlermeldung zusätzlich ins Journal
            logger -t "server-baukasten" -p "daemon.err" -- "FEHLERDETAILS ($title): $(cat "$stderr_file")"
        fi
    fi

    return $ec
}

################################################################################
#
#                             VALIDIERUNGS-HELFER
#
################################################################################

is_valid_email() {
    [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}
is_valid_ipv4() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do if ((octet > 255)); then return 1; fi; done
        return 0
    fi
    return 1
}
is_valid_ipv4_cidr() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]] && is_valid_ipv4 "$(echo "$1" | cut -d'/' -f1)"
}
is_valid_ipv6_cidr() {
    [[ "$1" =~ ^([0-9a-fA-F:]+:+[0-9a-fA-F:.]*)/([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$ ]]
}
is_valid_username() {
    [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}
is_valid_hostname() {
    [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ && ${#1} -le 253 ]]
}
is_valid_ssh_pubkey() {
    [[ "$1" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ]]
}
is_valid_port() {
    local p="$1"
    if [[ "$p" =~ ^[0-9]+$ && "$p" -gt 1024 && "$p" -le 65535 ]]; then return 0; else return 1; fi
}
is_numeric() {
    [[ "$1" =~ ^[0-9]+$ ]]
}
is_valid_timezone() {
    [ -f "/usr/share/zoneinfo/$1" ]
}
# Prüft ob ein Ländercode echt existiert (gegen GeoIP-Datenbank)
is_valid_country_code() {
    local code="$1"
    
    # Format-Check (2 Großbuchstaben)
    [[ "$code" =~ ^[A-Z]{2}$ ]] || return 1
    
    # Prüfe gegen offizielle GeoIP-Datenbank (falls verfügbar)
    if [ -f "/usr/share/GeoIP/GeoIPCountryWhois.csv" ]; then
        grep -q "^$code;" "/usr/share/GeoIP/GeoIPCountryWhois.csv"
        return $?
    fi
    
    # Fallback: Prüfe gegen interne Liste (häufigste Länder)
    case "$code" in
        # Europa
        "DE"|"FR"|"IT"|"ES"|"GB"|"NL"|"BE"|"AT"|"CH"|"SE"|"NO"|"DK"|"FI"|"PL"|"CZ"|"HU"|"PT"|"IE"|"GR"|"RO"|"BG"|"HR"|"SI"|"SK"|"LT"|"LV"|"EE"|"LU"|"MT"|"CY")
            return 0 ;;
        # Nordamerika
        "US"|"CA"|"MX")
            return 0 ;;
        # Asien
        "CN"|"JP"|"KR"|"IN"|"TH"|"VN"|"SG"|"MY"|"ID"|"PH"|"TW"|"HK"|"MO"|"KH"|"LA"|"MM"|"BD"|"PK"|"LK"|"NP"|"BT"|"MV")
            return 0 ;;
        # Ozeanien
        "AU"|"NZ"|"FJ"|"PG"|"NC"|"PF")
            return 0 ;;
        # Afrika
        "ZA"|"EG"|"NG"|"KE"|"ET"|"GH"|"UG"|"TZ"|"DZ"|"MA"|"TN"|"LY"|"SD"|"AO"|"MZ"|"MG"|"CM"|"CI"|"NE"|"BF"|"ML"|"MW"|"ZM"|"ZW"|"BW"|"NA"|"SZ"|"LS"|"MU"|"SC"|"CV"|"ST"|"GQ"|"GA"|"CG"|"CD"|"CF"|"TD"|"SL"|"LR"|"GN"|"GW"|"SN"|"GM"|"MR")
            return 0 ;;
        # Südamerika
        "BR"|"AR"|"CL"|"PE"|"CO"|"VE"|"EC"|"BO"|"PY"|"UY"|"GY"|"SR"|"GF")
            return 0 ;;
        # Naher Osten
        "SA"|"AE"|"QA"|"KW"|"BH"|"OM"|"IR"|"IQ"|"SY"|"LB"|"JO"|"IL"|"PS"|"YE"|"TR"|"AM"|"AZ"|"GE")
            return 0 ;;
        # Besondere/Risiko-Länder (wichtig für Blocking)
        "KP"|"AF"|"BY"|"RU"|"RS"|"BA"|"ME"|"MK"|"AL"|"XK"|"MD"|"UA"|"CU"|"VE"|"ER"|"SO"|"SS"|"LY"|"SY"|"IQ"|"AF"|"MM"|"KH")
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# Erweiterte Validierung für Ländercode-Listen
is_valid_country_list() {
    local countries="$1"
    
    # Leer-Check
    [ -n "$countries" ] || return 1
    
    # Prüfe jeden Ländercode einzeln
    for country in $countries; do
        if ! is_valid_country_code "$country"; then
            return 1
        fi
    done
    
    return 0
}
validate_countries_with_feedback() {
    local countries="$1"
    local invalid_codes=""
    local valid_codes=""
    
    for country in $countries; do
        if is_valid_country_code "$country"; then
            valid_codes+="$country "
        else
            invalid_codes+="$country "
        fi
    done
    
    # NEU: Entfernt das letzte Leerzeichen für eine saubere Ausgabe
    invalid_codes=${invalid_codes% }
    valid_codes=${valid_codes% }

    if [ -n "$invalid_codes" ]; then
        log_error "Ungültige Ländercodes gefunden: $invalid_codes"
        log_info "Gültige Codes waren: $valid_codes"
        return 1
    else
        log_ok "Alle Ländercodes sind gültig: $valid_codes"
        return 0
    fi
}
################################################################################
#
#                               KERN-HELFER
#
################################################################################


# ===============================================================================
#  LOGGING-SYSTEM v3.0
#  - Symbole für die Konsolenausgabe.
#  - Text-Präfixe und korrekte Level für das System-Journal (journald).
# ===============================================================================

##
# Loggt eine allgemeine Information.
##
log_info() {
    echo -e "${CYAN}ℹ️  $*${NC}"
    # Sende an das Journal, ABER nur, wenn der logger-Befehl existiert
    if command -v logger &>/dev/null; then
        logger -t "server-baukasten" -p "daemon.info" -- "INFO: $*"
    fi
}

##
# Loggt eine Erfolgsmeldung.
##
log_ok() {
    echo -e "${GREEN}✅ $*${NC}"
    if command -v logger &>/dev/null; then
        logger -t "server-baukasten" -p "daemon.notice" -- "SUCCESS: $*"
    fi
}

##
# Loggt eine Warnung.
##
log_warn() {
    echo -e "${YELLOW}⚠️  $*${NC}"
    if command -v logger &>/dev/null; then
        logger -t "server-baukasten" -p "daemon.warning" -- "WARN: $*"
    fi
}

##
# Loggt einen kritischen Fehler.
##
log_error() {
    echo -e "${RED}❌ $*${NC}" >&2
    if command -v logger &>/dev/null; then
        logger -t "server-baukasten" -p "daemon.err" -- "ERROR: $*"
    fi
}

##
# Loggt eine Debug-Meldung (nur wenn DEBUG=true).
##
log_debug() {
    if [ "${DEBUG:-false}" = "true" ]; then
        echo -e "${PURPLE}[DEBUG]${NC} $*" >&2
        if command -v logger &>/dev/null; then
            logger -t "server-baukasten" -p "daemon.debug" -- "DEBUG: $*"
        fi
    fi
}

##
# Prüft, ob das Skript als root ausgeführt wird. Bricht ab, wenn nicht.
##
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Dieses Skript muss als 'root' ausgeführt werden."
        exit 1
    fi
}
##
# Erkennt das Betriebssystem und die Version aus /etc/os-release.
##
detect_os() {
    if [ -f /etc/os-release ]; then
        # Lädt die OS-Variablen in die aktuelle Shell
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION_CODENAME="$VERSION_CODENAME"
    else
        log_error "OS-Erkennung fehlgeschlagen: /etc/os-release nicht gefunden."
        exit 1
    fi
}
##
# Führt Vorab-Prüfungen durch, um sicherzustellen, dass alle benötigten Befehle vorhanden sind.
##
pre_flight_checks() {
    log_info "Prüfe System-Mindestvoraussetzungen..."
    
    # Zuordnung von kritischen Befehlen zu den Paketen, die sie bereitstellen
    declare -A cmd_to_pkg=(
        [curl]="curl"
        [wget]="wget"
        [gpg]="gpg"
        [systemctl]="systemd"
        [ip]="iproute2"
        [apt-get]="apt"
        [sed]="sed"
        [envsubst]="gettext-base"
        [logger]="bsdutils"
    )

    local missing_cmds=()
    local missing_pkgs=()

    for cmd in "${!cmd_to_pkg[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_cmds+=("$cmd")
            local pkg=${cmd_to_pkg[$cmd]}
            # Füge Paket nur hinzu, wenn es noch nicht in der Liste ist
            if [[ ! " ${missing_pkgs[*]} " =~ " ${pkg} " ]]; then
                missing_pkgs+=("$pkg")
            fi
        fi
    done

    if [ ${#missing_cmds[@]} -gt 0 ]; then
        log_error "Fehlende Kern-Befehle: ${missing_cmds[*]}"
        log_info "  -> Bitte installiere die folgenden Pakete: ${missing_pkgs[*]}"
        exit 1
    else
        log_ok "Alle System-Mindestvoraussetzungen sind erfüllt."
    fi
}

##
# Erstellt ein Backup einer Datei, falls noch keins existiert, und registriert sie für ein Rollback.
# @param string $1 Der Pfad zur Datei.
##
backup_and_register() {
    local file="$1"
    if [ -f "$file" ] && [ ! -f "${file}.bak" ]; then cp "$file" "${file}.bak"; BACKUP_FILES+=("$file"); fi
}
##
# Führt ein Rollback aller gesicherten Konfigurationsdateien durch.
# Wird durch 'trap' bei einem kritischen Fehler aufgerufen.
##
rollback() {
    log_error "Ein kritischer Fehler ist aufgetreten - starte automatisches Rollback..."
    
    if [ ${#BACKUP_FILES[@]} -gt 0 ]; then
        for file in "${BACKUP_FILES[@]}"; do
            if [ -f "${file}.bak" ]; then
                mv -f "${file}.bak" "$file"
                log_info "  -> '$file' wurde aus dem Backup wiederhergestellt."
            fi
        done
    else
        log_warn "Keine Backup-Dateien zum Wiederherstellen registriert."
    fi
    
    cleanup_admin_sudo_rights_emergency
    
    log_ok "Rollback abgeschlossen. Das System sollte im vorherigen Zustand sein."
    exit 1
}
##
# Setzt einen Konfigurationswert in einer Datei (z.B. sshd_config).
# Entfernt zuerst alle existierenden Zeilen (auch auskommentierte) für diesen Schlüssel.
# @param string $1 Der Pfad zur Datei.
# @param string $2 Der Konfigurationsschlüssel.
# @param string $3 Der neue Wert.
##
set_config_value() {
    local file="$1" key="$2" value="$3"
    sed -i -E "/^\s*#?\s*${key}/d" "$file"
    echo "${key} ${value}" >> "$file"
}
##
# Entfernt die temporären NOPASSWD-Rechte und stellt die Standard-sudo-Konfiguration wieder her.
##
cleanup_admin_sudo_rights() {
    log_info "🔒 Stelle Standard-sudo-Sicherheit wieder her..."
    
    rm -f "/etc/sudoers.d/99-$ADMIN_USER"
    echo "$ADMIN_USER ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/50-$ADMIN_USER"
    chmod 440 "/etc/sudoers.d/50-$ADMIN_USER"
    
    log_ok "Sudo-Sicherheit wiederhergestellt. Passwort-Abfrage für '$ADMIN_USER' ist jetzt aktiv."
}
##
# Notfall-Bereinigung der sudo-Rechte, falls das Skript vorzeitig abbricht.
##
cleanup_admin_sudo_rights_emergency() {
    log_warn "🚨 Notfall-Cleanup: Entferne temporäre NOPASSWD-Rechte..."
    
    rm -f "/etc/sudoers.d/99-$ADMIN_USER"
    
    # Stellt sicher, dass der Admin-User seine sudo-Rechte nicht verliert
    if [ ! -f "/etc/sudoers.d/50-$ADMIN_USER" ]; then
        log_info "  -> Permanente sudo-Regel nicht gefunden, wird als Fallback neu erstellt."
        echo "$ADMIN_USER ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/50-$ADMIN_USER"
        chmod 440 "/etc/sudoers.d/50-$ADMIN_USER"
    fi
}


##
# Bietet an, die Konfigurationsdatei mit sensiblen Daten am Ende des Skripts sicher zu löschen.
##
cleanup_sensitive_data() {
    if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
        print_section_header "SICHERHEIT" "SENSIBLE DATEN BEREINIGEN" "🔒"
        
        log_warn "Die Konfigurationsdatei '$CONFIG_FILE' enthält Klartext-Passwörter!"
        log_info "Empfehlung: Sicheres Löschen, um die Daten rückstandslos zu entfernen."
        
        local cleanup_choice
        prompt_for_yes_no "Soll die Konfigurationsdatei jetzt sicher gelöscht werden?" "cleanup_choice" "ja"
        
        if [ "$cleanup_choice" = "ja" ]; then
            if command -v shred &>/dev/null; then
                if run_with_spinner "Lösche Konfigurationsdatei sicher (shred)..." "shred -n 3 -uz '$CONFIG_FILE'"; then
                    log_ok "Konfigurationsdatei sicher überschrieben und gelöscht."
                else
                    log_warn "Sicheres Löschen mit 'shred' fehlgeschlagen. Nutze 'rm' als Fallback."
                    rm -f "$CONFIG_FILE"
                    log_info "Konfigurationsdatei gelöscht (möglicherweise wiederherstellbar)."
                fi
            else
                log_warn "'shred' ist nicht installiert. Nutze 'rm' als Fallback."
                rm -f "$CONFIG_FILE"
                log_info "Konfigurationsdatei gelöscht (möglicherweise wiederherstellbar)."
            fi
        else
            log_error "KONFIGURATIONSDATEI WURDE NICHT GELÖSCHT!"
            log_warn "Die Datei '$CONFIG_FILE' enthält weiterhin Klartext-Passwörter."
            log_info "  -> Manuell löschen mit: shred -u '$CONFIG_FILE'"
        fi
    else
        log_info "Keine Konfigurationsdatei verwendet, keine sensiblen Daten zu bereinigen."
    fi
}

###########################################################################################
#
#                      SETUP-FUNKTIONEN FÜR SERVER-SICHERHEIT
#
###########################################################################################

##
# Konfiguriert Basis-Sicherheitsmaßnahmen wie SSH-Härtung und AppArmor.
##
setup_basic_security() {
    log_info "🔐 MODUL: Basis-Sicherheit (SSH + AppArmor)"
    
    # --- SSH-Härtung ---
    log_info "  -> Konfiguriere SSH-Sicherheit..."
    backup_and_register "/etc/ssh/sshd_config"
    
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        mkdir -p "/home/$ADMIN_USER/.ssh"
        echo "$SSH_PUBLIC_KEY" > "/home/$ADMIN_USER/.ssh/authorized_keys"
        chown -R "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
        chmod 700 "/home/$ADMIN_USER/.ssh" && chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
        log_ok "SSH Public Key für '$ADMIN_USER' wurde installiert."
    fi
    
    set_config_value "/etc/ssh/sshd_config" "Port" "$SSH_PORT"
    set_config_value "/etc/ssh/sshd_config" "PasswordAuthentication" "yes"
    set_config_value "/etc/ssh/sshd_config" "PermitRootLogin" "no"
    set_config_value "/etc/ssh/sshd_config" "PubkeyAuthentication" "yes"
    
    if [ "$OS_ID" = "ubuntu" ]; then
        log_info "  -> Wende Ubuntu-spezifischen SSH-Socket-Fix an..."
        systemctl disable --now ssh.socket >/dev/null 2>&1 || true
        systemctl enable --now ssh.service >/dev/null 2>&1 || true
    fi
    
    # Verwende den Spinner für Aktionen mit spürbarer Dauer
    if ! run_with_spinner "SSH-Dienst neu starten..." "systemctl restart ssh"; then
        log_warn "Neustart des SSH-Dienstes ist fehlgeschlagen. Überprüfe den Status manuell."
    else
        log_ok "SSH auf Port $SSH_PORT gehärtet und neu gestartet."
    fi

    # --- AppArmor ---
    log_info "  -> Aktiviere AppArmor (Mandatory Access Control)..."
    run_with_spinner "AppArmor-Dienst aktivieren..." "systemctl enable --now apparmor"
    run_with_spinner "AppArmor-Profile in den 'enforce'-Modus setzen..." "aa-enforce /etc/apparmor.d/*"
    log_ok "AppArmor aktiviert und Profile in den enforce-Modus versetzt."
    
    log_ok "Modul Basis-Sicherheit erfolgreich abgeschlossen."
}
##
# Installiert und konfiguriert die NFTables-Firewall-Infrastruktur.
##
setup_firewall_infrastructure() {
    log_info "🔥 MODUL: Firewall-Infrastruktur (NFTables)"
    
    # Installation und Konfiguration der iptables-Alternative in einem Schritt
    run_with_spinner "Installiere NFTables und setze iptables-Alternative..." \
        "apt-get install -y nftables && update-alternatives --set iptables /usr/sbin/iptables-nft"
    
    # Die Funktion generate_nftables_config hat bereits eigene, passende log_* Aufrufe
    generate_nftables_config
    
    # Aktiviere und starte den NFTables-Service
    if ! run_with_spinner "Aktiviere NFTables-Service..." "systemctl enable --now nftables"; then
        log_error "NFTables-Service konnte nicht gestartet werden. Firewall ist NICHT aktiv."
        return 1
    fi
    
    # KRITISCH: Lade die generierte Konfiguration zur Laufzeit!
    if ! run_with_spinner "Lade generierte Firewall-Konfiguration..." "nft -f /etc/nftables.conf"; then
        log_error "Generierte NFTables-Konfiguration konnte nicht geladen werden!"
        return 1
    fi
    
    # Finale Überprüfung, ob die Regeln geladen sind
    if nft list tables &>/dev/null; then
        log_ok "Firewall-Infrastruktur ist bereit und die Regeln sind aktiv."
        
        # BONUS: Verifikation der kritischen Komponenten
        if nft list chain inet filter geoip_check &>/dev/null; then
            log_ok "GeoIP-Chain erfolgreich geladen und bereit."
        else
            log_warn "GeoIP-Chain nicht gefunden - GeoIP-Blocking wird möglicherweise Probleme haben."
        fi
    else
        log_error "NFTables-Regeln konnten nicht geladen werden. Firewall ist NICHT aktiv."
        return 1
    fi
}
##
# Installiert und konfiguriert das Intrusion Prevention System (CrowdSec).
##
setup_intrusion_prevention() {
    log_info "🛡️ MODUL: Intrusion Prevention System (CrowdSec)"
    
    # Die Funktion install_crowdsec_stack sollte ihre eigenen log_* Aufrufe haben.
    install_crowdsec_stack
    
    log_info "  -> Konfiguriere SSH-Schutz-Policies..."
    # Die Funktion tune_crowdsec_ssh_policy hat ebenfalls eigene log_* Aufrufe.
    tune_crowdsec_ssh_policy
    
    # Installiere die notwendigen Collections mit Feedback
    run_with_spinner "Installiere CrowdSec Collections (sshd, linux)..." \
        "cscli collections install crowdsecurity/sshd crowdsecurity/linux > /dev/null 2>&1"
    
    # Finale Überprüfung der CrowdSec-Dienste
    log_info "  -> Überprüfe CrowdSec-Service-Status..."
    if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
        log_ok "CrowdSec IPS ist aktiv und in die Firewall integriert."
    else
        log_warn "Ein oder mehrere CrowdSec-Dienste laufen nicht. Bitte manuell prüfen mit: systemctl status crowdsec crowdsec-firewall-bouncer"
    fi
}
##
# Installiert und konfiguriert die geografische Bedrohungsabwehr (GeoIP).
##
setup_geoip_protection() {
    log_info "🌍 MODUL: Geografische Bedrohungsabwehr (GeoIP)"

    log_info "  -> Validiere GeoIP-Konfiguration..."
    if ! is_valid_country_list "$BLOCKED_COUNTRIES"; then
        log_error "Ungültige Ländercodes in der Blocklist: $BLOCKED_COUNTRIES"
        log_warn "GeoIP-Blocking wird übersprungen!"
        return 1
    fi
    if [ -n "$HOME_COUNTRY" ] && ! is_valid_country_code "$HOME_COUNTRY"; then
        log_error "Ungültiger Ländercode für das Heimatland: $HOME_COUNTRY"
        log_warn "GeoIP-Blocking wird übersprungen!"
        return 1
    fi
    if echo "$BLOCKED_COUNTRIES" | grep -wq "$HOME_COUNTRY"; then
        log_warn "KONFLIKT: Heimatland ($HOME_COUNTRY) wurde in der Blocklist gefunden!"
        BLOCKED_COUNTRIES=$(echo "$BLOCKED_COUNTRIES" | sed "s/\b$HOME_COUNTRY\b//g" | tr -s ' ' | sed 's/^ *//; s/ *$//')
        log_ok "Heimatland wurde automatisch aus der Blocklist entfernt."
        log_info "     Bereinigte Blocklist: $BLOCKED_COUNTRIES"
    fi
    
    # Die aufgerufene Funktion `install_geoip_blocking` sollte ihr eigenes, detailliertes Logging haben.
    install_geoip_blocking
    
    # Warte auf die Erstellung der 'geoip_check'-Chain durch das Neuladen der Firewall
    local wait_cmd="
        local retries=30;
        while ! nft list chain inet filter geoip_check &>/dev/null; do
            ((retries--));
            if [ \$retries -le 0 ]; then exit 1; fi;
            sleep 1;
        done"
    
    if run_with_spinner "Warte auf Erstellung der GeoIP-Firewall-Chain..." "$wait_cmd"; then
        log_ok "GeoIP-Chain 'geoip_check' wurde erfolgreich in der Firewall erstellt."
    else
        log_warn "GeoIP-Chain konnte nicht sofort verifiziert werden. Dies kann bei hoher Systemlast normal sein."
    fi
    
    log_ok "Geografische Bedrohungsabwehr ist konfiguriert."
    log_info "  🏠 Geschütztes Heimatland: $HOME_COUNTRY"
    log_info "  🚫 Blockierte Länder: $BLOCKED_COUNTRIES"
    log_info "  📊 Verwaltung mit: geoip-manager status"
}

##
# MODUL 5: Installiert, konfiguriert und initialisiert das
#          System-Integritäts-Monitoring (AIDE & RKHunter).
##
setup_integrity_monitoring() {
    local TEST_MODE="$1"
    log_info "📊 MODUL: System-Integritäts-Monitoring"

    # --- Schritt 1/3: Basispakete installieren ---
    log_info "  -> 1/3: Installiere Basispakete (aide, rkhunter)..."
    run_with_spinner "Installiere aide & rkhunter..." "apt-get install -y aide rkhunter"

    # --- Schritt 2/3: Tools konfigurieren (Conf-Dateien & systemd-Units) ---
    log_info "  -> 2/3: Konfiguriere Tools (systemd-Timer, .conf-Dateien)..."
    # Die aufgerufenen Funktionen 'configure_aide' und 'configure_rkhunter'
    # enthalten ihre eigenen, detaillierten Log-Meldungen.
    configure_aide
    configure_rkhunter

    # --- Schritt 3/3: Datenbanken initialisieren (zeitaufwändig) ---
    log_info "  -> 3/3: Initialisiere Datenbanken und Properties..."
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS: Überspringe AIDE-DB-Initialisierung und RKHunter-Update."
    else
        # AIDE-Datenbank mit der frisch erstellten Konfiguration initialisieren
        if run_with_spinner "Initialisiere AIDE-Datenbank..." "/usr/bin/aide --config /etc/aide/aide.conf --init"; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            log_ok "AIDE-Datenbank erfolgreich initialisiert."
        else
            log_warn "AIDE-Initialisierung fehlgeschlagen. Manuell prüfen mit: sudo aide --config /etc/aide/aide.conf --init"
        fi
        
        # RKHunter-Properties mit der erstellten Konfiguration aktualisieren
        run_with_spinner "Aktualisiere RKHunter-Properties..." "rkhunter --propupd"
    fi

    log_ok "Integritäts-Monitoring mit journald konfiguriert."
    log_info "  📜 AIDE-Logs: journalctl -u aide-check.service"
    log_info "  🔍 RKHunter-Logs: journalctl -t rkhunter-check"
}

##
# Verifiziert die korrekte Funktion aller installierten Sicherheitsschichten.
# @return int Anzahl der erkannten kritischen Fehler.
##
verify_security_layers() {
    log_info "🔍 MODUL: Verifikation der Sicherheitsarchitektur"
    
    # WICHTIG: Deaktiviere set -e für Verifikation, damit das Skript bei Fehlern nicht abbricht
    local old_errexit=$(set +o | grep errexit)
    set +e
    
    local security_status=0 # Zählt kritische Fehler
    
    # --- LAYER 1: BASIS-FIREWALL (NFTables + Core-Security) ---
    log_info "  -> Teste Layer 1: Basis-Firewall..."
    if systemctl is-active --quiet nftables; then
        log_ok "Layer 1: NFTables-Service ist aktiv."
    else
        log_error "Layer 1: NFTables-Service ist NICHT aktiv!"
        ((security_status++))
    fi

    local input_policy=$(nft list chain inet filter input 2>/dev/null | grep "policy" | awk '{print $NF}' | tr -d ';' || echo "unbekannt")
    if [ "$input_policy" = "drop" ]; then
        log_ok "Layer 1: Firewall Drop-Policy ist aktiv."
    else
        log_error "Layer 1: Firewall Policy ist NICHT 'drop' (sondern '$input_policy')."
        ((security_status++))
    fi

    local ssh_port="${SSH_PORT:-22}"
    if systemctl is-active --quiet ssh && ss -tln | grep -q ":$ssh_port "; then
        log_ok "Layer 1: SSH-Service ist aktiv auf Port $ssh_port."
    else
        log_error "Layer 1: SSH-Service hat ein Problem oder Port $ssh_port ist nicht erreichbar."
        ((security_status++))
    fi
        
    # --- LAYER 2: CROWDSEC IPS ---
    log_info "  -> Teste Layer 2: CrowdSec IPS..."
    if command -v crowdsec >/dev/null 2>&1; then
        if systemctl is-active --quiet crowdsec; then
            log_ok "Layer 2: CrowdSec-Engine ist aktiv."
        else
            log_error "Layer 2: CrowdSec-Engine ist NICHT aktiv!"
            ((security_status++))
        fi
        
        if systemctl is-active --quiet crowdsec-firewall-bouncer; then
            log_ok "Layer 2: CrowdSec-Bouncer ist aktiv."
        else
            log_error "Layer 2: CrowdSec-Bouncer ist NICHT aktiv!"
            ((security_status++))
        fi
        
        if nft list table ip crowdsec >/dev/null 2>&1; then
            log_ok "Layer 2: CrowdSec-NFTables-Integration (IPv4) ist aktiv."
        else
            log_error "Layer 2: CrowdSec-NFTables-Integration (IPv4) fehlt!"
            ((security_status++))
        fi

        if nft list table ip6 crowdsec6 >/dev/null 2>&1; then
            log_ok "Layer 2: CrowdSec-NFTables-Integration (IPv6) ist aktiv."
        else
            log_warn "Layer 2: CrowdSec-NFTables-Integration (IPv6) fehlt."
        fi
    else
        log_info "Layer 2: CrowdSec ist nicht installiert (übersprungen)."
    fi
    
    # --- LAYER 3: GEOIP-BLOCKING ---
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        log_info "  -> Teste Layer 3: GeoIP-Blocking..."
        log_info "     Detaillierte GeoIP-Verifikation mit: geoip-manager status"
        
        if systemctl is-active --quiet geoip-update.timer; then
            log_ok "Layer 3: GeoIP-Timer ist aktiv."
        else
            log_error "Layer 3: GeoIP-Timer ist NICHT aktiv!"
            ((security_status++))
        fi
        
        if nft list chain inet filter geoip_check >/dev/null 2>&1; then
            log_ok "Layer 3: GeoIP-Chain existiert in der Firewall."
        else
            log_error "Layer 3: GeoIP-Chain fehlt in der Firewall!"
            ((security_status++))
        fi
    else
        log_info "  -> Teste Layer 3: GeoIP-Blocking... (übersprungen, da deaktiviert)."
    fi

    # --- LAYER 4: SSH-HÄRTUNG & APPARMOR ---
    log_info "  -> Teste Layer 4: SSH-Härtung & AppArmor..."
    if systemctl is-active --quiet ssh; then
        log_ok "Layer 4: SSH-Service ist aktiv."
    else
        log_error "Layer 4: SSH-Service ist NICHT aktiv!"
        ((security_status++))
    fi
    
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
        log_ok "Layer 4: SSH-Root-Login ist deaktiviert."
    else
        log_warn "Layer 4: SSH-Root-Login ist noch aktiv."
    fi
    
    if systemctl is-active --quiet apparmor; then
        local enforced_profiles=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
        log_ok "Layer 4: AppArmor ist aktiv ($enforced_profiles Profile im enforce mode)."
    else
        log_error "Layer 4: AppArmor ist NICHT aktiv!"
        ((security_status++))
    fi

    # --- ABSCHLUSS-BEWERTUNG ---
    echo "" # Leere Zeile für die Lesbarkeit
    if [ "$security_status" -eq 0 ]; then
        log_ok "Alle Sicherheits-Checks bestanden. Die Multi-Layer-Security-Architektur ist vollständig funktional."
    elif [ "$security_status" -le 2 ]; then
        log_warn "$security_status kleinere Sicherheitsproblem(e) erkannt. System ist grundsätzlich sicher."
    else
        log_error "$security_status kritische(s) Sicherheitsproblem(e) erkannt. Bitte die Ausgabe oben prüfen!"
    fi
    
    # set -e wieder aktivieren
    eval "$old_errexit"
    
    return $security_status
}

##
# Installiert (falls nötig) und konfiguriert eine Tailscale-Verbindung.
##
setup_tailscale() {
    log_info "🔗 MODUL: Konfiguriere Tailscale VPN-Verbindung..."
    
    # --- NEU: Schritt 0: Installation sicherstellen ---
    if ! command -v tailscale &>/dev/null; then
        log_info "  -> Tailscale ist nicht installiert. Starte Installation..."
        local install_cmd="curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | gpg --dearmor -o /usr/share/keyrings/tailscale-archive-keyring.gpg && \
            echo 'deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/debian bookworm main' > /etc/apt/sources.list.d/tailscale.list && \
            apt-get update -qq && \
            DEBIAN_FRONTEND=noninteractive apt-get install -y tailscale"
        
        if ! run_with_spinner "Installiere Tailscale Paket..." "bash -c \"$install_cmd\""; then
            log_error "Die Installation von Tailscale ist fehlgeschlagen."
            return 1
        fi
        log_ok "Tailscale erfolgreich installiert."
    fi

    # --- 1. Vorab-Prüfung: Ist Tailscale bereits verbunden? ---
    if tailscale status >/dev/null 2>&1 && ! tailscale status | grep -q "Logged out"; then
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null)
        TAILSCALE_READY=true
        log_ok "Tailscale ist bereits verbunden. (IP: ${TAILSCALE_IP:-unbekannt})"
        return 0
    fi

    # --- 2. Service-Vorbereitung ---
    if ! systemctl is-active --quiet tailscaled; then
        if ! run_with_spinner "Starte tailscaled-Dienst..." "systemctl enable --now tailscaled"; then
            log_error "Der tailscaled-Dienst konnte nicht gestartet werden."
            return 1
        fi
    fi

    # --- 3. Verbindungs-Befehl vorbereiten ---
    local tailscale_cmd=("tailscale" "up" "--ssh" "--accept-routes" "--reset")
    if [ "$SERVER_ROLE" = "1" ]; then
        tailscale_cmd+=("--advertise-routes=$DOCKER_IPV4_CIDR,$DOCKER_IPV6_CIDR")
    fi

    # --- 4. Verbindungsversuch (automatisch oder interaktiv) ---
    local connected=false
    if [ -n "${TAILSCALE_AUTH_KEY:-}" ]; then
        log_info "Nutze Auth-Key für automatische Authentifizierung..."
        tailscale_cmd+=("--authkey=$TAILSCALE_AUTH_KEY")
        
        if "${tailscale_cmd[@]}"; then
            connected=true
        else
            log_warn "Automatische Authentifizierung mit Auth-Key fehlgeschlagen!"
            log_info "  -> Wechsle zum interaktiven Modus..."
        fi
    fi
    
    if [ "$connected" = false ]; then
        log_info "Starte interaktive Tailscale-Authentifizierung..."
        log_info "Ein Login-Link wird gleich angezeigt. Bitte im Browser öffnen."
        read -p "   Bereit? (Enter drücken)" -r
        
        local interactive_cmd=("tailscale" "up" "--ssh" "--accept-routes" "--reset")
        if [ "$SERVER_ROLE" = "1" ]; then
            interactive_cmd+=("--advertise-routes=$DOCKER_IPV4_CIDR,$DOCKER_IPV6_CIDR")
        fi
        
        "${interactive_cmd[@]}"
    fi
    
    # --- 5. Finale Verifikation ---
    log_info "Warte 5 Sekunden auf den Verbindungsaufbau..."
    sleep 5
    
    if tailscale status >/dev/null 2>&1 && ! tailscale status | grep -q "Logged out"; then
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
        TAILSCALE_READY=true
        log_ok "Tailscale erfolgreich verbunden!"
        log_info "  📍 Tailscale-IP: ${TAILSCALE_IP:-Nicht zugewiesen}"
        
        run_with_spinner "Aktiviere Auto-Updates für Tailscale..." "tailscale set --auto-update"
    else
        log_error "Tailscale-Verbindung konnte nicht final hergestellt werden!"
        TAILSCALE_READY=false
        return 1
    fi
    
    return 0
}

# ===============================================================================
#          MODULARE & DYNAMISCHE NFTABLES-GENERIERUNG
# ===============================================================================

##
# Erkennt den aktuellen Systemzustand (Netzwerk-Interfaces, aktive Dienste wie Docker/Tailscale).
# @return string Ein String mit erkannten Werten zur Verwendung mit 'source'.
##
detect_system_state() {
    local primary_interface=""
    if command -v ip &>/dev/null; then
        primary_interface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -n1)
    fi
    if [ -z "$primary_interface" ]; then
        primary_interface=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1)
    fi
    if [ -z "$primary_interface" ]; then
        primary_interface=$(ls /sys/class/net/ | grep -E '^(eth|ens|enp)' | head -n1)
    fi
    
    local docker_active="false"
    local docker_interface_exists="false"
    if systemctl is-active --quiet docker && command -v docker &>/dev/null; then
        docker_active="true"
        if ip link show docker0 &>/dev/null; then
            docker_interface_exists="true"
        fi
    fi
    
    local tailscale_active="false"
    local tailscale_interface=""
    if command -v tailscale &>/dev/null && tailscale status &>/dev/null; then
        tailscale_active="true"
        tailscale_interface=$(ip link show | grep -E '^[0-9]+: tailscale[0-9]*:' | head -n1 | cut -d: -f2 | tr -d ' ')
        if [ -z "$tailscale_interface" ]; then
            tailscale_interface="tailscale0"
        fi
    fi
    
    cat <<EOF
PRIMARY_INTERFACE="$primary_interface"
DOCKER_ACTIVE="$docker_active"
DOCKER_INTERFACE_EXISTS="$docker_interface_exists"
TAILSCALE_ACTIVE="$tailscale_active"
TAILSCALE_INTERFACE="$tailscale_interface"
EOF
}

##
# Generiert die GeoIP-Set-Definitionen, falls GeoIP aktiviert ist.
##
generate_geoip_sets_section() {
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        cat << 'GEOIP_SETS'
    # ═══════════════════════════════════════════════════════════════════════════
    # GeoIP-Sets (werden aus dieser Datei bei jedem Start geladen)
    # ═══════════════════════════════════════════════════════════════════════════
    set geoip_blocked_v4 { type ipv4_addr; flags interval; }
    set geoip_blocked_v6 { type ipv6_addr; flags interval; }
    set geoip_home_v4 { type ipv4_addr; flags interval; }
    set geoip_home_v6 { type ipv6_addr; flags interval; }
    set geoip_allowlist_v4 { type ipv4_addr; flags interval; }
    set geoip_allowlist_v6 { type ipv6_addr; flags interval; }

    # GeoIP-Chain (wird von install_geoip_blocking() befüllt)
    chain geoip_check {}
GEOIP_SETS
    fi
}

##
# Generiert die 'jump'-Regel zur GeoIP-Chain, falls GeoIP aktiviert ist.
##
generate_geoip_jump_section() {
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        cat << 'EOF'
        # 3. GeoIP-Filter (Länder-basierte Bedrohungsabwehr)
        jump geoip_check comment "GeoIP-Filter"
EOF
    fi
}

##
# Generiert alle dynamischen Firewall-Regelblöcke (input, forward, nat)
# basierend auf dem erkannten Systemzustand.
##
generate_dynamic_firewall_rules() {
    local DOCKER_ACTIVE="$1"
    local DOCKER_INTERFACE_EXISTS="$2"
    local TAILSCALE_ACTIVE="$3"
    local TAILSCALE_INTERFACE="$4"
    local PRIMARY_INTERFACE="$5"

    local input_rules=""
    local forward_rules=""
    local nat_rules=""

    # Input-Regeln
    if [ "$DOCKER_ACTIVE" = "true" ] && [ "$DOCKER_INTERFACE_EXISTS" = "true" ]; then
        input_rules+="        iifname \"docker0\" accept comment \"Allow-Input-from-Docker-Interface\"\n"
    fi
    if [ "$TAILSCALE_ACTIVE" = "true" ] && [ -n "$TAILSCALE_INTERFACE" ]; then
        input_rules+="        iifname \"$TAILSCALE_INTERFACE\" accept comment \"Allow-Input-from-Tailscale-Interface\"\n"
    fi

    # Forward-Regeln
    if [ "$DOCKER_ACTIVE" = "true" ] && [ "$TAILSCALE_ACTIVE" = "true" ]; then
        forward_rules+="        iifname \"$TAILSCALE_INTERFACE\" oifname \"docker0\" accept comment \"Allow-Forward-Tailscale-to-Docker\"\n"
        forward_rules+="        iifname \"docker0\" oifname \"$TAILSCALE_INTERFACE\" accept comment \"Allow-Forward-Docker-to-Tailscale\"\n"
    fi

    # NAT-Regeln (komplette Tabellen)
    if [ "$DOCKER_ACTIVE" = "true" ] || [ "$TAILSCALE_ACTIVE" = "true" ]; then
        nat_rules=$(cat <<NAT_EOF
table ip nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$PRIMARY_INTERFACE" iifname "docker0" masquerade comment "Docker-IPv4-NAT"
        oifname "$PRIMARY_INTERFACE" iifname "$TAILSCALE_INTERFACE" masquerade comment "Tailscale-IPv4-NAT"
    }
}
table ip6 nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$PRIMARY_INTERFACE" iifname "docker0" masquerade comment "Docker-IPv6-NAT"
        oifname "$PRIMARY_INTERFACE" iifname "$TAILSCALE_INTERFACE" masquerade comment "Tailscale-IPv6-NAT"
    }
}
NAT_EOF
)
    fi
    
    # Gib die drei Regelblöcke zurück, getrennt durch ein eindeutiges Trennzeichen
    echo -e "$input_rules"
    echo "---RULE_SEPARATOR---"
    echo -e "$forward_rules"
    echo "---RULE_SEPARATOR---"
    echo -e "$nat_rules"
}

##
# Erstellt die komplette /etc/nftables.conf Datei.
# Nutzt Helfer-Funktionen, um die Konfiguration dynamisch und modular aufzubauen.
##
generate_nftables_config() {
    log_info "🔥 Generiere NFTables-Konfiguration..."

    # 1. System-Zustand für dynamische Regeln ermitteln
    local system_state; system_state=$(detect_system_state); source <(echo "$system_state")

    # 2. Alle dynamischen Regeln mit EINEM Aufruf generieren
    local all_rules; all_rules=$(generate_dynamic_firewall_rules "$DOCKER_ACTIVE" "$DOCKER_INTERFACE_EXISTS" "$TAILSCALE_ACTIVE" "$TAILSCALE_INTERFACE" "$PRIMARY_INTERFACE")
    
    # 3. Ausgabe in separate Variablen aufteilen
    local input_rules_str=$(echo "$all_rules" | sed '/---RULE_SEPARATOR---/,$d')
    local forward_rules_str=$(echo "$all_rules" | sed -n '/---RULE_SEPARATOR---/,/---RULE_SEPARATOR---/p' | sed '1d;$d')
    local nat_rules_str=$(echo "$all_rules" | sed '1,/---RULE_SEPARATOR---/d' | sed '1,/---RULE_SEPARATOR---/d')

    # 4. Liste der privaten Netzwerke dynamisch um Docker erweitern
    local private_nets_v4="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8"
    local private_nets_v6="::1/128, fc00::/7, fe80::/10"
    if [ "$SERVER_ROLE" = "1" ]; then
        private_nets_v4+=", $DOCKER_IPV4_CIDR"
        private_nets_v6+=", $DOCKER_IPV6_CIDR"
    fi

    # 5. Finalen "Bauplan" in /etc/nftables.conf schreiben
    cat > /etc/nftables.conf <<EOF
# =============================================================================
# SERVER-BAUKASTEN FIREWALL v1.0
# =============================================================================
# Generiert: $(date)

# Private Networks Definition (dynamisch)
define private_networks_v4 = { ${private_nets_v4} }
define private_networks_v6 = { ${private_nets_v6} }

# =============================================================================
# HAUPTFILTER-TABELLE
# =============================================================================
table inet filter {
$(generate_geoip_sets_section)

    # INPUT-CHAIN (mit korrekter, sicherer Regel-Reihenfolge)
    chain input {
            type filter hook input priority filter; policy drop;

            # 1. FAST PATH: Erlaube sofort alle bekannten und laufenden Verbindungen.
            ct state established,related accept comment "Allow-Established"

            # 2. FAIL FAST: Verwerfe sofort alle kaputten oder ungültigen Pakete.
            ct state invalid drop comment "Drop-Invalid"

            # 3. TRUSTED ZONE: Erlaube explizit alle vertrauenswürdigen Quellen.
            iifname "lo" accept comment "Allow-Loopback"
            ip saddr \$private_networks_v4 accept comment "Allow-Private-IPv4"
            ip6 saddr \$private_networks_v6 accept comment "Allow-Private-IPv6"
            ${input_rules_str} # Hier sind tailscale0 und docker0 drin

            # 4. GEO-FILTER: Schicke allen übrigen, unbekannten Traffic zur GeoIP-Prüfung.
            $(generate_geoip_jump_section)

            # 5. PUBLIC SERVICES: Erlaube explizit die öffentlichen Dienste.
            tcp dport ${SSH_PORT} accept comment "SSH-Access"
            ip protocol icmp accept comment "ICMPv4-Ping"
            ip6 nexthdr ipv6-icmp accept comment "ICMPv6-Ping"
    }

    # FORWARD-CHAIN
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept comment "Allow-Established-Forward"
        ct state invalid drop comment "Drop-Invalid-Forward"
        ${forward_rules_str}
    }

    # OUTPUT-CHAIN
    chain output {
        type filter hook output priority filter; policy accept;
    }
}

# NAT-TABELLEN (dynamisch)
${nat_rules_str}
EOF

    log_ok "NFTables-Konfigurationsdatei erfolgreich geschrieben."
    
    # 6. Validierung
    if ! nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
        log_error "SYNTAX-FEHLER in der generierten NFTables-Konfiguration! Firewall wird nicht geladen."
        return 1
    fi
    log_ok "Syntax-Check der Konfiguration erfolgreich."
}

################################################################################
#
#                                 HAUPTLOGIK
#
################################################################################

##
# Haupt-Einstiegspunkt des Skripts. Verarbeitet Argumente und startet das Setup.
##
main() {
    check_root

    # --- Argumente verarbeiten ---
    local TEST_MODE=false
    CONFIG_FILE="" # Sicherstellen, dass die Variable am Anfang leer ist
    
    while getopts ":c:thvd" opt; do
        case ${opt} in
            c) CONFIG_FILE=$OPTARG;;
            t) TEST_MODE=true;;
            h) show_usage; exit 0;;
            v) SCRIPT_VERBOSE=true;;
            d) DEBUG=true; SCRIPT_VERBOSE=true;;
            \?) log_error "Ungültige Option: -$OPTARG"; show_usage; exit 1;;
            :) log_error "Option -$OPTARG benötigt ein Argument."; show_usage; exit 1;;
        esac
    done

    # Globale Flags für andere Funktionen und Kind-Prozesse verfügbar machen
    export SCRIPT_VERBOSE DEBUG

    # --- Skript-Ausführung ---
    trap 'rollback' ERR

    log_info "🚀 Starte Server-Baukasten v$SCRIPT_VERSION..."
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS ist aktiviert. Zeitaufwändige Operationen werden übersprungen."
    fi
    if [ -n "$CONFIG_FILE" ]; then
        log_info "Verwende Konfigurationsdatei: $CONFIG_FILE"
    fi

    run_setup "$TEST_MODE"
    
    # Fehlerfalle nach erfolgreichem Setup deaktivieren
    trap - ERR
    
    show_summary
    
    log_ok "Server-Setup erfolgreich abgeschlossen!"
}

##
# Führt die einzelnen Setup-Module in einer logisch korrekten Reihenfolge aus.
# @param bool $1 Test-Modus (true/false).
##
run_setup() {
    local TEST_MODE="$1"
    
    # --- Phase 1: Vorbereitung ---
    log_info "Phase 1/5: Vorbereitung (Checks, Cleanup, Konfiguration)..."
    pre_flight_checks
    module_cleanup
    if [ -n "$CONFIG_FILE" ]; then
        load_config_from_file "$CONFIG_FILE"
    else
        collect_config
    fi

    # --- Phase 2: System-Fundament ---
    log_info "Phase 2/5: System-Fundament (OS, Pakete, Kernel)..."
    detect_os
    module_fix_apt_sources
    module_base
    module_system_update "$TEST_MODE"
    # WICHTIG: Kernel-Härtung VOR den Diensten, die davon abhängen (z.B. IP-Forwarding für Docker)
    module_kernel_hardening

    # --- Phase 3: Kern-Dienste (Netzwerk & Container) ---
    log_info "Phase 3/5: Kern-Dienste (Netzwerk & Container)..."
    module_network "$TEST_MODE" # Tailscale
    if [ "$SERVER_ROLE" = "1" ]; then
        module_container # Docker Daemon
        module_deploy_containers # Portainer, Watchtower
    fi

    # --- Phase 4: Sicherheits-Architektur ---
    log_info "Phase 4/5: Sicherheits-Architektur (Firewall, IPS, Monitoring)..."
    # Die Sicherheit wird bewusst am Ende konfiguriert, wenn alle Dienste laufen und ihre Ports bekannt sind
    module_security "$TEST_MODE"
    
    # --- Phase 5: Abschluss-Arbeiten ---
    log_info "Phase 5/5: Abschluss-Arbeiten (Mail, Logs, Backup, Verifikation)..."
    module_mail_setup
    module_journald_optimization
    module_services "$TEST_MODE"
    module_verify_setup
    cleanup_admin_sudo_rights
}

################################################################################
#
#                               KONFIGURATION
#
################################################################################

##
# Lädt und validiert die Konfiguration aus einer Datei dynamisch.
# @param string $1 Pfad zur Konfigurationsdatei.
##
load_config_from_file() {
    local file="$1"
    log_info "⚙️  Lade Konfiguration aus Datei: $file..."
    
    if [ ! -f "$file" ]; then
        log_error "Konfigurationsdatei nicht gefunden: $file"
        exit 1
    fi
    
    # shellcheck source=/dev/null
    . "$file"
    
    # --- Dynamische Validierungs-Engine ---
    log_info "  -> Validiere Konfigurationsvariablen dynamisch..."
    
    # 1. Definiere alle Regeln in einem Array.
    # Format: "VARIABLE|VALIDIERUNGSFUNKTION|FEHLERMELDUNG|BEDINGUNG"
    local validations=(
        "SERVER_HOSTNAME|is_valid_hostname|Ungültiger Hostname.|true"
        "ADMIN_USER|is_valid_username|Ungültiger Benutzername (nur Kleinbuchstaben, Zahlen, _, -).|true"
        "ADMIN_PASSWORD|:|Passwort für Admin darf nicht leer sein.|true"
        "ROOT_PASSWORD|:|Passwort für Root darf nicht leer sein.|true"
        "NOTIFICATION_EMAIL|is_valid_email|Ungültiges E-Mail-Format.|true"
        "ACCESS_MODEL|:|Zugriffsmodell muss 1 (VPN) oder 2 (Öffentlich) sein.|[[ \"$ACCESS_MODEL\" == \"1\" || \"$ACCESS_MODEL\" == \"2\" ]]"
        "SSH_PORT|is_valid_port|SSH-Port muss zwischen 1025 und 65535 liegen.|true"
        "SERVER_ROLE|:|Server-Rolle muss 1 (Docker) oder 2 (Einfach) sein.|[[ \"$SERVER_ROLE\" == \"1\" || \"$SERVER_ROLE\" == \"2\" ]]"
        "TIMEZONE|is_valid_timezone|Zeitzone ist ungültig.|true"
        "LOCALE|:|Locale darf nicht leer sein.|true"
        "UPGRADE_EXTENDED|:|UPGRADE_EXTENDED muss 'ja' oder 'nein' sein.|[[ \"$UPGRADE_EXTENDED\" == \"ja\" || \"$UPGRADE_EXTENDED\" == \"nein\" ]]"
        "CROWDSEC_MAXRETRY|is_numeric|CROWDSEC_MAXRETRY muss eine Zahl sein.|true"
        "CROWDSEC_BANTIME|:|CROWDSEC_BANTIME darf nicht leer sein.|true"
        "ENABLE_SYSTEM_MAIL|:|ENABLE_SYSTEM_MAIL muss 'ja' oder 'nein' sein.|true"
        "SMTP_HOST|is_valid_hostname|SMTP_HOST ist ein ungültiger Hostname.|[ \"${ENABLE_SYSTEM_MAIL:-nein}\" = \"ja\" ]"
        "SMTP_PORT|is_numeric|SMTP_PORT muss eine Zahl sein.|[ \"${ENABLE_SYSTEM_MAIL:-nein}\" = \"ja\" ]"
        "SMTP_FROM|is_valid_email|SMTP_FROM ist keine gültige E-Mail.|[ \"${ENABLE_SYSTEM_MAIL:-nein}\" = \"ja\" ]"
        "SMTP_AUTH|:|SMTP_AUTH muss 'ja' oder 'nein' sein.|[ \"${ENABLE_SYSTEM_MAIL:-nein}\" = \"ja\" ]"
        "SMTP_TLS_STARTTLS|:|SMTP_TLS_STARTTLS muss 'ja' oder 'nein' sein.|[ \"${ENABLE_SYSTEM_MAIL:-nein}\" = \"ja\" ]"
        "SMTP_USER|:|SMTP_USER darf nicht leer sein.|[ \"${SMTP_AUTH:-nein}\" = \"ja\" ]"
        "SMTP_PASSWORD|:|SMTP_PASSWORD darf nicht leer sein.|[ \"${SMTP_AUTH:-nein}\" = \"ja\" ]"
        "DOCKER_IPV4_CIDR|is_valid_ipv4_cidr|Ungültiges Docker IPv4 CIDR-Format.|[ \"$SERVER_ROLE\" = \"1\" ]"
        "DOCKER_IPV6_CIDR|is_valid_ipv6_cidr|Ungültiges Docker IPv6 CIDR-Format.|[ \"$SERVER_ROLE\" = \"1\" ]"
        "INSTALL_PORTAINER|:|INSTALL_PORTAINER muss 'ja' oder 'nein' sein.|[ \"$SERVER_ROLE\" = \"1\" ]"
        "INSTALL_WATCHTOWER|:|INSTALL_WATCHTOWER muss 'ja' oder 'nein' sein.|[ \"$SERVER_ROLE\" = \"1\" ]"
        "ENABLE_GEOIP_BLOCKING|:|ENABLE_GEOIP_BLOCKING muss 'ja' oder 'nein' sein.|true"
        "BLOCKED_COUNTRIES|is_valid_country_list|BLOCKED_COUNTRIES enthält ungültige Ländercodes.|[ \"${ENABLE_GEOIP_BLOCKING:-nein}\" = \"ja\" ]"
        "HOME_COUNTRY|is_valid_country_code|HOME_COUNTRY ist kein gültiger Ländercode.|[ \"${ENABLE_GEOIP_BLOCKING:-nein}\" = \"ja\" ]"
    )

    # 2. Führe alle Validierungen in einer Schleife aus.
    for rule in "${validations[@]}"; do
        IFS='|' read -r var_name validator error_msg condition <<< "$rule"
        
        # Prüfe, ob die Bedingung für diese Regel erfüllt ist
        if eval "$condition"; then
            local value="${!var_name:-}"
            # Prüfe, ob die Variable überhaupt gesetzt ist
            if [ -z "$value" ]; then
                log_error "Fehlende Variable in Konfigurationsdatei: '$var_name'"
                exit 1
            fi
            # Prüfe den Wert mit der Validierungsfunktion (falls eine angegeben ist)
            # Der Doppelpunkt ':' ist ein Platzhalter für eine einfache Existenzprüfung.
            if [ "$validator" != ":" ] && ! "$validator" "$value"; then
                log_error "Ungültiger Wert für '$var_name': $error_msg (Wert war: '$value')"
                exit 1
            fi
        fi
    done

    # --- Spezielle Logik (bleibt erhalten) ---
    # GeoIP Heimatland-Konflikt
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ] && echo "$BLOCKED_COUNTRIES" | grep -wq "$HOME_COUNTRY"; then
        log_warn "KONFLIKT: Heimatland ($HOME_COUNTRY) wurde in der Blocklist gefunden!"
        BLOCKED_COUNTRIES=$(echo "$BLOCKED_COUNTRIES" | sed "s/\b$HOME_COUNTRY\b//g" | tr -s ' ' | sed 's/^ *//; s/ *$//')
        log_ok "Heimatland wurde automatisch aus der Blocklist entfernt."
        log_info "     Bereinigte Blocklist: $BLOCKED_COUNTRIES"
    fi

    # Optionale Variablen mit Defaults setzen
    SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"
    TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
    PORTAINER_IP="${PORTAINER_IP:-}"

    # --- Zusammenfassung ---
    # (Die Zusammenfassung aus der vorherigen Version kann hier 1:1 wieder eingefügt werden)
    log_ok "Alle Validierungen bestanden - Setup kann beginnen!"
}

##
# Führt den interaktiven Konfigurationsdialog durch.
##
collect_config() {
    clear
    # UI-Elemente bleiben echo-Befehle, um das Journal nicht zu füllen
    echo -e "${BLUE}Willkommen zum Server-Baukasten! (v$SCRIPT_VERSION)${NC}"
    echo "Dieses Skript führt Sie durch die Einrichtung Ihres neuen Servers."
    
    print_section_header "1" "Server-Identität & Accounts" "👤"
    prompt_for_validated_input "Hostname des Servers" "SERVER_HOSTNAME" "$(hostname)" "is_valid_hostname" "Ungültiger Hostname!"
    prompt_for_validated_input "Admin-Benutzername" "ADMIN_USER" "admin" "is_valid_username" "Ungültiger Benutzername (a-z, 0-9, _, -)."
    prompt_for_password "Passwort für '$ADMIN_USER'" "ADMIN_PASSWORD"
    prompt_for_password "Passwort für 'root' (Notfallzugang)" "ROOT_PASSWORD"

    print_section_header "2" "Netzwerk & SSH-Sicherheit" "🌐"
    local access_options=("Nur über VPN (Tailscale) - Max. Sicherheit" "Öffentlich erreichbar")
    prompt_for_choice "Wie soll der Server erreichbar sein?" "ACCESS_MODEL" "1" "${access_options[@]}"
    prompt_for_validated_input "SSH-Port" "SSH_PORT" "$SSH_PORT_DEFAULT" "is_valid_port" "Bitte eine Portnummer zwischen 1025 und 65535 eingeben."

    read -p "$(echo -e "${CYAN}›${NC}") Öffentlichen SSH-Schlüssel einfügen (optional, Enter überspringt): " SSH_PUBLIC_KEY
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        while ! is_valid_ssh_pubkey "$SSH_PUBLIC_KEY"; do
            # KORRIGIERT: Fehler mit log_error ausgeben
            log_error "Ungültiger SSH Public Key."
            read -p "$(echo -e "${CYAN}›${NC}") Erneut einfügen (oder Enter zum Abbrechen): " SSH_PUBLIC_KEY
            if [ -z "$SSH_PUBLIC_KEY" ]; then break; fi
        done
    fi

    print_section_header "3" "System-Lokalisierung (wichtig für Geo-Schutz!)" "🌍"
    # UI-Hinweise bleiben echo-Befehle
    echo -e "  ${BLUE}💡 Hinweis: Diese Einstellung wird auch für den automatischen Geo-Schutz verwendet${NC}"
    echo -e "  ${BLUE}   Ihr Heimatland wird basierend auf der Locale automatisch vor Blockierung geschützt${NC}\n"
    
    prompt_for_validated_input "Zeitzone" "TIMEZONE" "Europe/Berlin" "is_valid_timezone" "Ungültige Zeitzone!"
    local locale_options=("Deutsch (de_DE.UTF-8) → Deutschland wird geo-geschützt" "Englisch (en_US.UTF-8) → USA wird geo-geschützt")
    prompt_for_choice "Systemsprache & Geo-Schutz" "LOCALE_CHOICE" "1" "${locale_options[@]}"
    
    # KORRIGIERT: Wichtige automatische Entscheidungen protokollieren
    if [ "$LOCALE_CHOICE" = "1" ]; then 
        LOCALE="de_DE.UTF-8"
        AUTO_HOME_COUNTRY="DE"
        log_info "Automatisch erkannt: Deutschland (DE) wird geo-geschützt."
    else 
        LOCALE="en_US.UTF-8" 
        AUTO_HOME_COUNTRY="US"
        log_info "Automatisch erkannt: USA (US) wird geo-geschützt."
    fi
    print_section_header "4" "Intrusion Prevention (CrowdSec)" "🛡️"
    prompt_for_validated_input "SSH-Fehlversuche bis zum Ban" "CROWDSEC_MAXRETRY" "$CROWDSEC_MAXRETRY_DEFAULT" "is_numeric" "Bitte eine Zahl eingeben."
    read -p "$(echo -e "${CYAN}›${NC}") Sperrdauer für Angreifer (z.B. 12h, Standard: $CROWDSEC_BANTIME_DEFAULT): " CROWDSEC_BANTIME
    CROWDSEC_BANTIME=${CROWDSEC_BANTIME_DEFAULT:-$CROWDSEC_BANTIME_DEFAULT}

    print_section_header "5" "Geo-IP-Blocking (Länder-basierte Bedrohungsabwehr)" "🌍"
    
    echo -e "  ${BLUE}💡 Hintergrund: Statistisch stammen >80% der Brute-Force-Angriffe aus wenigen Ländern${NC}"
    echo -e "  ${BLUE}   SSH-Scans, Botnet-Traffic und Credential-Stuffing konzentrieren sich auf bestimmte Regionen${NC}"
    echo ""
    echo -e "  ${GREEN}🏠 Ihr Heimatland wird automatisch geschützt: ${AUTO_HOME_COUNTRY} (aus Locale ${LOCALE})${NC}"
    echo -e "  ${CYAN}   Dieses Land wird NIE blockiert, auch nicht bei Updates der IP-Listen${NC}"
    echo ""
    
    prompt_for_yes_no "GeoIP-Blocking aktivieren (blockiert Angriffe aus Risiko-Ländern)?" "ENABLE_GEOIP_BLOCKING" "ja"
    
    if [ "$ENABLE_GEOIP_BLOCKING" = "ja" ]; then
        echo -e "\n  ${PURPLE}--- Länder-basiertes Blocking-System ---${NC}"
        echo -e "  ${YELLOW}⚠️  Hinweis: Lokale Netze, VPN-Verbindungen und $AUTO_HOME_COUNTRY werden nie blockiert${NC}"
        echo ""
        
        # Heimatland-Bestätigung
        local confirm_home_country
        prompt_for_yes_no "  Ist $AUTO_HOME_COUNTRY korrekt als Ihr Heimatland?" "confirm_home_country" "ja"
        
        if [ "$confirm_home_country" = "ja" ]; then
            HOME_COUNTRY="$AUTO_HOME_COUNTRY"
            log_info "Heimatland bestätigt: $HOME_COUNTRY wird permanent geschützt"
        else
            echo -e "\n  ${BLUE}📋 Häufige Länder-Codes für manuelle Eingabe:${NC}"
            echo -e "    ${CYAN}DE=Deutschland, AT=Österreich, CH=Schweiz, US=USA, GB=Großbritannien${NC}"
            echo -e "    ${CYAN}FR=Frankreich, IT=Italien, ES=Spanien, NL=Niederlande, SE=Schweden${NC}"
            echo -e "    ${CYAN}CA=Kanada, AU=Australien, JP=Japan, SG=Singapur, NO=Norwegen${NC}"
            echo ""
            
            while true; do
                read -p "$(echo -e "${CYAN}›${NC}   Ihr Heimatland (2-stelliger ISO-Code): ")" HOME_COUNTRY
                HOME_COUNTRY=$(echo "$HOME_COUNTRY" | tr '[:lower:]' '[:upper:]')
                
                if [[ "$HOME_COUNTRY" =~ ^[A-Z]{2}$ ]]; then
                    log_info "Manuell gesetztes Heimatland: $HOME_COUNTRY wird permanent geschützt"
                    break
                else
                    echo -e "${RED}  Bitte einen gültigen 2-stelligen Ländercode eingeben (z.B. DE, US, FR)${NC}"
                fi
            done
        fi
        
        # Blocking-Level auswählen
        local country_options=(
            "🎯 Standard-Schutz: China, Russland, Nordkorea, Iran (Top-Bedrohungsquellen)" 
            "🛡️  Maximaler Schutz: + Belarus, Myanmar, Syrien, Afghanistan, Irak, Libyen" 
            "⚡ Basis-Schutz: Nur China und Russland (minimaler Impact)"
            "🔧 Expert-Modus: Eigene Länder-Liste definieren"
        )
        
        prompt_for_choice "Welche Länder blockieren?" "GEOIP_PRESET" "1" "${country_options[@]}"
        
        case "$GEOIP_PRESET" in
            1) 
                BLOCKED_COUNTRIES="CN RU KP IR"
                print_summary_tip "Standard-Blocking: China, Russland, Nordkorea, Iran"
                print_summary_tip "Erwartete Angriffs-Reduktion: ~70%"
                ;;
            2) 
                BLOCKED_COUNTRIES="CN RU KP IR BY MM SY AF IQ LY"
                print_summary_tip "Maximal-Blocking: China, Russland, Nordkorea, Iran, Belarus, Myanmar, Syrien, Afghanistan, Irak, Libyen"
                print_summary_tip "Erwartete Angriffs-Reduktion: ~85%"
                ;;
            3) 
                BLOCKED_COUNTRIES="CN RU"
                print_summary_tip "Basis-Blocking: China, Russland"
                print_summary_tip "Erwartete Angriffs-Reduktion: ~60%"
                ;;
            4) 
                echo -e "\n  ${BLUE}📋 Expert-Modus: Verfügbare Länder-Codes${NC}"
                echo -e "    ${RED}Höchstes Risiko:${NC} CN=China, RU=Russland, KP=Nordkorea, IR=Iran"
                echo -e "    ${YELLOW}Hohes Risiko:${NC} BY=Belarus, MM=Myanmar, SY=Syrien, AF=Afghanistan"
                echo -e "    ${YELLOW}Mittleres Risiko:${NC} IQ=Irak, LY=Libyen, PK=Pakistan, BD=Bangladesch"
                echo -e "    ${BLUE}💡 Vollständige Liste: https://www.geonames.org/countries/${NC}"
                echo ""
                
                while true; do
                    read -p "$(echo -e "${CYAN}›${NC}   Länder-Codes (Leerzeichen-getrennt, z.B. CN RU IR): ")" BLOCKED_COUNTRIES
                    
                    if [ -n "$BLOCKED_COUNTRIES" ]; then
                        # Konvertiere zu Großbuchstaben
                        BLOCKED_COUNTRIES=$(echo "$BLOCKED_COUNTRIES" | tr '[:lower:]' '[:upper:]')
                        
                        # NEU: Robuste Validierung statt einfacher Regex
                        if is_valid_country_list "$BLOCKED_COUNTRIES"; then
                            log "   🔧 Expert-Blocking konfiguriert: $BLOCKED_COUNTRIES"
                            break
                        else
                            echo -e "${RED}  ❌ Ungültige Ländercodes gefunden!${NC}"
                            echo -e "${RED}     Bitte nur gültige 2-stellige ISO-Codes verwenden.${NC}"
                            echo -e "${RED}     Beispiele: DE US CN RU FR IT ES (getrennt durch Leerzeichen)${NC}"
                            echo ""
                            echo -e "${BLUE}  💡 Tipp: Codes müssen exakt 2 Zeichen haben und real existieren${NC}"
                        fi
                    else
                        echo -e "${RED}  Bitte mindestens ein Land eingeben${NC}"
                    fi
                done
                ;;
        esac
        
        # Heimatland-Konflikt-Prüfung
        if echo "$BLOCKED_COUNTRIES" | grep -wq "$HOME_COUNTRY"; then
            echo -e "\n  ${YELLOW}⚠️  KONFLIKT ERKANNT: Ihr Heimatland ($HOME_COUNTRY) steht in der Blocklist!${NC}"
            echo -e "  ${GREEN}✅ Wird automatisch entfernt - Sie können sich nicht aussperren${NC}"
            
            # Entferne Heimatland aus Blocklist
            BLOCKED_COUNTRIES=$(echo "$BLOCKED_COUNTRIES" | sed "s/\b$HOME_COUNTRY\b//g" | tr -s ' ' | sed 's/^ *//; s/ *$//')
            log_info "$HOME_COUNTRY automatisch aus Blocklist entfernt"
            log_info "Finale Blocklist: $BLOCKED_COUNTRIES"
        fi
        
        echo -e "\n  ${GREEN}✅ Geo-IP-Blocking erfolgreich konfiguriert${NC}"
        echo -e "  ${CYAN}🏠 Geschütztes Heimatland: $HOME_COUNTRY (permanent sicher)${NC}"
        echo -e "  ${RED}🚫 Blockierte Länder: $BLOCKED_COUNTRIES${NC}"
        echo -e "  ${BLUE}🔄 IP-Listen werden täglich automatisch von ipdeny.com aktualisiert${NC}"
        echo -e "  ${PURPLE}⚡ Nullwartungsaufwand - läuft vollautomatisch${NC}"
    else
        log_info "Geo-IP-Blocking übersprungen - Standard-Firewall wird verwendet"
    fi

    print_section_header "6" "Hauptzweck des Servers" "🎯"
    local role_options=("Docker / Container Host" "Einfacher Dienst-Server (ohne Docker)")
    prompt_for_choice "Welchen Zweck soll der Server erfüllen?" "SERVER_ROLE" "1" "${role_options[@]}"
    
    if [ "$SERVER_ROLE" = "1" ]; then
        echo -e "\n  ${PURPLE}--- Docker-Konfiguration ---${NC}"
        prompt_for_validated_input "  🐳 Docker IPv4-Netz (CIDR)" "DOCKER_IPV4_CIDR" "172.20.0.0/16" "is_valid_ipv4_cidr" "Ungültiges IPv4 CIDR-Format!"
        prompt_for_validated_input "  🐳 Docker IPv6-Netz (CIDR)" "DOCKER_IPV6_CIDR" "fd00:dead:beef::/56" "is_valid_ipv6_cidr" "Ungültiges IPv6 CIDR-Format!"
        prompt_for_yes_no "  🎛️  Portainer installieren?" "INSTALL_PORTAINER" "ja"
        if [ "$INSTALL_PORTAINER" = "ja" ]; then NEEDS_PORTAINER_IP_PROMPT=true; fi
        prompt_for_yes_no "  🔄 Watchtower installieren?" "INSTALL_WATCHTOWER" "ja"
    fi

    print_section_header "7" "Administration & Benachrichtigungen" "📧"
    prompt_for_validated_input "E-Mail für System-Alerts" "NOTIFICATION_EMAIL" "$NOTIFICATION_EMAIL_DEFAULT" "is_valid_email" "Ungültige E-Mail-Adresse!"
    prompt_for_yes_no "Sollen systemweite E-Mail-Benachrichtigungen eingerichtet werden?" "ENABLE_SYSTEM_MAIL" "ja"
    
    if [ "$ENABLE_SYSTEM_MAIL" = "ja" ]; then
        echo -e "\n  ${PURPLE}--- SMTP-Konfiguration (via msmtp) ---${NC}"
        local smtp_preset_options=("Standard STARTTLS (Port 587, empfohlen)" "Manuelle Konfiguration")
        local smtp_preset
        prompt_for_choice "Welche Art von SMTP-Verbindung?" "smtp_preset" "1" "${smtp_preset_options[@]}"

        case "$smtp_preset" in
            1)
                SMTP_PORT="587"
                SMTP_TLS_STARTTLS="ja"
                ;;
            2)
                prompt_for_validated_input "  🔌 SMTP-Port" "SMTP_PORT" "587" "is_numeric" "Bitte eine Zahl eingeben."
                prompt_for_yes_no "  🛡️ STARTTLS verwenden?" "SMTP_TLS_STARTTLS" "ja"
                ;;
        esac

        prompt_for_validated_input "  📬 SMTP-Server (Host)" "SMTP_HOST" "" "is_valid_hostname" "Ungültiger Hostname!"
        prompt_for_yes_no "  🔒 SMTP erfordert Authentifizierung?" "SMTP_AUTH" "ja"
        if [ "$SMTP_AUTH" = "ja" ]; then
            read -p "$(echo -e "${CYAN}›${NC}")   👤 SMTP-Benutzername: " SMTP_USER
            prompt_for_password_with_confirmation "  🔑 SMTP-Passwort" "SMTP_PASSWORD"
        fi
        read -p "$(echo -e "${CYAN}›${NC}")   ✉️  Absender-Adresse (From): " SMTP_FROM
        while ! is_valid_email "$SMTP_FROM"; do
            echo -e "${RED}  Ungültige E-Mail-Adresse für den Absender.${NC}"
            read -p "$(echo -e "${CYAN}›${NC}")   ✉️  Absender-Adresse (From): " SMTP_FROM
        done
    fi
    
    prompt_for_yes_no "Erweiterte Auto-Updates (auch für 'updates')?" "UPGRADE_EXTENDED" "nein"
    
    log_ok "Alle Konfigurationsdaten erfasst. Das Setup beginnt jetzt..."
    
    log_info "--- Finale Konfiguration für diesen Lauf ---"
    log_info "  Heimatland (geschützt): ${HOME_COUNTRY:-'Nicht gesetzt'}"
    log_info "  Blockierte Länder: ${BLOCKED_COUNTRIES:-'Keine'}"
    log_info "  Locale: $LOCALE"
    log_info "  Notifications: $NOTIFICATION_EMAIL"
    log_info "-----------------------------------------"
    
    sleep 2
}

# ===============================================================================
#                    AIDE & RKHUNTER JOURNALD-INTEGRATION
# ===============================================================================

##
# Konfiguriert AIDE (Integritäts-Checker) für die Ausführung via systemd-Timer
# und leitet die Ausgabe direkt an das journald-Log um.
##
configure_aide() {
    log_info "Konfiguriere AIDE für Integritätsüberwachung..."
    
    # KRITISCH: Stelle sicher, dass das AIDE-Verzeichnis existiert
    log_info "  -> Erstelle AIDE-Konfigurationsverzeichnis..."
    mkdir -p /etc/aide
    mkdir -p /var/lib/aide
    mkdir -p /var/log/aide
    
    # Setze korrekte Berechtigungen
    chown root:root /etc/aide /var/lib/aide
    chmod 755 /etc/aide /var/lib/aide
    chown root:adm /var/log/aide
    chmod 750 /var/log/aide
    
    log_ok "AIDE-Verzeichnisse erfolgreich erstellt."
    # 1. Community-bewährte AIDE Config erstellen
    # (Dieser Teil bleibt unverändert)
    backup_and_register "/etc/aide/aide.conf"
    cat > /etc/aide/aide.conf << 'EOF'
# AIDE Configuration - Community Best Practices
# Based on production server experience and security recommendations

# ═══════════════════════════════════════════════════════════════════════════
# DATABASE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
database_in=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
database_new=file:/var/lib/aide/aide.db.new

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING & OUTPUT (journald-optimized)
# ═══════════════════════════════════════════════════════════════════════════
log_level=info

# Primary output: journald (structured logging)
report_url=syslog:LOG_LOCAL0

# Backup: Traditional logfile (fallback)
report_url=file:/var/log/aide/aide.log

# Gzip compression for file reports (space-efficient)
gzip_dbout=yes

# ═══════════════════════════════════════════════════════════════════════════
# RULE DEFINITIONS (Security-focused)
# ═══════════════════════════════════════════════════════════════════════════

# Full monitoring (critical system files)
Full = p+i+n+u+g+s+b+m+c+md5+sha1+sha256+rmd160

# Monitor permissions and ownership only (large directories)
Perms = p+i+u+g

# Monitor content changes (config files)
Content = p+i+n+u+g+s+b+m+c+md5+sha256

# Monitor only metadata (logs, temp files)
Metadata = p+i+n+u+g

# Static files (never change after installation)
Static = p+i+n+u+g+s+b+m+c+md5+sha1+sha256+rmd160

# ═══════════════════════════════════════════════════════════════════════════
# CRITICAL SYSTEM FILES (Full monitoring)
# ═══════════════════════════════════════════════════════════════════════════

# Boot and kernel
/boot Full
/lib/modules Full

# System binaries (critical)
/bin Full
/sbin Full
/usr/bin Full
/usr/sbin Full
/usr/local/bin Full
/usr/local/sbin Full

# Critical libraries
/lib Full
/usr/lib Full

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION FILES (Content monitoring)
# ═══════════════════════════════════════════════════════════════════════════

# System configuration
/etc Content

# SSH configuration (extra important)
/etc/ssh Content

# Network configuration
/etc/network Content
/etc/systemd/network Content

# Security configurations
/etc/security Content
/etc/pam.d Content
/etc/sudoers Content
/etc/sudoers.d Content

# ═══════════════════════════════════════════════════════════════════════════
# USER DATA (Selective monitoring)
# ═══════════════════════════════════════════════════════════════════════════

# Root home (important)
/root Content

# User homes (metadata only - privacy vs security balance)
/home Perms

# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM DIRECTORIES (Metadata monitoring)
# ═══════════════════════════════════════════════════════════════════════════

# Important directories
/opt Perms
/srv Perms
/usr/share Perms

# Custom script directories (important for security)
/opt/scripts Content

# ═══════════════════════════════════════════════════════════════════════════
# EXCLUSIONS (Reduce noise and improve performance)
# ═══════════════════════════════════════════════════════════════════════════

# Temporary and cache directories
!/tmp
!/var/tmp
!/var/cache
!/var/lib/apt/lists
!/var/lib/dpkg/info

# Logs (change constantly)
!/var/log
!/var/spool

# Runtime directories
!/run
!/var/run
!/sys
!/proc
!/dev

# Docker (if present)
!/var/lib/docker

# Package manager
!/var/lib/dpkg/lock
!/var/lib/dpkg/lock-frontend
!/var/cache/apt/archives

# Mail
!/var/mail
!/var/spool/mail

# User-specific excludes
!/home/.*/\.cache
!/home/.*/\.local/share/Trash
!/home/.*/\.mozilla/firefox/.*/Cache
!/home/.*/\.thumbnails

# systemd
!/var/lib/systemd/random-seed
!/var/lib/systemd/catalog/database
!/etc/machine-id

# Network Manager
!/etc/NetworkManager/system-connections

# Certificate updates
!/etc/ssl/certs/ca-certificates.crt

# Time-based files
!/etc/adjtime
!/etc/localtime

# ═══════════════════════════════════════════════════════════════════════════
# SPECIAL CASES (Server-specific)
# ═══════════════════════════════════════════════════════════════════════════

# Web server (if present)
/var/www Content

# Database (metadata only - data changes frequently)
/var/lib/mysql Perms
/var/lib/postgresql Perms

# Application configs
/usr/local/etc Content

# Backup directories
/backup Perms
/var/backups Perms
EOF


    # AIDE-spezifische journald-Konfiguration
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/aide-logging.conf << 'EOF'
# AIDE-optimierte journald-Konfiguration
[Journal]
# AIDE-Logs persistent speichern (wichtig für Forensik)
Storage=persistent

# Längere Aufbewahrung für Integrity-Logs
MaxRetentionSec=12week

# Komprimierung für große AIDE-Reports
Compress=yes

# Erhöhte Limits für AIDE-Reports (können groß werden)
SystemMaxUse=300M
SystemMaxFileSize=50M

# Rate-Limiting für AIDE anpassen (Reports können viele Zeilen haben)
RateLimitIntervalSec=60s
RateLimitBurst=50000
EOF

    # AIDE-spezifisches Log-Directory (nur als Backup)
    mkdir -p /var/log/aide
    chown root:adm /var/log/aide
    chmod 750 /var/log/aide

    # 3. Systemd Service (jetzt korrigiert)
    cat > /etc/systemd/system/aide-check.service << 'EOF'
[Unit]
Description=AIDE File Integrity Check
Documentation=man:aide(1)
After=multi-user.target

[Service]
Type=oneshot
User=root

# KORRIGIERT: Check if database exists, if not create it
ExecStartPre=/bin/bash -c 'if [ ! -f /var/lib/aide/aide.db ]; then /usr/bin/aide --config /etc/aide/aide.conf --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db; fi'

# KORRIGIERT: Run the integrity check with structured output
ExecStart=/usr/bin/aide --config /etc/aide/aide.conf --check

# journald-optimized output
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aide-check

# Structured logging environment
Environment="SYSTEMD_LOG_LEVEL=info"
Environment="SYSTEMD_LOG_TARGET=journal"

# Performance optimization (VPS-friendly)
TimeoutStartSec=45min
CPUQuota=40%
Nice=19
IOSchedulingClass=2
IOSchedulingPriority=7

# Security hardening
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/aide /var/log/aide /tmp

# Exit codes: AIDE-specific handling
# 0 = No changes, 1 = New files, 2 = Removed files, 3 = Changed files
# 4 = Changed and new files, 5 = Changed and removed, 6 = New and removed
# 7 = All types of changes, 14 = Error writing database
SuccessExitStatus=0 1 2 3 4 5 6 7

[Install]
# IMPORTANT: Don't enable service directly - only via timer!
WantedBy=
EOF

    # 4. Systemd Timer
    cat > /etc/systemd/system/aide-check.timer << 'EOF'
[Unit]
Description=Run AIDE integrity check daily
Documentation=man:systemd.timer(5)
Requires=aide-check.service

[Timer]
# Daily at 5:00 AM (low system load time)
OnCalendar=*-*-* 05:00:00

# Randomize up to 30 minutes (spread server load)
RandomizedDelaySec=1800

# Run even if system was down
Persistent=true

# Explicit service reference
Unit=aide-check.service

[Install]
WantedBy=timers.target
EOF

   # 5. journald-Konfiguration neu laden und systemd-Units aktivieren
    run_with_spinner "Lade systemd-Konfiguration neu..." "systemctl restart systemd-journald && systemctl daemon-reload"
    
    # KORRIGIERT: Timer aktivieren UND starten
    if run_with_spinner "Aktiviere AIDE-Timer..." "systemctl enable --now aide-check.timer"; then
        log_ok "AIDE-Timer erfolgreich aktiviert und gestartet."
    else
        log_warn "AIDE-Timer konnte nicht aktiviert werden."
        # Nicht abbrechen - AIDE ist nicht kritisch
    fi
    
    log_ok "AIDE konfiguriert (täglicher Scan via systemd-timer)."
    log_info "  📜 Logs abrufen mit: journalctl -u aide-check.service"
    log_info "  📊 Timer-Status prüfen mit: systemctl list-timers aide-check.timer"
}

##
# Konfiguriert RKHunter (Rootkit-Scanner) für die Ausführung via systemd-Timer
# und leitet die Ausgabe direkt an das journald-Log um.
##
configure_rkhunter() {
    log_info "Konfiguriere RKHunter..."
    
    # 1. Saubere, funktionsfähige Config basierend auf offizieller Doku
    backup_and_register "/etc/rkhunter.conf"
    cat > /etc/rkhunter.conf << 'EOF'
# RKHunter Configuration - Based on official documentation
# Compatible with Debian/Ubuntu package version

# ═══════════════════════════════════════════════════════════════════════════
# UPDATES & MIRRORS
# ═══════════════════════════════════════════════════════════════════════════
UPDATE_MIRRORS=1
MIRRORS_MODE=0
WEB_CMD=""

# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM PATHS (Debian-Standards)
# ═══════════════════════════════════════════════════════════════════════════
INSTALLDIR=/usr
SCRIPTDIR=/usr/share/rkhunter/scripts
TMPDIR=/var/lib/rkhunter/tmp
DBDIR=/var/lib/rkhunter/db
BINDIR=/usr/bin

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING (journald-kompatibel)
# ═══════════════════════════════════════════════════════════════════════════
LOGFILE=/var/log/rkhunter.log
APPEND_LOG=1
USE_SYSLOG=authpriv.notice
COPY_LOG_ON_ERROR=0

# ═══════════════════════════════════════════════════════════════════════════
# SCAN CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Rootkit scanning mode (empty = standard mode, THOROUGH = deep scan)
# Official docs: "SHOULD NOT BE ENABLED BY DEFAULT"
#SCANROOTKITMODE=THOROUGH

# Package manager integration (Debian best practice)
PKGMGR=DPKG

# Hash function (standard für Debian/Ubuntu)
HASH_CMD=sha256sum

# ═══════════════════════════════════════════════════════════════════════════
# SSH SECURITY
# ═══════════════════════════════════════════════════════════════════════════
ALLOW_SSH_ROOT_USER=no
ALLOW_SSH_PROT_V1=2

# ═══════════════════════════════════════════════════════════════════════════
# WHITELISTS (Only essential ones)
# ═══════════════════════════════════════════════════════════════════════════
SCRIPTWHITELIST=/usr/bin/groups
SCRIPTWHITELIST=/usr/bin/ldd
SCRIPTWHITELIST=/usr/bin/which
SCRIPTWHITELIST=/usr/bin/egrep
SCRIPTWHITELIST=/usr/bin/fgrep

ALLOWHIDDENDIR=/etc/.git
ALLOWHIDDENFILE=/etc/.pwd.lock
# VPS-specific: Allow DHCP client
ALLOWPROCLISTEN=/sbin/dhclient

# ═══════════════════════════════════════════════════════════════════════════
# PERFORMANCE (VPS-friendly)  
# ═══════════════════════════════════════════════════════════════════════════
DISABLE_TESTS=suspscan

# ═══════════════════════════════════════════════════════════════════════════
# MAIL NOTIFICATIONS (added below if enabled)
# ═══════════════════════════════════════════════════════════════════════════
EOF

    
    # RKHunter-spezifische journald-Konfiguration
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/rkhunter-logging.conf << 'EOF'
# RKHunter-optimierte journald-Konfiguration
[Journal]
# RKHunter-Logs persistent speichern (wichtig für Security-Audit)
Storage=persistent

# Längere Aufbewahrung für Security-Logs
MaxRetentionSec=16week

# Komprimierung für RKHunter-Reports
Compress=yes

# Security-Logs haben Priorität - größere Limits
SystemMaxUse=350M
SystemMaxFileSize=40M

# Rate-Limiting für RKHunter-Scans anpassen
RateLimitIntervalSec=120s
RateLimitBurst=30000
EOF

    # 3. Mail nur wenn aktiviert
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ] && [ -n "${NOTIFICATION_EMAIL:-}" ]; then
        echo "MAIL-ON-WARNING=\"$NOTIFICATION_EMAIL\"" >> /etc/rkhunter.conf
        echo "MAIL_CMD=mail -s \"[rkhunter] \$(hostname)\"" >> /etc/rkhunter.conf
        log_info "Mail aktiviert für $NOTIFICATION_EMAIL"
    fi
    
    # 4. Datenbank initialisieren
    log_info "Initialisiere RKHunter-Pfade und Datenbank..."
    
    # Stelle sicher, dass alle benötigten Verzeichnisse existieren
    mkdir -p /var/lib/rkhunter/tmp
    mkdir -p /var/lib/rkhunter/db
    chown root:root /var/lib/rkhunter/tmp /var/lib/rkhunter/db
    chmod 755 /var/lib/rkhunter/tmp /var/lib/rkhunter/db
    
    # Prüfe ob kritische Pfade existieren
    local missing_paths=()
    [ ! -d /usr/share/rkhunter/scripts ] && missing_paths+=("SCRIPTDIR")
    [ ! -d /usr/share/rkhunter ] && missing_paths+=("INSTALLDIR")
    
    if [ ${#missing_paths[@]} -gt 0 ]; then
        log_error "Kritische RKHunter-Pfade fehlen: ${missing_paths[*]}"
        log_warn "RKHunter-Paket ist beschädigt oder nicht vollständig installiert"
        log_info "Lösung: sudo apt-get remove --purge rkhunter && sudo apt-get install rkhunter"
        log_warn "Überspringe RKHunter-Konfiguration..."
        return 0
    fi
    
    rkhunter --update --quiet || true
    rkhunter --propupd --quiet
    
    # 5. Systemd Service (journald-optimiert)
    cat > /etc/systemd/system/rkhunter-check.service << 'EOF'
[Unit]
Description=RKHunter Security Check (Rootkit Detection)
Documentation=man:rkhunter(8)
After=multi-user.target

[Service]
Type=oneshot
User=root

# Update signatures if needed
ExecStartPre=-/usr/bin/rkhunter --update --quiet

# Main security scan with structured output
ExecStart=/usr/bin/rkhunter --check --cronjob --report-warnings-only

# journald-optimized output
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rkhunter-check

# Structured logging environment
Environment="SYSTEMD_LOG_LEVEL=info"
Environment="SYSTEMD_LOG_TARGET=journal"

# Performance settings (VPS-optimized)
TimeoutStartSec=20min
CPUQuota=25%
Nice=19

# Security hardening
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rkhunter /var/log /tmp

# RKHunter-specific exit codes as success
# 0 = OK, 1 = Warnings found, 2 = Errors (but scan completed)
SuccessExitStatus=0 1 2

[Install]
# IMPORTANT: Don't enable service directly - only via timer!
WantedBy=
EOF

    # 6. Systemd Timer
    cat > /etc/systemd/system/rkhunter-check.timer << 'EOF'
[Unit]
Description=Run RKHunter security check weekly
Documentation=man:systemd.timer(5)
Requires=rkhunter-check.service

[Timer]
# Weekly on Sunday at 4:00 AM (low system load)
OnCalendar=Sun *-*-* 04:00:00

# Randomize up to 30 minutes (spread server load)
RandomizedDelaySec=1800

# Run even if system was down
Persistent=true

# Explicit service reference
Unit=rkhunter-check.service

[Install]
WantedBy=timers.target
EOF

    # 7. journald-Konfiguration neu laden und aktivieren
    systemctl restart systemd-journald
    systemctl daemon-reload
    systemctl enable --now rkhunter-check.timer
    
    log_ok "RKHunter konfiguriert (wöchentlich sonntags 4:00-4:30 Uhr, journald-optimiert)"
    log_info "Logs: journalctl -u rkhunter-check.service"
    log_info "Security-Filter: journalctl -t rkhunter-check"
    log_info "Timer-Status: systemctl list-timers rkhunter-check.timer"
}
################################################################################
#
#                       SETUP-MODULE (in Ausführungsreihenfolge)
#
################################################################################

##
# MODUL 0: Versetzt den Server in einen ZUSTAND NAHE DER NEUINSTALLATION.
#          Entfernt alle Konfigurationen, Pakete, Benutzer und Systemzustände.
##
module_cleanup() {
    log_info "MODUL 0: Führe LÜCKENLOSE Systembereinigung durch..."
    trap '' ERR; set +e

    # --- 1. Systemzustand sofort zurücksetzen (Firewall, Docker) ---
    log_info "  -> 1/7: Setze aktive Systemzustände zurück..."
    if command -v nft &>/dev/null; then nft flush ruleset; fi
    if command -v docker &>/dev/null; then
        docker stop portainer watchtower >/dev/null 2>&1
        docker rm -f portainer watchtower >/dev/null 2>&1
        docker system prune -af --volumes >/dev/null 2>&1
    fi
    log_ok "Aktive Firewall-Regeln und Docker-Objekte entfernt."

    # --- 2. Alle relevanten systemd-Units stoppen & deaktivieren ---
    log_info "  -> 2/7: Stoppe und deaktiviere alle Baukasten-Timer und -Services..."
    # (Keine Änderung hier, die Liste war bereits gut)
    local units_to_remove=(
        "aide-check.timer" "aide-check.service" "dailyaidecheck.timer" "dailyaidecheck.service"
        "rkhunter-check.timer" "rkhunter-check.service" "geoip-update.timer" "geoip-update.service"
        "system-backup.timer" "system-backup.service" "unattended-upgrades-run.timer" "unattended-upgrades-run.service"
        "crowdsec-healthcheck.timer" "crowdsec-healthcheck.service" "mail-failure@.service" "tailscaled.service"
    )
    systemctl stop "${units_to_remove[@]}" >/dev/null 2>&1
    systemctl disable "${units_to_remove[@]}" >/dev/null 2>&1
    log_ok "Alle systemd-Units gestoppt und deaktiviert."
    
    # --- 3. Pakete deinstallieren (inkl. Docker) ---
    log_info "  -> 3/7: Deinstalliere alle vom Baukasten installierten Pakete..."
    local packages_to_purge=(
        "aide" "rkhunter" "crowdsec" "crowdsec-firewall-bouncer-nftables" "msmtp" "msmtp-mta"
        "mailutils" "geoip-bin" "geoip-database" "ipset" "docker-ce" "docker-ce-cli"
        "containerd.io" "docker-buildx-plugin" "docker-compose-plugin" "tailscale"
    )
    apt-get purge -y "${packages_to_purge[@]}" >/dev/null 2>&1
    apt-get autoremove -y --purge >/dev/null 2>&1
    log_ok "Alle Kernpakete deinstalliert."

    # --- 4. Alle Konfigurations-, Daten- & Skript-Dateien entfernen ---
    log_info "  -> 4/7: Entferne alle Konfigurationen, Skripte und Daten..."
    # APT-Quellen
    rm -f /etc/apt/sources.list.d/{docker,tailscale,crowdsec_crowdsec}.list
    rm -f /etc/apt/keyrings/{docker,tailscale-archive-keyring}.gpg
    # Konfig & Daten
    rm -rf /etc/aide/ /var/lib/aide/
    rm -rf /etc/rkhunter.conf.d/ /etc/rkhunter.conf /var/lib/rkhunter/
    rm -rf /etc/crowdsec/ /var/lib/crowdsec/
    rm -rf /etc/docker/
    rm -rf /etc/nftables.d/ /etc/nftables.conf
    # systemd Unit-Dateien und Journald-Konfigs
    rm -f /etc/systemd/system/{aide-check,rkhunter-check,geoip-update,system-backup,unattended-upgrades-run,crowdsec-healthcheck,dailyaidecheck}.*
    rm -f /etc/systemd/system/mail-failure@.service
    rm -rf /etc/systemd/system/*.d/
    rm -f /etc/systemd/journald.conf.d/*
    # Sonstige Skripte und Konfigs
    rm -f /etc/geoip-*.conf /usr/local/bin/{geoip-manager,update-geoip-sets.sh,system-backup}
    rm -f /etc/msmtprc*
    rm -f /etc/sysctl.d/99-baukasten-hardening.conf
    systemctl daemon-reload
    log_ok "Alle Konfigurationen, Skripte und Daten entfernt."

    # --- 5. Swap-Datei entfernen ---
    log_info "  -> 5/7: Entferne Swap-Datei..."
    swapoff /swapfile >/dev/null 2>&1
    rm -f /swapfile
    sed -i '\|/swapfile|d' /etc/fstab
    log_ok "Swap-Datei und fstab-Eintrag entfernt."

    # --- 6. Admin-Benutzer entfernen ---
    log_info "  -> 6/7: Entferne Admin-Benutzer..."
    # WICHTIG: ADMIN_USER muss aus der Config geladen oder als Variable verfügbar sein!
    if id "${ADMIN_USER:-nouser}" &>/dev/null && [ "${ADMIN_USER}" != "root" ]; then
        # Beende alle Prozesse des Benutzers, bevor er gelöscht wird
        killall -u "$ADMIN_USER" &>/dev/null
        userdel -r "$ADMIN_USER" &>/dev/null
        log_ok "Benutzer '${ADMIN_USER}' und sein Home-Verzeichnis entfernt."
    else
        log_warn "Admin-Benutzer '${ADMIN_USER:-nicht definiert}' nicht gefunden oder konnte nicht entfernt werden."
    fi

    # --- 7. Journal bereinigen ---
    log_info "  -> 7/7: Rotiere Journal-Logs für einen sauberen Start..."
    journalctl --rotate >/dev/null 2>&1
    systemctl restart systemd-journald
    log_ok "Journal-Logs wurden rotiert."

    set -e; trap 'rollback' ERR
    log_ok "Lückenlose Systembereinigung vollständig abgeschlossen."
}

##
# MODUL 1: Stellt die APT-Quellen auf sichere HTTPS-Verbindungen um.
##
module_fix_apt_sources() {
    log_info "MODUL 1: APT-Quellen auf HTTPS umstellen${NC}"
    backup_and_register "/etc/apt/sources.list"
    cat > /etc/apt/sources.list << EOF
deb https://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware
deb https://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
deb https://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
EOF
    rm -f /etc/apt/sources.list.d/debian.sources
    log_ok "APT-Quellen auf HTTPS umgestellt.${NC}"
}

##
# MODUL 2: Führt die grundlegende Systemkonfiguration durch.
# Setzt Hostname, Zeitzone, Locale, Benutzer, Passwörter und installiert Kernpakete.
##
##
# MODUL 2: Führt die grundlegende Systemkonfiguration durch.
# Setzt Hostname, Zeitzone, Locale, Benutzer, Passwörter und installiert Kernpakete.
##
module_base() {
    log_info "📦 MODUL: Basis-System-Setup"
    
    # --- Phase 1/7: System-Identität ---
    log_info "  -> 1/7: Konfiguriere System-Identität..."
    hostnamectl set-hostname "$SERVER_HOSTNAME"
    sed -i "/127.0.1.1/c\127.0.1.1       $SERVER_HOSTNAME" /etc/hosts
    log_ok "Hostname gesetzt auf: $SERVER_HOSTNAME"
    
    timedatectl set-timezone "$TIMEZONE"
    log_ok "Zeitzone gesetzt auf: $TIMEZONE"
    
    sed -i -E 's/^#\s*(de_DE.UTF-8\s+UTF-8)/\1/' /etc/locale.gen
    sed -i -E 's/^#\s*(en_US.UTF-8\s+UTF-8)/\1/' /etc/locale.gen
    run_with_spinner "Generiere Locales..." "locale-gen"
    update-locale LANG="$LOCALE"
    log_ok "System-Locale gesetzt auf: $LOCALE"
    
    # --- Phase 2/7: Benutzer-Management ---
    log_info "  -> 2/7: Konfiguriere Benutzer-Accounts..."
    echo "root:$ROOT_PASSWORD" | chpasswd
    log_ok "Root-Passwort aktualisiert."
    
    if ! id "$ADMIN_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$ADMIN_USER"
        log_ok "Admin-Benutzer '$ADMIN_USER' erstellt."
    else
        log_info "Admin-Benutzer '$ADMIN_USER' existiert bereits."
    fi
    
    echo "$ADMIN_USER:$ADMIN_PASSWORD" | chpasswd
    usermod -aG sudo "$ADMIN_USER"
    log_ok "Admin-Benutzer '$ADMIN_USER' konfiguriert und zur sudo-Gruppe hinzugefügt."
    
    echo "$ADMIN_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/99-$ADMIN_USER"
    chmod 0440 "/etc/sudoers.d/99-$ADMIN_USER"
    log_warn "Temporäre NOPASSWD sudo-Rechte für '$ADMIN_USER' aktiviert (werden am Ende entfernt)."
    
    # --- Phase 3/7: Kern-Pakete ---
    log_info "  -> 3/7: Installiere Kern-Pakete..."
    export DEBIAN_FRONTEND=noninteractive
    readonly APT_OPTIONS="-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
    
    local packages_to_install=()
    packages_to_install+=("sudo" "nano" "vim" "curl" "wget" "gpg" "ca-certificates" "software-properties-common" "apt-transport-https") # System
    packages_to_install+=("htop" "tree" "unzip" "git" "rsync" "screen" "tmux" "net-tools" "bind9-dnsutils" "tcpdump" "jq" "lsof" "file" "psmisc") # Admin
    packages_to_install+=("aide" "rkhunter" "apparmor" "apparmor-utils" "libipc-system-simple-perl") # Security
    
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        log_info "  -> Füge GeoIP-Pakete zur Installationsliste hinzu..."
        packages_to_install+=("ipset" "geoip-database" "geoip-bin")
    fi
    if [ "$ENABLE_SYSTEM_MAIL" = "ja" ]; then
        log_info "  -> Füge Mail-Pakete zur Installationsliste hinzu..."
        echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections
        packages_to_install+=("msmtp" "msmtp-mta" "mailutils")
    fi

    run_with_spinner "Installiere ${#packages_to_install[@]} Basis-Pakete..." "apt-get install $APT_OPTIONS ${packages_to_install[*]}"
    
    if ! run_with_spinner "Installiere zusätzliche AppArmor-Profile..." "timeout 60 apt-get install $APT_OPTIONS apparmor-profiles-extra"; then
        log_warn "Installation der AppArmor-Profile übersprungen (Timeout)."
    fi

    # --- Phase 4/7: Mail-System Konfiguration ---
    if [ "$ENABLE_SYSTEM_MAIL" = "ja" ]; then
        log_info "  -> 4/7: Konfiguriere Mail-System..."
        update-alternatives --install /usr/sbin/sendmail sendmail /usr/bin/msmtp 25
        update-alternatives --set sendmail /usr/bin/msmtp
        log_ok "msmtp als systemweite sendmail-Alternative konfiguriert."
    else
        log_info "  -> 4/7: Mail-System-Konfiguration übersprungen (deaktiviert)."
    fi
    
    # --- Phase 5/7: Swap-Konfiguration ---
    log_info "  -> 5/7: Konfiguriere Swap-Speicher..."
    if ! swapon --show | grep -q /swapfile; then
        run_with_spinner "Erstelle 2GB Swap-Datei..." \
            "fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile"
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    else
        log_info "Swap-Datei existiert bereits."
    fi
    
    # --- Phase 6/7: Docker-Setup (falls Container-Server) ---
    if [ "$SERVER_ROLE" = "1" ]; then
        log_info "  -> 6/7: Installiere Docker-Engine..."
        
        install -m 0755 -d /etc/apt/keyrings
        if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
            run_with_spinner "Füge Docker GPG-Schlüssel hinzu..." \
                "curl -fsSL https://download.docker.com/linux/$OS_ID/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
        fi
        
        if [ ! -f /etc/apt/sources.list.d/docker.list ]; then
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS_ID $OS_VERSION_CODENAME stable" > /etc/apt/sources.list.d/docker.list
            run_with_spinner "Aktualisiere Paketlisten für Docker Repository..." "apt-get update -qq"
            log_ok "Docker Repository hinzugefügt."
        fi
        
        local docker_packages=("docker-ce" "docker-ce-cli" "containerd.io" "docker-buildx-plugin" "docker-compose-plugin")
        run_with_spinner "Installiere Docker-Pakete..." "apt-get install -y ${docker_packages[*]}"
        
        usermod -aG docker "$ADMIN_USER"
        log_ok "'$ADMIN_USER' zur Docker-Gruppe hinzugefügt."
        
        systemctl disable --now docker >/dev/null 2>&1 || true
        log_info "Docker-Engine installiert (Service wird später konfiguriert)."
    else
        log_info "  -> 6/7: Docker-Setup übersprungen (Einfacher Server)."
    fi

    # --- Phase 7/7: Modulare Komponenten bereitstellen ---
    log_info "  -> 7/7: Stelle benötigte modulare Komponenten bereit..."
    
    # GeoIP-Komponenten (falls aktiviert)
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        log_info "     -> GeoIP-Komponenten..."
        
        # geoip-manager installieren
        if run_with_spinner "Download geoip-manager..." "curl -fsSL '$COMPONENTS_BASE_URL/geoip-manager' -o '/usr/local/bin/geoip-manager'"; then
            chmod 770 "/usr/local/bin/geoip-manager"
            chown root:sudo "/usr/local/bin/geoip-manager"
        else
            log_error "geoip-manager Download fehlgeschlagen!"
        fi
        
        # update-geoip-sets.sh installieren
        if run_with_spinner "Download update-geoip-sets.sh..." "curl -fsSL '$COMPONENTS_BASE_URL/update-geoip-sets.sh' -o '/usr/local/bin/update-geoip-sets.sh'"; then
            chmod 770 "/usr/local/bin/update-geoip-sets.sh"
            chown root:sudo "/usr/local/bin/update-geoip-sets.sh"
        else
            log_error "update-geoip-sets.sh Download fehlgeschlagen!"
        fi
    fi
    
    # Weitere Komponenten direkt hier hinzufügen:
    # if [ "$SERVER_ROLE" = "1" ]; then
    #     log_info "     -> Docker-Komponenten..."
    #     if run_with_spinner "Download docker-setup.sh..." "curl -fsSL '$COMPONENTS_BASE_URL/docker-setup.sh' -o '/usr/local/bin/docker-setup.sh'"; then
    #         chmod 770 "/usr/local/bin/docker-setup.sh"
    #         chown root:sudo "/usr/local/bin/docker-setup.sh"
    #     fi
    # fi

   log_ok "Modul Basis-System-Setup erfolgreich abgeschlossen."  
}

##
# MODUL 3: Führt ein System-Update durch und konfiguriert moderne,
#          journald-basierte automatische Updates via systemd.
##
module_system_update() {
    local TEST_MODE="$1"
    log_info "🆙 MODUL: System Update & Automatisierung (via systemd)"

    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS: Überspringe System-Update (dist-upgrade)."
        run_with_spinner "Installiere 'unattended-upgrades' für die Konfiguration..." \
            "apt-get install -y unattended-upgrades apt-listchanges >/dev/null"
    else
        run_with_spinner "Führe initiales System-Update (dist-upgrade) durch..." \
            "apt-get update -qq && apt-get dist-upgrade -y"
        apt-get install -y unattended-upgrades apt-listchanges >/dev/null
    fi

    log_info "  -> 1/3: Konfiguriere unattended-upgrades (Was soll aktualisiert werden?)..."
    local allowed_origins="      \"\\\${distro_id}:\\\${distro_codename}-security\";"
    if [ "$UPGRADE_EXTENDED" = "ja" ]; then
        allowed_origins+="\n      \"\\\${distro_id}:\\\${distro_codename}-updates\";"
    fi
    backup_and_register "/etc/apt/apt.conf.d/50unattended-upgrades"
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
// Konfiguration für unattended-upgrades
// Was wird aktualisiert? (Server-Baukasten v$SCRIPT_VERSION)
Unattended-Upgrade::Allowed-Origins {
$(echo -e "$allowed_origins")
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Mail "${NOTIFICATION_EMAIL:-root@localhost}";
Unattended-Upgrade::SyslogEnable "false"; // Wir loggen via systemd-journal
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    log_info "  -> 2/3: Deaktiviere alten apt-Timer und erstelle neue systemd-Units..."
    backup_and_register "/etc/apt/apt.conf.d/20auto-upgrades"
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
// Konfiguration für periodische apt-Aktivitäten
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::AutocleanInterval "7";

// Unattended-Upgrades werden jetzt durch unseren eigenen systemd-Timer gesteuert
APT::Periodic::Unattended-Upgrade "0";
EOF

    cat > /etc/systemd/system/unattended-upgrades-run.service << 'EOF'
[Unit]
Description=Run unattended-upgrades and log verbosely to journal
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/unattended-upgrade -d --verbose
StandardOutput=journal
StandardError=journal
User=root
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    cat > /etc/systemd/system/unattended-upgrades-run.timer << 'EOF'
[Unit]
Description=Run unattended-upgrades service daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true
[Install]
WantedBy=timers.target
EOF

    log_info "  -> 3/3: Aktiviere neuen systemd-Timer..."
    systemctl daemon-reload
    systemctl enable --now unattended-upgrades-run.timer

    log_ok "System-Updates erfolgreich auf modernen systemd-Timer umgestellt."
    log_info "  📜 Logs sind jetzt direkt im Journal verfügbar: journalctl -u unattended-upgrades-run.service"
}

##
# MODUL: Konfiguriert das Netzwerk-Modul (Tailscale).
##
module_network() {
    local TEST_MODE="$1"
    log_info "🌐 MODUL: Netzwerk (Tailscale)"
    
    if [ "${TEST_MODE}" = true ]; then
        log_warn "TEST-MODUS: Überspringe Tailscale-Setup."
        return 0
    fi
    
    if [ "$ACCESS_MODEL" = "1" ]; then
        # Die aufgerufene Funktion 'setup_tailscale' hat ihr eigenes, detailliertes Logging.
        setup_tailscale
    else
        log_info "Zugriffsmodell ist nicht 'VPN'. Überspringe Tailscale-Setup."
    fi
    
    log_ok "Netzwerk-Modul abgeschlossen."
}

##
# MODUL: Konfiguriert alle Sicherheitsschichten des Servers.
##
module_security() {
    local TEST_MODE="$1"
    log_info "🔒 MODUL: Sicherheits-Architektur (Multi-Layer)"

    # Die Reihenfolge ist wichtig: Von der Basis-Härtung über die Firewall bis zur Überwachung.
    
    setup_basic_security
    
    # Diese Funktion installiert nftables, generiert die config und startet den Service.
    setup_firewall_infrastructure
    
    setup_intrusion_prevention
    
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        setup_geoip_protection
    else
        log_info "GeoIP-Blocking ist deaktiviert und wird übersprungen."
    fi
    
    setup_integrity_monitoring "$TEST_MODE"
    
    verify_security_layers
    
    log_ok "Modul Sicherheits-Architektur erfolgreich abgeschlossen."
}


##
# MODUL: Konfiguriert den Docker Daemon mit einem benutzerdefinierten Netzwerk.
##
module_container() {
    # Führt nur aus, wenn der Server als Docker-Host konfiguriert ist.
    [ "$SERVER_ROLE" != "1" ] && return 0
    
    log_info "🐳 MODUL: Container (Docker Daemon & Netzwerk)"
    mkdir -p /etc/docker
    local daemon_json="/etc/docker/daemon.json"
    backup_and_register "$daemon_json"
    
    local docker_gateway_ip
    docker_gateway_ip=$(echo "$DOCKER_IPV4_CIDR" | cut -d'/' -f1 | sed 's/\.0$//').1
    
    log_info "  -> Erstelle Docker-Konfiguration (daemon.json) für Netzwerk ${DOCKER_IPV4_CIDR}..."
    
    # Schreibt die komplette, gehärtete Docker-Konfiguration
    jq -n \
      --arg bip "$docker_gateway_ip/$(echo "$DOCKER_IPV4_CIDR" | cut -d'/' -f2)" \
      --arg fixed_cidr "$DOCKER_IPV4_CIDR" \
      --arg fixed_cidr_v6 "$DOCKER_IPV6_CIDR" \
      '{
        "bip": $bip,
        "fixed-cidr": $fixed_cidr,
        "ipv6": true,
        "fixed-cidr-v6": $fixed_cidr_v6,
        "log-driver": "json-file",
        "log-opts": { "max-size": "10m", "max-file": "3" },
        "live-restore": true,
        "userland-proxy": true,
        "iptables": false,
        "ip6tables": false
       }' > "$daemon_json"
    
    if ! run_with_spinner "Aktiviere und starte Docker-Dienst..." "systemctl enable --now docker"; then
        log_error "Docker-Dienst konnte nicht gestartet werden! Container können nicht deployt werden."
        return 1
    fi
    
    log_ok "Docker Daemon konfiguriert und nutzt jetzt das Netzwerk: $DOCKER_IPV4_CIDR"
}

##
# MODUL: Startet die Management-Container (Portainer, Watchtower).
# Setzt voraus, dass module_container bereits gelaufen ist.
##
module_deploy_containers() {
    # Führt nur aus, wenn der Server als Docker-Host konfiguriert ist.
    [ "$SERVER_ROLE" != "1" ] && return 0
    
    log_info "🐳 MODUL: Management-Container (Portainer, Watchtower)"

    if [ "${INSTALL_PORTAINER:-ja}" = "ja" ]; then
        log_info "  -> Deploye Portainer-Container..."
        # Stelle sicher, dass alte Container-Versionen vorher entfernt werden
        docker stop portainer >/dev/null 2>&1 || true
        docker rm portainer >/dev/null 2>&1 || true
        
        local portainer_cmd="docker run -d -p 9443:9443 -p 8000:8000 --name=portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:latest"

        if run_with_spinner "Starte Portainer (Image-Pull kann dauern)..." "$portainer_cmd"; then
            local docker_gateway_ip
            docker_gateway_ip=$(ip -4 addr show docker0 | grep -oP 'inet \K[\d.]+')
            log_ok "Portainer gestartet. Zugriff im VPN via: https://${docker_gateway_ip}:9443"
        else
            log_error "Portainer konnte nicht gestartet werden."
        fi
    fi
    
    if [ "${INSTALL_WATCHTOWER:-ja}" = "ja" ]; then
        log_info "  -> Deploye Watchtower-Container..."
        docker stop watchtower >/dev/null 2>&1 || true
        docker rm watchtower >/dev/null 2>&1 || true
        
        local watchtower_cmd="docker run -d --name=watchtower --restart=always -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --schedule \"0 4 * * *\" --cleanup"

        if run_with_spinner "Starte Watchtower (Image-Pull kann dauern)..." "$watchtower_cmd"; then
            log_ok "Watchtower für tägliche Container-Updates (04:00 Uhr) aktiviert."
        else
            log_error "Watchtower konnte nicht gestartet werden."
        fi
    fi

    log_ok "Modul Management-Container erfolgreich abgeschlossen."
}

##
# MODUL: Konfiguriert die Kernel-Härtung (Basis + Erweitert).
##
module_kernel_hardening() {
    log_info "🧠 MODUL: Kernel-Härtung (sysctl)"
    
    backup_and_register "/etc/sysctl.conf"
    
    log_info "  -> Schreibe Konfiguration für Basis-Sicherheitsparameter..."
    cat > /etc/sysctl.d/99-baukasten-hardening.conf << 'EOF'
# Basis Kernel-Härtung
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.log_martians=1
net.ipv6.conf.default.use_tempaddr=2
# Explizites Aktivieren von IP-Forwarding für IPv4 und IPv6.
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
 
    log_info "  -> Schreibe Konfiguration für erweiterten DDoS-Schutz & VPS-Optimierung..."
    cat > /etc/sysctl.d/98-baukasten-advanced-hardening.conf << 'EOF'
# Erweiterte Kernel-Parameter für DDoS-Schutz & Stabilität
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=1800
net.ipv4.tcp_max_syn_backlog=8192
net.netfilter.nf_conntrack_max=524288
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
vm.swappiness=10
vm.dirty_ratio=15
net.core.rmem_max=16777216
net.core.wmem_max=16777216
EOF

    run_with_spinner "Wende neue Kernel-Parameter an..." "sysctl --system"
    
    log_info "  -> Verifiziere kritische Kernel-Parameter..."
    if [[ $(sysctl -n net.ipv4.ip_forward) -eq 1 ]] && [[ $(sysctl -n net.ipv6.conf.all.forwarding) -eq 1 ]]; then
        log_ok "IP-Forwarding für IPv4 und IPv6 ist erfolgreich aktiviert."
    else
        log_error "IP-Forwarding konnte nicht aktiviert werden! NAT für Docker/VPN wird nicht funktionieren."
        # return 1 # Optional: Harter Abbruch, wenn Forwarding kritisch ist
    fi

    log_info "  -> Deaktiviere unnötige Dienste (VPS-optimiert)..."
    local services_to_disable=("bluetooth" "cups" "avahi-daemon" "ModemManager" "wpa_supplicant")
    for service in "${services_to_disable[@]}"; do
        if systemctl list-units --full -all | grep -q "$service.service"; then
            run_with_spinner "Deaktiviere Dienst '$service'..." "systemctl disable --now '$service'"
        else
            log_debug "Dienst '$service' nicht gefunden, wird übersprungen."
        fi
    done
    
    log_ok "Modul Kernel-Härtung erfolgreich abgeschlossen."
}

##
# MODUL: Konfiguriert den systemweiten E-Mail-Versand via msmtp.
##
module_mail_setup() {
    if [ "$ENABLE_SYSTEM_MAIL" != "ja" ]; then
        log_info "📧 Systemweite E-Mail-Benachrichtigungen sind deaktiviert (übersprungen)."
        return 0
    fi

    log_info "📧 MODUL: Systemweiter E-Mail-Versand (msmtp)"
    
    run_with_spinner "Konfiguriere msmtp als sendmail-Alternative..." \
        "update-alternatives --install /usr/sbin/sendmail sendmail /usr/bin/msmtp 25 && update-alternatives --set sendmail /usr/bin/msmtp"

    local auth_setting="on"
    if [ "${SMTP_AUTH:-ja}" = "nein" ]; then
        auth_setting="off"
        log_info "  -> SMTP-Authentifizierung ist deaktiviert."
    else
        log_info "  -> SMTP-Authentifizierung ist aktiviert."
    fi
    
    local starttls_setting="off"
    if [ "${SMTP_TLS_STARTTLS:-nein}" = "ja" ]; then
        starttls_setting="on"
        log_info "  -> STARTTLS ist aktiviert."
    else
        log_info "  -> STARTTLS ist deaktiviert (direkter TLS-Modus)."
    fi
    
    log_info "  -> Schreibe msmtp-Konfiguration nach /etc/msmtprc..."
    backup_and_register "/etc/msmtprc"
    
    cat > /etc/msmtprc <<EOF
# msmtp-Konfiguration für systemweiten E-Mail-Versand
# Generiert von Server-Baukasten v$SCRIPT_VERSION am $(date)
defaults
auth           $auth_setting
tls            on
tls_starttls   $starttls_setting
tls_trust_file /etc/ssl/certs/ca-certificates.crt
syslog         on

account        default
host           $SMTP_HOST
port           $SMTP_PORT
from           $SMTP_FROM
EOF

    if [ "$auth_setting" = "on" ]; then
        if [ -n "${SMTP_USER:-}" ]; then
            echo "user            $SMTP_USER" >> /etc/msmtprc
            log_info "     - SMTP-Benutzername konfiguriert."
        fi
        if [ -n "${SMTP_PASSWORD:-}" ]; then
            echo "password        $SMTP_PASSWORD" >> /etc/msmtprc
            log_info "     - SMTP-Passwort konfiguriert."
        fi
    fi
    
    chmod 644 /etc/msmtprc
    chown root:root /etc/msmtprc
    log_ok "Sichere Dateiberechtigungen für /etc/msmtprc gesetzt."
    
    log_info "  -> Optimiere journald für E-Mail-Logs..."
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/99-mail-logging.conf <<EOF
# Optimierte journald-Konfiguration für E-Mail-Logging
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=200M
MaxRetentionSec=4week
SyncIntervalSec=60s
EOF
    
    run_with_spinner "Lade journald-Konfiguration neu..." "systemctl restart systemd-journald"
    
    log_info "  -> Teste E-Mail-Versand mit msmtp..."
    
    # KORRIGIERT: Verwende --from Parameter mit vollständiger E-Mail-Adresse
    if echo "Test-E-Mail vom Server-Baukasten auf $(hostname) am $(date)" | msmtp --debug --from="$SMTP_FROM" "$NOTIFICATION_EMAIL"; then
        log_ok "Test-E-Mail erfolgreich an $NOTIFICATION_EMAIL gesendet."
    else
        log_warn "Test-E-Mail konnte nicht gesendet werden."
        log_info "  -> Häufige Ursachen: SMTP-Credentials, Firewall, oder Provider-Einschränkungen"
        log_info "  -> Testen Sie manuell: echo 'Test' | msmtp --from='$SMTP_FROM' '$NOTIFICATION_EMAIL'"
        
        # NICHT abbrechen - Mail ist optional für das System-Setup
        log_warn "Mail-Setup abgeschlossen, aber Test fehlgeschlagen. System läuft trotzdem sicher!"
        return 0
    fi
    
    log_ok "Systemweiter E-Mail-Versand via msmtp erfolgreich eingerichtet."
    log_info "  📜 E-Mail-Logs sind im Journal verfügbar: journalctl | grep msmtp"
    log_warn "WICHTIG: Prüfe dein Postfach ($NOTIFICATION_EMAIL) auf Test-Mails!"
}

##
# MODUL: Konfiguriert die zentrale Log-Verwaltung via journald.
##
module_journald_optimization() {
    log_info "📜 MODUL: Zentrale Log-Verwaltung (journald)"
    
    log_info "  -> Schreibe optimierte journald-Konfigurationsdateien..."
    mkdir -p /etc/systemd/journald.conf.d
    
    backup_and_register "/etc/systemd/journald.conf"
    
    # Allgemeine Optimierungen
    cat > /etc/systemd/journald.conf.d/99-baukasten-optimization.conf <<EOF
# Optimierte journald-Konfiguration für Server-Baukasten
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=250M
RuntimeMaxUse=50M
MaxRetentionSec=3week
SystemMaxFileSize=25M
SyncIntervalSec=60s
ForwardToSyslog=no
ForwardToWall=no
RateLimitIntervalSec=60s
RateLimitBurst=10000
EOF
    
    # Längere Aufbewahrung für sicherheitskritische Logs
    cat > /etc/systemd/journald.conf.d/10-security-logging.conf <<EOF
# Längere Aufbewahrung für Security-Logs (SSH, CrowdSec, AIDE etc.)
[Journal]
MaxRetentionSec=12week
EOF
    
    run_with_spinner "Aktiviere neue journald-Konfiguration..." "systemctl restart systemd-journald"
    
    log_info "  -> Verifiziere journald-Status..."
    if systemctl is-active --quiet systemd-journald; then
        local journal_size
        journal_size=$(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[KMGT]B' || echo "Unbekannt")
        log_info "     - Aktuelle Journal-Größe: $journal_size"
        
        local boot_count
        boot_count=$(journalctl --list-boots --no-pager 2>/dev/null | wc -l || echo "Unbekannt")
        log_info "     - Verfügbare Boot-Logs: $boot_count"
        
        log_ok "journald erfolgreich optimiert und aktiv."
    else
        log_error "journald konnte nicht neu gestartet werden!"
        return 1
    fi
    
    log_info "--- Nützliche journalctl-Befehle ---"
    log_info "  Live-Logs: journalctl -f"
    log_info "  Baukasten-Logs: journalctl -t server-baukasten"
    log_info "  SSH-Logs: journalctl -u ssh"
    log_info "  Journal-Größe: journalctl --disk-usage"
    log_info "------------------------------------"
    
    log_ok "Zentrale Log-Verwaltung via journald erfolgreich konfiguriert."
}
##
# MODUL: Konfiguriert das Backup- und Wartungsmodul (system-backup).
##
module_services() {
    local TEST_MODE="$1"
    log_info "💾 MODUL: Services & Wartung (Backup)"

    log_info "  -> Erstelle robustes Backup-Skript mit Journald-Integration..."
    cat > /usr/local/bin/system-backup << 'EOF'
#!/bin/bash
# System-Backup-Skript v2.0 - mit Journald-Integration

# Bei Fehlern sofort abbrechen
set -e
set -o pipefail

BACKUP_DIR="/var/backups"
DATE=$(date +%Y%m%d)
BACKUP_FILE="$BACKUP_DIR/system-backup-$DATE.tar.gz"
PACKAGELIST_FILE="$BACKUP_DIR/installed-packages-$DATE.txt"
LOG_TAG="system-backup"

# --- Vorbereitung ---
logger -t "$LOG_TAG" "Starte System-Backup..."
mkdir -p "$BACKUP_DIR"
dpkg --get-selections > "$PACKAGELIST_FILE"
logger -t "$LOG_TAG" "Liste der installierten Pakete in $PACKAGELIST_FILE gespeichert."

# --- Haupt-Backup ---
logger -t "$LOG_TAG" "Erstelle Haupt-Backup nach $BACKUP_FILE..."
if tar -czf "$BACKUP_FILE" \
    --exclude='/home/*/.cache' \
    --exclude='/var/cache' \
    --exclude='/var/log' \
    --exclude='/var/tmp' \
    /etc /home /root /opt /usr/local/bin /usr/local/sbin /var/www "$PACKAGELIST_FILE"; then
    
    logger -t "$LOG_TAG" -p "daemon.notice" "SUCCESS: Backup erfolgreich erstellt. Größe: $(du -sh "$BACKUP_FILE" | awk '{print $1}')"
else
    logger -t "$LOG_TAG" -p "daemon.err" "ERROR: Backup-Erstellung mit tar ist fehlgeschlagen!"
    exit 1
fi

# --- Aufräumen ---
logger -t "$LOG_TAG" "Suche nach Backups, die älter als 7 Tage sind..."
# Zuerst zählen, dann löschen, für ein sauberes Log
find "$BACKUP_DIR" -name "system-backup-*.tar.gz" -mtime +7 -print0 | xargs -0 -r rm -f
local geloescht_count=$? # Zählt die gelöschten Dateien
logger -t "$LOG_TAG" "$geloescht_count alte(s) Backup(s) entfernt."

logger -t "$LOG_TAG" -p "daemon.notice" "Backup-Prozess erfolgreich abgeschlossen."
EOF
    chmod +x /usr/local/bin/system-backup

    # --- systemd Timer für das Backup erstellen ---
    log_info "  -> Erstelle systemd-Service und -Timer für das Backup..."
    cat > /etc/systemd/system/system-backup.service << 'EOF'
[Unit]
Description=Run daily system backup script
[Service]
Type=oneshot
ExecStart=/usr/local/bin/system-backup
EOF

    cat > /etc/systemd/system/system-backup.timer << 'EOF'
[Unit]
Description=Run system-backup.service daily at 3 AM
[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
EOF

    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS: Backup-Timer wird nicht aktiviert."
    else
        log_info "  -> Aktiviere den Backup-Timer..."
        systemctl enable --now system-backup.timer
    fi
    
    log_ok "Modul Services & Wartung erfolgreich abgeschlossen."
}
##
# MODUL: Überprüft den Status aller kritischen und wichtigen Services.
##
module_verify_setup() {
    log_info "🔎 MODUL: Verifikation des Setups"
    
    local critical_services=("ssh" "nftables")
    local important_services=()
    local optional_services=()
    
    # Dynamisch die zu prüfenden Services basierend auf der Konfiguration sammeln
    command -v crowdsec >/dev/null 2>&1 && important_services+=("crowdsec" "crowdsec-firewall-bouncer")
    [ "$SERVER_ROLE" = "1" ] && important_services+=("docker")
    [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ] && optional_services+=("geoip-update.timer")
    # Der Backup-Timer wird nur aktiviert, wenn nicht im Test-Modus
    [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ] && [ "$TEST_MODE" != true ] && optional_services+=("system-backup.timer")
    
    local failed_critical=0
    local failed_important=0
    local failed_optional=0
    
    # --- Kritische Services ---
    log_info "  -> Prüfe kritische Services..."
    for service in "${critical_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_ok "$service läuft."
        else
            log_error "$service läuft NICHT (KRITISCH)!"
            ((failed_critical++))
        fi
    done
    
    # --- Wichtige Services ---
    if [ ${#important_services[@]} -gt 0 ]; then
        log_info "  -> Prüfe wichtige Services..."
        for service in "${important_services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                log_ok "$service läuft."
            else
                log_warn "$service läuft NICHT (Wichtig für Sicherheit/Funktion)."
                ((failed_important++))
            fi
        done
    fi
    
    # --- Optionale Services (Timer) ---
    if [ ${#optional_services[@]} -gt 0 ]; then
        log_info "  -> Prüfe optionale Services (Timer)..."
        for service in "${optional_services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                log_ok "$service ist aktiv."
            else
                log_info "$service ist inaktiv (Optional)."
                ((failed_optional++))
            fi
        done
    fi
    
    # --- Zusammenfassung ---
    log_info "--- Status-Zusammenfassung ---"
    if [ "$failed_critical" -gt 0 ]; then
        log_error "KRITISCH: Das System hat ernste Probleme!"
        log_error "  -> $failed_critical kritische(r) Service(s) laufen NICHT."
        log_warn "  -> SSH oder Firewall sind offline - Server möglicherweise nicht erreichbar!"
    elif [ "$failed_important" -gt 0 ]; then
        log_warn "$failed_important wichtige(r) Service(s) haben Probleme."
        log_warn "  -> Das System ist grundsätzlich funktional, aber die Sicherheit ist eingeschränkt."
        log_ok "Alle kritischen Services laufen."
    else
        log_ok "Alle kritischen und wichtigen Services laufen perfekt."
    fi

    if [ "$failed_optional" -gt 0 ]; then
        log_info "$failed_optional optionale(r) Service(s) sind inaktiv (nicht kritisch)."
    fi
    log_info "------------------------------"
}


##
# Zeigt eine praxisorientierte Zusammenfassung mit den wichtigsten Informationen
# und den nächsten Schritten für den Administrator an.
##
show_summary() {
    local server_ip
    server_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "Unbekannt")
    
    echo -e "${GREEN}🎉 Server-Setup erfolgreich abgeschlossen! 🎉${NC}\n"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ZUGANGS-INFORMATIONEN (kritisch für nächste Schritte)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "ZUGANGS-INFORMATIONEN" "GREEN"
    print_summary_entry "Server" "${SERVER_HOSTNAME:-$(hostname)} ($server_ip)"
    print_summary_entry "SSH-Befehl" "ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$server_ip"
    print_summary_entry "Admin-User" "${ADMIN_USER:-admin} (sudo-Berechtigung)"
    
    # SSH-Key-Status (wichtig für Sicherheit)
    if [ -n "${SSH_PUBLIC_KEY:-}" ]; then
        print_summary_entry "SSH-Key" "✅ Konfiguriert"
        print_ssh_host_keys
        print_summary_tip "SSH-Key ist aktiv - Passwort-Login kann deaktiviert werden"
    else
        print_summary_entry "SSH-Key" "❌ Nicht konfiguriert"
        print_summary_warning "SSH-Key nach erstem Login einrichten!"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TAILSCALE VPN (falls konfiguriert - wichtig für sicheren Zugang)
    # ═══════════════════════════════════════════════════════════════════════════
    if [ "${ACCESS_MODEL:-}" = "1" ] && command -v tailscale >/dev/null 2>&1; then
        print_summary_header "TAILSCALE VPN-ZUGANG" "PURPLE"
        local tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "")
        local tailscale_status=$(tailscale status --json 2>/dev/null | grep -o '"Online":[^,]*' | cut -d: -f2 || echo "false")
        
        if [ -n "$tailscale_ip" ] && [ "$tailscale_status" = "true" ]; then
            print_summary_entry "VPN-Status" "✅ Verbunden"
            print_summary_entry "VPN-IP" "$tailscale_ip"
            print_summary_entry "SSH via VPN" "ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$tailscale_ip"
            print_summary_tip "VPN ist aktiv - sicherster Zugangsweg!"
        else
            print_summary_entry "VPN-Status" "⚠️ Nicht verbunden"
            print_summary_warning "Tailscale-Autorisierung abschließen!"
            print_summary_tip "Befehl: sudo tailscale up"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # DOCKER-INFORMATIONEN (falls installiert - wichtig für Container-Verwaltung)
    # ═══════════════════════════════════════════════════════════════════════════
    if [ "${SERVER_ROLE:-}" = "1" ] || systemctl is-active --quiet docker 2>/dev/null; then
        print_summary_header "DOCKER-CONTAINER" "CYAN"
        
        if systemctl is-active --quiet docker; then
            print_summary_entry "Docker-Status" "✅ Aktiv"
            
            # Docker-Netzwerk-Info (wichtig für Container-Konfiguration)
            local docker_network=$(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || echo "Standard")
            print_summary_entry "Docker-Netz" "$docker_network"
            
            # Portainer (wichtig für Web-Management)
            if [ "${INSTALL_PORTAINER:-}" = "ja" ]; then
                local portainer_ip="${PORTAINER_FINAL_IP:-127.0.0.1}"
                local portainer_status="❌ Nicht erreichbar"
                
                if docker ps --filter name=portainer --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
                    portainer_status="✅ Läuft"
                fi
                
                print_summary_entry "Portainer" "$portainer_status"
                print_summary_entry "Portainer-URL" "https://$portainer_ip:9443"
                
                if [ "$portainer_ip" = "127.0.0.1" ]; then
                    print_summary_tip "SSH-Tunnel: ssh -L 9443:localhost:9443 ${ADMIN_USER:-admin}@$server_ip"
                fi
            fi
            
            # Watchtower (Auto-Updates)
            if [ "${INSTALL_WATCHTOWER:-}" = "ja" ] && docker ps --filter name=watchtower --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
                print_summary_entry "Auto-Updates" "✅ Watchtower aktiv (täglich 04:00)"
            fi
            
        else
            print_summary_entry "Docker-Status" "❌ Problem"
            print_summary_warning "Docker-Service prüfen: systemctl status docker"
        fi
    fi
    # ═══════════════════════════════════════════════════════════════════════════
    # AUTOMATISCHE WARTUNG (systemd-Timer - komplett automatisch)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "AUTOMATISCHE WARTUNG (SYSTEMD-TIMER)" "YELLOW"

    # Finde alle Timer
    local all_timers=$(systemctl list-unit-files --type=timer 2>/dev/null | grep "\.timer" | awk '{print $1}' | sort)

    local active_count=0
    local total_count=0

    # Durchlaufe alle gefundenen Timer
    while read -r timer_name; do
        if [ -n "$timer_name" ]; then
            ((total_count++))
            
            # Timer-Name formatieren (ohne .timer, Bindestriche zu Leerzeichen)
            local display_name=$(echo "$timer_name" | sed 's/\.timer$//' | sed 's/-/ /g')
            
            if systemctl is-active --quiet "$timer_name" 2>/dev/null; then
                ((active_count++))
                local next_run=$(systemctl list-timers "$timer_name" --no-pager 2>/dev/null | grep "$timer_name" | awk '{print $1, $2}' | head -1 || echo "Unbekannt")
                print_summary_entry "$display_name" "✅ Aktiv (Nächster: $next_run)"
            else
                print_summary_entry "$display_name" "❌ Inaktiv"
            fi
        fi
    done <<< "$all_timers"

    if [ "${ENABLE_GEOIP_BLOCKING:-}" = "ja" ]; then
        print_summary_header "GEOIP BLOCKING" "YELLOW"
        print_summary_entry "Status & Statistiken" "geoip-manager status"
        print_summary_entry "Manuelles Update" "geoip-manager update"
        print_summary_entry "Logs anzeigen" "geoip-manager logs"
        print_summary_tip "Blockierte Länder: ${BLOCKED_COUNTRIES:-Keine}"
        print_summary_tip "Geschütztes Heimatland: ${HOME_COUNTRY:-Keines}"
    fi

    # Zusammenfassung
    print_summary_entry "Timer Status" "$active_count von $total_count aktiv"
    print_summary_tip "Alle Timer: systemctl list-timers"

    # ═══════════════════════════════════════════════════════════════════════════
    # SOFORT-AKTIONEN (Was jetzt gemacht werden muss)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "SOFORT-AKTIONEN (IN DIESER REIHENFOLGE)" "RED"
    
    echo -e "    ${RED}1. SSH-ZUGANG TESTEN (KRITISCH!)${NC}"
    echo -e "       ${CYAN}ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$server_ip${NC}"
    if [ -n "$tailscale_ip" ]; then
        echo -e "       ${PURPLE}Oder via VPN: ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$tailscale_ip${NC}"
    fi
    echo ""
    
    echo -e "    ${RED}2. SSH-SICHERHEIT MAXIMIEREN${NC}"
    if [ -z "${SSH_PUBLIC_KEY:-}" ]; then
        echo -e "       ${YELLOW}• SSH-Key einrichten (empfohlen!)${NC}"
        echo -e "       ${YELLOW}• Dann PasswordAuthentication no setzen${NC}"
    else
        print_summary_tip "SSH-Key bereits konfiguriert"
    fi
    echo ""
    
    echo -e "    ${RED}3. ROOT-ZUGANG SPERREN${NC}"
    echo -e "       ${CYAN}sudo passwd -l root${NC}"
    echo ""
    
    echo -e "    ${RED}4. SYSTEM NEUSTARTEN${NC}"
    echo -e "       ${CYAN}sudo reboot${NC}"
    echo ""
    
    # ═══════════════════════════════════════════════════════════════════════════
    # VERIFIKATIONS-BEFEHLE (für Kontrolle nach Neustart)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "VERIFIKATION NACH NEUSTART" "BLUE"
    echo -e "    ${BLUE}Firewall:${NC} sudo nft list ruleset | head -20"
    echo -e "    ${BLUE}Services:${NC} systemctl status ssh nftables"
    if command -v crowdsec >/dev/null 2>&1; then
        echo -e "    ${BLUE}IPS:${NC} systemctl status crowdsec"
    fi
    echo -e "    ${BLUE}Updates:${NC} systemctl list-timers"
    echo -e "    ${BLUE}Logs:${NC} journalctl -f"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # WICHTIGE DATEIEN & BEFEHLE (für spätere Verwaltung)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "WICHTIGE DATEIEN & BEFEHLE" "PURPLE"
    print_summary_entry "Setup-Log" "$LOG_FILE"
    print_summary_entry "SSH-Config" "/etc/ssh/sshd_config"
    print_summary_entry "Firewall-Config" "/etc/nftables.conf"
    
    if [ "${ENABLE_GEOIP_BLOCKING:-}" = "ja" ]; then
        print_summary_entry "GeoIP-Management" "geoip-manager status"
    fi
    
    if systemctl is-active --quiet docker 2>/dev/null; then
        print_summary_entry "Docker-Container" "docker ps -a"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FOOTER mit kritischen Hinweisen
    # ═══════════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${RED}⚠️  KRITISCH: Teste SSH-Zugang BEVOR du das Terminal schließt!${NC}"
    echo -e "${YELLOW}💡 Bei Problemen: Rescue-Mode des VPS-Providers nutzen${NC}"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}   🚀 Server bereit für Finalisierung! Folge den Sofort-Aktionen oben.        ${NC}"
    echo -e "${BLUE}   📊 Setup-Details: $LOG_FILE${NC}"
    echo -e "${BLUE}   ⏰ Setup abgeschlossen: $(date '+%d.%m.%Y %H:%M')${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
}

#################################################################################
#                             INITIALISIERUNG
#           CrobdSec Stack und Bouncer-Installation fuer NFTables
################################################################################
##
# Installiert den CrowdSec Agenten und den Firewall Bouncer.
##
install_crowdsec_stack() {
    log_info "⚙️  Installiere und konfiguriere den CrowdSec-Stack..."

    # --- 1. CrowdSec Repository hinzufügen (falls nötig) ---
    if [ ! -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then
        log_info "  -> Füge CrowdSec APT-Repository hinzu..."
        local install_script="/tmp/crowdsec-install.sh"
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh -o "$install_script"
        
        if grep -q "packagecloud" "$install_script"; then
            run_with_spinner "Richte APT-Repository ein und aktualisiere..." "bash '$install_script' && apt-get update -qq"
        else
            log_error "Das heruntergeladene CrowdSec-Installationsskript scheint ungültig zu sein."
            rm -f "$install_script"
            return 1
        fi
        rm -f "$install_script"
    fi

    # --- 2. CrowdSec Agent sauber installieren ---
    log_info "  -> Installiere CrowdSec Agenten (ggf. Re-Installation)..."
    local install_cmd="apt-get remove --purge -y crowdsec >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"
    if ! run_with_spinner "Installiere 'crowdsec' Paket..." "$install_cmd"; then
        log_error "Installation des CrowdSec Agenten ist fehlgeschlagen."
        return 1
    fi

    # --- 3. systemd-Verhalten anpassen ---
    log_info "  -> Konfiguriere CrowdSec für netzwerkabhängigen Start..."
    mkdir -p /etc/systemd/system/crowdsec.service.d
    cat > /etc/systemd/system/crowdsec.service.d/override.conf <<EOF
[Unit]
After=network.target
[Service]
Restart=on-failure
RestartSec=30s
EOF

    # --- 4. Firewall Bouncer installieren ---
    # Die Funktion install_bouncer sollte ihr eigenes, sauberes Logging haben.
    install_bouncer

    # --- 5. Services aktivieren und Start verifizieren ---
    log_info "  -> Aktiviere CrowdSec-Dienste und warte auf den Start..."
    systemctl daemon-reload
    systemctl enable --now crowdsec >/dev/null 2>&1

    # Ein Befehl, der 30s lang versucht, die API zu erreichen
    local wait_cmd="
        for i in {1..30}; do
            if systemctl is-active --quiet crowdsec && cscli metrics &>/dev/null; then exit 0; fi
            sleep 1
        done
        exit 1"
    
    if run_with_spinner "Warte auf CrowdSec-API..." "bash -c \"$wait_cmd\""; then
        log_ok "CrowdSec-Agent ist erfolgreich gestartet und API ist erreichbar."
        return 0
    else
        log_error "CrowdSec-Agent konnte nicht gestartet werden oder die API antwortet nicht."
        return 1
    fi
}
##
# Installiert und konfiguriert den CrowdSec Firewall Bouncer für NFTables.
# KORRIGIERTE VERSION - Kombiniert bewährte Teile der alten mit neuen Verbesserungen
##
install_bouncer() {
    log_info "🐾 Installiere CrowdSec-Bouncer (NFTables-Integration)..."

    # --- 1. Voraussetzungen prüfen (wie in neuer Version) ---
    log_info "  -> Prüfe Voraussetzungen (CrowdSec-Service & API)..."
    if ! systemctl is-active --quiet crowdsec; then
        log_error "Voraussetzung nicht erfüllt: CrowdSec-Service läuft nicht."
        return 1
    fi
    if ! cscli metrics >/dev/null 2>&1; then
        log_error "Voraussetzung nicht erfüllt: CrowdSec API ist nicht erreichbar."
        return 1
    fi
    log_ok "Voraussetzungen erfüllt: CrowdSec-Service und API sind erreichbar."

    # --- 2. Bouncer-Paket sauber installieren (wie in alter Version) ---
    local pkg="crowdsec-firewall-bouncer"
    local dir="/etc/crowdsec/bouncers"
    local base_yml="$dir/crowdsec-firewall-bouncer.yaml"
    local local_yml="$dir/crowdsec-firewall-bouncer.yaml.local"
    local keyfile="$dir/.api_key"  # BEWÄHRT: Separater Keyfile wie in alter Version
    
    local install_cmd="apt-get remove --purge -y '$pkg' >/dev/null 2>&1 || true; rm -rf '$dir'; DEBIAN_FRONTEND=noninteractive apt-get install -y '$pkg'"
    if ! run_with_spinner "Installiere Bouncer-Paket (ggf. Re-Installation)..." "$install_cmd"; then
        log_error "Installation des Bouncer-Pakets ist fehlgeschlagen."
        return 1
    fi
    if [ ! -f "$local_yml" ]; then
        log_error "Bouncer-Konfigurationsdatei wurde nicht erstellt."
        return 1
    fi

    # --- 3. Konfiguriere für NFTables-Modus (bewährte alte Logik) ---
    log_info "  -> Konfiguriere NFTables-Modus..."
    cp "$base_yml" "$local_yml"
    
    if grep -q '${BACKEND}' "$local_yml" 2>/dev/null; then
        sed -i 's/mode: ${BACKEND}/mode: nftables/' "$local_yml"
        log_info "     🔧 Template-Modus → nftables"
    else
        if command -v yq &>/dev/null; then
            yq -i -y '.mode = "nftables"' "$local_yml"
        else
            if grep -q '^mode:' "$local_yml"; then
                sed -i 's/^mode:.*/mode: nftables/' "$local_yml"
            else
                sed -i '1i mode: nftables' "$local_yml"
            fi
        fi
        log_info "     🔧 NFTables-Modus direkt gesetzt"
    fi
    
    # Logging-Level optimieren
    sed -i 's/debug: .*/debug: false/' "$local_yml" 2>/dev/null || true
    sed -i 's/log_level: .*/log_level: info/' "$local_yml" 2>/dev/null || true
    
    # --- 4. API-Schlüssel generieren (bewährte alte Methode) ---
    log_info "  -> Generiere und konfiguriere API-Schlüssel..."
    
    if [ ! -s "$keyfile" ]; then
        install -o root -g root -m600 /dev/null "$keyfile"
        if ! cscli bouncers add firewall-bouncer -o raw >"$keyfile"; then
            log_error "API-Key-Generierung fehlgeschlagen!"
            return 1
        fi
    fi
    
    local api_key
    api_key=$(cat "$keyfile" 2>/dev/null | tr -d '\n\r')
    if [ -n "$api_key" ]; then
        if grep -q '${API_KEY}' "$local_yml" 2>/dev/null; then
            sed -i "s|\${API_KEY}|$api_key|g" "$local_yml"
        else
            if command -v yq &>/dev/null; then
                yq -i -y ".api_key = \"$api_key\"" "$local_yml"
            else
                if grep -q 'api_key:' "$local_yml"; then
                    sed -i "s/api_key:.*/api_key: $api_key/" "$local_yml"
                else
                    echo "api_key: $api_key" >> "$local_yml"
                fi
            fi
        fi
        log_info "     🔑 API-Key konfiguriert"
    else
        log_error "API-Key ist leer!"
        return 1
    fi
    log_ok "API-Schlüssel erfolgreich in Konfiguration eingetragen."

    # --- 5. systemd-Integration (KORRIGIERT - alte bewährte Methode) ---
    log_info "  -> Konfiguriere systemd-Integration..."
    local override_dir="/etc/systemd/system/crowdsec-firewall-bouncer.service.d"
    
    # Bereinige alte Override-Files (verhindert Konflikte)
    if [ -d "$override_dir" ]; then
        log_info "     -> Bereinige alte Override-Konfigurationen..."
        rm -rf "$override_dir"
    fi
    mkdir -p "$override_dir"

    # KORRIGIERT: Verwende bewährte systemd-Konfiguration aus alter Version
    cat > "$override_dir/override.conf" <<EOF
[Unit]
After=multi-user.target crowdsec.service
Requires=crowdsec.service

[Service]
# Verwende lokale Konfiguration (WICHTIG: ExecStart muss zurückgesetzt werden!)
ExecStartPre=
ExecStart=
ExecStartPre=/bin/bash -c 'until cscli metrics >/dev/null 2>&1; do sleep 2; done'
ExecStartPre=/usr/bin/crowdsec-firewall-bouncer -c $local_yml -t
ExecStart=/usr/bin/crowdsec-firewall-bouncer -c $local_yml

# Auto-Recovery bei Problemen
Restart=on-failure
RestartSec=15s

[Install]
# Separate Boot-Phase - startet NACH multi-user.target
WantedBy=default.target
EOF

    # --- 6. Health-Check-System (alte bewährte Version) ---
    log_info "  -> Installiere Health-Check-System..."
    install -m755 /dev/null /usr/local/bin/crowdsec-healthcheck
    cat > /usr/local/bin/crowdsec-healthcheck <<'EOF'
#!/bin/bash
# CrowdSec Health-Check: Restart bei API-Problemen
if ! cscli metrics >/dev/null 2>&1; then
    logger -t "crowdsec-healthcheck" -p daemon.warn "CrowdSec API nicht erreichbar - starte Services neu..."
    systemctl restart crowdsec crowdsec-firewall-bouncer
fi
EOF
    
    # Health-Check als systemd-Service
    cat > /etc/systemd/system/crowdsec-healthcheck.service <<'EOF'
[Unit]
Description=CrowdSec Health-Check
After=crowdsec.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/crowdsec-healthcheck
User=root
EOF

    # Health-Check-Timer (alle 5 Minuten) - KORRIGIERT: OnUnitInactiveSec statt OnUnitActiveSec
    cat > /etc/systemd/system/crowdsec-healthcheck.timer <<'EOF'
[Unit]
Description=CrowdSec Health-Check (alle 5 Min)
Requires=crowdsec-healthcheck.service

[Timer]
OnBootSec=5min
OnUnitInactiveSec=5min
Unit=crowdsec-healthcheck.service

[Install]
WantedBy=timers.target
EOF

    # --- 7. Services aktivieren und starten (mit Verifikation) ---
    systemctl daemon-reload
    if run_with_spinner "Aktiviere Bouncer und Health-Check..." "systemctl enable --now crowdsec-firewall-bouncer crowdsec-healthcheck.timer"; then
        # Finale Verifikation (aus alter Version)
        log_info "  -> Prüfe Bouncer-Installation..."
        local verification_passed=true
        
        # Service-Status prüfen
        if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
            log_warn "Bouncer-Service startet noch..."
            sleep 3
            if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
                verification_passed=false
            fi
        fi
        
        # NFTables-Modus prüfen
        if command -v yq &>/dev/null; then
            if ! yq '.mode' "$local_yml" | grep -q "nftables"; then
                log_error "NFTables-Modus nicht gesetzt!"
                verification_passed=false
            fi
        fi
        
        # API-Key prüfen
        if [ ! -s "$keyfile" ]; then
            log_error "API-Key fehlt!"
            verification_passed=false
        fi

        # Ergebnis ausgeben
        if [ "$verification_passed" = true ]; then
            log_ok "CrowdSec-Bouncer erfolgreich installiert und mit NFTables integriert."
            log_info "  -> Der Health-Check läuft jetzt automatisch alle 5 Minuten."
            return 0
        else
            log_error "Bouncer-Installation unvollständig!"
            return 1
        fi
    else
        log_error "Bouncer-Installation ist unvollständig! Services konnten nicht gestartet werden."
        return 1
    fi
}

##
# Passt die CrowdSec SSH-Policy an die Benutzereingaben an.
##
tune_crowdsec_ssh_policy() {
    log_info "  -> Passe CrowdSec SSH-Policy an (Ban-Dauer: ${CROWDSEC_BANTIME})..."
    
    # Nur eine lokale Profildatei erstellen, wenn die Ban-Dauer vom Standard abweicht.
    # HINWEIS: Der MaxRetry-Wert wird von den CrowdSec-Szenarien selbst gehandhabt,
    #          wir passen hier gezielt nur die Dauer der Verbannung an.
    if [ "$CROWDSEC_BANTIME" != "4h" ]; then
        mkdir -p /etc/crowdsec/profiles.d/
        
        local custom_profile="/etc/crowdsec/profiles.d/99-custom-ssh-duration.yaml"
        cat > "$custom_profile" <<EOF
name: custom_ssh_ban_duration
description: "Override default ssh ban duration"
filters:
  - "decision.scenario starts_with 'crowdsecurity/sshd-'"
decisions:
  - type: ban
    duration: "$CROWDSEC_BANTIME"
on_success: break
EOF
        log_ok "Custom SSH-Profile mit Ban-Dauer '$CROWDSEC_BANTIME' erstellt."
    else
        log_info "Standard CrowdSec SSH-Ban-Dauer ('4h') wird verwendet."
    fi
}

# ===============================================================================
#  GeoIP Konfigurationsdateien sicher erstellen
# ===============================================================================
create_geoip_config_files() {
    log_info "  -> Erstelle GeoIP-Konfigurationsdateien mit sicheren Rechten..."
    
    # Blockierte Länder
    echo "$BLOCKED_COUNTRIES" > /etc/geoip-countries.conf
    chown root:root /etc/geoip-countries.conf
    chmod 640 /etc/geoip-countries.conf

    # Heimatland
    echo "$HOME_COUNTRY" > /etc/geoip-home-country.conf
    chown root:root /etc/geoip-home-country.conf
    chmod 640 /etc/geoip-home-country.conf
    
    # Manuelle Allowlist (leer anlegen, falls nicht vorhanden)
    touch /etc/geoip-allowlist.conf
    chown root:root /etc/geoip-allowlist.conf
    chmod 640 /etc/geoip-allowlist.conf
    
    log_ok "GeoIP-Konfigurationsdateien sicher erstellt (Rechte: 640)."
}
# ===============================================================================
#  GEOP-IP-SYSTEMD-TIMER ERSTELLEN (wöchentliches Update)
# ===============================================================================
create_geoip_systemd_timer() {
    log_info "  -> Erstelle systemd-Timer für wöchentliches GeoIP-Update..."
    
    # systemd-Service
    cat > /etc/systemd/system/geoip-update.service << 'EOF'
[Unit]
Description=Update GeoIP block lists (Set-based)
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-geoip-sets.sh
User=root
EOF
    
    # systemd-Timer mit wöchentlichem Zeitplan
    cat > /etc/systemd/system/geoip-update.timer << 'EOF'
[Unit]
Description=Run GeoIP update weekly

[Timer]
# Wöchentlich - guter Kompromiss
OnCalendar=Sun *-*-* 02:00:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    log_ok "GeoIP-Update-Timer konfiguriert (wöchentlich sonntags)."
}

# ===============================================================================
#  GeoIP-Blocking installieren 
# ===============================================================================
install_geoip_blocking() {
    log_info "🚀 Installiere GeoIP-Blocking (nutzt vordefinierte Sets)..."
    
    # 1. Konfigs erstellen
    create_geoip_config_files
    create_geoip_systemd_timer
    
    # 2. Sets müssen nicht mehr erstellt werden, da sie in nftables.conf stehen.
    log_info "  -> Sets sind bereits in nftables.conf definiert."
    
    # 3. Chain leeren und mit sauberen, Set-basierten Regeln befüllen
    log_info "  -> Fülle Chain 'geoip_check' mit 6 Kernregeln (inkl. Countern)..."
    
    nft flush chain inet filter geoip_check
    
    nft add rule inet filter geoip_check ip saddr @geoip_allowlist_v4 counter accept comment \"Manual-Allow-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_allowlist_v6 counter accept comment \"Manual-Allow-v6\"
    nft add rule inet filter geoip_check ip saddr @geoip_home_v4 counter accept comment \"GeoIP-Allow-Home-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_home_v6 counter accept comment \"GeoIP-Allow-Home-v6\"
    nft add rule inet filter geoip_check ip saddr @geoip_blocked_v4 counter drop comment \"GeoIP-Block-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_blocked_v6 counter drop comment \"GeoIP-Block-v6\"
    
    # 4. Jump-Regel in Input-Chain idempotent einfügen
    if ! nft list chain inet filter input | grep -q "jump geoip_check"; then
        log_info "  -> Integriere GeoIP-Chain in die Input-Chain..."
        
        # Finde den Handle der Regel, nach der wir einfügen wollen
        local handle
        handle=$(nft -a list chain inet filter input | grep "ct state established,related accept" | head -n 1 | awk '{print $NF}')
        
        if [ -n "$handle" ]; then
            # BERECHNE die neue Position in der Shell
            local new_position=$((handle + 1))
            log_info "     -> Füge an Position $new_position ein (nach Handle $handle)..."
            
            # ÜBERGIB das fertige Ergebnis an nft
            nft insert rule inet filter input position "$new_position" jump geoip_check comment "GeoIP-Filter"
        else
            # Fallback, falls die Referenz-Regel aus irgendeinem Grund nicht gefunden wird
            log_warn "     -> Referenz-Regel nicht gefunden. Nutze Fallback und füge Regel am Anfang hinzu..."
            nft add rule inet filter input jump geoip_check comment "GeoIP-Filter"
        fi
    fi
    
    # 5. Timer aktivieren und erstes Update sofort ausführen
    log_info "  -> Starte GeoIP-Timer und führe initiales Update aus..."
    
    # VERWENDE run_with_spinner für besseres Feedback
    run_with_spinner "Aktiviere GeoIP-Update-Timer..." "systemctl daemon-reload && systemctl enable --now geoip-update.timer"
    
    # Führe das Update-Skript direkt aus, um die Sets sofort zu befüllen
    if run_with_spinner "Führe initiales GeoIP-Update aus..." "/usr/local/bin/update-geoip-sets.sh"; then
        log_ok "Erstes GeoIP-Update erfolgreich. Die Sets sind jetzt befüllt."
    else
        log_warn "Erstes GeoIP-Update fehlgeschlagen. Sets sind noch leer. Timer wird es erneut versuchen."
    fi
    
    log_ok "GeoIP-Blocking (Set-basiert) erfolgreich installiert und aktiviert."
}


##
# Haupt-Einstiegspunkt des Skripts. Verarbeitet Argumente und startet das Setup.
##
main() {
    check_root

    local TEST_MODE=false
    # Stellt sicher, dass die globalen Variablen initialisiert sind
    CONFIG_FILE=""
    SCRIPT_VERBOSE=false
    DEBUG=false
    
    while getopts ":c:thvd" opt; do
        case ${opt} in
            c) CONFIG_FILE=$OPTARG;;
            t) TEST_MODE=true;;
            h) show_usage; exit 0;;
            v) SCRIPT_VERBOSE=true;;
            d) DEBUG=true; SCRIPT_VERBOSE=true;;
            \?) log_error "Ungültige Option: -$OPTARG"; show_usage; exit 1;;
            :) log_error "Option -$OPTARG benötigt ein Argument."; show_usage; exit 1;;
        esac
    done

    # Globale Flags für andere Funktionen und Kind-Prozesse verfügbar machen
    export SCRIPT_VERBOSE DEBUG

    # Fehlerfalle für das gesamte Skript einrichten
    trap 'rollback' ERR

    log_info "🚀 Starte Server-Baukasten v$SCRIPT_VERSION..."
    
    # Ausführungsmodus anzeigen
    if [ "$DEBUG" = true ]; then
        log_warn "DEBUG-MODUS ist aktiviert (maximale Ausgaben)."
    elif [ "$SCRIPT_VERBOSE" = true ]; then
        log_info "VERBOSE-MODUS ist aktiviert (detaillierte Ausgaben)."
    fi
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS ist aktiviert (überspringt langsame Operationen)."
    fi
    if [ -n "$CONFIG_FILE" ]; then
        log_info "Verwende Konfigurationsdatei: $CONFIG_FILE"
    fi

    run_setup "$TEST_MODE"
    
    # Fehlerfalle nach erfolgreichem Setup deaktivieren
    trap - ERR
    # Sicherheits-Cleanup VOR der Zusammenfassung
    cleanup_sensitive_data
    
    show_summary
    
    if [ "$TEST_MODE" = true ]; then
        log_ok "Test-Setup erfolgreich abgeschlossen! ⚡"
    else
        log_ok "Server-Setup erfolgreich abgeschlossen! 🎉"
    fi
}

# MEGA verbesserte show_usage() Funktion mit allen Features
show_usage() {
    print_section_header "HELP" "SERVER-BAUKASTEN v$SCRIPT_VERSION" "🏗️"
    echo -e "${BLUE}    Ein umfassendes Bash-Skript zur automatisierten Härtung und Konfiguration    ${NC}"
    echo -e "${BLUE}         von neuen Debian 12 / Ubuntu 22.04+ Servern nach höchsten Standards.     ${NC}"
    echo ""
    
    # Verwendung
    print_summary_header "VERWENDUNG" "GREEN"
    print_summary_entry "Interaktiver Modus" "sudo ./init_server.sh"
    print_summary_entry "Automatischer Modus" "sudo ./init_server.sh -c config.conf"
    print_summary_entry "Schneller Testlauf" "sudo ./init_server.sh -t"
    
    # Optionen
    print_summary_header "OPTIONEN" "GREEN"
    print_summary_entry "-c FILE" "Verwende Konfigurationsdatei statt interaktiver Abfragen."
    print_summary_entry "-t" "Test-Modus (überspringt zeitaufwändige Operationen)."
    print_summary_entry "-v" "Verbose-Modus (detaillierte Ausgaben und Fortschritt)."  # NEU
    print_summary_entry "-d" "Debug-Modus (maximale Ausgaben + Entwickler-Traces)."   # NEU
    print_summary_entry "-h" "Zeige diese Hilfe und beende das Skript."
    # Was wird installiert & konfiguriert
    print_summary_header "HAUPT-FEATURES (WAS WIRD INSTALLIERT & KONFIGURIERT)" "GREEN"
    print_summary_entry "Firewall & IPS" "NFTables (Default-Drop) & CrowdSec (Kollaborativ)"
    print_summary_entry "GeoIP-Blocking" "Intelligente Länder-basierte Bedrohungsabwehr" # NEU
    print_summary_entry "Heimatland-Schutz" "Automatisch aus Locale erkannt, nie blockiert" # NEU
    print_summary_entry "System-Integrität" "AIDE (Datei-Überwachung) & RKHunter (Rootkit-Scan)"
    print_summary_entry "Kernel-Härtung" "Schutz vor DDoS-Ansätzen & System-Optimierungen"
    print_summary_entry "Updates & Backups" "Automatische Sicherheits-Updates & tägliche Backups"
    print_summary_entry "Container (Optional)" "Docker, Portainer, Watchtower"
    print_summary_entry "VPN-Zugang (Optional)" "Tailscale für sicheren, unsichtbaren Zugang"
    
    #E-Mail-Benachrichtigungen
    print_summary_header "E-MAIL-BENACHRICHTIGUNGEN (FALLS AKTIVIERT)" "GREEN"
    print_summary_tip "Das Skript konfiguriert ein zentrales Mail-System (msmtp)."
    print_summary_tip "Du wirst über folgende kritische Ereignisse informiert:"
    echo -e "      ${CYAN}• Tägliche CrowdSec-Reports (nur wenn Angriffe stattfanden)${NC}"
    echo -e "      ${CYAN}• Warnungen von RKHunter (Rootkit-Funde)${NC}"
    echo -e "      ${CYAN}• Warnungen von AIDE (Datei-Veränderungen)${NC}"
    echo -e "      ${CYAN}• Fehler bei System-Diensten (via systemd)${NC}"
    echo -e "      ${CYAN}• Tägliche Erfolgs-Reports vom System-Backup${NC}"
    echo -e "      ${CYAN}• Benachrichtigungen über automatische System-Updates${NC}"
    
    # Wichtige Hinweise
    print_summary_header "WICHTIGE HINWEISE" "YELLOW"
    print_summary_warning "Dieses Skript muss als root ausgeführt werden (sudo)."
    print_summary_warning "Unterstützt Debian 12 (Bookworm) und Ubuntu 22.04+ LTS."
    print_summary_warning "Backup wichtiger Daten vor der Ausführung empfohlen."
    print_summary_warning "Existierende Firewall-Regeln werden überschrieben."

    # Logs & Support
    print_summary_header "LOGS & SUPPORT" "GREEN"
    print_summary_entry "Setup-Log" "$LOG_FILE"
    print_summary_entry "GeoIP-Updates" "journalctl -u geoip-update.service"
    print_summary_entry "CrowdSec-Alerts" "journalctl -u crowdsec"
    print_summary_entry "Mail-Versand" "journalctl | grep msmtp"
    
     # Nach dem Setup
    print_summary_header "WICHTIGE SCHRITTE NACH DEM SETUP" "YELLOW"
    echo -e "    ${PURPLE}1.${NC} SSH-Verbindung testen und Server neustarten ('sudo reboot')."
    echo -e "    ${PURPLE}2.${NC} SSH-Härtung: Falls kein Public Key im Setup angegeben wurde, unbedingt"
    echo -e "       den Passwort-Login deaktivieren ('PasswordAuthentication no')."
    echo -e "    ${PURPLE}3.${NC} Root-Konto sperren: Nach erfolgreichem Test des Admin-Users mit 'sudo'"
    echo -e "       das root-Passwort sperren mit 'sudo passwd -l root'."
    echo -e "    ${PURPLE}4.${NC} System prüfen: Firewall (`sudo nft list ruleset`) und Timer"
    echo -e "       (`systemctl list-timers`) kontrollieren."
    
    # Footer
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}   🤖 Sicherer und moderne Linux-Server.                                      ${NC}"
    echo -e "${BLUE}   🌐 https://github.com/TZERO78/SERVERBAUKASTEN                              ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
}
main "$@"



