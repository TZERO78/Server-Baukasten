#!/bin/bash
################################################################################
#
# UI-HELPER-FUNKTIONEN
#
# @description: Funktionen für die Benutzeroberfläche und Konsolenausgabe.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

# Farben für die Ausgabe
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'

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