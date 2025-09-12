#!/bin/bash
################################################################################
#
# VALIDIERUNGS-HELFER-FUNKTIONEN
#
# @description: Funktionen zur Validierung von Eingaben, Dateipfaden und Werten.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

is_valid_email() {
    [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

## Prüft, ob eine IPv4-Adresse gültig ist.
## param string $1 Die zu prüfende IP-Adresse.
## return int 0=gültig, 1=ungültig
is_valid_ipv4() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do if ((octet > 255)); then return 1; fi; done
        return 0
    fi
    return 1
}

## Prüft, ob eine IPv6-Adresse gültig ist.
## param string $1 Die zu prüfende IP-Adresse.
## return int 0=gültig, 1=ungültig 
## Hinweis: Diese Prüfung ist relativ einfach und deckt nicht alle Randfälle ab.
is_valid_ipv4_cidr() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]] && is_valid_ipv4 "$(echo "$1" | cut -d'/' -f1)"
}

## Prüft, ob eine IPv6-Adresse gültig ist.
## param string $1 Die zu prüfende IP-Adresse.
## return int 0=gültig, 1=ungültig
is_valid_ipv6_cidr() {
    [[ "$1" =~ ^([0-9a-fA-F:]+:+[0-9a-fA-F:.]*)/([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$ ]]
}

## Prüft, ob Username gültig ist (Linux-Standard).
##  param string $1 Der zu prüfende Username.
##  return int 0=gültig, 1=ungültig
is_valid_username() {
    [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

## Prüft, ob ein Hostname gültig ist (RFC 1123).
## param string $1 Der zu prüfende Hostname.
## return int 0=gültig, 1=ungültig
is_valid_hostname() {
    [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ && ${#1} -le 253 ]]
}

##  Prüft, ob ein SSH Public Key gültig ist (sehr einfache Prüfung).
##  param string $1 Der zu prüfende SSH Public Key.
##  return int 0=gültig, 1=ungültig
##  Hinweis: Diese Prüfung ist relativ einfach und deckt nicht alle Randfälle ab.
is_valid_ssh_pubkey() {
    [[ "$1" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ]]
}

## Prüft, ob ein Port gültig ist (1025-65535).
## param string $1 Der zu prüfende Port.
## return int 0=gültig, 1=ungültig
is_valid_port() {
    local p="$1"
    if [[ "$p" =~ ^[0-9]+$ && "$p" -gt 1024 && "$p" -le 65535 ]]; then return 0; else return 1; fi
}
## Prüft, ob ein Wert numerisch ist (ganzzahlig).
## param string $1 Der zu prüfende Wert.
## return int 0=numerisch, 1=nicht numerisch
is_numeric() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

## Prüft ob eine Zeitzone echt existiert
## param string $1 Die zu prüfende Zeitzone (z.B. "Europe/Berlin").
## return int 0=gültig, 1=ungültig 
is_valid_timezone() {
    [ -f "/usr/share/zoneinfo/$1" ]
}

## Prüft ob ein Ländercode echt existiert (gegen GeoIP-Datenbank)
## param string $1 Der zu prüfende Ländercode (ISO 3166-1 alpha-2, z.B. "DE").
## return int 0=gültig, 1=ungültig
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

## Prüft, ob eine Liste von Ländercodes gültig ist.
## param string $1 Die zu prüfende Liste von Ländercodes (z.B. "DE FR IT").
## return int 0=gültig, 1=ungültig
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

## Validiert eine Liste von Ländercodes und gibt Feedback.
## param string $1 Die zu prüfende Liste von Ländercodes (z.B. "DE FR IT XX").
## return int 0=alle gültig, 1=ungültige Codes gefunden und Feedback ausgegeben
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

## Prüft, ob Wert 1 oder 2 ist
## param string $1 Der zu prüfende Wert.
## return int 0=gültig, 1=ungültig
is_choice_1_2() { [[ "$1" =~ ^[12]$ ]]; }

## Prüft, ob Wert 'ja' oder 'nein' ist
## param string $1 Der zu prüfende Wert.
## return int 0=gültig, 1=ungültig  
is_yes_no() { [[ "$1" =~ ^(ja|nein)$ ]]; }

