#!/bin/bash
################################################################################
#
# KERN-HELFER-FUNKTIONEN
#
# @description: Zentrale Hilfsfunktionen für das Skript-Management und die Ausführung.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

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
# LOGIK- & SYSTEM-FUNKTIONEN
# - Vorab-Prüfungen, Dateiverwaltung und Rollback.
#
################################################################################

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

##
## Erkennt das Betriebssystem und die Version aus /etc/os-release.
## Setzt die globalen Variablen OS_ID und OS_VERSION_CODENAME.
## Bricht mit einem Fehler ab, wenn die Datei nicht gefunden wird.
## @return int 0=Erfolg, 1=Fehler 
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
## Führt Vorab-Prüfungen durch, um sicherzustellen, dass alle benötigten Befehle vorhanden sind.
## Bricht das Skript mit einer Fehlermeldung ab, wenn kritische Befehle fehlen.
## @return int 0=Erfolg, 1=Fehler
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
# Erstellt ein Backup einer Datei, falls noch keins existiert, und registriert sie für ein Rollback.
# @param string $1 Der Pfad zur Datei.
##
backup_and_register() {
    local file="$1"
    if [ -f "$file" ] && [ ! -f "${file}.bak" ]; then cp "$file" "${file}.bak"; BACKUP_FILES+=("$file"); fi
}


##
## Führt ein Rollback aller registrierten Dateien durch, falls ein kritischer Fehler auftritt.
## Stellt die Dateien aus den Backups wieder her und bereinigt temporäre sudo-Einträge.
## Bricht das Skript mit einem Fehlercode ab.
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
## Bietet an, die Konfigurationsdatei mit sensiblen Daten am Ende des Skripts sicher zu löschen.
## @param bool $1 TEST_MODE (true/false) - Wenn true, wird die Löschung übersprungen.
## Hinweis: Diese Funktion sollte am Ende des Hauptskripts aufgerufen werden.
##
cleanup_sensitive_data() {
    local TEST_MODE="$1"

    # Prüfe, ob der Test-Modus aktiv ist
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS: Überspringe Bereinigung der sensiblen Konfigurationsdatei."
        return 0
    fi

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
                fi
            else
                log_warn "'shred' ist nicht installiert. Nutze 'rm' als Fallback."
                rm -f "$CONFIG_FILE"
                log_ok "Konfigurationsdatei gelöscht (möglicherweise wiederherstellbar)."
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

################################################################################
#
# KONFIGURATIONS- & TEMPLATE-ENGINE
# - Funktionen zum Laden, Schreiben und Verarbeiten von Konfigurationsdateien.
#
################################################################################

##
# Lädt eine Konfigurations-Vorlage von GitHub herunter, ersetzt Variablen (falls vorhanden)
# und setzt die korrekten Berechtigungen.
# @param string $1 Name der Vorlage auf GitHub (z.B. "aide.conf.template").
# @param string $2 Zieldatei auf dem Server (z.B. "/etc/aide/aide.conf").
# @param string $3 Oktale Dateiberechtigungen (z.B. "640").
# @param string $4 Besitzer und Gruppe (z.B. "root:root").
##
download_and_process_template() {
    local template_name="$1"
    local dest_path="$2"
    local permissions="$3"
    local owner="$4"
    
    local source_url="${CONF_BASE_URL}/${template_name}"
    local temp_file
    temp_file=$(mktemp)

    if ! run_with_spinner "Lade Vorlage '$template_name'..." "curl -fsSL '$source_url' -o '$temp_file'"; then
        log_error "Download der Vorlage '$template_name' ist fehlgeschlagen."
        rm -f "$temp_file"
        return 1
    fi
    
    # Erstelle Zielverzeichnis, falls es nicht existiert
    mkdir -p "$(dirname "$dest_path")"
    
    # Ersetze alle ${VARIABLE} Platzhalter und schreibe die finale Datei.
    # Funktioniert auch, wenn keine Variablen zu ersetzen sind.
    envsubst < "$temp_file" > "$dest_path"
    rm -f "$temp_file"
    
    # Setze Berechtigungen und Besitzer
    chmod "$permissions" "$dest_path"
    chown "$owner" "$dest_path"
    
    log_ok "Vorlage '$template_name' erfolgreich nach '$dest_path' installiert."
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

#################################################################################
#  LOGGING-SYSTEM
#  - Symbole für die Konsolenausgabe.
#  - Text-Präfixe und korrekte Level für das System-Journal (journald).
#################################################################################

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

##################################################################################
# SUDOERS BEST PRACTICE INTEGRATION
# - Sicheres, atomares Schreiben von sudoers-Einträgen
##################################################################################

# Validiert und schreibt sudoers-Einträge atomar mit vollständiger Fehlerprüfung.
# @param string $1 Der sudoers-Inhalt (z.B. "user ALL=(ALL:ALL) ALL")
# @param string $2 Zieldatei (z.B. "/etc/sudoers.d/50-user")
# @return int 0=Erfolg, 1=Fehler
##
write_sudoers_entry_safe() {
    local content="$1"
    local target_file="$2"
    
    # 🛡️ GUARD: Parameter-Validierung
    if [ -z "$content" ] || [ -z "$target_file" ]; then
        log_error "write_sudoers_entry_safe: Fehlende Parameter"
        return 1
    fi
    
    # 🧪 Erstelle temporäre Datei für Validierung
    local temp_file
    temp_file=$(mktemp) || {
        log_error "Konnte temporäre Datei nicht erstellen"
        return 1
    }
    
    # 🔒 Cleanup-Trap für temp file (lokaler scope)
    trap "rm -f '$temp_file'" RETURN
    
    # ✍️ Schreibe Inhalt in temporäre Datei
    printf '%s\n' "$content" > "$temp_file"
    
    # 🔍 KRITISCH: visudo-Validierung VOR dem Schreiben
    if ! visudo -cf "$temp_file" >/dev/null 2>&1; then
        log_error "sudoers-Syntax ungültig: '$content'"
        return 1
    fi
    
    # 🎯 Atomares Installieren mit korrekten Berechtigungen
    if ! install -o root -g root -m 0440 "$temp_file" "$target_file"; then
        log_error "Konnte sudoers-Datei nicht schreiben: $target_file"
        return 1
    fi
    
    # 🧹 Finale Konsistenz-Prüfung des gesamten sudoers-Systems
    if ! visudo -c >/dev/null 2>&1; then
        log_error "KRITISCH: sudoers-System ist inkonsistent geworden!"
        # Versuche Rollback
        rm -f "$target_file"
        return 1
    fi
    
    log_debug "sudoers-Eintrag sicher geschrieben: $target_file"
    return 0
}

##
# ZENTRALE sudo-Rechte-Verwaltung für Admin-User
# @param string $1 Aktion: "grant_temp"|"restore_normal"|"emergency_cleanup"
# @return int 0=Erfolg, 1=Fehler
##
manage_admin_sudo_rights() {
    local action="$1"
    
    # 🛡️ GUARD: Validierung
    if [ -z "${ADMIN_USER:-}" ]; then
        log_error "ADMIN_USER ist nicht gesetzt – sudo-Verwaltung nicht möglich"
        return 1
    fi
    
    if [ -z "$action" ]; then
        log_error "manage_admin_sudo_rights: Keine Aktion angegeben"
        return 1
    fi
    
    case "$action" in
        "grant_temp")
            log_info "🔓 Gewähre temporäre NOPASSWD-Rechte für Setup-Phase..."
            if write_sudoers_entry_safe \
                "$ADMIN_USER ALL=(ALL:ALL) NOPASSWD:ALL" \
                "/etc/sudoers.d/99-temp-setup-$ADMIN_USER"; then
                log_ok "Temporäre sudo-Rechte ohne Passwort für '$ADMIN_USER' gewährt."
            else
                log_error "Konnte temporäre sudo-Rechte nicht gewähren!"
                return 1
            fi
            ;;
            
        "restore_normal")
            log_info "🔒 Stelle Standard-sudo-Sicherheit wieder her..."
            
            # 1) Entferne ALLE temporären Berechtigungen
            rm -f "/etc/sudoers.d/99-temp-setup-$ADMIN_USER"
            rm -f "/etc/sudoers.d/99-$ADMIN_USER"  # Legacy cleanup
            
            # 2) Setze Standard-Berechtigung (MIT Passwort-Abfrage)
            if write_sudoers_entry_safe \
                "$ADMIN_USER ALL=(ALL:ALL) ALL" \
                "/etc/sudoers.d/50-$ADMIN_USER"; then
                log_ok "Standard-sudo-Sicherheit wiederhergestellt. '$ADMIN_USER' benötigt jetzt Passwort."
            else
                log_error "Konnte Standard-sudo-Regel nicht setzen!"
                return 1
            fi
            ;;
            
        "emergency_cleanup")
            log_warn "🚨 Notfall-Cleanup der sudo-Rechte..."
            
            # Entferne ALLE temporären Dateien (sicher)
            rm -f "/etc/sudoers.d/99-temp-setup-$ADMIN_USER"
            rm -f "/etc/sudoers.d/99-$ADMIN_USER"
            
            # Nur Fallback erstellen, wenn keine normale Regel existiert
            if [ ! -f "/etc/sudoers.d/50-$ADMIN_USER" ]; then
                log_warn "Erstelle Notfall-sudo-Regel für '$ADMIN_USER'..."
                if write_sudoers_entry_safe \
                    "$ADMIN_USER ALL=(ALL:ALL) ALL" \
                    "/etc/sudoers.d/50-$ADMIN_USER"; then
                    log_ok "Notfall-sudo-Regel erfolgreich erstellt."
                else
                    log_error "KRITISCH: Konnte Notfall-sudo-Regel nicht erstellen!"
                    log_error "User '$ADMIN_USER' hat möglicherweise KEINE sudo-Rechte mehr!"
                    return 1
                fi
            else
                log_info "Standard-sudo-Regel für '$ADMIN_USER' bereits vorhanden."
            fi
            ;;
            
        *)
            log_error "Ungültige Aktion für manage_admin_sudo_rights: '$action'"
            log_error "Gültige Aktionen: grant_temp, restore_normal, emergency_cleanup"
            return 1
            ;;
    esac
    
    return 0
}

##
# Audit-Funktion für sudo-Berechtigungen (für Debugging/Verifikation)
##
audit_sudo_permissions() {
    log_info "🔍 Audit der aktuellen sudo-Berechtigungen:"
    
    # Zeige alle sudoers.d-Dateien mit Inhalt
    if ls /etc/sudoers.d/* >/dev/null 2>&1; then
        for file in /etc/sudoers.d/*; do
            if [ -f "$file" ] && [ -r "$file" ]; then
                log_info "  📄 $(basename "$file"):"
                while IFS= read -r line; do
                    # Nur nicht-leere, nicht-kommentierte Zeilen anzeigen
                    if [[ "$line" =~ ^[^#]*[A-Za-z] ]]; then
                        log_info "    → $line"
                    fi
                done < "$file"
            fi
        done
    else
        log_info "  📄 Keine Dateien in /etc/sudoers.d/"
    fi
    
    # Zeige sudo-Gruppenmitglieder
    local sudo_members
    sudo_members=$(getent group sudo 2>/dev/null | cut -d: -f4 || echo "")
    if [ -n "$sudo_members" ]; then
        log_info "  👥 sudo-Gruppe: $sudo_members"
    else
        log_info "  👥 sudo-Gruppe: keine Mitglieder"
    fi
    
    # Konsistenz-Check
    if visudo -c >/dev/null 2>&1; then
        log_info "  ✅ sudoers-System ist konsistent"
    else
        log_error "  ❌ sudoers-System hat SYNTAXFEHLER!"
    fi
    
    # Spezifische Prüfung für ADMIN_USER
    if [ -n "${ADMIN_USER:-}" ]; then
        if id "$ADMIN_USER" >/dev/null 2>&1; then
            local user_groups
            user_groups=$(groups "$ADMIN_USER" 2>/dev/null)
            log_info "  🙋 '$ADMIN_USER' Gruppen: $user_groups"
            
            # Test sudo-Fähigkeit (ohne Command auszuführen)
            if sudo -l -U "$ADMIN_USER" >/dev/null 2>&1; then
                log_info "  ✅ '$ADMIN_USER' hat sudo-Berechtigung"
            else
                log_warn "  ⚠️ '$ADMIN_USER' hat KEINE sudo-Berechtigung"
            fi
        else
            log_warn "  ⚠️ User '$ADMIN_USER' existiert nicht auf dem System"
        fi
    fi
}

##
# SECURITY: Bereinige ALLE temporären sudo-Einträge (für module_cleanup)
##
cleanup_all_temporary_sudo_entries() {
    log_info "🧹 Bereinige alle temporären sudo-Einträge systemweit..."
    
    local cleaned=0
    
    # Entferne alle Dateien mit temporären Mustern
    for pattern in "99-temp-*" "99-*-temp-*" "*-temporary-*"; do
        find /etc/sudoers.d/ -name "$pattern" -type f 2>/dev/null | while read -r file; do
            log_info "  🗑️ Entferne temporäre sudo-Datei: $(basename "$file")"
            rm -f "$file"
            ((cleaned++))
        done
    done
    
    # Prüfe verbliebene 99-* Dateien auf NOPASSWD (Legacy cleanup)
    find /etc/sudoers.d/ -name "99-*" -type f 2>/dev/null | while read -r file; do
        if grep -q "NOPASSWD" "$file" 2>/dev/null; then
            log_info "  🗑️ Entferne Legacy-NOPASSWD-Datei: $(basename "$file")"
            rm -f "$file"
            ((cleaned++))
        fi
    done
    
    if [ $cleaned -gt 0 ]; then
        log_ok "$cleaned temporäre sudo-Dateien bereinigt."
    else
        log_info "Keine temporären sudo-Dateien gefunden."
    fi
    
    # Finale Konsistenz-Prüfung nach Cleanup
    if ! visudo -c >/dev/null 2>&1; then
        log_error "WARNUNG: sudoers-System nach Cleanup inkonsistent!"
    fi
}

##
# Entfernt die temporären NOPASSWD-Rechte und stellt die Standard-sudo-Konfiguration wieder her.
##
cleanup_admin_sudo_rights() {
    manage_admin_sudo_rights "restore_normal"
}
##
# Notfall-Bereinigung der sudo-Rechte, falls das Skript vorzeitig abbricht.
##
cleanup_admin_sudo_rights_emergency() {
    manage_admin_sudo_rights "emergency_cleanup"
}

##
# Gewährt temporäre NOPASSWD-Rechte für die Setup-Phase.
# Wrapper-Funktion für manage_admin_sudo_rights mit "grant_temp" Aktion.
##
grant_temporary_sudo_rights() {
    manage_admin_sudo_rights "grant_temp"
}