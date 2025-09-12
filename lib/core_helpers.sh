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

################################################################################
#
# LOGIK- & SYSTEM-FUNKTIONEN
# - Vorab-Prüfungen, Dateiverwaltung und Rollback.
#
################################################################################

##
# Prüft, ob der Kernel IPv6-NAT unterstützt (mit praktischem Test)
# @return string "true" oder "false"
##
check_ipv6_nat_kernel() {
    log_debug "IPv6-NAT: Starte umfassende Kernel-Support-Prüfung..."
    
    # TEST 1: Kernel-Konfiguration prüfen
    local kconfig="/boot/config-$(uname -r)"
    if [ -f "$kconfig" ] && grep -q 'CONFIG_NF_NAT_MASQUERADE_IPV6=y\|CONFIG_IP6_NF_TARGET_MASQUERADE=y' "$kconfig"; then
        log_debug "IPv6-NAT: Kernel-Config zeigt Support (CONFIG gefunden)."
    else
        log_debug "IPv6-NAT: Kernel-Config zeigt keinen expliziten Support."
    fi
    
    # TEST 2: Modul-Verfügbarkeit prüfen
    if modinfo ip6t_MASQUERADE &>/dev/null; then
        log_debug "IPv6-NAT: Modul ip6t_MASQUERADE ist verfügbar."
        if modprobe ip6t_MASQUERADE 2>/dev/null; then
            log_debug "IPv6-NAT: Modul ip6t_MASQUERADE erfolgreich geladen."
        else
            log_debug "IPv6-NAT: Modul ip6t_MASQUERADE konnte nicht geladen werden."
        fi
    else
        log_debug "IPv6-NAT: Modul ip6t_MASQUERADE nicht gefunden."
    fi
    
    # TEST 3: Praktischer Funktions-Test (KRITISCH!)
    # Dies ist der ultimative Test - wenn das funktioniert, ist IPv6-NAT definitiv verfügbar
    log_debug "IPv6-NAT: Führe praktischen Funktionstest durch..."
    
    # Verwende harmlose Test-Regel in OUTPUT-Chain (sicher, kollidiert mit nichts)
    local test_successful=false
    local cleanup_needed=false
    
    # Versuche Test-Regel zu erstellen
    if ip6tables -t nat -A OUTPUT -p tcp --dport 59999 -j DNAT --to-destination [::1]:59999 >/dev/null 2>&1; then
        log_debug "IPv6-NAT: Test-Regel erfolgreich erstellt."
        test_successful=true
        cleanup_needed=true
    else
        log_debug "IPv6-NAT: Test-Regel konnte nicht erstellt werden."
        # Prüfe ob es ein ip6tables-Problem oder ein NAT-Problem ist
        if ip6tables -t filter -L OUTPUT >/dev/null 2>&1; then
            log_debug "IPv6-NAT: ip6tables funktioniert, aber NAT-Tabelle nicht verfügbar."
        else
            log_debug "IPv6-NAT: Grundlegendes ip6tables-Problem."
        fi
    fi
    
    # Cleanup der Test-Regel (falls erfolgreich erstellt)
    if [ "$cleanup_needed" = true ]; then
        if ip6tables -t nat -D OUTPUT -p tcp --dport 59999 -j DNAT --to-destination [::1]:59999 >/dev/null 2>&1; then
            log_debug "IPv6-NAT: Test-Regel erfolgreich entfernt."
        else
            log_warn "IPv6-NAT: Test-Regel konnte nicht entfernt werden (nicht kritisch)."
            # Versuche Fallback-Cleanup
            ip6tables -t nat -F OUTPUT >/dev/null 2>&1 || true
        fi
    fi
    
    # Endergebnis basierend auf praktischem Test
    if [ "$test_successful" = true ]; then
        log_debug "IPv6-NAT: Praktischer Test erfolgreich - IPv6-NAT ist voll funktional."
        echo "true"
    else
        log_debug "IPv6-NAT: Praktischer Test fehlgeschlagen - IPv6-NAT nicht verfügbar."
        echo "false"
    fi
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
## Führt Vorab-Prüfungen durch und installiert fehlende Pakete automatisch.
## Nutzt den apt_repair_helpers für provider-spezifische Fixes
## @return int 0=Erfolg, 1=Fehler
##
pre_flight_checks() {
    log_info "Prüfe System-Mindestvoraussetzungen..."
    
    # Debug: System-Info ausgeben
    log_debug "  -> System-Information:"
    log_debug "    - Hostname: $(hostname -f 2>/dev/null || hostname)"
    log_debug "    - Kernel: $(uname -r)"
    log_debug "    - Architektur: $(uname -m)"
    
    # Zuordnung von kritischen Befehlen zu den Paketen, die sie bereitstellen
    declare -A cmd_to_pkg=(
        [curl]="curl"
        [wget]="wget"
        [gpg]="gnupg"
        [systemctl]="systemd"
        [ip]="iproute2"
        [apt-get]="apt"
        [sed]="sed"
        [envsubst]="gettext-base"
        [logger]="bsdutils"
    )

    local missing_cmds=()
    local missing_pkgs=()
    
    log_debug "  -> Prüfe ${#cmd_to_pkg[@]} kritische Befehle..."

    for cmd in "${!cmd_to_pkg[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_cmds+=("$cmd")
            local pkg=${cmd_to_pkg[$cmd]}
            # Füge Paket nur hinzu, wenn es noch nicht in der Liste ist
            if [[ ! " ${missing_pkgs[*]} " =~ ${pkg} ]]; then
                missing_pkgs+=("$pkg")
            fi
            log_debug "    - ❌ $cmd fehlt (Paket: $pkg)"
        else
            log_debug "    - ✓ $cmd vorhanden ($(command -v $cmd))"
        fi
    done

    # Auto-Installation wenn Pakete fehlen
    if [ ${#missing_cmds[@]} -gt 0 ]; then
        log_warn "⚠️  Fehlende Befehle erkannt: ${missing_cmds[*]}"
        log_info "  -> Versuche automatische Installation der Pakete: ${missing_pkgs[*]}"
        
        # APT-Reparatur-Helper laden falls noch nicht geschehen
        if ! type -t fix_apt_sources_if_needed &>/dev/null; then
            log_debug "  -> APT-Reparatur-Helper noch nicht geladen"
            if [ -f "lib/apt_repair_helpers.sh" ]; then
                log_debug "  -> Lade lib/apt_repair_helpers.sh..."
                source lib/apt_repair_helpers.sh
                log_debug "  -> Helper erfolgreich geladen"
            else
                log_error "❌ APT-Reparatur-Helper nicht gefunden: lib/apt_repair_helpers.sh"
                log_debug "  -> Verfügbare Dateien in lib/:"
                log_debug "$(ls -la lib/ 2>/dev/null | head -10)"
                exit 1
            fi
        else
            log_debug "  -> APT-Reparatur-Helper bereits geladen"
        fi
        
        # Provider erkennen und APT-Quellen reparieren
        log_info "  -> Erkenne VPS-Provider und repariere APT-Quellen..."
        fix_apt_sources_if_needed
        
        # APT-Update mit Debug-Ausgaben
        log_info "  -> Aktualisiere Paket-Listen..."
        log_debug "  -> Führe 'apt-get update' aus..."
        
        local update_attempts=0
        local max_attempts=3
        local update_success=false
        
        while [ $update_attempts -lt $max_attempts ] && [ "$update_success" = false ]; do
            ((update_attempts++))
            log_debug "  -> APT-Update Versuch $update_attempts/$max_attempts"
            
            local update_output
            update_output=$(apt-get update 2>&1)
            local update_result=$?
            
            if [ $update_result -eq 0 ]; then
                update_success=true
                log_debug "  -> APT-Update erfolgreich (Exit-Code: 0)"
                
                # Statistik ausgeben
                local repo_count
                repo_count=$(echo "$update_output" | grep -c "^Get:\|^Hit:")
                log_debug "  -> $repo_count Repositories verarbeitet"
            else
                log_warn "  -> APT-Update fehlgeschlagen (Exit-Code: $update_result)"
                
                # Fehler analysieren
                if echo "$update_output" | grep -q "Could not get lock"; then
                    log_debug "  -> APT ist gesperrt, warte 10 Sekunden..."
                    sleep 10
                elif echo "$update_output" | grep -q "NO_PUBKEY"; then
                    log_debug "  -> GPG-Schlüssel fehlen"
                    apt-key update 2>/dev/null
                fi
                
                if [ $update_attempts -lt $max_attempts ]; then
                    log_debug "  -> Warte 5 Sekunden vor erneutem Versuch..."
                    sleep 5
                else
                    log_error "❌ APT-Update fehlgeschlagen nach $max_attempts Versuchen"
                    log_debug "  -> Letzte Ausgabe:"
                    echo "$update_output" | tail -20
                    exit 1
                fi
            fi
        done
        
        # Pakete installieren mit Debug
        log_info "  -> Installiere fehlende Pakete..."
        log_debug "  -> Zu installierende Pakete: ${missing_pkgs[*]}"
        
        local install_output
        install_output=$(DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_pkgs[@]}" 2>&1)
        local install_result=$?
        
        if [ $install_result -eq 0 ]; then
            log_ok "✅ Fehlende Pakete wurden installiert: ${missing_pkgs[*]}"
            
            # Installation verifizieren
            for pkg in "${missing_pkgs[@]}"; do
                if dpkg -l | grep -q "^ii.*$pkg"; then
                    log_debug "  -> ✓ $pkg erfolgreich installiert"
                else
                    log_debug "  -> ⚠ $pkg Status unklar"
                fi
            done
        else
            log_error "❌ Installation fehlgeschlagen (Exit-Code: $install_result)"
            log_debug "  -> Fehlerausgabe:"
            echo "$install_output" | grep -E "^E:|^W:" | head -10
            
            # dpkg reparieren falls nötig
            if echo "$install_output" | grep -q "dpkg was interrupted"; then
                log_info "  -> Repariere unterbrochene dpkg-Installation..."
                dpkg --configure -a
                
                # Nochmal versuchen
                log_info "  -> Wiederhole Installation nach dpkg-Reparatur..."
                if apt-get install -y "${missing_pkgs[@]}"; then
                    log_ok "✅ Installation nach Reparatur erfolgreich"
                else
                    exit 1
                fi
            else
                exit 1
            fi
        fi
        
        # Finale Verifikation mit Debug
        log_debug "  -> Verifiziere Installation..."
        local still_missing=()
        
        for cmd in "${missing_cmds[@]}"; do
            if ! command -v "$cmd" &>/dev/null; then
                still_missing+=("$cmd")
                log_debug "  -> ❌ $cmd fehlt weiterhin"
                
                # Debug-Info warum es fehlt
                local pkg=${cmd_to_pkg[$cmd]}
                local dpkg_status
                dpkg_status=$(dpkg -l $pkg 2>/dev/null | grep "^ii" || echo "nicht installiert")
                log_debug "    - Paket $pkg Status: $dpkg_status"
                
                # Prüfe ob es in alternativen Pfaden liegt
                local alt_paths="/usr/local/bin /usr/sbin /sbin"
                for path in $alt_paths; do
                    if [ -x "$path/$cmd" ]; then
                        log_debug "    - Gefunden in $path/$cmd (aber nicht im PATH)"
                    fi
                done
            else
                log_debug "  -> ✓ $cmd jetzt verfügbar: $(command -v $cmd)"
            fi
        done
        
        if [ ${#still_missing[@]} -gt 0 ]; then
            log_error "❌ Befehle fehlen weiterhin: ${still_missing[*]}"
            log_debug "  -> PATH: $PATH"
            exit 1
        fi
        
        # Erfolgs-Zusammenfassung
        log_ok "✅ Alle fehlenden Pakete erfolgreich installiert"
        log_debug "  -> Zusammenfassung:"
        log_debug "    - Provider: ${VPS_PROVIDER:-unknown}"
        log_debug "    - Installierte Pakete: ${#missing_pkgs[@]}"
        log_debug "    - Alle Befehle verfügbar: ${#missing_cmds[@]}/${#missing_cmds[@]}"
        
    else
        log_ok "✅ Alle System-Mindestvoraussetzungen sind erfüllt"
        
        # Trotzdem Provider erkennen für spätere Verwendung
        if ! type -t detect_vps_provider &>/dev/null; then
            log_debug "  -> Lade APT-Helper für Provider-Detection..."
            if [ -f "lib/apt_repair_helpers.sh" ]; then
                source lib/apt_repair_helpers.sh
            fi
        fi
        
        if type -t detect_vps_provider &>/dev/null; then
            local vps_provider
            vps_provider=$(detect_vps_provider)
            export VPS_PROVIDER="$vps_provider"
            log_debug "  -> VPS-Provider: ${VPS_PROVIDER}"
        fi
        
        # Debug: Zeige vorhandene Befehle
        log_debug "  -> Alle ${#cmd_to_pkg[@]} kritischen Befehle sind vorhanden"
    fi
		# IMMER APT-Quellen prüfen bei bekannten Problem-Providern
		if [ "${VPS_PROVIDER}" = "ionos" ] || [ -d /etc/apt/mirrors ]; then
			log_warn "  -> IONOS/Problem-Provider erkannt - prüfe APT-Quellen..."
			if type -t fix_apt_sources_if_needed &>/dev/null; then
				fix_apt_sources_if_needed
			fi
		fi	

    return 0
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
