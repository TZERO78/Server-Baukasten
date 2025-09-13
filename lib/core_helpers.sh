#!/bin/bash
################################################################################
#
# KERN-HELFER-FUNKTIONEN
#
# @description: Zentrale Hilfsfunktionen für das Skript-Management und die Ausführung.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------ 
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

# ======= Guards & Defaults (wichtig für set -u) ===============================

# Farb-Variablen defensiv initialisieren, falls log_helper noch nicht geladen ist
: "${RED:=}"; : "${GREEN:=}"; : "${YELLOW:=}"; : "${NC:=}"

# Globale OS-Variablen defensiv anlegen
: "${OS_ID:=}"; : "${OS_VERSION_CODENAME:=}"

# Backup-Array immer vorhanden halten (verhindert "unbound variable")
if ! declare -p BACKUP_FILES >/dev/null 2>&1; then
  declare -ag BACKUP_FILES=()
fi

ensure_backup_array() {
  declare -p BACKUP_FILES >/dev/null 2>&1 || declare -ag BACKUP_FILES=()
}

# Einheitliche Registrierung (optional „SRC::DST“-Form)
#   register_backup "/etc/ssh/sshd_config"
#   register_backup "/etc/ssh/sshd_config.bak.2025-01-01::/etc/ssh/sshd_config"
register_backup() {
  ensure_backup_array
  BACKUP_FILES+=("$1")
}

################################################################################
# LOGIK- & SYSTEM-FUNKTIONEN
################################################################################

## IPv6-NAT-Kernel-Test (praktisch & konservativ)
check_ipv6_nat_kernel() {
    log_debug "IPv6-NAT: Starte umfassende Kernel-Support-Prüfung..."

    local kconfig="/boot/config-$(uname -r)"
    if [ -f "$kconfig" ] && grep -q 'CONFIG_NF_NAT_MASQUERADE_IPV6=y\|CONFIG_IP6_NF_TARGET_MASQUERADE=y' "$kconfig"; then
        log_debug "IPv6-NAT: Kernel-Config zeigt Support (CONFIG gefunden)."
    else
        log_debug "IPv6-NAT: Kernel-Config zeigt keinen expliziten Support."
    fi

    if modinfo ip6t_MASQUERADE &>/dev/null; then
        log_debug "IPv6-NAT: Modul ip6t_MASQUERADE ist verfügbar."
        modprobe ip6t_MASQUERADE 2>/dev/null && log_debug "IPv6-NAT: Modul geladen." || log_debug "IPv6-NAT: Modul konnte nicht geladen werden."
    else
        log_debug "IPv6-NAT: Modul ip6t_MASQUERADE nicht gefunden."
    fi

    log_debug "IPv6-NAT: Führe praktischen Funktionstest durch..."
    local test_successful=false cleanup_needed=false

    if ip6tables -t nat -A OUTPUT -p tcp --dport 59999 -j DNAT --to-destination [::1]:59999 >/dev/null 2>&1; then
        log_debug "IPv6-NAT: Test-Regel erfolgreich erstellt."
        test_successful=true; cleanup_needed=true
    else
        log_debug "IPv6-NAT: Test-Regel konnte nicht erstellt werden."
        if ip6tables -t filter -L OUTPUT >/dev/null 2>&1; then
            log_debug "IPv6-NAT: ip6tables ok, aber NAT-Tabelle nicht verfügbar."
        else
            log_debug "IPv6-NAT: Grundlegendes ip6tables-Problem."
        fi
    fi

    if [ "$cleanup_needed" = true ]; then
        ip6tables -t nat -D OUTPUT -p tcp --dport 59999 -j DNAT --to-destination [::1]:59999 >/dev/null 2>&1 && \
          log_debug "IPv6-NAT: Test-Regel entfernt." || \
          { log_warn "IPv6-NAT: Test-Regel konnte nicht entfernt werden (nicht kritisch)."; ip6tables -t nat -F OUTPUT >/dev/null 2>&1 || true; }
    fi

    if [ "$test_successful" = true ]; then
        log_debug "IPv6-NAT: Praktischer Test erfolgreich."
        echo "true"
    else
        log_debug "IPv6-NAT: Praktischer Test fehlgeschlagen."
        echo "false"
    fi
}

## Spinner-Ausführung (failsafe Farben)
run_with_spinner() {
    local title="$1" command="$2"

    if [ "${SCRIPT_VERBOSE:-false}" = "true" ]; then
        log_info "Ausführung (verbose): $title..."
        eval "$command"
        local ec=$?
        [ $ec -eq 0 ] && log_ok "$title: Erfolg!" || log_error "$title: Fehlgeschlagen! (Exit-Code: $ec)"
        return $ec
    fi

    local stderr_file; stderr_file=$(mktemp)
    trap 'rm -f "$stderr_file"' RETURN

    local spinner_chars="/|\\-"; local i=0
    log_info "Starte: $title..."
    eval "$command" >/dev/null 2>"$stderr_file" & local pid=$!

    printf "${YELLOW}⏳ %s ${NC}" "$title"
    while ps -p $pid &>/dev/null; do
        i=$(((i + 1) % 4)); printf "\b${spinner_chars:$i:1}"; sleep 0.1
    done

    wait $pid; local ec=$?
    if [ $ec -eq 0 ]; then
        printf "\b${GREEN}✔${NC}\n"; log_ok "$title: Abgeschlossen."
    else
        printf "\b${RED}✖${NC}\n"; log_error "$title: Fehlgeschlagen!"
        if [ -s "$stderr_file" ]; then
            echo -e "${RED}┌─── FEHLERMELDUNG ─────────────────────────────────────────┐${NC}"
            while IFS= read -r line; do echo -e "${RED}│${NC} $line"; done < "$stderr_file"
            echo -e "${RED}└──────────────────────────────────────────────────────────┘${NC}"
            logger -t "server-baukasten" -p "daemon.err" -- "FEHLERDETAILS ($title): $(cat "$stderr_file")"
        fi
    fi
    return $ec
}

## OS-Erkennung
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION_CODENAME="$VERSION_CODENAME"
    else
        log_error "OS-Erkennung fehlgeschlagen: /etc/os-release nicht gefunden."
        exit 1
    fi
}

## Datei sichern & für Rollback registrieren
backup_and_register() {
    local file="$1"
    ensure_backup_array
    if [ -f "$file" ] && ! compgen -G "${file}.bak*" >/dev/null; then
        local ts; ts="$(date +%Y%m%d_%H%M%S)"
        cp -a "$file" "${file}.bak.${ts}"
        register_backup "${file}.bak.${ts}::${file}"
    fi
}

## Robustes Rollback (unabhängig von set -u)
rollback() {
    # Fehlerpfade nie streng behandeln
    set +e +u
    trap - ERR

    log_error "Ein kritischer Fehler ist aufgetreten - starte automatisches Rollback..."

    ensure_backup_array
    if [ ${#BACKUP_FILES[@]} -gt 0 ]; then
        log_info "Stelle Backups wieder her (${#BACKUP_FILES[@]})..."
        local entry src dst latest
        for entry in "${BACKUP_FILES[@]}"; do
            if [[ "$entry" == *"::"* ]]; then
                src="${entry%%::*}"; dst="${entry#*::}"
                if [ -e "$src" ]; then
                    cp -a "$src" "$dst"
                    log_info "  -> '$dst' aus '$src' wiederhergestellt."
                else
                    log_warn "  -> Backup fehlt: $src"
                fi
            else
                # Legacy: nur Originalpfad registriert – nimm neuestes *.bak*
                dst="$entry"
                if compgen -G "${dst}.bak*" >/dev/null; then
                    latest="$(ls -1t "${dst}".bak* 2>/dev/null | head -n1)"
                    [ -n "$latest" ] && mv -f "$latest" "$dst" && log_info "  -> '$dst' aus '$latest' wiederhergestellt." || log_warn "  -> Kein gültiges Backup für '$dst'."
                else
                    [ -f "${dst}.bak" ] && mv -f "${dst}.bak" "$dst" && log_info "  -> '$dst' aus '${dst}.bak' wiederhergestellt." || log_warn "  -> Kein Backup für '$dst' gefunden."
                fi
            fi
        done
    else
        log_warn "Keine Backup-Dateien zum Wiederherstellen registriert."
    fi

    cleanup_admin_sudo_rights_emergency || true
    log_ok "Rollback abgeschlossen. Das System sollte im vorherigen Zustand sein."
    exit 1
}

## Sensible Konfig aufräumen (optional)
cleanup_sensitive_data() {
    local TEST_MODE="$1"
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS: Überspringe Bereinigung der sensiblen Konfigurationsdatei."
        return 0
    fi
    if [ -n "${CONFIG_FILE:-}" ] && [ -f "$CONFIG_FILE" ]; then
        print_section_header "SICHERHEIT" "SENSIBLE DATEN BEREINIGEN" "🔒"
        log_warn "Die Konfigurationsdatei '$CONFIG_FILE' enthält Klartext-Passwörter!"
        log_info "Empfehlung: Sicheres Löschen (shred)"
        local cleanup_choice; prompt_for_yes_no "Soll die Konfigurationsdatei jetzt sicher gelöscht werden?" "cleanup_choice" "ja"
        if [ "$cleanup_choice" = "ja" ]; then
            if command -v shred &>/dev/null; then
                run_with_spinner "Lösche Konfigurationsdatei sicher (shred)..." "shred -n 3 -uz '$CONFIG_FILE'" || rm -f "$CONFIG_FILE"
                log_ok "Konfigurationsdatei sicher gelöscht."
            else
                log_warn "'shred' nicht installiert – nutze 'rm'."
                rm -f "$CONFIG_FILE"; log_ok "Konfigurationsdatei gelöscht (evtl. wiederherstellbar)."
            fi
        else
            log_error "KONFIGURATIONSDATEI WURDE NICHT GELÖSCHT!"
            log_warn  "Die Datei enthält weiterhin Klartext-Passwörter."
            log_info  "  -> Manuell löschen mit: shred -u '$CONFIG_FILE'"
        fi
    else
        log_info "Keine Konfigurationsdatei verwendet."
    fi
}

################################################################################
# KONFIG & TEMPLATES
################################################################################

download_and_process_template() {
    local template_name="$1" dest_path="$2" permissions="$3" owner="$4"
    local source_url="${CONF_BASE_URL}/${template_name}"
    local temp_file; temp_file=$(mktemp)

    if ! run_with_spinner "Lade Vorlage '$template_name'..." "curl -fsSL '$source_url' -o '$temp_file'"; then
        log_error "Download der Vorlage '$template_name' fehlgeschlagen."
        rm -f "$temp_file"; return 1
    fi

    mkdir -p "$(dirname "$dest_path")"
    envsubst < "$temp_file" > "$dest_path"
    rm -f "$temp_file"

    chmod "$permissions" "$dest_path"
    chown "$owner" "$dest_path"
    log_ok "Vorlage '$template_name' → '$dest_path' installiert."
}

##################################################################################
# SUDOERS BEST PRACTICE
##################################################################################

write_sudoers_entry_safe() {
    local content="$1" target_file="$2"
    [ -n "$content" ] && [ -n "$target_file" ] || { log_error "write_sudoers_entry_safe: Fehlende Parameter"; return 1; }

    local temp_file; temp_file=$(mktemp) || { log_error "Konnte temporäre Datei nicht erstellen"; return 1; }
    trap "rm -f '$temp_file'" RETURN

    printf '%s\n' "$content" > "$temp_file"
    visudo -cf "$temp_file" >/dev/null 2>&1 || { log_error "sudoers-Syntax ungültig: '$content'"; return 1; }

    install -o root -g root -m 0440 "$temp_file" "$target_file" || { log_error "Konnte sudoers-Datei nicht schreiben: $target_file"; return 1; }

    visudo -c >/dev/null 2>&1 || { log_error "KRITISCH: sudoers inkonsistent!"; rm -f "$target_file"; return 1; }
    log_debug "sudoers-Eintrag sicher geschrieben: $target_file"
    return 0
}

manage_admin_sudo_rights() {
    local action="$1"
    [ -n "${ADMIN_USER:-}" ] || { log_error "ADMIN_USER ist nicht gesetzt – sudo-Verwaltung nicht möglich"; return 1; }
    [ -n "$action" ] || { log_error "manage_admin_sudo_rights: Keine Aktion angegeben"; return 1; }

    case "$action" in
        grant_temp)
            log_info "🔓 Gewähre temporäre NOPASSWD-Rechte..."
            write_sudoers_entry_safe "$ADMIN_USER ALL=(ALL:ALL) NOPASSWD:ALL" "/etc/sudoers.d/99-temp-setup-$ADMIN_USER" \
              && log_ok "Temporäre sudo-Rechte für '$ADMIN_USER' gewährt." \
              || { log_error "Konnte temporäre sudo-Rechte nicht gewähren!"; return 1; }
            ;;
        restore_normal)
            log_info "🔒 Stelle Standard-sudo-Sicherheit wieder her..."
            rm -f "/etc/sudoers.d/99-temp-setup-$ADMIN_USER" "/etc/sudoers.d/99-$ADMIN_USER"
            write_sudoers_entry_safe "$ADMIN_USER ALL=(ALL:ALL) ALL" "/etc/sudoers.d/50-$ADMIN_USER" \
              && log_ok "Standard-sudo wiederhergestellt." \
              || { log_error "Konnte Standard-sudo-Regel nicht setzen!"; return 1; }
            ;;
        emergency_cleanup)
            log_warn "🚨 Notfall-Cleanup der sudo-Rechte..."
            rm -f "/etc/sudoers.d/99-temp-setup-$ADMIN_USER" "/etc/sudoers.d/99-$ADMIN_USER"
            if [ ! -f "/etc/sudoers.d/50-$ADMIN_USER" ]; then
              write_sudoers_entry_safe "$ADMIN_USER ALL=(ALL:ALL) ALL" "/etc/sudoers.d/50-$ADMIN_USER" \
                && log_ok "Notfall-sudo-Regel erstellt." \
                || { log_error "KRITISCH: Konnte Notfall-sudo-Regel nicht erstellen!"; return 1; }
            else
              log_info "Standard-sudo-Regel bereits vorhanden."
            fi
            ;;
        *) log_error "Ungültige Aktion: '$action'"; return 1 ;;
    esac
}

audit_sudo_permissions() {
    log_info "🔍 Audit der aktuellen sudo-Berechtigungen:"
    if ls /etc/sudoers.d/* >/dev/null 2>&1; then
        for file in /etc/sudoers.d/*; do
            [ -f "$file" ] && [ -r "$file" ] || continue
            log_info "  📄 $(basename "$file"):"
            while IFS= read -r line; do
                [[ "$line" =~ ^[^#]*[A-Za-z] ]] && log_info "    → $line"
            done < "$file"
        done
    else
        log_info "  📄 Keine Dateien in /etc/sudoers.d/"
    fi

    local sudo_members; sudo_members=$(getent group sudo 2>/dev/null | cut -d: -f4 || echo "")
    [ -n "$sudo_members" ] && log_info "  👥 sudo-Gruppe: $sudo_members" || log_info "  👥 sudo-Gruppe: keine Mitglieder"

    visudo -c >/dev/null 2>&1 && log_info "  ✅ sudoers-System ist konsistent" || log_error "  ❌ sudoers-SYNTAXFEHLER!"
    if [ -n "${ADMIN_USER:-}" ] && id "$ADMIN_USER" >/dev/null 2>&1; then
        log_info "  🙋 '$ADMIN_USER' Gruppen: $(groups "$ADMIN_USER" 2>/dev/null)"
        sudo -l -U "$ADMIN_USER" >/dev/null 2>&1 && log_info "  ✅ '$ADMIN_USER' hat sudo-Berechtigung" || log_warn "  ⚠️ '$ADMIN_USER' hat KEINE sudo-Berechtigung"
    fi
}

cleanup_all_temporary_sudo_entries() {
    log_info "🧹 Bereinige alle temporären sudo-Einträge systemweit..."
    local cleaned=0
    for pattern in "99-temp-*" "99-*-temp-*" "*-temporary-*"; do
        find /etc/sudoers.d/ -name "$pattern" -type f 2>/dev/null | while read -r file; do
            log_info "  🗑️ Entferne temporäre sudo-Datei: $(basename "$file")"
            rm -f "$file"; ((cleaned++))
        done
    done
    find /etc/sudoers.d/ -name "99-*" -type f 2>/dev/null | while read -r file; do
        grep -q "NOPASSWD" "$file" 2>/dev/null && { log_info "  🗑️ Entferne Legacy-NOPASSWD-Datei: $(basename "$file")"; rm -f "$file"; ((cleaned++)); }
    done

    [ $cleaned -gt 0 ] && log_ok "$cleaned temporäre sudo-Dateien bereinigt." || log_info "Keine temporären sudo-Dateien gefunden."
    visudo -c >/dev/null 2>&1 || log_error "WARNUNG: sudoers-System nach Cleanup inkonsistent!"
}

cleanup_admin_sudo_rights()          { manage_admin_sudo_rights "restore_normal"; }
cleanup_admin_sudo_rights_emergency() { manage_admin_sudo_rights "emergency_cleanup"; }
grant_temporary_sudo_rights()        { manage_admin_sudo_rights "grant_temp"; }
