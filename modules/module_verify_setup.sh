#!/bin/bash
################################################################################
#
# MODUL: VERIFIKATION DES SETUPS
#
# @description: Prüft den Status aller kritischen Services und die
#               korrekte Konfiguration der Sicherheitsschichten.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

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
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ✅ NEUER BLOCK: sudo-Berechtigungen Audit
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "  -> Prüfe sudo-Berechtigungen und Sicherheit..."
    
    # Führe das Audit durch und capture eventuelle Fehler
    if audit_sudo_permissions >/dev/null 2>&1; then
        log_ok "sudo-System ist korrekt konfiguriert."
    else
        log_warn "sudo-System hat möglicherweise Probleme."
        ((failed_important++))
    fi
    
    # Spezielle Prüfung: Sind noch temporäre NOPASSWD-Rechte aktiv?
    local temp_sudo_files=()
    while IFS= read -r -d '' file; do
        temp_sudo_files+=("$file")
    done < <(find /etc/sudoers.d/ -name "*temp*" -o -name "99-*" -type f -print0 2>/dev/null)
    
    if [ ${#temp_sudo_files[@]} -gt 0 ]; then
        log_warn "Temporäre sudo-Dateien noch vorhanden:"
        for file in "${temp_sudo_files[@]}"; do
            if grep -q "NOPASSWD" "$file" 2>/dev/null; then
                log_warn "  ⚠️ $(basename "$file") - enthält NOPASSWD"
                ((failed_important++))
            else
                log_info "  ✅ $(basename "$file") - OK"
            fi
        done
    else
        log_ok "Keine temporären sudo-Dateien gefunden."
    fi
    
    # Prüfe, ob ADMIN_USER korrekte sudo-Rechte hat (MIT Passwort)
    if [ -n "${ADMIN_USER:-}" ]; then
        if [ -f "/etc/sudoers.d/50-$ADMIN_USER" ]; then
            if grep -q "NOPASSWD" "/etc/sudoers.d/50-$ADMIN_USER" 2>/dev/null; then
                log_error "SICHERHEITSPROBLEM: '$ADMIN_USER' hat noch NOPASSWD-Rechte!"
                ((failed_critical++))
            else
                log_ok "'$ADMIN_USER' hat korrekte sudo-Rechte (mit Passwort-Abfrage)."
            fi
        else
            log_warn "'$ADMIN_USER' hat keine explizite sudo-Regel (nur Gruppenmitgliedschaft)."
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ✅ NEUER BLOCK: Netzwerk & Firewall Verifikation
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "  -> Prüfe Netzwerk-Konfiguration..."
    
    # SSH-Port Erreichbarkeit
    local ssh_port="${SSH_PORT:-22}"
    if ss -tln | grep -q ":$ssh_port "; then
        log_ok "SSH-Port $ssh_port ist gebunden."
    else
        log_error "SSH-Port $ssh_port ist NICHT erreichbar!"
        ((failed_critical++))
    fi
    
    # NFTables-Regeln
    local nft_rules_count
    nft_rules_count=$(nft list ruleset 2>/dev/null | grep -c "^[[:space:]]*[^#]" || echo "0")
    if [ "$nft_rules_count" -gt 10 ]; then
        log_ok "NFTables-Firewall hat $nft_rules_count aktive Regeln."
    else
        log_warn "NFTables-Firewall hat nur $nft_rules_count Regeln (möglicherweise unvollständig)."
        ((failed_important++))
    fi
    
    # Docker-spezifische Prüfungen
    if [ "$SERVER_ROLE" = "1" ] && systemctl is-active --quiet docker; then
        # Docker-Netzwerk prüfen
        if ip link show docker0 >/dev/null 2>&1; then
            local docker_subnet
            docker_subnet=$(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || echo "unbekannt")
            log_ok "Docker-Bridge aktiv (Subnet: $docker_subnet)."
        else
            log_warn "Docker-Bridge 'docker0' nicht gefunden."
            ((failed_important++))
        fi
    fi
    
    # Tailscale-spezifische Prüfungen
    if command -v tailscale >/dev/null 2>&1 && [ "${ACCESS_MODEL:-}" = "1" ]; then
        if tailscale status >/dev/null 2>&1 && ! tailscale status | grep -q "Logged out"; then
            local tailscale_ip
            tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "keine IPv4")
            log_ok "Tailscale VPN verbunden (IP: $tailscale_ip)."
        else
            log_warn "Tailscale VPN nicht verbunden oder nicht authentifiziert."
            ((failed_important++))
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ZUSAMMENFASSUNG & BEWERTUNG
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "--- Verifikations-Zusammenfassung ---"
    
    if [ "$failed_critical" -gt 0 ]; then
        log_error "🚨 KRITISCHE PROBLEME: $failed_critical"
        log_error "Das System hat ernste Probleme und ist möglicherweise nicht funktionsfähig!"
        if [ "$failed_critical" -ge 2 ]; then
            log_error "  -> SSH oder Firewall sind offline - Server möglicherweise nicht erreichbar!"
            log_error "  -> NOTFALL-ZUGANG über VPS-Console/Rescue-Mode verwenden!"
        fi
    elif [ "$failed_important" -gt 0 ]; then
        log_warn "⚠️ WICHTIGE PROBLEME: $failed_important"
        log_warn "Das System ist grundsätzlich funktional, aber die Sicherheit oder Funktion ist eingeschränkt."
        log_ok "✅ Alle kritischen Services laufen."
    else
        log_ok "🎉 PERFEKT: Alle kritischen und wichtigen Services laufen einwandfrei."
    fi

    if [ "$failed_optional" -gt 0 ]; then
        log_info "ℹ️ OPTIONALE PROBLEME: $failed_optional (nicht kritisch für den Betrieb)"
    else
        log_ok "✅ Auch alle optionalen Services sind aktiv."
    fi
    
    # Gesamtbewertung
    local total_issues=$((failed_critical + failed_important))
    if [ "$total_issues" -eq 0 ]; then
        log_ok "🏆 SYSTEM-STATUS: EXZELLENT - Bereit für den Produktivbetrieb!"
    elif [ "$total_issues" -le 2 ]; then
        log_warn "📊 SYSTEM-STATUS: GUT - Kleinere Probleme sollten behoben werden."
    elif [ "$total_issues" -le 5 ]; then
        log_warn "📊 SYSTEM-STATUS: AKZEPTABEL - Mehrere Probleme erfordern Aufmerksamkeit."
    else
        log_error "📊 SYSTEM-STATUS: PROBLEMATISCH - Umfassende Fehlerbehandlung erforderlich!"
    fi
    
    log_info "-------------------------------------"
    
    # Return Code für weitere Verarbeitung
    return $total_issues
}