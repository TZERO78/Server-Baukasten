#!/bin/bash
################################################################################
#
# MODUL: VERIFIKATION DES SETUPS - v4.5 SUDO-NFT KORRIGIERT
#
# @description: Prüft den Status der zweistufigen Firewall-Architektur und
#               aller kritischen Services nach dem neuen Setup-Konzept
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# KORREKTUREN v4.5:
# - Fixed NFTables-Zugriff: Alle nft-Befehle mit sudo für korrekte Erkennung
# - Fixed Tailscale/CrowdSec/Docker Verifikation
# - Behebt falsche "2 Probleme" Meldung bei funktionierender Firewall
#
################################################################################

##
# Hauptfunktion: Umfassende Verifikation aller Setup-Komponenten
##
module_verify_setup() {
    log_info "🔎 MODUL: Setup-Verifikation (Zweistufige Firewall-Architektur v4.5)"
    
    # Sammle Services basierend auf tatsächlicher Konfiguration
    local critical_services=("ssh" "nftables")
    local important_services=()
    local optional_services=()
    
    # Dynamische Service-Erkennung basierend auf CONFIG und Installation
    command -v crowdsec >/dev/null 2>&1 && important_services+=("crowdsec" "crowdsec-bouncer-setonly")
    [ "${SERVER_ROLE:-2}" = "1" ] && command -v docker >/dev/null 2>&1 && important_services+=("docker")
    [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ] && optional_services+=("geoip-update.timer")
    [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ] && [ "${TEST_MODE:-false}" != "true" ] && optional_services+=("system-backup.timer")
    
    local failed_critical=0
    local failed_important=0
    local failed_optional=0
    
    # ═══════════════════════════════════════════════════════════════════════════
    # KRITISCHE SERVICES (System muss funktionieren)
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "  -> 1/6: Prüfe kritische Services (System-Grundfunktionen)..."
    for service in "${critical_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_ok "    ✅ $service läuft"
        else
            log_error "    ❌ $service läuft NICHT (KRITISCH)!"
            failed_critical=$((failed_critical + 1))
        fi
    done
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FIREWALL-ARCHITEKTUR VERIFIKATION
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "  -> 2/6: Prüfe zweistufige Firewall-Architektur..."
    
    # Basis-Firewall prüfen
    verify_base_firewall_architecture
    local base_firewall_status=$?
    
    # Dynamische Erweiterungen prüfen
    verify_dynamic_firewall_extensions  
    local dynamic_firewall_status=$?
    
    # Firewall-Gesamtbewertung
    if [ $base_firewall_status -eq 0 ] && [ $dynamic_firewall_status -eq 0 ]; then
        log_ok "    🎉 Firewall-Architektur: VOLLSTÄNDIG FUNKTIONAL"
    elif [ $base_firewall_status -eq 0 ]; then
        log_warn "    ⚠️ Firewall-Architektur: BASIS OK, Erweiterungen unvollständig"
        failed_important=$((failed_important + 1))
    else
        log_error "    ❌ Firewall-Architektur: BASIS-PROBLEME erkannt!"
        failed_critical=$((failed_critical + 1))
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # WICHTIGE SERVICES (Sicherheit und Hauptfunktionen)
    # ═══════════════════════════════════════════════════════════════════════════
    if [ ${#important_services[@]} -gt 0 ]; then
        log_info "  -> 3/6: Prüfe wichtige Services (Sicherheit/Hauptfunktionen)..."
        for service in "${important_services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                log_ok "    ✅ $service läuft"
            else
                log_warn "    ❌ $service läuft NICHT (Wichtig für Sicherheit/Funktion)"
                failed_important=$((failed_important + 1))
            fi
        done
    else
        log_info "  -> 3/6: Keine wichtigen Services konfiguriert"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SUDO-BERECHTIGUNGEN AUDIT (Sicherheitskritisch)
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "  -> 4/6: Prüfe sudo-Berechtigungen und Sicherheit..."
    verify_sudo_security_status
    local sudo_status=$?
    
    if [ $sudo_status -eq 0 ]; then
        log_ok "    ✅ sudo-System ist sicher konfiguriert"
    else
        log_error "    ❌ sudo-System hat Sicherheitsprobleme!"
        failed_critical=$((failed_critical + 1))
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # NETZWERK & KONNEKTIVITÄT (SSH, VPN, Container)
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "  -> 5/6: Prüfe Netzwerk-Konnektivität und Integration..."
    verify_network_connectivity
    local network_status=$?
    
    if [ $network_status -eq 0 ]; then
        log_ok "    ✅ Netzwerk-Konnektivität vollständig"
    else
        log_warn "    ⚠️ Netzwerk hat kleinere Probleme"
        failed_important=$((failed_important + 1))
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # OPTIONALE SERVICES (Timer, Monitoring)
    # ═══════════════════════════════════════════════════════════════════════════
    if [ ${#optional_services[@]} -gt 0 ]; then
        log_info "  -> 6/6: Prüfe optionale Services (Automatisierung/Monitoring)..."
        for service in "${optional_services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                log_ok "    ✅ $service ist aktiv"
            else
                log_info "    ❌ $service ist inaktiv (Optional)"
                failed_optional=$((failed_optional + 1))
            fi
        done
    else
        log_info "  -> 6/6: Keine optionalen Services konfiguriert"
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # GESAMTBEWERTUNG & HANDLUNGSEMPFEHLUNGEN
    # ═══════════════════════════════════════════════════════════════════════════
    log_info "--- SETUP-VERIFIKATION ZUSAMMENFASSUNG ---"
    
    # Kritische Probleme (Server nicht nutzbar)
    if [ "$failed_critical" -gt 0 ]; then
        log_error "🚨 KRITISCHE PROBLEME: $failed_critical"
        
        if [ "$failed_critical" -ge 2 ]; then
            log_error "  ❌ MEHRERE KRITISCHE SERVICES AUSGEFALLEN!"
            log_error "     -> Server ist möglicherweise nicht erreichbar!"
            log_error "     -> NOTFALL-ZUGANG: VPS-Console/Rescue-Mode verwenden"
        else
            log_error "  ❌ EIN KRITISCHER SERVICE AUSGEFALLEN"
            log_error "     -> Sofortige Reparatur erforderlich"
        fi
        
        log_info "  🔧 Debug-Befehle:"
        log_info "     systemctl status ssh nftables"
        log_info "     journalctl -u ssh -u nftables --since '5 minutes ago'"
        
    else
        log_ok "✅ KRITISCHE SERVICES: Alle laufen einwandfrei"
    fi

    # Wichtige Probleme (Sicherheit/Funktionalität eingeschränkt)
    if [ "$failed_important" -gt 0 ]; then
        log_warn "⚠️ WICHTIGE PROBLEME: $failed_important"
        log_warn "   System ist grundsätzlich funktional, aber Sicherheit/Funktion ist eingeschränkt"
        
        if command -v crowdsec >/dev/null 2>&1 && ! systemctl is-active --quiet crowdsec; then
            log_warn "   -> CrowdSec IPS ist nicht aktiv (weniger Angriffserkennung)"
        fi
        
        if [ "${SERVER_ROLE:-2}" = "1" ] && ! systemctl is-active --quiet docker; then
            log_warn "   -> Docker ist nicht aktiv (Container-Funktionen nicht verfügbar)"
        fi
        
    else
        log_ok "✅ WICHTIGE SERVICES: Alle laufen einwandfrei"
    fi

    # Optionale Services
    if [ "$failed_optional" -gt 0 ]; then
        log_info "ℹ️ OPTIONALE PROBLEME: $failed_optional (nicht kritisch für den Betrieb)"
        log_info "   Timer und Monitoring-Services teilweise inaktiv"
    else
        log_ok "✅ OPTIONALE SERVICES: Alle aktiv"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # GESAMTBEWERTUNG & KORRIGIERTE RETURN-LOGIC
    # ═══════════════════════════════════════════════════════════════════════════
    local total_issues=$((failed_critical + failed_important))
    
    echo ""
    log_info "=== FINALE SYSTEM-BEWERTUNG ==="
    
    if [ "$total_issues" -eq 0 ]; then
        log_ok "🏆 SYSTEM-STATUS: EXZELLENT"
        log_ok "   ✅ Alle kritischen und wichtigen Services laufen"
        log_ok "   ✅ Firewall-Architektur ist vollständig funktional"
        log_ok "   ✅ Server ist bereit für den Produktivbetrieb!"
        
    elif [ "$failed_critical" -eq 0 ] && [ "$total_issues" -le 2 ]; then
        log_warn "📊 SYSTEM-STATUS: GUT"
        log_warn "   ⚠️ $total_issues kleinere Problem(e) sollten behoben werden"
        log_ok "   ✅ Server ist grundsätzlich einsatzbereit"
        
    elif [ "$failed_critical" -eq 0 ] && [ "$total_issues" -le 5 ]; then
        log_warn "📊 SYSTEM-STATUS: AKZEPTABEL"  
        log_warn "   ⚠️ $total_issues Problem(e) erfordern Aufmerksamkeit"
        log_warn "   ⚠️ Sicherheit oder Funktionalität ist eingeschränkt"
        
    else
        log_error "📊 SYSTEM-STATUS: PROBLEMATISCH"
        log_error "   ❌ $total_issues schwerwiegende Problem(e) erkannt!"
        log_error "   ❌ Umfassende Fehlerbehandlung erforderlich"
        log_error "   ❌ Server ist möglicherweise nicht produktionstauglich"
    fi
    
    # Spezifische Handlungsempfehlungen
    if [ "$failed_critical" -gt 0 ]; then
        log_info "--- SOFORT-MASSNAHMEN ---"
        log_info "  1. SSH-Zugang testen: ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@server-ip"
        log_info "  2. Firewall prüfen: sudo nft list ruleset"
        log_info "  3. Service-Status: sudo systemctl status ssh nftables"
    fi
    
    if [ "$failed_important" -gt 0 ]; then
        log_info "--- EMPFOHLENE REPARATUREN ---"
        command -v crowdsec >/dev/null 2>&1 && log_info "  • CrowdSec: sudo systemctl restart crowdsec crowdsec-bouncer-setonly"
        [ "${SERVER_ROLE:-2}" = "1" ] && log_info "  • Docker: sudo systemctl restart docker"
        log_info "  • Firewall: sudo systemctl reload nftables"
    fi
    
    log_info "-------------------------------------"
    
    # KORRIGIERTE RETURN-LOGIC: Nur bei kritischen Problemen Rollback auslösen
    if [ "$failed_critical" -gt 0 ]; then
        return 1  # Echter kritischer Fehler -> Rollback
    else
        return 0  # System ist grundsätzlich OK -> Kein Rollback
    fi
}

##
# Verifikation der Basis-Firewall-Architektur
##
verify_base_firewall_architecture() {
    log_info "    -> Prüfe Basis-Firewall-Architektur..."
    local base_errors=0
    
    # 1. NFTables-Service
    if ! systemctl is-active --quiet nftables; then
        log_error "      ❌ NFTables-Service nicht aktiv"
        base_errors=$((base_errors + 1))
        return $base_errors
    fi
    
    # 2. Haupt-Tabellen existieren
    local required_tables=("inet filter" "ip nat")
    [ "${SERVER_ROLE:-2}" = "1" ] && required_tables+=("ip6 nat")
    
    for table in "${required_tables[@]}"; do
        if sudo nft list table $table >/dev/null 2>&1; then
            log_debug "      ✅ Tabelle '$table' existiert"
        else
            log_error "      ❌ Tabelle '$table' fehlt!"
            base_errors=$((base_errors + 1))
        fi
    done
    
    # 3. Haupt-Chains existieren und haben korrekte Policy
    local input_policy
    input_policy=$(sudo nft list chain inet filter input 2>/dev/null | grep "policy" | awk '{print $NF}' | tr -d ';' || echo "")
    
    if [ "$input_policy" = "drop" ]; then
        log_ok "      ✅ Input-Policy: drop (sicher)"
    else
        log_error "      ❌ Input-Policy: '$input_policy' (sollte 'drop' sein)!"
        base_errors=$((base_errors + 1))
    fi
    
    # 4. GeoIP-Integration (falls aktiviert)
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        if sudo nft list chain inet filter geoip_check >/dev/null 2>&1; then
            log_ok "      ✅ GeoIP-Chain existiert"
            
            # Prüfe ob GeoIP-Sets definiert sind
            local geoip_sets=("geoip_blocked_v4" "geoip_home_v4" "geoip_allowlist_v4")
            local missing_sets=0
            
            for set in "${geoip_sets[@]}"; do
                if ! sudo nft list set inet filter "$set" >/dev/null 2>&1; then
                    missing_sets=$((missing_sets + 1))
                fi
            done
            
            if [ $missing_sets -eq 0 ]; then
                log_ok "      ✅ GeoIP-Sets vollständig definiert"
            else
                log_warn "      ⚠️ $missing_sets GeoIP-Sets fehlen"
            fi
        else
            log_error "      ❌ GeoIP-Chain fehlt (aber GeoIP ist aktiviert)!"
            base_errors=$((base_errors + 1))
        fi
    fi
    
    # 5. Regel-Count Plausibilität
    local total_rules
    total_rules=$(sudo nft list ruleset 2>/dev/null | grep -c "^[[:space:]]*[^#]" || echo "0")
    
    if [ "$total_rules" -gt 5 ]; then
        log_ok "      ✅ Firewall hat $total_rules aktive Regeln (plausibel)"
    else
        log_warn "      ⚠️ Firewall hat nur $total_rules Regeln (möglicherweise unvollständig)"
    fi
    
    return $base_errors
}

##
# KORRIGIERTE VERSION: Verifikation der dynamischen Firewall-Erweiterungen
##
verify_dynamic_firewall_extensions() {
    log_info "    -> Prüfe dynamische Firewall-Erweiterungen..."
    local extension_issues=0
    
    # 1. Tailscale-Integration (falls VPN-Modell) - KORRIGIERT
    if [ "${ACCESS_MODEL:-2}" = "1" ]; then
        log_info "      -> VPN-Modell konfiguriert: Prüfe Tailscale-Integration..."
        
        # Prüfe Tailscale-Firewall-Regeln
        if sudo nft list ruleset 2>/dev/null | grep -q "tailscale0"; then
            log_ok "        ✅ Tailscale-Firewall-Integration aktiv"
            
            # Prüfe NAT-Regeln
            if sudo nft list table ip nat 2>/dev/null | grep -q "tailscale0"; then
                log_ok "        ✅ Tailscale-NAT-Regeln aktiv"
            else
                log_warn "        ⚠️ Tailscale-NAT-Regeln fehlen"
                extension_issues=$((extension_issues + 1))
            fi
        else
            log_error "        ❌ Tailscale-Firewall-Regeln fehlen!"
            extension_issues=$((extension_issues + 1))
        fi
        
        # Prüfe Tailscale-Verbindung (verbesserte Logik)
        if command -v tailscale >/dev/null 2>&1; then
            local ts_status
            ts_status=$(tailscale status 2>/dev/null)
            if [ $? -eq 0 ] && ! echo "$ts_status" | grep -q "Logged out"; then
                log_ok "        ✅ Tailscale VPN ist verbunden"
            else
                log_warn "        ⚠️ Tailscale VPN nicht verbunden"
                extension_issues=$((extension_issues + 1))
            fi
        else
            log_warn "        ⚠️ Tailscale-CLI nicht installiert"
            extension_issues=$((extension_issues + 1))
        fi
    else
        log_info "      -> Öffentliches Modell: Tailscale-Integration nicht erforderlich"
    fi
    
    # 2. Docker-Integration (falls Container-Host) - KORRIGIERT
    if [ "${SERVER_ROLE:-2}" = "1" ]; then
        log_info "      -> Container-Host konfiguriert: Prüfe Docker-Integration..."
        
        if systemctl is-active --quiet docker 2>/dev/null; then
            # Prüfe Docker-Firewall-Integration
            if sudo nft list ruleset 2>/dev/null | grep -q "docker"; then
                log_ok "        ✅ Docker-Firewall-Integration aktiv"
            else
                log_warn "        ⚠️ Docker-Firewall-Regeln nicht sichtbar"
                extension_issues=$((extension_issues + 1))
            fi
            
            # Prüfe Docker-Bridge
            if ip link show docker0 >/dev/null 2>&1; then
                log_ok "        ✅ Docker-Bridge (docker0) aktiv"
            else
                log_error "        ❌ Docker-Bridge fehlt!"
                extension_issues=$((extension_issues + 1))
            fi
            
            # VERBESSERTE Docker-Netzwerk-Prüfung
            local docker_subnet
            if command -v docker >/dev/null 2>&1; then
                docker_subnet=$(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
                if [ -n "$docker_subnet" ] && [ "$docker_subnet" != "<no value>" ]; then
                    log_ok "        ✅ Docker-Netzwerk: $docker_subnet"
                else
                    log_warn "        ⚠️ Docker-Netzwerk-Info nicht verfügbar"
                    extension_issues=$((extension_issues + 1))
                fi
            else
                log_error "        ❌ Docker-CLI nicht verfügbar"
                extension_issues=$((extension_issues + 1))
            fi
        else
            log_error "        ❌ Docker-Service ist nicht aktiv"
            extension_issues=$((extension_issues + 1))
        fi
    else
        log_info "      -> Einfacher Server: Docker-Integration nicht erforderlich"
    fi
    
    # 3. CrowdSec-Integration - KORRIGIERT
    if command -v crowdsec >/dev/null 2>&1; then
        log_info "      -> CrowdSec installiert: Prüfe Firewall-Integration..."
        
        # Prüfe CrowdSec-Tabellen (robuster)
        local crowdsec_tables
        crowdsec_tables=$(sudo nft list tables 2>/dev/null | grep -E "(crowdsec|crowdsec6)" | wc -l)
        if [ "$crowdsec_tables" -gt 0 ]; then
            log_ok "        ✅ CrowdSec-Firewall-Tabellen aktiv ($crowdsec_tables gefunden)"
        else
            log_warn "        ⚠️ CrowdSec-Firewall-Tabellen nicht gefunden"
            extension_issues=$((extension_issues + 1))
        fi
        
        # Prüfe verschiedene CrowdSec-Bouncer
        local bouncer_active=false
        for bouncer in crowdsec-bouncer-setonly crowdsec-firewall-bouncer; do
            if systemctl is-active --quiet "$bouncer" 2>/dev/null; then
                log_ok "        ✅ $bouncer aktiv"
                bouncer_active=true
                break
            fi
        done
        
        if [ "$bouncer_active" = false ]; then
            log_warn "        ⚠️ Kein CrowdSec-Bouncer aktiv"
            extension_issues=$((extension_issues + 1))
        fi
        
        # BONUS: Prüfe CrowdSec-Service selbst
        if ! systemctl is-active --quiet crowdsec 2>/dev/null; then
            log_error "        ❌ CrowdSec-Service nicht aktiv"
            extension_issues=$((extension_issues + 1))
        fi
    fi
    
    # BONUS: Zusammenfassung der gefundenen Probleme
    if [ $extension_issues -eq 0 ]; then
        log_ok "    -> Alle dynamischen Firewall-Erweiterungen funktionieren korrekt"
    else
        log_warn "    -> $extension_issues Problem(e) bei dynamischen Firewall-Erweiterungen gefunden"
    fi
    
    # ERR-Trap temporär deaktivieren für return
    set +e
    return $extension_issues
    set -e
}

##
# Sudo-Sicherheits-Status prüfen
##
verify_sudo_security_status() {
    local sudo_issues=0
    
    # 1. Temporäre NOPASSWD-Dateien suchen
    local temp_sudo_files=()
    while IFS= read -r -d '' file; do
        temp_sudo_files+=("$file")
    done < <(find /etc/sudoers.d/ -name "*temp*" -o -name "99-*" -type f -print0 2>/dev/null)
    
    if [ ${#temp_sudo_files[@]} -gt 0 ]; then
        log_warn "      ⚠️ Temporäre sudo-Dateien gefunden:"
        for file in "${temp_sudo_files[@]}"; do
            if grep -q "NOPASSWD" "$file" 2>/dev/null; then
                log_error "        ❌ $(basename "$file") - enthält NOPASSWD (SICHERHEITSRISIKO!)"
                sudo_issues=$((sudo_issues + 1))
            else
                log_info "        ✅ $(basename "$file") - OK (kein NOPASSWD)"
            fi
        done
    else
        log_ok "      ✅ Keine temporären sudo-Dateien gefunden"
    fi
    
    # 2. ADMIN_USER sudo-Rechte prüfen
    if [ -n "${ADMIN_USER:-}" ]; then
        if [ -f "/etc/sudoers.d/50-$ADMIN_USER" ]; then
            if grep -q "NOPASSWD" "/etc/sudoers.d/50-$ADMIN_USER" 2>/dev/null; then
                log_error "      ❌ SICHERHEITSPROBLEM: '$ADMIN_USER' hat noch NOPASSWD-Rechte!"
                sudo_issues=$((sudo_issues + 1))
            else
                log_ok "      ✅ '$ADMIN_USER' hat sichere sudo-Rechte (mit Passwort)"
            fi
        else
            log_info "      ℹ️ '$ADMIN_USER' nutzt Gruppen-basierte sudo-Rechte"
        fi
        
        # Teste sudo-Fähigkeit
        if sudo -l -U "$ADMIN_USER" >/dev/null 2>&1; then
            log_ok "      ✅ '$ADMIN_USER' hat funktionsfähige sudo-Berechtigung"
        else
            log_error "      ❌ '$ADMIN_USER' hat KEINE sudo-Berechtigung!"
            sudo_issues=$((sudo_issues + 1))
        fi
    fi
    
    # 3. sudoers-System Konsistenz
    if visudo -c >/dev/null 2>&1; then
        log_ok "      ✅ sudoers-System ist konsistent"
    else
        log_error "      ❌ sudoers-System hat SYNTAXFEHLER!"
        sudo_issues=$((sudo_issues + 1))
    fi
    
    return $sudo_issues
}

##
# Netzwerk-Konnektivität prüfen
##
verify_network_connectivity() {
    local network_issues=0
    
    # 1. SSH-Port Verfügbarkeit
    local ssh_port="${SSH_PORT:-22}"
    if ss -tln | grep -q ":$ssh_port "; then
        log_ok "      ✅ SSH-Port $ssh_port ist gebunden und erreichbar"
    else
        log_error "      ❌ SSH-Port $ssh_port ist NICHT erreichbar!"
        network_issues=$((network_issues + 1))
    fi
    
    # 2. Primäres Interface
    if [ -n "${PRIMARY_INTERFACE:-}" ]; then
        if ip link show "${PRIMARY_INTERFACE}" >/dev/null 2>&1; then
            local interface_status
            interface_status=$(ip link show "${PRIMARY_INTERFACE}" | grep -o "state [A-Z]*" | awk '{print $2}')
            if [ "$interface_status" = "UP" ]; then
                log_ok "      ✅ Primäres Interface '${PRIMARY_INTERFACE}' ist UP"
            else
                log_warn "      ⚠️ Primäres Interface '${PRIMARY_INTERFACE}' Status: $interface_status"
            fi
        else
            log_error "      ❌ Primäres Interface '${PRIMARY_INTERFACE}' nicht gefunden!"
            network_issues=$((network_issues + 1))
        fi
    fi
    
    # 3. Tailscale-Status (falls VPN-Modell)
    if [ "${ACCESS_MODEL:-2}" = "1" ]; then
        if command -v tailscale >/dev/null 2>&1; then
            if tailscale status >/dev/null 2>&1 && ! tailscale status 2>/dev/null | grep -q "Logged out"; then
                local tailscale_ip
                tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "")
                log_ok "      ✅ Tailscale VPN verbunden (IP: ${tailscale_ip:-keine IPv4})"
            else
                log_error "      ❌ Tailscale VPN nicht verbunden oder nicht authentifiziert!"
                network_issues=$((network_issues + 1))
            fi
        else
            log_error "      ❌ Tailscale nicht installiert (aber VPN-Modell konfiguriert)!"
            network_issues=$((network_issues + 1))
        fi
    fi
    
    # 4. Docker-Netzwerk (falls Container-Host)
    if [ "${SERVER_ROLE:-2}" = "1" ] && systemctl is-active --quiet docker; then
        if ip link show docker0 >/dev/null 2>&1; then
            local docker_ip
            docker_ip=$(ip -4 addr show docker0 | grep -oP 'inet \K[\d.]+' || echo "")
            log_ok "      ✅ Docker-Bridge aktiv (Gateway: ${docker_ip:-unbekannt})"
        else
            log_error "      ❌ Docker-Bridge 'docker0' nicht gefunden!"
            network_issues=$((network_issues + 1))
        fi
    fi
    
    # 5. Internet-Konnektivität (Basis-Test)
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        log_ok "      ✅ Internet-Konnektivität verfügbar"
    else
        log_warn "      ⚠️ Internet-Konnektivität nicht testbar (Ping blockiert?)"
    fi
    
    return $network_issues
}

################################################################################
# ENDE MODUL SETUP-VERIFIKATION v4.5 SUDO-NFT KORRIGIERT
################################################################################
