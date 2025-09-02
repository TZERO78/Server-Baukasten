#!/bin/bash
################################################################################
#
# MODUL: NETZWERK (v4.3) - KORRIGIERT
#
# @description: Installiert und konfiguriert Tailscale VPN mit dynamischer
#               Firewall-Integration über die neue activate_tailscale_rules()
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ÄNDERUNGEN v4.3:
# - Nutzt activate_tailscale_rules() für dynamische Firewall-Integration
# - Bessere Interface-Erkennung und Validierung
# - Robuste Fehlerbehandlung bei Tailscale-Setup
# - Erweiterte Status-Verifikation
#
################################################################################

##
# Installiert (falls nötig) und konfiguriert eine Tailscale-VPN-Verbindung
# mit automatischer Firewall-Integration.
##
setup_tailscale() {
    log_info "🔗 SETUP: Tailscale VPN-Verbindung mit Firewall-Integration..."
    
    # --- SCHRITT 1: Installation sicherstellen ---
    if ! command -v tailscale &>/dev/null; then
        log_info "  -> Tailscale ist nicht installiert. Starte Installation..."
        
        # Tailscale APT-Repository und Installation
        local install_cmd="curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | gpg --dearmor -o /usr/share/keyrings/tailscale-archive-keyring.gpg && \
            echo 'deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/debian bookworm main' > /etc/apt/sources.list.d/tailscale.list && \
            apt-get update -qq && \
            DEBIAN_FRONTEND=noninteractive apt-get install -y tailscale"
        
        if ! run_with_spinner "Installiere Tailscale-Paket..." "bash -c \"$install_cmd\""; then
            log_error "Tailscale-Installation fehlgeschlagen!"
            return 1
        fi
        log_ok "Tailscale erfolgreich installiert."
    else
        log_info "  -> Tailscale ist bereits installiert."
    fi

    # --- SCHRITT 2: Vorab-Prüfung - Ist bereits verbunden? ---
    log_info "  -> Prüfe aktuellen Tailscale-Status..."
    if tailscale status >/dev/null 2>&1 && ! tailscale status 2>/dev/null | grep -q "Logged out"; then
        local current_ip
        current_ip=$(tailscale ip -4 2>/dev/null || echo "")
        local current_interface
        current_interface=$(ip link show | grep -E '^[0-9]+: tailscale[0-9]*:' | head -n1 | cut -d: -f2 | tr -d ' ' || echo "")
        
        if [ -n "$current_ip" ] && [ -n "$current_interface" ]; then
            log_ok "Tailscale ist bereits verbunden (IP: $current_ip, Interface: $current_interface)"
            
            # Setze globale Variablen für andere Module
            export TAILSCALE_IP="$current_ip"
            export TAILSCALE_INTERFACE="$current_interface" 
            export TAILSCALE_ACTIVE="true"
            export TAILSCALE_READY="true"
            
            # Aktiviere Firewall-Regeln für bestehendes Interface
            log_info "  -> Aktiviere Firewall-Regeln für vorhandenes Tailscale-Interface..."
            if activate_tailscale_rules "$current_interface"; then
                log_ok "Firewall-Integration für Tailscale erfolgreich aktiviert."
            else
                log_warn "Firewall-Integration fehlgeschlagen, aber Tailscale funktioniert."
            fi
            return 0
        fi
    fi

    # --- SCHRITT 3: Tailscale-Daemon starten (falls nicht aktiv) ---
    if ! systemctl is-active --quiet tailscaled; then
        log_info "  -> Starte tailscaled-Daemon..."
        if ! run_with_spinner "Aktiviere tailscaled-Service..." "systemctl enable --now tailscaled"; then
            log_error "tailscaled-Daemon konnte nicht gestartet werden!"
            return 1
        fi
        
        # Kurz warten bis der Daemon bereit ist
        sleep 3
    fi

    # --- SCHRITT 4: Verbindungs-Befehl vorbereiten ---
    log_info "  -> Bereite Tailscale-Verbindung vor..."
    local tailscale_cmd=("tailscale" "up" "--ssh" "--accept-routes" "--reset")
    
    # Subnet-Routing für Docker-Host konfigurieren
    if [ "$SERVER_ROLE" = "1" ]; then
        log_info "     -> Docker-Host erkannt: Konfiguriere Subnet-Routing..."
        tailscale_cmd+=("--advertise-routes=$DOCKER_IPV4_CIDR,$DOCKER_IPV6_CIDR")
        log_info "     -> Advertised Subnets: $DOCKER_IPV4_CIDR, $DOCKER_IPV6_CIDR"
    fi

    # --- SCHRITT 5: Verbindungsversuch (automatisch oder interaktiv) ---
    local connection_successful=false
    
    if [ -n "${TAILSCALE_AUTH_KEY:-}" ]; then
        log_info "  -> Verwende Auth-Key für automatische Authentifizierung..."
        tailscale_cmd_with_key=("${tailscale_cmd[@]}" "--authkey=$TAILSCALE_AUTH_KEY")
        
        if run_with_spinner "Verbinde mit Tailscale (automatisch)..." "${tailscale_cmd_with_key[*]}"; then
            connection_successful=true
            log_ok "Automatische Tailscale-Authentifizierung erfolgreich."
        else
            log_warn "Automatische Authentifizierung mit Auth-Key fehlgeschlagen!"
            log_info "  -> Wechsle zum interaktiven Modus..."
        fi
    else
        log_info "  -> Kein Auth-Key konfiguriert - verwende interaktiven Modus."
    fi
    
    # Fallback: Interaktive Authentifizierung
    if [ "$connection_successful" = false ]; then
        log_info "  -> Starte interaktive Tailscale-Authentifizierung..."
        echo ""
        echo "📋 INTERAKTIVE TAILSCALE-ANMELDUNG:"
        echo "   1. Ein Browser-Link wird gleich angezeigt"
        echo "   2. Öffne den Link in deinem Browser"  
        echo "   3. Melde dich bei Tailscale an"
        echo "   4. Autorisiere diesen Server"
        echo ""
        read -p "   Bereit für die Anmeldung? (Enter drücken)" -r
        
        # Interaktiver Befehl (ohne Auth-Key)
        interactive_cmd=("${tailscale_cmd[@]}")
        
        echo "🔗 Führe Tailscale-Verbindung aus..."
        if "${interactive_cmd[@]}"; then
            connection_successful=true
            log_ok "Interaktive Tailscale-Authentifizierung erfolgreich."
        else
            log_error "Auch die interaktive Authentifizierung ist fehlgeschlagen!"
            return 1
        fi
    fi
    
    # --- SCHRITT 6: Verbindung verifizieren und Interface ermitteln ---
    log_info "  -> Warte auf vollständige Verbindungsherstellung..."
    
    # Warte bis zu 15 Sekunden auf die Verbindung
    local wait_time=0
    local max_wait=15
    local tailscale_ip=""
    local tailscale_interface=""
    
    while [ $wait_time -lt $max_wait ]; do
        sleep 1
        ((wait_time++))
        
        # Prüfe ob Tailscale verbunden ist
        if tailscale status >/dev/null 2>&1 && ! tailscale status 2>/dev/null | grep -q "Logged out"; then
            # Ermittle IP und Interface
            tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "")
            tailscale_interface=$(ip link show | grep -E '^[0-9]+: tailscale[0-9]*:' | head -n1 | cut -d: -f2 | tr -d ' ' || echo "")
            
            if [ -n "$tailscale_ip" ] && [ -n "$tailscale_interface" ]; then
                log_ok "Tailscale-Verbindung erfolgreich hergestellt!"
                log_info "  📍 Tailscale-IP: $tailscale_ip"
                log_info "  🔌 Interface: $tailscale_interface"
                break
            fi
        fi
    done
    
    # Finale Validierung
    if [ -z "$tailscale_ip" ] || [ -z "$tailscale_interface" ]; then
        log_error "Tailscale-Verbindung konnte nicht vollständig hergestellt werden!"
        log_error "  -> IP: ${tailscale_ip:-NICHT ERHALTEN}"
        log_error "  -> Interface: ${tailscale_interface:-NICHT GEFUNDEN}"
        return 1
    fi

    # --- SCHRITT 7: Globale Variablen setzen für andere Module ---
    export TAILSCALE_IP="$tailscale_ip"
    export TAILSCALE_INTERFACE="$tailscale_interface"
    export TAILSCALE_ACTIVE="true"
    export TAILSCALE_READY="true"

    # --- SCHRITT 8: Firewall-Integration aktivieren ---
    log_info "  -> Integriere Tailscale in die Firewall-Konfiguration..."
    if activate_tailscale_rules "$tailscale_interface"; then
        log_ok "Firewall-Regeln für Tailscale erfolgreich aktiviert."
    else
        log_error "Firewall-Integration fehlgeschlagen!"
        log_warn "Tailscale funktioniert, aber Firewall-Regeln sind möglicherweise unvollständig."
        # Nicht return 1 - Tailscale selbst funktioniert ja
    fi

    # --- SCHRITT 9: Auto-Update aktivieren ---
    log_info "  -> Aktiviere automatische Tailscale-Updates..."
    if run_with_spinner "Konfiguriere Auto-Updates..." "tailscale set --auto-update"; then
        log_ok "Auto-Updates für Tailscale aktiviert."
    else
        log_warn "Auto-Updates konnten nicht aktiviert werden (nicht kritisch)."
    fi

    # --- SCHRITT 10: Erweiterte Konfiguration für Docker-Hosts ---
    if [ "$SERVER_ROLE" = "1" ]; then
        log_info "  -> Konfiguriere erweiterte Docker-Host-Features..."
        
        # Subnet-Router Status prüfen
        if tailscale status --json 2>/dev/null | grep -q "SubnetRoutes"; then
            log_ok "Subnet-Routing für Docker-Netzwerke ist aktiv."
        else
            log_warn "Subnet-Routing scheint nicht aktiv zu sein."
            log_info "  -> Manuell aktivieren in der Tailscale-Admin-Console"
        fi
    fi

    # --- ERFOLGS-ZUSAMMENFASSUNG ---
    log_ok "🎉 Tailscale VPN-Setup erfolgreich abgeschlossen!"
    log_info "--- VERBINDUNGSDETAILS ---"
    log_info "  🌐 Tailscale-IP: $tailscale_ip"
    log_info "  🔌 Interface: $tailscale_interface" 
    log_info "  🔐 SSH-Zugang via VPN: ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$tailscale_ip"
    
    if [ "$SERVER_ROLE" = "1" ]; then
        log_info "  🐳 Docker-Subnets über VPN: $DOCKER_IPV4_CIDR, $DOCKER_IPV6_CIDR"
    fi
    
    return 0
}

##
# HAUPT-MODUL: Netzwerk-Konfiguration
# Orchestriert Tailscale-Setup basierend auf ACCESS_MODEL
##
module_network() {
    #TEST_MODE="$1"
    log_info "🌐 MODUL: Netzwerk-Konfiguration (Tailscale VPN)"
    log_info "DEBUG: Eingeparameter - ACCESS_MODEL='${ACCESS_MODEL:-UNSET}', TEST_MODE='$TEST_MODE'"
    # Test-Modus: Überspringe zeitaufwändiges Tailscale-Setup
    if [ "${TEST_MODE}" = true ]; then
        log_warn "TEST-MODUS: Überspringe Tailscale-Setup (simuliere erfolgreiche Verbindung)."
        
        # Setze Dummy-Werte für Tests
        export TAILSCALE_IP="100.64.0.1"
        export TAILSCALE_INTERFACE="tailscale0"
        export TAILSCALE_ACTIVE="true"
        export TAILSCALE_READY="true"
        
        # Aktiviere trotzdem die Firewall-Regeln für Tests
        if [ "$ACCESS_MODEL" = "1" ]; then
            log_info "  -> Aktiviere Test-Firewall-Regeln für Tailscale..."
            activate_tailscale_rules "tailscale0" >/dev/null 2>&1 || true
        fi
        
        log_ok "Netzwerk-Modul im Test-Modus abgeschlossen."
        return 0
    fi
    
    # Produktiv-Modus: Führe echtes Tailscale-Setup durch
    if [ "$ACCESS_MODEL" = "1" ]; then
        log_info "  -> ACCESS_MODEL=1: Konfiguriere VPN-only Zugang über Tailscale..."
        
        # Die setup_tailscale() Funktion hat bereits ihr eigenes detailliertes Logging
        if setup_tailscale; then
            log_ok "VPN-only Netzwerk-Konfiguration erfolgreich."
            
            # Zusätzliche Sicherheits-Empfehlung
            log_info "💡 SICHERHEITS-TIPP: Sperre den öffentlichen SSH-Port bei deinem VPS-Provider!"
            log_info "   -> Dann ist der Server nur noch über Tailscale erreichbar (maximale Sicherheit)"
        else
            log_error "VPN-Setup fehlgeschlagen! Fallback auf öffentlichen Zugang."
            log_warn "  -> Server bleibt über öffentlichen SSH-Port erreichbar"
            log_warn "  -> Tailscale kann später manuell konfiguriert werden"
            
            # Setze Fallback-Variablen
            export TAILSCALE_ACTIVE="false"
            export TAILSCALE_READY="false"
            # Nicht return 1 - Server soll trotzdem funktionieren
        fi
    else
        log_info "  -> ACCESS_MODEL=2: Öffentlicher Zugang konfiguriert."
        log_info "     Tailscale-Setup wird übersprungen (kann später manuell hinzugefügt werden)."
        
        # Setze Variablen für öffentlichen Modus
        export TAILSCALE_ACTIVE="false" 
        export TAILSCALE_READY="false"
    fi
    
    log_ok "Modul Netzwerk-Konfiguration abgeschlossen."
    
    # Debug-Info für andere Module
    if [ "${DEBUG:-false}" = "true" ]; then
        log_debug "Netzwerk-Variablen für nachfolgende Module:"
        log_debug "  TAILSCALE_ACTIVE: ${TAILSCALE_ACTIVE:-ungesetzt}"
        log_debug "  TAILSCALE_READY: ${TAILSCALE_READY:-ungesetzt}" 
        log_debug "  TAILSCALE_IP: ${TAILSCALE_IP:-ungesetzt}"
        log_debug "  TAILSCALE_INTERFACE: ${TAILSCALE_INTERFACE:-ungesetzt}"
    fi
}

################################################################################
# ENDE MODUL NETZWERK v4.3
################################################################################
