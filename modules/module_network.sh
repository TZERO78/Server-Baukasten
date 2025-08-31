#!/bin/bash
################################################################################
#
# MODUL: NETZWERK
#
# @description: Installiert und konfiguriert Tailscale als sichere
#               VPN-Verbindung.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

##
## Installiert (falls nötig) und konfiguriert eine Tailscale-Verbindung.
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
    
    # 6. Globale Variable mit dem erkannten Interface-Namen füllen
    TAILSCALE_INTERFACE=$(ip -br a | awk '/^tailscale0/ {print $1}')
    
    if [ -n "$TAILSCALE_INTERFACE" ]; then
        log_debug "Globaler Zustand aktualisiert: TAILSCALE_INTERFACE=$TAILSCALE_INTERFACE"
        
        #Das "Werkzeug" aus der Firewall-Bibliothek aufrufen
        generate_tailscale_rules "$TAILSCALE_INTERFACE"
        
        # 3. Die neu erstellten Firewall-Regeln sofort anwenden
        run_with_spinner "Aktualisiere Firewall-Regeln für Tailscale..." "systemctl reload nftables"
    else
        log_warn "Konnte Tailscale-Interface nicht finden. Firewall-Regeln werden übersprungen."
    fi

    return 0
}

##
## MODUL: NETZWERK
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
