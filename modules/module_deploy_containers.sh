#!/bin/bash
################################################################################
#
# MODUL: MANAGEMENT-CONTAINER - v4.3 KORRIGIERT
#
# @description: Startet Management-Container (Portainer, Watchtower) mit
#               intelligenter Netzwerk-Integration und Fehlerbehandlung
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ÄNDERUNGEN v4.3:
# - Robuste Container-Bereinigung vor Neustart
# - Intelligente Port-Bindung basierend auf Zugriffs-Modell
# - Bessere Fehlerbehandlung und Status-Verifikation
# - Tailscale-Integration für sichere Container-Verwaltung
# - Erweiterte Logging und Debug-Informationen
#
################################################################################

##
# Hauptfunktion: Startet die Management-Container mit optimaler Konfiguration
##
module_deploy_containers() {
    # Guard Clause: Nur ausführen wenn Docker-Host konfiguriert
    if [ "$SERVER_ROLE" != "1" ]; then
        log_info "🐳 Management-Container übersprungen (SERVER_ROLE != 1)"
        return 0
    fi
    
    log_info "🐳 MODUL: Management-Container (Portainer & Watchtower)"

    # --- VORAUSSETZUNGEN PRÜFEN ---
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker ist nicht installiert! Modul wird übersprungen."
        return 1
    fi
    
    if ! systemctl is-active --quiet docker; then
        log_error "Docker-Service ist nicht aktiv! Modul wird übersprungen."
        return 1
    fi
    
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker-Daemon ist nicht erreichbar! Modul wird übersprungen."
        return 1
    fi

    # --- PORTAINER DEPLOYMENT ---
    if [ "${INSTALL_PORTAINER:-ja}" = "ja" ]; then
        deploy_portainer_container
    else
        log_info "  -> Portainer-Installation übersprungen (INSTALL_PORTAINER=nein)"
    fi

    # --- WATCHTOWER DEPLOYMENT ---
    if [ "${INSTALL_WATCHTOWER:-ja}" = "ja" ]; then
        deploy_watchtower_container
    else
        log_info "  -> Watchtower-Installation übersprungen (INSTALL_WATCHTOWER=nein)"
    fi

    # --- ABSCHLUSS-VERIFIKATION ---
    verify_management_containers
    
    log_ok "Modul Management-Container erfolgreich abgeschlossen."
}

##
# Deployt den Portainer-Container mit optimaler Konfiguration
##
deploy_portainer_container() {
    log_info "  -> 1/2: Deploye Portainer Web-Management..."
    
    # --- Container-Bereinigung für sauberen Start ---
    local cleanup_output
    cleanup_output=$(docker stop portainer 2>&1 || true)
    [ -n "$cleanup_output" ] && log_debug "Portainer gestoppt: $cleanup_output"
    
    cleanup_output=$(docker rm portainer 2>&1 || true)  
    [ -n "$cleanup_output" ] && log_debug "Portainer entfernt: $cleanup_output"
    
    # --- Port-Bindung basierend auf Zugriffs-Modell bestimmen ---
    local portainer_bind=""
    local access_info=""
    
    if [ "${ACCESS_MODEL:-2}" = "1" ] && [ "${TAILSCALE_ACTIVE:-false}" = "true" ]; then
        # VPN-Modell: Binde nur an Tailscale oder localhost
        local tailscale_ip="${TAILSCALE_IP:-127.0.0.1}"
        portainer_bind="${tailscale_ip}:9443:9443 -p ${tailscale_ip}:8000:8000"
        access_info="VPN-only (https://${tailscale_ip}:9443)"
    else
        # Öffentliches Modell: Binde an alle Interfaces
        portainer_bind="9443:9443 -p 8000:8000"
        access_info="Öffentlich (https://$(hostname -I | awk '{print $1}'):9443)"
    fi
    
    log_info "     -> Port-Bindung: $access_info"
    
    # --- Portainer-Container starten ---
    local portainer_cmd="docker run -d \
        --name=portainer \
        --restart=always \
        -p $portainer_bind \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v portainer_data:/data \
        --label='service=portainer' \
        --label='managed-by=server-baukasten' \
        portainer/portainer-ce:latest"

    if run_with_spinner "Starte Portainer-Container (Image-Pull kann dauern)..." "$portainer_cmd"; then
        log_ok "Portainer erfolgreich gestartet."
        
        # --- Container-Status verifizieren ---
        sleep 3  # Kurz warten bis Container vollständig gestartet
        local container_status
        container_status=$(docker inspect portainer --format '{{.State.Status}}' 2>/dev/null || echo "unknown")
        
        if [ "$container_status" = "running" ]; then
            log_ok "  ✅ Container-Status: Läuft"
            log_info "  🌐 Web-Zugang: $access_info"
            
            # Erste Setup-Hinweise
            log_info "  📋 Erste Anmeldung: Admin-Account in Web-UI erstellen"
            if [ "${ACCESS_MODEL:-2}" = "2" ]; then
                log_warn "  🔒 SICHERHEIT: Portainer ist öffentlich erreichbar!"
                log_info "     -> Starkes Admin-Passwort wählen"
                log_info "     -> Eventuell Firewall-Regel hinzufügen für Port 9443"
            fi
        else
            log_error "  ❌ Container-Status: $container_status"
            log_info "Debug: docker logs portainer"
        fi
        
    else
        log_error "Portainer-Container konnte nicht gestartet werden!"
        log_info "Debug-Befehle:"
        log_info "  -> docker logs portainer"
        log_info "  -> docker inspect portainer"
    fi
}

##  
# Deployt den Watchtower-Container für automatische Updates
##
deploy_watchtower_container() {
    log_info "  -> 2/2: Deploye Watchtower Auto-Update-Service..."
    
    # --- Container-Bereinigung ---
    docker stop watchtower >/dev/null 2>&1 || true
    docker rm watchtower >/dev/null 2>&1 || true
    
    # --- Watchtower-Konfiguration ---
    # Täglich um 04:00 Uhr, nur Container mit Label updaten
    local watchtower_cmd="docker run -d \
        --name=watchtower \
        --restart=always \
        -v /var/run/docker.sock:/var/run/docker.sock \
        --label='service=watchtower' \
        --label='managed-by=server-baukasten' \
        containrrr/watchtower \
        --schedule '0 4 * * *' \
        --cleanup \
        --label-enable \
        --rolling-restart \
        --include-restarting"

    if run_with_spinner "Starte Watchtower-Container (Image-Pull kann dauern)..." "$watchtower_cmd"; then
        log_ok "Watchtower erfolgreich gestartet."
        
        # --- Container-Status verifizieren ---
        sleep 3
        local container_status  
        container_status=$(docker inspect watchtower --format '{{.State.Status}}' 2>/dev/null || echo "unknown")
        
        if [ "$container_status" = "running" ]; then
            log_ok "  ✅ Container-Status: Läuft"
            log_info "  ⏰ Update-Schedule: Täglich 04:00 Uhr"
            log_info "  🏷️  Update-Modus: Nur Container mit Labels"
            log_info "  🧹 Cleanup: Alte Images werden automatisch entfernt"
        else
            log_error "  ❌ Container-Status: $container_status"
            log_info "Debug: docker logs watchtower"
        fi
        
    else
        log_error "Watchtower-Container konnte nicht gestartet werden!")
        log_info "Debug-Befehle:"
        log_info "  -> docker logs watchtower"
        log_info "  -> docker inspect watchtower"
    fi
}

##
# Verifiziert den Status aller Management-Container
##
verify_management_containers() {
    log_info "  -> Finale Verifikation der Management-Container..."
    
    local running_containers=0
    local total_expected=0
    
    # Prüfe Portainer
    if [ "${INSTALL_PORTAINER:-ja}" = "ja" ]; then
        ((total_expected++))
        if docker ps --filter "name=portainer" --format "{{.Names}}" | grep -q "portainer"; then
            ((running_containers++))
            log_ok "  ✅ Portainer: Läuft"
        else
            log_error "  ❌ Portainer: Nicht laufend"
        fi
    fi
    
    # Prüfe Watchtower
    if [ "${INSTALL_WATCHTOWER:-ja}" = "ja" ]; then
        ((total_expected++))
        if docker ps --filter "name=watchtower" --format "{{.Names}}" | grep -q "watchtower"; then
            ((running_containers++))
            log_ok "  ✅ Watchtower: Läuft"
        else
            log_error "  ❌ Watchtower: Nicht laufend"
        fi
    fi
    
    # Gesamtbewertung
    log_info "--- MANAGEMENT-CONTAINER STATUS ---"
    log_info "  Laufende Container: $running_containers/$total_expected"
    
    if [ $running_containers -eq $total_expected ] && [ $total_expected -gt 0 ]; then
        log_ok "🎉 Alle Management-Container erfolgreich deployt!"
    elif [ $running_containers -gt 0 ]; then
        log_warn "⚠️  Teilweise erfolgreich ($running_containers/$total_expected Container laufen)"
    else
        log_error "❌ Keine Management-Container erfolgreich gestartet!"
        return 1
    fi
    
    # Hilfreiche Informationen für den Admin
    log_info "--- CONTAINER-VERWALTUNG ---"
    log_info "  Alle Container: docker ps -a"
    log_info "  Nur laufende: docker ps"  
    log_info "  Container-Logs: docker logs <container-name>"
    log_info "  Container stoppen: docker stop <container-name>"
    log_info "  Container entfernen: docker rm <container-name>"
    
    if [ "${INSTALL_PORTAINER:-ja}" = "ja" ] && docker ps --filter "name=portainer" -q | grep -q .; then
        local portainer_ip
        if [ "${ACCESS_MODEL:-2}" = "1" ] && [ -n "${TAILSCALE_IP:-}" ]; then
            portainer_ip="${TAILSCALE_IP}"
        else
            portainer_ip=$(hostname -I | awk '{print $1}')
        fi
        
        log_info "--- PORTAINER-ZUGANG ---"
        log_info "  Web-Interface: https://${portainer_ip}:9443"
        
        if [ "${ACCESS_MODEL:-2}" = "2" ]; then
            log_info "  SSH-Tunnel (sicherer): ssh -L 9443:localhost:9443 ${ADMIN_USER:-admin}@${portainer_ip}"
            log_info "  Dann im Browser: https://localhost:9443"
        fi
    fi
    
    return 0
}

################################################################################
# ENDE MODUL MANAGEMENT-CONTAINER v4.3
################################################################################
