#!/bin/bash
################################################################################
#
# MODUL: MANAGEMENT-CONTAINER
#
# @description: Startet die Management-Container (Portainer, Watchtower).
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

##
# MODUL: Startet die Management-Container (Portainer, Watchtower).
# Setzt voraus, dass module_container bereits gelaufen ist.
##
module_deploy_containers() {
    # Führt nur aus, wenn der Server als Docker-Host konfiguriert ist.
    [ "$SERVER_ROLE" != "1" ] && return 0
    
    log_info "🐳 MODUL: Management-Container (Portainer, Watchtower)"

    if [ "${INSTALL_PORTAINER:-ja}" = "ja" ]; then
        log_info "  -> Deploye Portainer-Container..."
        # Stelle sicher, dass alte Container-Versionen vorher entfernt werden
        docker stop portainer >/dev/null 2>&1 || true
        docker rm portainer >/dev/null 2>&1 || true
        
        local portainer_cmd="docker run -d -p 9443:9443 -p 8000:8000 --name=portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:latest"

        if run_with_spinner "Starte Portainer (Image-Pull kann dauern)..." "$portainer_cmd"; then
            local docker_gateway_ip
            docker_gateway_ip=$(ip -4 addr show docker0 | grep -oP 'inet \K[\d.]+')
            log_ok "Portainer gestartet. Zugriff im VPN via: https://${docker_gateway_ip}:9443"
        else
            log_error "Portainer konnte nicht gestartet werden."
        fi
    fi
    
    if [ "${INSTALL_WATCHTOWER:-ja}" = "ja" ]; then
        log_info "  -> Deploye Watchtower-Container..."
        docker stop watchtower >/dev/null 2>&1 || true
        docker rm watchtower >/dev/null 2>&1 || true
        
        local watchtower_cmd="docker run -d --name=watchtower --restart=always -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --schedule \"0 4 * * *\" --cleanup"

        if run_with_spinner "Starte Watchtower (Image-Pull kann dauern)..." "$watchtower_cmd"; then
            log_ok "Watchtower für tägliche Container-Updates (04:00 Uhr) aktiviert."
        else
            log_error "Watchtower konnte nicht gestartet werden."
        fi
    fi

    log_ok "Modul Management-Container erfolgreich abgeschlossen."
}