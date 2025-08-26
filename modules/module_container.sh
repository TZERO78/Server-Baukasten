#!/bin/bash
################################################################################
#
# MODUL: CONTAINER (DOCKER)
#
# @description: Konfiguriert die Docker-Engine und deployt Management-Container.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

module_container() {
    # Führt nur aus, wenn der Server als Docker-Host konfiguriert ist.
    [ "$SERVER_ROLE" != "1" ] && return 0
    
    log_info "🐳 MODUL: Container (Docker Daemon & Netzwerk)"
    mkdir -p /etc/docker
    local daemon_json="/etc/docker/daemon.json"
    backup_and_register "$daemon_json"
    
    local docker_gateway_ip
    docker_gateway_ip=$(echo "$DOCKER_IPV4_CIDR" | cut -d'/' -f1 | sed 's/\.0$//').1
    
    log_info "  -> Erstelle Docker-Konfiguration (daemon.json)..."
    
    # Schreibt die komplette, gehärtete Docker-Konfiguration
    jq -n \
    --arg bip "$docker_gateway_ip/$(echo "$DOCKER_IPV4_CIDR" | cut -d'/' -f2)" \
    --arg fixed_cidr "$DOCKER_IPV4_CIDR" \
    --arg fixed_cidr_v6 "$DOCKER_IPV6_CIDR" \
    '{
        "bip": $bip,
        "fixed-cidr": $fixed_cidr,
        "ipv6": true,
        "fixed-cidr-v6": $fixed_cidr_v6,
        "ip6tables": true,
        "iptables": true,
        "log-driver": "journald",
        "log-opts": { 
        "tag": "{{.Name}}/{{.FullID}}"
        },
        "exec-opts": ["native.cgroupdriver=systemd"],
        "storage-driver": "overlay2",
        "live-restore": true,
        "userland-proxy": false
    }' > "$daemon_json"
    
    # --- NEU: systemd Drop-in für stabilen Start ---
    log_info "  -> Erstelle systemd-Abhängigkeit: Docker muss nach nftables starten..."
    local override_dir="/etc/systemd/system/docker.service.d"
    mkdir -p "$override_dir"

    cat > "$override_dir/dependencies.conf" <<'EOF'
[Unit]
# Stellt sicher, dass Docker erst startet, nachdem die Firewall aktiv ist.
# Dies verhindert die "Race Condition" beim Systemstart und bei der Erst-Installation.
Requires=nftables.service
After=nftables.service
EOF

    # Konfiguration des Service-Managers neu laden, um die Änderung zu übernehmen
    run_with_spinner "Lade systemd-Konfiguration neu..." "systemctl daemon-reload"
    
    # Jetzt, mit der garantierten Startreihenfolge, können wir Docker sicher starten.
    if ! run_with_spinner "Aktiviere und starte Docker-Dienst..." "systemctl enable --now docker"; then
        log_error "Docker-Dienst konnte nicht gestartet werden! Container können nicht deployt werden."
        return 1
    fi
    
    log_ok "Docker Daemon konfiguriert und startet jetzt zuverlässig nach der Firewall."
}