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

##
# MODUL: Konfiguriert die Docker-Engine, das Netzwerk und die dazugehörigen
# Firewall-Regeln. Passt sich dynamisch an die Kernel-Fähigkeiten an.
##
module_container() {
    # Guard Clause: Nur ausführen, wenn der Server als Docker-Host konfiguriert ist.
    [ "$SERVER_ROLE" != "1" ] && return 0

    log_info "🐳 MODUL: Container (Docker Daemon & Netzwerk)"

    # 1. Kernel-Unterstützung für IPv6-NAT prüfen
    log_info "  -> Prüfe Kernel-Unterstützung für IPv6-NAT..."
    if [ "$(check_ipv6_nat_kernel)" = "true" ]; then
        log_ok "Kernel unterstützt IPv6-NAT -> Docker IPv6 wird konfiguriert."
        local ipv6_enabled=true
    else
        log_warn "Kernel unterstützt kein IPv6-NAT -> Docker wird im IPv4-only-Modus konfiguriert."
        local ipv6_enabled=false
    fi

    # 2. Docker-Konfiguration (daemon.json) dynamisch erstellen
    log_info "  -> Erstelle Docker-Konfiguration (daemon.json)..."
    local daemon_json="/etc/docker/daemon.json"
    backup_and_register "$daemon_json"
    
    # Baue den jq-Befehl dynamisch auf, um Code-Dopplung zu vermeiden
    local jq_cmd='jq -n \
        --arg bip "$(echo "$DOCKER_IPV4_CIDR" | cut -d'"'"'/'"'"' -f1 | sed '"'"'s/\.0$//'"'"').1/$(echo "$DOCKER_IPV4_CIDR" | cut -d'"'"'/'"'"' -f2)" \
        --arg fixed_cidr "$DOCKER_IPV4_CIDR" \
        "{
            \"bip\": \$bip,
            \"fixed-cidr\": \$fixed_cidr,
            \"iptables\": true,
            \"log-driver\": \"journald\",
            \"log-opts\": { \"tag\": \"{{.Name}}/{{.FullID}}\" },
            \"exec-opts\": [\"native.cgroupdriver=systemd\"],
            \"storage-driver\": \"overlay2\",
            \"live-restore\": true,
            \"userland-proxy\": false
        }"'

    if [ "$ipv6_enabled" = true ]; then
        jq_cmd+=' | jq \
            --arg fixed_cidr_v6 "$DOCKER_IPV6_CIDR" \
            ".ipv6 = true | .\"fixed-cidr-v6\" = \$fixed_cidr_v6 | .ip6tables = true"'
    else
        jq_cmd+=' | jq ".ipv6 = false | .ip6tables = false"'
    fi
    eval "$jq_cmd" > "$daemon_json"

    # 3. systemd Drop-in für garantierte Start-Reihenfolge
    log_info "  -> Erstelle systemd-Abhängigkeit: Docker startet nach nftables..."
    mkdir -p "/etc/systemd/system/docker.service.d"
    cat > "/etc/systemd/system/docker.service.d/dependencies.conf" <<'EOF'
[Unit]
Requires=nftables.service
After=nftables.service
EOF
    run_with_spinner "Lade systemd-Konfiguration neu..." "systemctl daemon-reload"

    # 4. Docker-Dienst aktivieren und starten
    run_with_spinner "Aktiviere und starte Docker-Dienst..." "systemctl enable --now docker"
    log_ok "Docker Daemon ist konfiguriert und gestartet."

    # 5. Firewall-Regeln für Docker generieren und anwenden
    log_info "  -> Konfiguriere Firewall-Regeln für Docker..."
    local docker_interface
    docker_interface=$(docker network inspect bridge | jq -r '.[0].Options["com.docker.network.bridge.name"]')
    
    if [ -n "$docker_interface" ]; then
        log_debug "Docker-Interface '$docker_interface' erkannt."
        
        # Rufe das "Werkzeug" aus der Firewall-Bibliothek auf
        generate_docker_rules "$docker_interface" "$TAILSCALE_INTERFACE"
        
        # Wende die neu erstellten Firewall-Regeln sofort an
        run_with_spinner "Aktualisiere Firewall-Regeln für Docker..." "systemctl reload nftables"
    else
        log_warn "Konnte Docker-Interface nicht erkennen. Firewall-Regeln übersprungen."
    fi

    log_ok "Docker-Modul erfolgreich abgeschlossen."
}
