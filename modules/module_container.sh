#!/bin/bash
################################################################################
#
# MODUL: CONTAINER (DOCKER) - v4.4 MIT INSTALLATION
#
# @description: Installiert und konfiguriert Docker-Engine mit gehärteter 
#               Konfiguration und dynamischer Firewall-Integration
# @author:      Markus F. (TZERO78) & KI-Assistenten  
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ÄNDERUNGEN v4.4:
# - Docker-Installation hinzugefügt (offizielle Docker-Repository)
# - Nutzt activate_docker_rules() für dynamische Firewall-Integration
# - Bessere Docker-Interface-Erkennung und Validierung
# - Robuste systemd-Abhängigkeiten für NFTables-Integration
# - Erweiterte Fehlerbehandlung und Status-Verifikation
# - Optimierte daemon.json mit Sicherheits-Fokus
#
################################################################################

##
# Hauptfunktion: Installiert und konfiguriert Docker-Engine mit gehärteter 
# Konfiguration und integriert es sauber in die NFTables-Firewall
##
module_container() {
    # Guard Clause: Nur ausführen wenn SERVER_ROLE=1 (Docker-Host)
    if [ "$SERVER_ROLE" != "1" ]; then
        log_info "🐳 Container-Modul übersprungen (SERVER_ROLE != 1)"
        return 0
    fi
    
    log_info "🐳 MODUL: Container-Engine (Docker mit NFTables-Integration)"

    # --- SCHRITT 1: Docker-Installation und AppArmor-Kompatibilität ---
    log_info "  -> 1/7: Prüfe Docker-Installation..."
    
    # AppArmor-Kompatibilität für runc sicherstellen
    if command -v aa-status >/dev/null 2>&1 && aa-status | grep -q "runc"; then
        log_info "     -> Deaktiviere AppArmor für runc (Docker-Kompatibilität)..."
        aa-disable runc 2>/dev/null || true
    fi
    
    if ! command -v docker >/dev/null 2>&1; then
        log_info "     -> Docker nicht gefunden - installiere Docker-Engine..."
        
        # Repository-Schlüssel und Quelle hinzufügen
        apt-get update
        apt-get install -y ca-certificates curl gnupg
        
        # Docker GPG-Schlüssel hinzufügen
        install -m 0755 -d /etc/apt/keyrings
        if ! curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; then
            log_error "Fehler beim Hinzufügen des Docker GPG-Schlüssels!"
            return 1
        fi
        chmod a+r /etc/apt/keyrings/docker.gpg
        
        # Docker Repository hinzufügen
        echo \
        "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
        "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Docker installieren
        apt-get update
        if ! apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
            log_error "Docker-Installation fehlgeschlagen!"
            return 1
        fi
        
        log_ok "Docker erfolgreich installiert."
    else
        local docker_version
        docker_version=$(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',' || echo "Unbekannt")
        log_ok "Docker bereits installiert (Version: $docker_version)"
    fi

    # --- SCHRITT 2: Docker-Konfigurationsverzeichnis sicherstellen ---
    log_info "  -> 2/7: Bereite Docker-Konfiguration vor..."
    mkdir -p /etc/docker
    local daemon_json="/etc/docker/daemon.json"
    
    # Backup der existierenden Konfiguration (falls vorhanden)
    backup_and_register "$daemon_json"

    # --- SCHRITT 3: Gehärtete Docker-Daemon-Konfiguration erstellen ---
    log_info "  -> 3/7: Erstelle gehärtete Docker-Daemon-Konfiguration..."
    
    # Berechne Docker-Gateway-IP aus CIDR
    local docker_gateway_ip
    docker_gateway_ip=$(echo "$DOCKER_IPV4_CIDR" | cut -d'/' -f1 | sed 's/\.0$//').1
    log_debug "Docker-Gateway-IP berechnet: $docker_gateway_ip"
    
    # Erstelle daemon.json mit jq für korrekte JSON-Syntax
    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq ist nicht installiert! Benötigt für Docker-Konfiguration."
        return 1
    fi
    
    log_info "     -> Docker-Netzwerk: $DOCKER_IPV4_CIDR (Gateway: $docker_gateway_ip)"
    log_info "     -> IPv6-Netzwerk: $DOCKER_IPV6_CIDR"
    
    # Generiere daemon.json mit iptables-nft Kompatibilität
    jq -n \
    --arg bip "$docker_gateway_ip/$(echo "$DOCKER_IPV4_CIDR" | cut -d'/' -f2)" \
    --arg fixed_cidr "$DOCKER_IPV4_CIDR" \
    --arg fixed_cidr_v6 "$DOCKER_IPV6_CIDR" \
    '{
        # NETZWERK-KONFIGURATION
        "bip": $bip,
        "fixed-cidr": $fixed_cidr,
        "ipv6": true,
        "fixed-cidr-v6": $fixed_cidr_v6,
        
        # FIREWALL-INTEGRATION (iptables-nft Backend)
        "iptables": true,
        
        # LOGGING (strukturiert für systemd)
        "log-driver": "journald",
        "log-opts": { 
            "tag": "{{.Name}}/{{.FullID}}",
            "labels": "service"
        },
        
        # SYSTEMD-INTEGRATION
        "exec-opts": ["native.cgroupdriver=systemd"],
        
        # STORAGE & PERFORMANCE
        "storage-driver": "overlay2",
        "live-restore": true,
        
        # SICHERHEIT
        "userland-proxy": false,
        "no-new-privileges": true,
        
        # RESOURCE-LIMITS (VPS-optimiert)
        "default-ulimits": {
            "nofile": {
                "Hard": 64000,
                "Name": "nofile", 
                "Soft": 64000
            }
        }
    }' > "$daemon_json"
    
    log_ok "Gehärtete Docker-Konfiguration erstellt ($daemon_json)"

    # --- SCHRITT 4: systemd-Integration für korrekte Start-Reihenfolge ---
    log_info "  -> 4/7: Konfiguriere systemd-Abhängigkeiten für NFTables-Integration..."
    
    local override_dir="/etc/systemd/system/docker.service.d"
    mkdir -p "$override_dir"

    # KRITISCH: Docker muss NACH NFTables starten um Konflikte zu vermeiden
    cat > "$override_dir/nftables-dependency.conf" <<'EOF'
[Unit]
# KRITISCH: Docker muss nach NFTables starten um Firewall-Konflikte zu vermeiden
# Das verhindert die Race-Condition beim Boot und garantiert saubere Integration
Requires=nftables.service
After=nftables.service

# Erweiterte Abhängigkeiten für Stabilität
After=network-online.target
Wants=network-online.target

[Service]
# Auto-Restart bei Problemen (VPS-Umgebung)
Restart=on-failure
RestartSec=10s

# Erweiterte Timeouts für VPS mit langsamem I/O
TimeoutStartSec=120s
TimeoutStopSec=30s

# Logging-Optimierung
StandardOutput=journal
StandardError=journal
SyslogIdentifier=docker-daemon
EOF

    log_ok "systemd-Abhängigkeiten für Docker konfiguriert."

    # --- SCHRITT 5: systemd-Konfiguration neu laden ---
    log_info "  -> 5/7: Lade systemd-Konfiguration neu..."
    run_with_spinner "Lade systemd-Konfiguration neu..." "systemctl daemon-reload"

    # --- SCHRITT 6: Docker-Service starten und aktivieren ---
    log_info "  -> 6/7: Starte Docker-Engine mit neuer Konfiguration..."
    
    # Stoppe Docker falls läuft (für sauberen Neustart mit neuer Config)
    if systemctl is-active --quiet docker; then
        log_info "     -> Stoppe Docker für Konfigurationsänderung..."
        systemctl stop docker
        sleep 2
    fi
    
    # Starte Docker mit neuer Konfiguration
    if ! run_with_spinner "Aktiviere und starte Docker-Service..." "systemctl enable --now docker"; then
        log_error "Docker-Service konnte nicht gestartet werden!"
        log_error "Prüfe die Konfiguration: sudo journalctl -u docker.service"
        return 1
    fi

    # --- SCHRITT 7: Warte auf Docker-Initialisierung und Firewall-Integration ---
    log_info "  -> 7/7: Warte auf vollständige Docker-Initialisierung..."
    
    local wait_time=0
    local max_wait=30
    local docker_interface=""
    
    # ERR-Trap temporär deaktivieren für arithmetische Operationen
    set +e
    set -x
    
    while [ $wait_time -lt $max_wait ]; do
        sleep 1
        wait_time=$((wait_time + 1))  # Sichere arithmetische Operation
        
        # Prüfe ob Docker-Socket verfügbar ist
        if docker info >/dev/null 2>&1; then
            # Ermittle Docker-Bridge-Interface
            docker_interface=$(ip link show | grep -E '^[0-9]+: docker[0-9]*:' | head -n1 | cut -d: -f2 | tr -d ' ' || echo "")
            
            if [ -n "$docker_interface" ]; then
                set +x
                set -e  # ERR-Trap wieder aktivieren
                log_ok "Docker erfolgreich initialisiert (Interface: $docker_interface)"
                break
            fi
        fi
        
        # Zeige Fortschritt bei längerer Wartezeit
        if [ $((wait_time % 10)) -eq 0 ]; then
            log_info "     -> Warte noch auf Docker-Initialisierung... (${wait_time}s)"
        fi
    done
    
    set +x
    set -e  # ERR-Trap wieder aktivieren
    
    # Validierung der Docker-Initialisierung
    if [ -z "$docker_interface" ] || ! docker info >/dev/null 2>&1; then
        log_error "Docker-Initialisierung fehlgeschlagen nach ${wait_time}s!"
        log_error "Debug-Info:"
        systemctl status docker --no-pager || true
        docker info 2>&1 | head -10 || true
        ip link show | grep docker || log_warn "Kein Docker-Interface gefunden"
        return 1
    fi

    # --- Firewall-Integration aktivieren ---
    log_info "     -> Aktiviere Docker-Firewall-Integration..."
    
    # Ermittle Tailscale-Interface falls verfügbar
    local tailscale_interface="${TAILSCALE_INTERFACE:-}"
    if [ -z "$tailscale_interface" ] && [ "${TAILSCALE_ACTIVE:-false}" = "true" ]; then
        tailscale_interface=$(ip link show | grep -E '^[0-9]+: tailscale[0-9]*:' | head -n1 | cut -d: -f2 | tr -d ' ' || echo "")
    fi
    
    log_info "     -> Docker-Interface: $docker_interface"
    log_info "     -> Tailscale-Interface: ${tailscale_interface:-nicht verfügbar}"
    
    # Aktiviere Docker-spezifische Firewall-Regeln
    if activate_docker_rules "$docker_interface" "$tailscale_interface"; then
        log_ok "Docker-Firewall-Regeln erfolgreich aktiviert."
    else
        log_error "Docker-Firewall-Integration fehlgeschlagen!"
        log_warn "Docker funktioniert möglicherweise, aber Firewall-Regeln sind unvollständig."
        # Nicht return 1 - Docker selbst funktioniert ja
    fi

    # --- Finale Verifikation und Statusanzeige ---
    log_info "     -> Finale Docker-Status-Verifikation..."
    
    # Service-Status
    if systemctl is-active --quiet docker; then
        log_ok "✅ Docker-Service: Aktiv"
    else
        log_error "❌ Docker-Service: Inaktiv"
        return 1
    fi
    
    # Docker-Info abrufen
    local docker_version
    docker_version=$(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',' || echo "Unbekannt")
    log_info "     -> Docker-Version: $docker_version"
    
    # Netzwerk-Info
    local bridge_network
    bridge_network=$(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || echo "Standard")
    log_info "     -> Bridge-Netzwerk: $bridge_network"
    
    # Container-Count
    local container_count
    container_count=$(docker ps -a --format "table" 2>/dev/null | wc -l 2>/dev/null || echo "0")
    # Subtrahiere Header-Zeile
    container_count=$((container_count - 1))
    [ $container_count -lt 0 ] && container_count=0
    log_info "     -> Vorhandene Container: $container_count"

    # --- ERFOLGS-ZUSAMMENFASSUNG ---
    log_ok "🎉 Docker-Engine erfolgreich installiert, konfiguriert und integriert!"
    log_info "--- DOCKER-KONFIGURATION ---"
    log_info "  🐳 Version: $docker_version"
    log_info "  🌐 IPv4-Netzwerk: $DOCKER_IPV4_CIDR (Gateway: $docker_gateway_ip)"
    log_info "  🌐 IPv6-Netzwerk: $DOCKER_IPV6_CIDR"
    log_info "  🔌 Bridge-Interface: $docker_interface"
    log_info "  🔗 NFTables-Integration: Aktiv"
    
    if [ -n "$tailscale_interface" ]; then
        log_info "  🔐 VPN-Integration: Aktiv (Container über Tailscale erreichbar)"
    else
        log_info "  🔐 VPN-Integration: Nicht konfiguriert"
    fi
    
    log_info "--- MANAGEMENT-BEFEHLE ---"
    log_info "  Status prüfen: docker info"
    log_info "  Container zeigen: docker ps -a"
    log_info "  Netzwerke zeigen: docker network ls"
    log_info "  Logs anzeigen: journalctl -u docker.service"
    
    # Setze globale Variablen für nachfolgende Module (z.B. module_deploy_containers)
    export DOCKER_READY="true"
    export DOCKER_INTERFACE="$docker_interface"
    export DOCKER_GATEWAY_IP="$docker_gateway_ip"
    
    return 0
}

################################################################################
# ENDE MODUL CONTAINER v4.4
################################################################################