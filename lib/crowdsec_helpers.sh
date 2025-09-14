#!/bin/bash
################################################################################
#
# BIBLIOTHEK: CROWDSEC-HELFER-FUNKTIONEN
#
# @description: Funktionen für die Installation und Konfiguration des
#               CrowdSec-Agenten und des Firewall-Bouncers.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

##
# Bereinigt CrowdSec für Neuinstallation
##
cleanup_crowdsec() {
    log_info "Bereinige CrowdSec für Neuinstallation..."
    apt-get remove --purge crowdsec crowdsec-firewall-bouncer >/dev/null 2>&1 || true
    rm -rf /etc/crowdsec /var/lib/crowdsec
    apt-get autoremove -y >/dev/null 2>&1 || true
    log_ok "CrowdSec bereinigt"
}

##
# Erstellt einen dedizierten systemd-Service für set-only Mode
# Löst alle bekannten Probleme: Ordering Cycles, Type=notify, falsche Dependencies, Metrics-Flooding
##
create_setonly_bouncer_service() {
    log_info "  -> Erstelle dedizierten systemd-Service für set-only Mode..."
    
    local service_file="/etc/systemd/system/crowdsec-bouncer-setonly.service"
    local config_file="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"
    export CONFIG_FILE="$config_file"
    
    log_debug "Erstelle Service-Datei: $service_file"
    log_debug "Nutzt Config: $config_file"
    
    # VPS-spezifische Checks (UFW ist deinstalliert, nur NFTables)
    log_debug "VPS-Umgebung: Nur NFTables, kein UFW - optimal! ✅"
    
    # Prüfe verfügbare Interfaces (VPS haben oft nicht eth0)
    local primary_interface
    primary_interface=$(ip route | grep default | head -n1 | awk '{print $5}')
    log_debug "Primäres Interface: $primary_interface"
    
    # Prüfe ob NFTables-Struktur existiert (aus generate_crowdsec_rules)
    if ! nft list table ip crowdsec >/dev/null 2>&1; then
        log_warn "CrowdSec NFTables-Struktur nicht gefunden - wird bei nächstem NFTables-Reload geladen"
    else
        log_debug "CrowdSec NFTables-Struktur bereits vorhanden"
    fi
    
    # Template herunterladen und Service erstellen
    download_and_process_template "crowdsec-bouncer-setonly.service.template" \
                                  "$service_file" \
                                  "644" \
                                  "root:root"
    
    log_debug "Service-Datei erstellt mit korrekten Dependencies und Metrics-Fix"
    
    # Konfiguriere Bouncer für Server-Baukasten Integration + VPS-Optimierungen
    log_info "  -> Konfiguriere Bouncer für Server-Baukasten Sets..."
    
    # Basis-Konfiguration
    yq eval -i '.mode = "nftables"' "$config_file"
    yq eval -i '.log_level = "info"' "$config_file"
    yq eval -i '.debug = false' "$config_file"
    
    # Set-only Mode aktivieren
    yq eval -i '.nftables.ipv4."set-only" = true' "$config_file"
    yq eval -i '.nftables.ipv6."set-only" = true' "$config_file"
    
    # NFTables-Tabellen und Sets konfigurieren
    yq eval -i '.blacklists_ipv4 = "crowdsec-blacklists"' "$config_file"
    yq eval -i '.blacklists_ipv6 = "crowdsec6-blacklists"' "$config_file"
    yq eval -i '.nftables.ipv4.table = "crowdsec"' "$config_file"
    yq eval -i '.nftables.ipv6.table = "crowdsec6"' "$config_file"
    yq eval -i '.nftables.ipv4.chain = "crowdsec-chain"' "$config_file"
    yq eval -i '.nftables.ipv6.chain = "crowdsec6-chain"' "$config_file"
    
    # IPv4 und IPv6 standardmäßig aktivieren
    yq eval -i '.nftables.ipv4.enabled = true' "$config_file"
    yq eval -i '.nftables.ipv6.enabled = true' "$config_file"
    yq eval -i '.disable_ipv6 = false' "$config_file"
    
    # VPS-Optimierung: Niedrigere Update-Frequenz für bessere Performance
    yq eval -i '.update_frequency = "30s"' "$config_file"
    log_debug "Update-Frequenz auf 30s gesetzt (VPS-optimiert)"
    
    # Deaktiviere den Original-Service sauber
    log_info "  -> Migriere vom Original-Bouncer-Service..."
    if systemctl is-enabled crowdsec-firewall-bouncer.service >/dev/null 2>&1; then
        log_debug "Original-Service ist enabled, stoppe und deaktiviere ihn"
        systemctl stop crowdsec-firewall-bouncer.service 2>/dev/null || true
        systemctl disable crowdsec-firewall-bouncer.service 2>/dev/null || true
        log_ok "Migration vom Original-Service abgeschlossen"
    else
        log_debug "Original-Service bereits deaktiviert oder nicht vorhanden"
    fi
    
    # Aktiviere den neuen Service
    systemctl daemon-reload
    systemctl enable crowdsec-bouncer-setonly.service
    
    log_ok "Dedizierter set-only Service erstellt und aktiviert."
    log_info "  Service-Datei: $service_file"
    log_info "  Nutzt Sets: crowdsec-blacklists (IPv4) & crowdsec6-blacklists (IPv6)"
    log_info "  Zu starten mit: systemctl start crowdsec-bouncer-setonly"
}

##
# Installiert nur den CrowdSec-Agent
##
install_crowdsec() {
    log_info "Installiere CrowdSec-Agent..."
    
    # Repository einrichten
    setup_crowdsec_repository || return 1
    
    # CrowdSec-Agent-Paket installieren
    install_crowdsec_package || return 1
    
    # systemd-Konfiguration optimieren
    log_info "  -> Konfiguriere systemd-Service..."
    mkdir -p /etc/systemd/system/crowdsec.service.d
    cat > /etc/systemd/system/crowdsec.service.d/override.conf <<EOF
[Unit]
After=network.target
[Service]
Restart=on-failure
RestartSec=30s
EOF
    
    # Service aktivieren und starten
    systemctl daemon-reload
    systemctl enable --now crowdsec >/dev/null 2>&1
    
    # Warten auf API
    local wait_cmd="
        for i in {1..30}; do
            if systemctl is-active --quiet crowdsec && cscli metrics &>/dev/null; then exit 0; fi
            sleep 1
        done
        exit 1"
    
    if run_with_spinner "Warte auf CrowdSec-API..." "bash -c \"$wait_cmd\""; then
        log_ok "CrowdSec-Agent erfolgreich installiert und gestartet"
        return 0
    else
        log_error "CrowdSec-Agent konnte nicht gestartet werden"
        return 1
    fi
}

##
# Installiert nur den Firewall-Bouncer
##
install_crowdsec_firewall_bouncer() {
    log_info "🐾 Installiere CrowdSec-Firewall-Bouncer..."
    
    # Voraussetzungen prüfen
    log_info "  -> Prüfe Voraussetzungen..."
    if ! systemctl is-active --quiet crowdsec; then
        log_error "CrowdSec-Service läuft nicht - installiere zuerst CrowdSec-Agent"
        return 1
    fi
    
    if ! cscli metrics >/dev/null 2>&1; then
        log_error "CrowdSec API nicht erreichbar"
        return 1
    fi
    
    if ! command -v nft >/dev/null 2>&1; then
        log_error "NFTables nicht installiert"
        return 1
    fi
    
    log_ok "Voraussetzungen erfüllt: CrowdSec-Service, API und NFTables verfügbar"
    
    # Bouncer-Paket installieren
    local pkg="crowdsec-firewall-bouncer"
    local dir="/etc/crowdsec/bouncers"
    local base_yml="$dir/crowdsec-firewall-bouncer.yaml"
    local local_yml="$dir/crowdsec-firewall-bouncer.yaml.local"
    local keyfile="$dir/.api_key"
    
    mkdir -p "$dir"
    
    # Paket installieren (mit Repository-Setup falls nötig)
    install_crowdsec_packages "$pkg" || return 1
    
    # Warten auf Base-Config
    log_info "  -> Warte auf Bouncer-Konfigurationsdatei..."
    local wait_count=0
    while [ ! -f "$base_yml" ] && [ $wait_count -lt 30 ]; do
        sleep 1
        ((wait_count++))
    done
    
    if [ ! -f "$base_yml" ]; then
        log_error "Base-Konfiguration nicht gefunden: $base_yml"
        return 1
    fi
    log_debug "Base-Konfigurationsdatei verfügbar"
    
    # Config kopieren und Basis-Konfiguration
    log_info "  -> Konfiguriere NFTables-Modus..."
    cp "$base_yml" "$local_yml"
    log_debug "Vollständige Konfiguration kopiert: $base_yml -> $local_yml"
    
    # Template-Variable ${BACKEND} durch nftables ersetzen
    if grep -q '${BACKEND}' "$local_yml" 2>/dev/null; then
        sed -i 's/mode: ${BACKEND}/mode: nftables/' "$local_yml"
        log_info "     🔧 Template-Modus → nftables"
    else
        sed -i 's/^mode:.*/mode: nftables/' "$local_yml"
        log_info "     🔧 NFTables-Modus gesetzt"
    fi
    
    # Logging optimieren
    sed -i 's/debug: .*/debug: false/' "$local_yml"
    sed -i 's/log_level: .*/log_level: info/' "$local_yml"
    
    # Set-only Mode aktivieren (Basis-Konfiguration)
    log_info "  -> Konfiguriere für Server-Baukasten NFTables-Integration..."
    sed -i '/nftables:/,/^[^ ]/ s/set-only: false/set-only: true/g' "$local_yml"
    
    # Basis NFTables-Sets konfigurieren
    sed -i 's/blacklists_ipv4: .*/blacklists_ipv4: crowdsec-blacklists/' "$local_yml"
    sed -i 's/blacklists_ipv6: .*/blacklists_ipv6: crowdsec6-blacklists/' "$local_yml"
    
    log_info "     🔧 Set-only Modus aktiviert"
    log_info "     🎯 NFTables-Sets: crowdsec-blacklists (IPv4), crowdsec6-blacklists (IPv6)"
    
    # API-Key generieren und setzen
    log_info "  -> Generiere und konfiguriere API-Schlüssel..."
    if [ ! -s "$keyfile" ]; then
        install -o root -g root -m600 /dev/null "$keyfile"
        if ! cscli bouncers add firewall-bouncer -o raw >"$keyfile"; then
            log_error "API-Key-Generierung fehlgeschlagen"
            return 1
        fi
        log_debug "Neuer API-Key generiert"
    else
        log_debug "API-Key-File existiert bereits"
    fi
    
    # API-Key in Config einsetzen (yq-Methode)
    if [ -s "$keyfile" ]; then
        # Mikro-Check: Config-Datei noch da und nicht leer vor yq
        if [ ! -f "$local_yml" ] || [ ! -s "$local_yml" ]; then
            log_error "Config-Datei vor API-Key-Einbindung beschädigt: $local_yml"
            return 1
        fi
        
        export KEYFILE="$keyfile"
        yq e -i '.api_key = (load_str(env(KEYFILE)) | sub("\\r?\\n$"; ""))' "$local_yml"
        log_info "     🔑 API-Key konfiguriert"
    else
        log_error "API-Key ist leer"
        return 1
    fi
    
    # Set-only Service erstellen
    create_setonly_bouncer_service
    
    # Health-Check installieren
    log_info "  -> Installiere Health-Check-System..."
    install -m755 /dev/null /usr/local/bin/crowdsec-healthcheck
    cat > /usr/local/bin/crowdsec-healthcheck <<'EOF'
#!/bin/bash
if ! cscli metrics >/dev/null 2>&1; then
    logger -t "crowdsec-healthcheck" -p daemon.warn "CrowdSec API nicht erreichbar - starte Services neu..."
    systemctl restart crowdsec crowdsec-bouncer-setonly
fi
EOF
    
    # Health-Check Timer
    cat > /etc/systemd/system/crowdsec-healthcheck.service <<'EOF'
[Unit]
Description=CrowdSec Health-Check
After=crowdsec.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/crowdsec-healthcheck
User=root
EOF

    cat > /etc/systemd/system/crowdsec-healthcheck.timer <<'EOF'
[Unit]
Description=CrowdSec Health-Check (alle 5 Min)
Requires=crowdsec-healthcheck.service
[Timer]
OnBootSec=5min
OnUnitInactiveSec=5min
Unit=crowdsec-healthcheck.service
[Install]
WantedBy=timers.target
EOF

    # NFTables-Service Integration
    log_info "  -> Integriere mit nftables-Service..."
    local nft_override_dir="/etc/systemd/system/nftables.service.d"
    mkdir -p "$nft_override_dir"
    
    cat > "$nft_override_dir/crowdsec.conf" <<'EOF'
[Service]
ExecReloadPost=/usr/bin/systemctl try-restart crowdsec-bouncer-setonly
EOF
    
    # Services aktivieren
    systemctl daemon-reload
    
    if run_with_spinner "Aktiviere Bouncer-Services..." "systemctl enable --now crowdsec-bouncer-setonly crowdsec-healthcheck.timer"; then
        # Verifikation
        log_info "  -> Prüfe Installation..."
        local verification_passed=true
        
        # Service-Check mit Retry
        if ! systemctl is-active --quiet crowdsec-bouncer-setonly; then
            log_warn "Set-Only-Bouncer-Service nicht aktiv - versuche Start..."
            systemctl start crowdsec-bouncer-setonly
            sleep 5
            if ! systemctl is-active --quiet crowdsec-bouncer-setonly; then
                verification_passed=false
                log_error "Service konnte nicht gestartet werden!"
            fi
        fi
        
        # Config-Verifikationen
        if ! grep -q "set-only: true" "$local_yml"; then
            log_error "Set-only Modus nicht aktiviert!"
            verification_passed=false
        fi
        
        if [ ! -s "$keyfile" ]; then
            log_error "API-Key-Datei fehlt oder ist leer"
            verification_passed=false
        fi
        
        if [ "$verification_passed" = true ]; then
            log_ok "CrowdSec-Firewall-Bouncer erfolgreich installiert"
            log_info "  -> Set-only Mode: Nutzt vordefinierte NFTables-Struktur"
            log_info "  -> Health-Check läuft alle 5 Minuten"
            log_info "  -> Service: crowdsec-bouncer-setonly"
            return 0
        else
            log_error "Bouncer-Installation unvollständig"
            return 1
        fi
    else
        log_error "Bouncer-Services konnten nicht gestartet werden"
        return 1
    fi
}

##
# Passt CrowdSec SSH-Policy an (Ban-Dauer anpassen)
##
tune_crowdsec_ssh_policy() {
    local bantime="${CROWDSEC_BANTIME:-4h}"
    log_info "  -> Passe CrowdSec SSH-Policy an (Ban-Dauer: ${bantime})..."
    
    if [ "$bantime" != "4h" ]; then
        mkdir -p /etc/crowdsec/profiles.d/
        
        local custom_profile="/etc/crowdsec/profiles.d/99-custom-ssh-duration.yaml"
        cat > "$custom_profile" <<EOF
name: custom_ssh_ban_duration
description: "Override default ssh ban duration"
filters:
  - "decision.scenario starts_with 'crowdsecurity/sshd-'"
decisions:
  - type: ban
    duration: "${bantime}"
on_success: break
EOF
        chmod 0640 "$custom_profile" 2>/dev/null || true
        log_ok "Custom SSH-Profile mit Ban-Dauer '${bantime}' erstellt"
    else
        log_info "Standard CrowdSec SSH-Ban-Dauer ('4h') wird verwendet"
    fi
}

##
# Installiert kompletten CrowdSec-Stack (Agent + Bouncer)
##
install_crowdsec_stack() {
    log_info "⚙️  Installiere und konfiguriere den CrowdSec-Stack..."
    
    # Optional: Cleanup vor Installation
    # cleanup_crowdsec
    
    if install_crowdsec && install_crowdsec_firewall_bouncer; then
        # SSH-Policy anpassen falls gewünscht
        tune_crowdsec_ssh_policy
        log_ok "CrowdSec-Stack erfolgreich installiert"
        return 0
    else
        log_error "CrowdSec-Stack Installation fehlgeschlagen"
        return 1
    fi
}