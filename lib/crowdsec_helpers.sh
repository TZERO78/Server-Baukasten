#!/bin/bash
################################################################################
#
# BIBLIOTHEK: CROWDSEC-HELFER-FUNKTIONEN
#
# @description: Funktionen für die Installation und Konfiguration des
#               CrowdSec-Agenten und des Firewall-Bouncers.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

##
# Erstellt einen dedizierten systemd-Service für set-only Mode
# Löst alle bekannten Probleme: Ordering Cycles, Type=notify, falsche Dependencies, Metrics-Flooding
##
create_setonly_bouncer_service() {
    log_info "  -> Erstelle dedizierten systemd-Service für set-only Mode..."
    
    local service_file="/etc/systemd/system/crowdsec-bouncer-setonly.service"
    local config_file="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"
    
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
    
    cat > "$service_file" <<EOF
[Unit]
Description=CrowdSec Firewall Bouncer (Set-Only Mode) - Server-Baukasten
Documentation=https://docs.crowdsec.net/docs/bouncers/firewall/
After=multi-user.target crowdsec.service nftables.service
Wants=crowdsec.service nftables.service
ConditionPathExists=$config_file

[Service]
Type=simple
User=root
Group=root

# Warte bis CrowdSec API verfügbar ist
ExecStartPre=/bin/bash -c 'until cscli metrics >/dev/null 2>&1; do sleep 2; done'

# KORRIGIERT: Konfiguration testen
ExecStartPre=/usr/bin/crowdsec-firewall-bouncer -c $config_file -t

# Haupt-Service starten  
ExecStart=/usr/bin/crowdsec-firewall-bouncer -c $config_file

# Robuster Restart bei Problemen
Restart=on-failure
RestartSec=15s
StartLimitBurst=3
StartLimitIntervalSec=300

# Timeouts für bessere Kontrolle
TimeoutStartSec=60
TimeoutStopSec=30

# Sicherheits-Härtung
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/log /var/run

# Umgebung - WICHTIG: Metrics-Problem in set-only Mode beheben
Environment=BOUNCER_MODE=set-only
Environment=BOUNCER_DISABLE_METRICS=true
Environment=BOUNCER_LOG_LEVEL=info
StandardOutput=journal
StandardError=journal
SyslogIdentifier=crowdsec-bouncer-setonly

[Install]
WantedBy=multi-user.target
EOF

    log_debug "Service-Datei erstellt mit korrekten Dependencies und Metrics-Fix"
    
    # Konfiguriere Bouncer für Server-Baukasten Integration + VPS-Optimierungen
    log_info "  -> Konfiguriere Bouncer für Server-Baukasten Sets..."
    if command -v yq &>/dev/null; then
        log_debug "Verwende yq v4+ für Set-Namen-Konfiguration"
        yq eval -i '.blacklists_ipv4 = "crowdsec-blacklists"' "$config_file"
        yq eval -i '.blacklists_ipv6 = "crowdsec6-blacklists"' "$config_file"
        yq eval -i '.nftables.ipv4.table = "crowdsec"' "$config_file"
        yq eval -i '.nftables.ipv6.table = "crowdsec6"' "$config_file"
        
        # IPv4 und IPv6 standardmäßig aktivieren
        yq eval -i '.nftables.ipv4.enabled = true' "$config_file"
        yq eval -i '.nftables.ipv6.enabled = true' "$config_file"
        yq eval -i '.disable_ipv6 = false' "$config_file"
        
        # VPS-Optimierung: Niedrigere Update-Frequenz für bessere Performance
        yq eval -i '.update_frequency = "30s"' "$config_file"
        log_debug "Update-Frequenz auf 30s gesetzt (VPS-optimiert)"
        
    else
        log_debug "yq nicht verfügbar, verwende sed für Set-Namen"
        sed -i 's/blacklists_ipv4:.*/blacklists_ipv4: crowdsec-blacklists/' "$config_file"
        sed -i 's/blacklists_ipv6:.*/blacklists_ipv6: crowdsec6-blacklists/' "$config_file"
        sed -i 's/disable_ipv6:.*/disable_ipv6: false/' "$config_file"
    fi
    
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


#################################################################################
#                             INITIALISIERUNG
#           CrowdSec Stack und Bouncer-Installation fuer NFTables
################################################################################
##
# Installiert den CrowdSec Agenten und den Firewall Bouncer.
##
install_crowdsec_stack() {
    log_info "⚙️  Installiere und konfiguriere den CrowdSec-Stack..."

    # --- 1. CrowdSec Repository hinzufügen (falls nötig) ---
    if [ ! -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then
        log_info "  -> Füge CrowdSec APT-Repository hinzu..."
        local install_script="/tmp/crowdsec-install.sh"
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh -o "$install_script"
        
        if grep -q "packagecloud" "$install_script"; then
            run_with_spinner "Richte APT-Repository ein und aktualisiere..." "bash '$install_script' && apt-get update -qq"
        else
            log_error "Das heruntergeladene CrowdSec-Installationsskript scheint ungültig zu sein."
            rm -f "$install_script"
            return 1
        fi
        rm -f "$install_script"
    fi

    # --- 2. CrowdSec Agent sauber installieren ---
    log_info "  -> Installiere CrowdSec Agenten (ggf. Re-Installation)..."
    local install_cmd="apt-get remove --purge -y crowdsec >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec"
    if ! run_with_spinner "Installiere 'crowdsec' Paket..." "$install_cmd"; then
        log_error "Installation des CrowdSec Agenten ist fehlgeschlagen."
        return 1
    fi

    # --- 3. systemd-Verhalten anpassen ---
    log_info "  -> Konfiguriere CrowdSec für netzwerkabhängigen Start..."
    mkdir -p /etc/systemd/system/crowdsec.service.d
    cat > /etc/systemd/system/crowdsec.service.d/override.conf <<EOF
[Unit]
After=network.target
[Service]
Restart=on-failure
RestartSec=30s
EOF

    # --- 4. Firewall Bouncer installieren ---
    # Die Funktion install_bouncer sollte ihr eigenes, sauberes Logging haben.
    install_bouncer

    # --- 5. Services aktivieren und Start verifizieren ---
    log_info "  -> Aktiviere CrowdSec-Dienste und warte auf den Start..."
    systemctl daemon-reload
    systemctl enable --now crowdsec >/dev/null 2>&1

    # Ein Befehl, der 30s lang versucht, die API zu erreichen
    local wait_cmd="
        for i in {1..30}; do
            if systemctl is-active --quiet crowdsec && cscli metrics &>/dev/null; then exit 0; fi
            sleep 1
        done
        exit 1"
    
    if run_with_spinner "Warte auf CrowdSec-API..." "bash -c \"$wait_cmd\""; then
        log_ok "CrowdSec-Agent ist erfolgreich gestartet und API ist erreichbar."
        return 0
    else
        log_error "CrowdSec-Agent konnte nicht gestartet werden oder die API antwortet nicht."
        return 1
    fi
}

install_bouncer() {
    log_info "🐾 Installiere CrowdSec-Bouncer (NFTables-Integration)..."
    log_debug "Bouncer-Installation gestartet mit DEBUG-Modus"

    # --- 1. Voraussetzungen prüfen ---
    log_info "  -> Prüfe Voraussetzungen (CrowdSec-Service & API)..."
    if ! systemctl is-active --quiet crowdsec; then
        log_error "Voraussetzung nicht erfüllt: CrowdSec-Service läuft nicht."
        return 1
    fi
    
    if ! cscli metrics >/dev/null 2>&1; then
        log_error "Voraussetzung nicht erfüllt: CrowdSec API ist nicht erreichbar."
        return 1
    fi
    
    if ! command -v nft >/dev/null 2>&1; then
        log_error "NFTables nicht installiert!"
        return 1
    fi
    
    log_ok "Voraussetzungen erfüllt: CrowdSec-Service, API und NFTables verfügbar."

    # --- 3. Bouncer-Paket installieren ---
    local pkg="crowdsec-firewall-bouncer"
    local dir="/etc/crowdsec/bouncers"
    local base_yml="$dir/crowdsec-firewall-bouncer.yaml"
    local local_yml="$dir/crowdsec-firewall-bouncer.yaml.local"
    local keyfile="$dir/.api_key"
    
    # Stelle sicher, dass Bouncer-Verzeichnis existiert
    mkdir -p "$dir"
    
    local install_cmd="apt-get remove --purge -y '$pkg' >/dev/null 2>&1 || true; rm -rf '$dir'; DEBIAN_FRONTEND=noninteractive apt-get install -y '$pkg'"
    if ! run_with_spinner "Installiere Bouncer-Paket..." "$install_cmd"; then
        log_error "Installation des Bouncer-Pakets ist fehlgeschlagen."
        return 1
    fi

    # ROBUSTHEIT: Warte auf Base-Konfigurationsdatei (aus alter Version)
    local wait_count=0
    while [ ! -f "$base_yml" ] && [ $wait_count -lt 30 ]; do
        sleep 1
        ((wait_count++))
    done
    
    if [ ! -f "$base_yml" ]; then
        log_error "Base-Konfigurationsdatei nicht gefunden: $base_yml"
        return 1
    fi
    log_debug "Base-Konfigurationsdatei verfügbar"

    # --- 4. Konfiguriere für NFTables-Modus ---
    log_info "  -> Konfiguriere NFTables-Modus..."
    # Kopiere vollständige Base-Config zu Local-Config
    cp "$base_yml" "$local_yml"
    log_debug "Vollständige Konfiguration kopiert: $base_yml -> $local_yml"
    
    # Ersetze Template-Variable ${BACKEND} durch nftables
    if grep -q '${BACKEND}' "$local_yml" 2>/dev/null; then
        sed -i 's/mode: ${BACKEND}/mode: nftables/' "$local_yml"
        log_info "     🔧 Template-Modus → nftables"
    else
        sed -i 's/^mode:.*/mode: nftables/' "$local_yml"
        log_info "     🔧 NFTables-Modus gesetzt"
    fi
    
    # Optimiere Logging-Konfiguration
    sed -i 's/debug: .*/debug: false/' "$local_yml"
    sed -i 's/log_level: .*/log_level: info/' "$local_yml"

    # --- 5. KRITISCH: Server-Baukasten NFTables-Integration (set-only) ---
    log_info "  -> Konfiguriere für Server-Baukasten NFTables-Integration..."
    
    # Set-only Mode aktivieren (der fehlende Schlüssel!)
    sed -i '/nftables:/,/^[^ ]/ s/set-only: false/set-only: true/g' "$local_yml"
    
    # Konfiguriere Set-Namen für vordefinierte NFTables-Struktur
    sed -i 's/blacklists_ipv4: .*/blacklists_ipv4: crowdsec-blacklists/' "$local_yml"
    sed -i 's/blacklists_ipv6: .*/blacklists_ipv6: crowdsec6-blacklists/' "$local_yml"
    
    # NFTables-Tabellen und Chains konfigurieren
    if command -v yq &>/dev/null && yq --help 2>&1 | grep -q "mikefarah"; then
        yq eval -i '.nftables.ipv4.table = "crowdsec"' "$local_yml"
        yq eval -i '.nftables.ipv4.chain = "crowdsec-chain"' "$local_yml"
        yq eval -i '.nftables.ipv6.table = "crowdsec6"' "$local_yml" 
        yq eval -i '.nftables.ipv6.chain = "crowdsec6-chain"' "$local_yml"
        
        # IPv4 und IPv6 standardmäßig aktivieren
        yq eval -i '.nftables.ipv4.enabled = true' "$local_yml"
        yq eval -i '.nftables.ipv6.enabled = true' "$local_yml"
        yq eval -i '.disable_ipv6 = false' "$local_yml"
        
        log_debug "NFTables-Tabellen mit yq konfiguriert"
    fi
    
    log_info "     🔧 Set-only Modus aktiviert"
    log_info "     🎯 NFTables-Sets: crowdsec-blacklists (IPv4), crowdsec6-blacklists (IPv6)"

    # --- 6. API-Schlüssel (robuste Methode aus alter Version) ---
    log_info "  -> Generiere und konfiguriere API-Schlüssel..."
    
    if [ ! -s "$keyfile" ]; then
        install -o root -g root -m600 /dev/null "$keyfile"
        if ! cscli bouncers add firewall-bouncer -o raw >"$keyfile"; then
            log_error "API-Key-Generierung fehlgeschlagen!"
            return 1
        fi
        log_debug "Neuer API-Key generiert"
    else
        log_debug "API-Key-File existiert bereits"
    fi
    
    # ROBUSTE API-KEY-ERSETZUNG (temp-file Methode aus alter Version)
    local api_key
    api_key=$(cat "$keyfile" 2>/dev/null | tr -d '\n\r')
    if [ -n "$api_key" ]; then
        if grep -q '${API_KEY}' "$local_yml" 2>/dev/null; then
            log_debug "Template-Variable \${API_KEY} gefunden, ersetze durch echten Key"
            # Sichere Methode mit temp-file (verhindert Probleme mit Sonderzeichen)
            printf '%s\n' "$(cat "$local_yml")" | sed "s|\${API_KEY}|$api_key|g" > "$local_yml.tmp"
            mv "$local_yml.tmp" "$local_yml"
        else
            log_debug "Keine Template-Variable, setze API-Key direkt"
            printf '%s\n' "$(cat "$local_yml")" | sed "s|^api_key:.*|api_key: $api_key|" > "$local_yml.tmp"
            mv "$local_yml.tmp" "$local_yml"
        fi
        log_info "     🔑 API-Key konfiguriert"
    else
        log_error "API-Key ist leer!"
        return 1
    fi

    # --- 7. Dedizierter systemd-Service für set-only Mode ---
    log_info "  -> Erstelle dedizierten systemd-Service für set-only Mode..."
    create_setonly_bouncer_service

    # --- 8. Health-Check-System (aus alter Version) ---
    log_info "  -> Installiere Health-Check-System..."
    install -m755 /dev/null /usr/local/bin/crowdsec-healthcheck
    cat > /usr/local/bin/crowdsec-healthcheck <<'EOF'
#!/bin/bash
if ! cscli metrics >/dev/null 2>&1; then
    logger -t "crowdsec-healthcheck" -p daemon.warn "CrowdSec API nicht erreichbar - starte Services neu..."
    systemctl restart crowdsec crowdsec-bouncer-setonly
fi
EOF
    
    # Health-Check systemd Service und Timer
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

    # NFTables-Service Integration (aus alter Version)
    log_info "  -> Integriere mit nftables-Service..."
    local nft_override_dir="/etc/systemd/system/nftables.service.d"
    mkdir -p "$nft_override_dir"
    
    cat > "$nft_override_dir/crowdsec.conf" <<'EOF'
[Service]
ExecReloadPost=/usr/bin/systemctl try-restart crowdsec-bouncer-setonly
EOF

    # --- 9. Services aktivieren mit Retry-Mechanismus (aus alter Version) ---
    systemctl daemon-reload
    
    if run_with_spinner "Aktiviere Set-Only-Bouncer und Health-Check..." "systemctl enable --now crowdsec-bouncer-setonly crowdsec-healthcheck.timer"; then
        log_info "  -> Prüfe Installation..."
        local verification_passed=true
        
        # ROBUSTER SERVICE-CHECK mit Retry
        if ! systemctl is-active --quiet crowdsec-bouncer-setonly; then
            log_warn "Set-Only-Bouncer-Service nicht aktiv - versuche Start..."
            systemctl start crowdsec-bouncer-setonly
            sleep 5
            if ! systemctl is-active --quiet crowdsec-bouncer-setonly; then
                verification_passed=false
                log_error "Service konnte nicht gestartet werden!"
            fi
        fi
        
        # Weitere Verifikationen...
        if ! grep -q "set-only: true" "$local_yml"; then
            log_error "Set-only Modus nicht aktiviert!"
            verification_passed=false
        fi
        
        if [ ! -s "$keyfile" ]; then
            log_error "API-Key-Datei fehlt oder ist leer"
            verification_passed=false
        fi
        
        if [ "$verification_passed" = true ]; then
            log_ok "CrowdSec-Bouncer erfolgreich installiert"
            log_info "  -> Set-only Mode: Nutzt vordefinierte NFTables-Struktur"
            log_info "  -> Health-Check läuft alle 5 Minuten"
            log_info "  -> Service: crowdsec-bouncer-setonly"
            return 0
        else
            log_error "Bouncer-Installation unvollständig!"
            return 1
        fi
    else
        log_error "Services konnten nicht gestartet werden"
        return 1
    fi
}


# Passt die CrowdSec SSH-Policy an die Benutzereingaben an.
##
tune_crowdsec_ssh_policy() {
    log_info "  -> Passe CrowdSec SSH-Policy an (Ban-Dauer: ${CROWDSEC_BANTIME})..."
    
    # Nur eine lokale Profildatei erstellen, wenn die Ban-Dauer vom Standard abweicht.
    # HINWEIS: Der MaxRetry-Wert wird von den CrowdSec-Szenarien selbst gehandhabt,
    #          wir passen hier gezielt nur die Dauer der Verbannung an.
    if [ "$CROWDSEC_BANTIME" != "4h" ]; then
        mkdir -p /etc/crowdsec/profiles.d/
        
        local custom_profile="/etc/crowdsec/profiles.d/99-custom-ssh-duration.yaml"
        cat > "$custom_profile" <<EOF
name: custom_ssh_ban_duration
description: "Override default ssh ban duration"
filters:
  - "decision.scenario starts_with 'crowdsecurity/sshd-'"
decisions:
  - type: ban
    duration: "$CROWDSEC_BANTIME"
on_success: break
EOF
        log_ok "Custom SSH-Profile mit Ban-Dauer '$CROWDSEC_BANTIME' erstellt."
    else
        log_info "Standard CrowdSec SSH-Ban-Dauer ('48h') wird verwendet."
    fi
}

