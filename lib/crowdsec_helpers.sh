#!/bin/bash
################################################################################
#
# BIBLIOTHEK: CROWDSEC-HELFER-FUNKTIONEN (MODERNISIERT)
#
# @description: Funktionen für die Installation und Konfiguration des
#               CrowdSec-Agenten und des Firewall-Bouncers.
#               Unterstützt sowohl Debian Bookworm als auch Trixie
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

##
# Installiert CrowdSec für Debian Trixie aus offiziellen Repositories
##
install_crowdsec_for_trixie() {
    log_info "  -> Installiere CrowdSec aus offiziellen Trixie-Repositories..."
    
    # Einfach: Direkt aus Debian-Repos (keine externen Repos nötig)
    install_packages_safe crowdsec crowdsec-firewall-bouncer
    
    log_ok "CrowdSec aus offiziellen Debian-Repositories installiert"
}

##
# Installiert CrowdSec für Debian Bookworm (mit Wahlmöglichkeit)
##
install_crowdsec_for_bookworm() {
    log_info "  -> Installiere CrowdSec für Bookworm..."
    
    # Option 1: Offizielle Debian-Repos (ältere aber stabile Version)
    if [ "${CROWDSEC_USE_OFFICIAL_REPO:-true}" = "true" ]; then
        log_info "     📦 Nutze offizielle Bookworm-Repositories (v1.4.6-6~deb12u1)"
        install_packages_safe crowdsec crowdsec-firewall-bouncer
    else
        # Option 2: Externes Repository (neueste Version)
        log_info "     📦 Nutze externes packagecloud.io Repository (neueste Version)"
        setup_crowdsec_external_repository
        install_packages_safe crowdsec crowdsec-firewall-bouncer
    fi
    
    log_ok "CrowdSec für Bookworm installiert"
}

##
# Richtet externes CrowdSec-Repository ein (für Bookworm falls gewünscht)
##
setup_crowdsec_external_repository() {
    # Idempotenz: Nur einrichten wenn nicht bereits vorhanden
    if [ -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then
        log_debug "CrowdSec-Repository bereits eingerichtet"
        return 0
    fi
    
    log_info "     -> Füge CrowdSec APT-Repository hinzu..."
    local install_script="/tmp/crowdsec-install.sh"
    
    # Repository-Setup-Script herunterladen und validieren
    if ! curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh -o "$install_script"; then
        log_error "Download des CrowdSec-Repository-Scripts fehlgeschlagen"
        return 1
    fi
    
    # Grundlegende Validierung des Scripts
    if ! grep -q "packagecloud" "$install_script"; then
        log_error "Das heruntergeladene CrowdSec-Installationsskript scheint ungültig zu sein"
        rm -f "$install_script"
        return 1
    fi
    
    # Repository einrichten und Package-Liste aktualisieren
    if run_with_spinner "Richte APT-Repository ein und aktualisiere..." "bash '$install_script' && apt-get update -qq"; then
        log_ok "Externes CrowdSec-Repository erfolgreich eingerichtet"
    else
        log_error "Repository-Setup fehlgeschlagen"
        rm -f "$install_script"
        return 1
    fi
    
    # Cleanup
    rm -f "$install_script"
}

##
# Konfiguriert CrowdSec Bouncer YAML-sicher mit yq
##
configure_bouncer_with_yq() {
    log_info "  -> Konfiguriere NFTables-Modus mit yq (YAML-sicher)..."
    
    local dir="/etc/crowdsec/bouncers"
    local base_yml="$dir/crowdsec-firewall-bouncer.yaml"
    local local_yml="$dir/crowdsec-firewall-bouncer.yaml.local"
    local keyfile="$dir/.api_key"
    
    # Base-Config kopieren (idempotent)
    if [ ! -f "$local_yml" ] || [ "$base_yml" -nt "$local_yml" ]; then
        cp "$base_yml" "$local_yml"
        log_debug "Base-Config kopiert"
    fi
    
    # API-Key generieren falls nötig
    if [ ! -s "$keyfile" ]; then
        install -o root -g root -m600 /dev/null "$keyfile"
        if ! cscli bouncers add firewall-bouncer -o raw >"$keyfile"; then
            log_error "API-Key-Generierung fehlgeschlagen!"
            return 1
        fi
        log_debug "API-Key generiert"
    fi
    
    local api_key
    api_key=$(cat "$keyfile" | tr -d '\n\r')
    
    # YAML-Konfiguration mit yq (Template-Variablen ersetzen)
    yq eval -i '.mode = "nftables"' "$local_yml"
    yq eval -i '.log_level = "info"' "$local_yml"
    yq eval -i '.update_frequency = "30s"' "$local_yml"
    yq eval -i '.disable_ipv6 = false' "$local_yml"
    yq eval -i '.api_key = "'"$api_key"'"' "$local_yml"
    
    # NFTables IPv4-Konfiguration
    yq eval -i '.nftables.ipv4.enabled = true' "$local_yml"
    yq eval -i '.nftables.ipv4.set-only = true' "$local_yml"
    yq eval -i '.nftables.ipv4.table = "crowdsec"' "$local_yml"
    yq eval -i '.nftables.ipv4.chain = "crowdsec-chain"' "$local_yml"
    yq eval -i '.blacklists_ipv4 = "crowdsec-blacklists"' "$local_yml"
    
    # NFTables IPv6-Konfiguration
    yq eval -i '.nftables.ipv6.enabled = true' "$local_yml"
    yq eval -i '.nftables.ipv6.set-only = true' "$local_yml"
    yq eval -i '.nftables.ipv6.table = "crowdsec6"' "$local_yml"
    yq eval -i '.nftables.ipv6.chain = "crowdsec6-chain"' "$local_yml"
    yq eval -i '.blacklists_ipv6 = "crowdsec6-blacklists"' "$local_yml"
    
    log_info "     🔧 NFTables set-only Mode konfiguriert"
    log_info "     🎯 IPv4: crowdsec/crowdsec-blacklists"
    log_info "     🎯 IPv6: crowdsec6/crowdsec6-blacklists"
    
    # Konfiguration validieren
    log_info "  -> Teste Konfiguration..."
    if /usr/bin/crowdsec-firewall-bouncer -c "$local_yml" -t >/dev/null 2>&1; then
        log_ok "Bouncer-Konfiguration ist gültig"
        return 0
    else
        log_error "Konfiguration fehlerhaft!"
        log_info "Config-Datei: $local_yml"
        return 1
    fi
}

##
# Erstelle NFTables-Sets vor dem Service-Start
##
ensure_nftables_sets() {
    log_info "  -> Stelle NFTables-Sets sicher..."
    
    # IPv4-Sets
    if ! nft list set ip crowdsec crowdsec-blacklists >/dev/null 2>&1; then
        nft add table ip crowdsec 2>/dev/null || true
        nft add set ip crowdsec crowdsec-blacklists '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
        log_debug "IPv4-Set crowdsec-blacklists erstellt"
    else
        log_debug "IPv4-Set crowdsec-blacklists bereits vorhanden"
    fi
    
    # IPv6-Sets
    if ! nft list set ip6 crowdsec6 crowdsec6-blacklists >/dev/null 2>&1; then
        nft add table ip6 crowdsec6 2>/dev/null || true
        nft add set ip6 crowdsec6 crowdsec6-blacklists '{ type ipv6_addr; flags interval; }' 2>/dev/null || true
        log_debug "IPv6-Set crowdsec6-blacklists erstellt"
    else
        log_debug "IPv6-Set crowdsec6-blacklists bereits vorhanden"
    fi
    
    log_ok "NFTables-Sets verfügbar"
}

##
# Erstellt einen dedizierten systemd-Service für set-only Mode
##
create_setonly_bouncer_service() {
    log_info "  -> Erstelle dedizierten systemd-Service für set-only Mode..."
    
    local service_file="/etc/systemd/system/crowdsec-bouncer-setonly.service"
    local config_file="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"
    
    log_debug "Erstelle Service-Datei: $service_file"
    log_debug "Nutzt Config: $config_file"
    
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

# Konfiguration testen
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

# Umgebung - Metrics-Problem in set-only Mode beheben
Environment=BOUNCER_MODE=set-only
Environment=BOUNCER_DISABLE_METRICS=true
Environment=BOUNCER_LOG_LEVEL=info
StandardOutput=journal
StandardError=journal
SyslogIdentifier=crowdsec-bouncer-setonly

[Install]
WantedBy=multi-user.target
EOF

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
    
    log_ok "Dedizierter set-only Service erstellt und aktiviert"
    log_info "  Service-Datei: $service_file"
    log_info "  Nutzt Sets: crowdsec-blacklists (IPv4) & crowdsec6-blacklists (IPv6)"
}

#################################################################################
#                             HAUPTFUNKTIONEN
#           CrowdSec Stack und Bouncer-Installation fuer NFTables
################################################################################

##
# Installiert den CrowdSec Agenten und den Firewall Bouncer (modernisiert für Debian-Versionen)
##
install_crowdsec_stack() {
    log_info "⚙️  Installiere und konfiguriere den CrowdSec-Stack..."

    # --- 1. Debian-Version erkennen und entsprechend installieren ---
    local debian_version
    debian_version=$(lsb_release -cs 2>/dev/null || echo "unknown")
    
    log_info "  -> Erkannte Debian-Version: $debian_version"
    
    case "$debian_version" in
        "trixie")
            install_crowdsec_for_trixie
            ;;
        "bookworm")
            install_crowdsec_for_bookworm
            ;;
        *)
            log_warn "Unbekannte/Unsupported Debian-Version: $debian_version"
            log_info "Fallback: Verwende externe Repository-Methode..."
            setup_crowdsec_external_repository
            install_packages_safe crowdsec crowdsec-firewall-bouncer
            ;;
    esac

    # --- 2. systemd-Verhalten anpassen ---
    log_info "  -> Konfiguriere CrowdSec für netzwerkabhängigen Start..."
    mkdir -p /etc/systemd/system/crowdsec.service.d
    cat > /etc/systemd/system/crowdsec.service.d/override.conf <<EOF
[Unit]
After=network.target
[Service]
Restart=on-failure
RestartSec=30s
EOF

    # --- 3. Bouncer ist bereits installiert, nur noch konfigurieren ---
    configure_bouncer

    # --- 4. Services aktivieren und Start verifizieren ---
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
        log_ok "CrowdSec-Agent ist erfolgreich gestartet und API ist erreichbar"
        return 0
    else
        log_error "CrowdSec-Agent konnte nicht gestartet werden oder die API antwortet nicht"
        return 1
    fi
}

##
# Konfiguriert den Firewall-Bouncer (Pakete sind bereits installiert)
##
configure_bouncer() {
    log_info "🐾 Konfiguriere CrowdSec-Bouncer (NFTables-Integration)..."
    log_debug "Bouncer-Konfiguration gestartet mit DEBUG-Modus"

    # --- 1. Voraussetzungen prüfen ---
    log_info "  -> Prüfe Voraussetzungen (CrowdSec-Service & API)..."
    if ! systemctl is-active --quiet crowdsec; then
        log_error "Voraussetzung nicht erfüllt: CrowdSec-Service läuft nicht"
        return 1
    fi

	# Im Script prüfen und reparieren:
	if dpkg --verify crowdsec-firewall-bouncer 2>&1 | grep -q "missing"; then
		log_info "Repariere beschädigte Paket-Installation..."
		apt-get install --reinstall crowdsec-firewall-bouncer
	fi

    
    if ! cscli metrics >/dev/null 2>&1; then
        log_error "Voraussetzung nicht erfüllt: CrowdSec API ist nicht erreichbar"
        return 1
    fi
    
    if ! command -v nft >/dev/null 2>&1; then
        log_error "NFTables nicht installiert!"
        return 1
    fi
    
    if ! command -v yq >/dev/null 2>&1; then
        log_error "yq nicht verfügbar für YAML-Konfiguration!"
        return 1
    fi
    
    log_ok "Voraussetzungen erfüllt: CrowdSec-Service, API, NFTables und yq verfügbar"

    # --- 2. Konfigurationsdateien vorbereiten ---
    local dir="/etc/crowdsec/bouncers"
    local base_yml="$dir/crowdsec-firewall-bouncer.yaml"
    
    # BOUNCER IST BEREITS INSTALLIERT - nur Konfiguration prüfen
    if [ ! -f "$base_yml" ]; then
        log_error "Base-Konfigurationsdatei nicht gefunden: $base_yml"
        log_error "Bouncer-Paket nicht korrekt installiert!"
        return 1
    fi
    log_debug "Base-Konfigurationsdatei verfügbar"

    # --- 3. NFTables-Sets sicherstellen ---
    ensure_nftables_sets

    # --- 4. YAML-Konfiguration mit yq ---
    configure_bouncer_with_yq

    # --- 5. Dedizierter systemd-Service für set-only Mode ---
    log_info "  -> Erstelle dedizierten systemd-Service für set-only Mode..."
    create_setonly_bouncer_service

    # --- 6. Health-Check-System ---
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

    # NFTables-Service Integration
    log_info "  -> Integriere mit nftables-Service..."
    local nft_override_dir="/etc/systemd/system/nftables.service.d"
    mkdir -p "$nft_override_dir"
    
    cat > "$nft_override_dir/crowdsec.conf" <<'EOF'
[Service]
ExecReloadPost=/usr/bin/systemctl try-restart crowdsec-bouncer-setonly
EOF

    # --- 7. Services aktivieren mit Retry-Mechanismus ---
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
        local local_yml="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"
        if ! yq eval '.nftables.ipv4.set-only' "$local_yml" | grep -q "true"; then
            log_error "Set-only Modus nicht aktiviert!"
            verification_passed=false
        fi
        
        local keyfile="/etc/crowdsec/bouncers/.api_key"
        if [ ! -s "$keyfile" ]; then
            log_error "API-Key-Datei fehlt oder ist leer"
            verification_passed=false
        fi
        
        if [ "$verification_passed" = true ]; then
            log_ok "CrowdSec-Bouncer erfolgreich konfiguriert"
            log_info "  -> Set-only Mode: Nutzt vordefinierte NFTables-Struktur"
            log_info "  -> Health-Check läuft alle 5 Minuten"
            log_info "  -> Service: crowdsec-bouncer-setonly"
            return 0
        else
            log_error "Bouncer-Konfiguration unvollständig!"
            return 1
        fi
    else
        log_error "Services konnten nicht gestartet werden"
        return 1
    fi
}

##
# Passt die CrowdSec SSH-Policy an die Benutzereingaben an
##
tune_crowdsec_ssh_policy() {
    log_info "  -> Passe CrowdSec SSH-Policy an (Ban-Dauer: ${CROWDSEC_BANTIME})..."
    
    # Nur eine lokale Profildatei erstellen, wenn die Ban-Dauer vom Standard abweicht
    if [ "$CROWDSEC_BANTIME" != "4h" ]; then
        mkdir -p /etc/crowdsec/profiles.d/
        
        local custom_profile="/etc/crowdsec/profiles.d/99-custom-ssh-duration.yaml"
        
        # Idempotenz: Nur erstellen wenn nicht bereits vorhanden oder veraltet
        if [ ! -f "$custom_profile" ] || ! grep -q "duration: \"$CROWDSEC_BANTIME\"" "$custom_profile"; then
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
            log_ok "Custom SSH-Profile mit Ban-Dauer '$CROWDSEC_BANTIME' erstellt"
        else
            log_debug "Custom SSH-Profile bereits korrekt konfiguriert"
        fi
    else
        log_info "Standard CrowdSec SSH-Ban-Dauer ('4h') wird verwendet"
    fi
}