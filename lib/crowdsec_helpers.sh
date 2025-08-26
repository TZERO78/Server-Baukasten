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
##
# Installiert und konfiguriert den CrowdSec Firewall Bouncer für NFTables.
# KORRIGIERTE VERSION - Kombiniert bewährte Teile der alten mit neuen Verbesserungen
##
install_bouncer() {
    log_info "🐾 Installiere CrowdSec-Bouncer (NFTables-Integration)..."

    # --- 1. Voraussetzungen prüfen (wie in neuer Version) ---
    log_info "  -> Prüfe Voraussetzungen (CrowdSec-Service & API)..."
    if ! systemctl is-active --quiet crowdsec; then
        log_error "Voraussetzung nicht erfüllt: CrowdSec-Service läuft nicht."
        return 1
    fi
    if ! cscli metrics >/dev/null 2>&1; then
        log_error "Voraussetzung nicht erfüllt: CrowdSec API ist nicht erreichbar."
        return 1
    fi
    log_ok "Voraussetzungen erfüllt: CrowdSec-Service und API sind erreichbar."

    # --- 2. Bouncer-Paket sauber installieren (wie in alter Version) ---
    local pkg="crowdsec-firewall-bouncer"
    local dir="/etc/crowdsec/bouncers"
    local base_yml="$dir/crowdsec-firewall-bouncer.yaml"
    local local_yml="$dir/crowdsec-firewall-bouncer.yaml.local"
    local keyfile="$dir/.api_key"  # BEWÄHRT: Separater Keyfile wie in alter Version
    
    local install_cmd="apt-get remove --purge -y '$pkg' >/dev/null 2>&1 || true; rm -rf '$dir'; DEBIAN_FRONTEND=noninteractive apt-get install -y '$pkg'"
    if ! run_with_spinner "Installiere Bouncer-Paket (ggf. Re-Installation)..." "$install_cmd"; then
        log_error "Installation des Bouncer-Pakets ist fehlgeschlagen."
        return 1
    fi
    if [ ! -f "$local_yml" ]; then
        log_error "Bouncer-Konfigurationsdatei wurde nicht erstellt."
        return 1
    fi

    # --- 3. Konfiguriere für NFTables-Modus (bewährte alte Logik) ---
    log_info "  -> Konfiguriere NFTables-Modus..."
    cp "$base_yml" "$local_yml"
    
    if grep -q '${BACKEND}' "$local_yml" 2>/dev/null; then
        sed -i 's/mode: ${BACKEND}/mode: nftables/' "$local_yml"
        log_info "     🔧 Template-Modus → nftables"
    else
        if command -v yq &>/dev/null; then
            yq -i -y '.mode = "nftables"' "$local_yml"
        else
            if grep -q '^mode:' "$local_yml"; then
                sed -i 's/^mode:.*/mode: nftables/' "$local_yml"
            else
                sed -i '1i mode: nftables' "$local_yml"
            fi
        fi
        log_info "     🔧 NFTables-Modus direkt gesetzt"
    fi
    
    # Logging-Level optimieren
    sed -i 's/debug: .*/debug: false/' "$local_yml" 2>/dev/null || true
    sed -i 's/log_level: .*/log_level: info/' "$local_yml" 2>/dev/null || true
    
    # --- 4. API-Schlüssel generieren (bewährte alte Methode) ---
    log_info "  -> Generiere und konfiguriere API-Schlüssel..."
    
    if [ ! -s "$keyfile" ]; then
        install -o root -g root -m600 /dev/null "$keyfile"
        if ! cscli bouncers add firewall-bouncer -o raw >"$keyfile"; then
            log_error "API-Key-Generierung fehlgeschlagen!"
            return 1
        fi
    fi
    
    local api_key
    api_key=$(cat "$keyfile" 2>/dev/null | tr -d '\n\r')
    if [ -n "$api_key" ]; then
        if grep -q '${API_KEY}' "$local_yml" 2>/dev/null; then
            sed -i "s|\${API_KEY}|$api_key|g" "$local_yml"
        else
            if command -v yq &>/dev/null; then
                yq -i -y ".api_key = \"$api_key\"" "$local_yml"
            else
                if grep -q 'api_key:' "$local_yml"; then
                    sed -i "s/api_key:.*/api_key: $api_key/" "$local_yml"
                else
                    echo "api_key: $api_key" >> "$local_yml"
                fi
            fi
        fi
        log_info "     🔑 API-Key konfiguriert"
    else
        log_error "API-Key ist leer!"
        return 1
    fi
    log_ok "API-Schlüssel erfolgreich in Konfiguration eingetragen."

    # --- 5. systemd-Integration (KORRIGIERT - alte bewährte Methode) ---
    log_info "  -> Konfiguriere systemd-Integration..."
    local override_dir="/etc/systemd/system/crowdsec-firewall-bouncer.service.d"
    
    # Bereinige alte Override-Files (verhindert Konflikte)
    if [ -d "$override_dir" ]; then
        log_info "     -> Bereinige alte Override-Konfigurationen..."
        rm -rf "$override_dir"
    fi
    mkdir -p "$override_dir"

    # KORRIGIERT: Verwende bewährte systemd-Konfiguration aus alter Version
    cat > "$override_dir/override.conf" <<EOF
[Unit]
After=multi-user.target crowdsec.service
Requires=crowdsec.service

[Service]
# Verwende lokale Konfiguration (WICHTIG: ExecStart muss zurückgesetzt werden!)
ExecStartPre=
ExecStart=
ExecStartPre=/bin/bash -c 'until cscli metrics >/dev/null 2>&1; do sleep 2; done'
ExecStartPre=/usr/bin/crowdsec-firewall-bouncer -c $local_yml -t
ExecStart=/usr/bin/crowdsec-firewall-bouncer -c $local_yml

# Auto-Recovery bei Problemen
Restart=on-failure
RestartSec=15s

[Install]
# Separate Boot-Phase - startet NACH multi-user.target
WantedBy=default.target
EOF

    # --- 6. Health-Check-System (alte bewährte Version) ---
    log_info "  -> Installiere Health-Check-System..."
    install -m755 /dev/null /usr/local/bin/crowdsec-healthcheck
    cat > /usr/local/bin/crowdsec-healthcheck <<'EOF'
#!/bin/bash
# CrowdSec Health-Check: Restart bei API-Problemen
if ! cscli metrics >/dev/null 2>&1; then
    logger -t "crowdsec-healthcheck" -p daemon.warn "CrowdSec API nicht erreichbar - starte Services neu..."
    systemctl restart crowdsec crowdsec-firewall-bouncer
fi
EOF
    
    # Health-Check als systemd-Service
    cat > /etc/systemd/system/crowdsec-healthcheck.service <<'EOF'
[Unit]
Description=CrowdSec Health-Check
After=crowdsec.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/crowdsec-healthcheck
User=root
EOF

    # Health-Check-Timer (alle 5 Minuten) - KORRIGIERT: OnUnitInactiveSec statt OnUnitActiveSec
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

    # --- 7. Services aktivieren und starten (mit Verifikation) ---
    systemctl daemon-reload
    if run_with_spinner "Aktiviere Bouncer und Health-Check..." "systemctl enable --now crowdsec-firewall-bouncer crowdsec-healthcheck.timer"; then
        # Finale Verifikation (aus alter Version)
        log_info "  -> Prüfe Bouncer-Installation..."
        local verification_passed=true
        
        # Service-Status prüfen
        if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
            log_warn "Bouncer-Service startet noch..."
            sleep 3
            if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
                verification_passed=false
            fi
        fi
        
        # NFTables-Modus prüfen
        if command -v yq &>/dev/null; then
            if ! yq '.mode' "$local_yml" | grep -q "nftables"; then
                log_error "NFTables-Modus nicht gesetzt!"
                verification_passed=false
            fi
        fi
        
        # API-Key prüfen
        if [ ! -s "$keyfile" ]; then
            log_error "API-Key fehlt!"
            verification_passed=false
        fi

        # Ergebnis ausgeben
        if [ "$verification_passed" = true ]; then
            log_ok "CrowdSec-Bouncer erfolgreich installiert und mit NFTables integriert."
            log_info "  -> Der Health-Check läuft jetzt automatisch alle 5 Minuten."
            return 0
        else
            log_error "Bouncer-Installation unvollständig!"
            return 1
        fi
    else
        log_error "Bouncer-Installation ist unvollständig! Services konnten nicht gestartet werden."
        return 1
    fi
}

##
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