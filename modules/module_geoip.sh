#!/bin/bash
################################################################################
#
# MODUL: GEOIP-BLOCKING-SYSTEM (v5.2-SLIM) - NUTZT GEOIP-MANAGER
#
# @description: Installiert das GeoIP-System und nutzt geoip-manager für alles andere
# @author:      Markus F. (TZERO78) & KI-Assistenten  
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# CHANGELOG v5.2:
# - Schlanke Version die auf geoip-manager basiert
# - Nur Installation und Grundkonfiguration
# - Alle Management-Funktionen delegiert an geoip-manager
#
################################################################################

##
# HAUPT-MODUL: GeoIP-Blocking-System installieren
##
module_geoip() {
    log_info "🌍 MODUL: GeoIP-Blocking-System"

    # Prüfen ob GeoIP aktiviert ist
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" != "ja" ]; then
        log_info "GeoIP-Blocking ist deaktiviert - überspringe Modul."
        return 0
    fi

    # Validierung der benötigten Variablen
    if [ -z "$HOME_COUNTRY" ]; then
        log_error "HOME_COUNTRY ist nicht gesetzt! Setze z.B. HOME_COUNTRY='DE'"
        return 1
    fi

    if [ -z "$BLOCKED_COUNTRIES" ]; then
        log_warn "BLOCKED_COUNTRIES ist nicht gesetzt - verwende Standard: 'CN RU KP IR'"
        BLOCKED_COUNTRIES="CN RU KP IR"
    fi

    log_info "Konfiguration:"
    log_info "  Heimatland: $HOME_COUNTRY"
    log_info "  Blockierte Länder: $BLOCKED_COUNTRIES"

    # Installation durchführen
    log_info "Installiere GeoIP-Blocking-System..."
    
    create_geoip_config_files
    install_geoip_scripts
    create_geoip_systemd_timer
    configure_geoip_nftables_rules
    initialize_geoip_system

    log_ok "Modul GeoIP-Blocking erfolgreich installiert."
    
    # Info über geoip-manager
    log_info "💡 Das GeoIP-System ist jetzt einsatzbereit!"
    log_info "💡 Verwalten mit: geoip-manager status"
    log_info "💡 Hilfe anzeigen: geoip-manager help"
}

##
# GeoIP Konfigurationsdateien erstellen
##
create_geoip_config_files() {
    log_info "  -> Erstelle GeoIP-Konfigurationsdateien..."

    # Blockierte Länder
    echo "$BLOCKED_COUNTRIES" > /etc/geoip-countries.conf
    chown root:root /etc/geoip-countries.conf
    chmod 640 /etc/geoip-countries.conf

    # Heimatland
    echo "$HOME_COUNTRY" > /etc/geoip-home-country.conf
    chown root:root /etc/geoip-home-country.conf
    chmod 640 /etc/geoip-home-country.conf

    # Manuelle Allowlist (leer anlegen)
    touch /etc/geoip-allowlist.conf
    chown root:root /etc/geoip-allowlist.conf
    chmod 640 /etc/geoip-allowlist.conf

    log_ok "Config-Dateien erstellt."
}

##
# GeoIP Scripts aus components/ kopieren
##
install_geoip_scripts() {
    log_info "  -> Installiere GeoIP-Scripts aus components/..."

    local script_dir="${SCRIPT_DIR}/components"
    local scripts=("geoip-manager" "update-geoip-sets")

    # Prüfe components/ Verzeichnis
    if [ ! -d "$script_dir" ]; then
        log_error "Components-Verzeichnis nicht gefunden: $script_dir"
        return 1
    fi

    # Scripts kopieren
    for script in "${scripts[@]}"; do
        local source_file="$COMP_DIR/$script"
        local target_file="/usr/local/bin/$script"

        if [ ! -f "$source_file" ]; then
            log_error "Script nicht gefunden: $source_file"
            return 1
        fi

        if cp "$source_file" "$target_file"; then
            chmod +x "$target_file"
            chown root:root "$target_file"
            log_debug "Script installiert: $script"
        else
            log_error "Fehler beim Kopieren: $script"
            return 1
        fi
    done

    log_ok "GeoIP-Scripts installiert."
}

##
# systemd-Services erstellen
##
create_geoip_systemd_timer() {
    log_info "  -> Erstelle systemd-Services..."

    # Boot-Service
    cat > /etc/systemd/system/geoip-boot-restore.service << 'EOF'
[Unit]
Description=Restore GeoIP Sets after boot
After=network-online.target nftables.service
Wants=network-online.target
Before=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-geoip-sets
User=root
TimeoutSec=300
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # Update-Service
    cat > /etc/systemd/system/geoip-update.service << 'EOF'
[Unit]
Description=Update GeoIP block lists (Set-based)
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-geoip-sets
User=root
EOF

    # Timer
    cat > /etc/systemd/system/geoip-update.timer << 'EOF'
[Unit]
Description=Run GeoIP update monthly

[Timer]
OnCalendar=monthly
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    log_ok "systemd-Services erstellt."
}

##
# NFTables-Regeln konfigurieren
##
configure_geoip_nftables_rules() {
    log_info "  -> Konfiguriere NFTables-Regeln..."

    # Prüfe ob Chain existiert
    if ! nft list chain inet filter geoip_check >/dev/null 2>&1; then
        log_error "Chain 'geoip_check' nicht gefunden! NFTables-Basis fehlt."
        return 1
    fi

    # Chain leeren und Regeln setzen
    nft flush chain inet filter geoip_check

    nft add rule inet filter geoip_check ip saddr @geoip_allowlist_v4 counter accept comment \"Manual-Allow-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_allowlist_v6 counter accept comment \"Manual-Allow-v6\"
    nft add rule inet filter geoip_check ip saddr @geoip_home_v4 counter accept comment \"GeoIP-Allow-Home-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_home_v6 counter accept comment \"GeoIP-Allow-Home-v6\"
    nft add rule inet filter geoip_check ip saddr @geoip_blocked_v4 counter drop comment \"GeoIP-Block-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_blocked_v6 counter drop comment \"GeoIP-Block-v6\"

    log_ok "NFTables-Regeln konfiguriert."
}

##
# GeoIP-System initialisieren
##
initialize_geoip_system() {
    log_info "  -> Starte GeoIP-System..."

    # Services aktivieren
    systemctl daemon-reload
    systemctl enable geoip-boot-restore.service
    systemctl enable --now geoip-update.timer

    # Initiales Update - Sets befüllen
    log_info "  -> Führe initiales Update aus (Sets befüllen)..."
    if [ -x "/usr/local/bin/geoip-manager" ]; then
        log_info "  -> Starte Set-Befüllung mit geoip-manager (kann 1-2 Minuten dauern)..."
        if timeout 600 /usr/local/bin/geoip-manager update; then
            log_ok "Sets erfolgreich befüllt - GeoIP-Blocking ist aktiv!"
        else
            log_warn "Set-Befüllung fehlgeschlagen - Boot-Service wird es beim nächsten Neustart versuchen."
        fi
    elif [ -x "/usr/local/bin/update-geoip-sets" ]; then
        log_info "  -> Starte Set-Befüllung mit update-geoip-sets..."
        if timeout 600 /usr/local/bin/update-geoip-sets; then
            log_ok "Sets erfolgreich befüllt - GeoIP-Blocking ist aktiv!"
        else
            log_warn "Set-Befüllung fehlgeschlagen - Boot-Service wird es versuchen."
        fi
    else
        log_warn "Kein Update-Script verfügbar - Boot-Service führt ersten Update aus."
    fi

    # Status-Check nach Update
    if command -v /usr/local/bin/geoip-manager >/dev/null 2>&1; then
        log_info "  -> Prüfe GeoIP-Status nach Installation..."
        /usr/local/bin/geoip-manager status | head -15
    fi

    log_ok "GeoIP-System initialisiert."
}

################################################################################
# ENDE MODUL GEOIP-BLOCKING-SYSTEM v5.2-SLIM
################################################################################