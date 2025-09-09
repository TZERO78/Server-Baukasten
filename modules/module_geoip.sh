#!/bin/bash
################################################################################
#
# MODUL: GEOIP-BLOCKING-SYSTEM (v5.0) - VOLLSTÄNDIG EIGENSTÄNDIG
#
# @description: Konfiguriert das GeoIP-Blocking-System vollständig
# @author:      Markus F. (TZERO78) & KI-Assistenten  
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# Dieses Modul ist vollständig eigenständig und enthält alle benötigten
# GeoIP-Funktionen ohne externe Dependencies.
#
################################################################################

##
# HAUPT-MODUL: GeoIP-Blocking-System konfigurieren
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
    
    # GeoIP-System Schritt für Schritt konfigurieren
    log_info "Konfiguriere GeoIP-Blocking-System..."
    
    create_geoip_config_files
    create_geoip_systemd_timer
    configure_geoip_nftables_rules
    initialize_geoip_system
    
    # Verifikation
    verify_geoip_installation
    
    log_ok "Modul GeoIP-Blocking erfolgreich abgeschlossen."
}

##
# GeoIP Konfigurationsdateien erstellen
##
create_geoip_config_files() {
    log_info "  -> Erstelle GeoIP-Konfigurationsdateien mit sicheren Rechten..."
    
    # Blockierte Länder
    echo "$BLOCKED_COUNTRIES" > /etc/geoip-countries.conf
    chown root:root /etc/geoip-countries.conf
    chmod 640 /etc/geoip-countries.conf

    # Heimatland
    echo "$HOME_COUNTRY" > /etc/geoip-home-country.conf
    chown root:root /etc/geoip-home-country.conf
    chmod 640 /etc/geoip-home-country.conf
    
    # Manuelle Allowlist (leer anlegen, falls nicht vorhanden)
    touch /etc/geoip-allowlist.conf
    chown root:root /etc/geoip-allowlist.conf
    chmod 640 /etc/geoip-allowlist.conf
    
    log_ok "GeoIP-Konfigurationsdateien sicher erstellt (Rechte: 640)."
}

##
# GeoIP systemd-Timer erstellen
##
create_geoip_systemd_timer() {
    log_info "  -> Erstelle systemd-Timer für wöchentliches GeoIP-Update..."
    
    # systemd-Service
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
    
    # systemd-Timer mit wöchentlichem Zeitplan
    cat > /etc/systemd/system/geoip-update.timer << 'EOF'
[Unit]
Description=Run GeoIP update weekly

[Timer]
# Wöchentlich - guter Kompromiss
OnCalendar=Sun *-*-* 02:00:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    log_ok "GeoIP-Update-Timer konfiguriert (wöchentlich sonntags)."
}

##
# GeoIP NFTables-Regeln konfigurieren
##
configure_geoip_nftables_rules() {
    log_info "  -> Fülle Chain 'geoip_check' mit Kernregeln (inkl. Countern)..."
    
    # Chain leeren und mit sauberen, Set-basierten Regeln befüllen
    nft flush chain inet filter geoip_check
    
    nft add rule inet filter geoip_check ip saddr @geoip_allowlist_v4 counter accept comment \"Manual-Allow-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_allowlist_v6 counter accept comment \"Manual-Allow-v6\"
    nft add rule inet filter geoip_check ip saddr @geoip_home_v4 counter accept comment \"GeoIP-Allow-Home-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_home_v6 counter accept comment \"GeoIP-Allow-Home-v6\"
    nft add rule inet filter geoip_check ip saddr @geoip_blocked_v4 counter drop comment \"GeoIP-Block-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_blocked_v6 counter drop comment \"GeoIP-Block-v6\"
    
    log_ok "GeoIP-Regeln erfolgreich konfiguriert."
}

##
# GeoIP-System initialisieren
##
initialize_geoip_system() {
    log_info "  -> Aktiviere GeoIP-Services und führe initiales Update aus..."
    
    # Services aktivieren
    systemctl daemon-reload
    systemctl enable geoip-boot-restore.service
    systemctl enable --now geoip-update.timer
    
    # Erstes Update ausführen um Sets zu befüllen
    log_info "  -> Führe initiales GeoIP-Update aus (kann einige Minuten dauern)..."
    if /usr/local/bin/update-geoip-sets; then
        log_ok "Erstes GeoIP-Update erfolgreich. Die Sets sind jetzt befüllt."
    else
        log_warn "Erstes GeoIP-Update fehlgeschlagen. Boot-Service wird es beim nächsten Neustart versuchen."
    fi
    
    log_ok "GeoIP-System erfolgreich initialisiert (Boot-Restore + Timer aktiv)."
}

################################################################################
# ENDE MODUL GEOIP-BLOCKING-SYSTEM v5.0
################################################################################
