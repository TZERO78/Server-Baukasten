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
# GeoIP systemd-Services erstellen
##
create_geoip_systemd_timer() {
    log_info "  -> Erstelle systemd-Services für GeoIP-Management..."
    
    # Boot-Service für automatisches Laden nach Reboot
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
    
    # Update-Service für wöchentliche Updates
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
    
    # Wöchentlicher Update-Timer
    cat > /etc/systemd/system/geoip-update.timer << 'EOF'
[Unit]
Description=Run GeoIP update weekly

[Timer]
OnCalendar=Sun *-*-* 02:00:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    log_ok "GeoIP-Services konfiguriert (Boot-Restore + wöchentliche Updates)."
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

##
# Verifikation der GeoIP-Installation
##
verify_geoip_installation() {
    log_info "  -> Verifiziere GeoIP-Installation..."
    
    local verification_errors=0
    
    # Prüfe Konfigurationsdateien
    for config_file in /etc/geoip-countries.conf /etc/geoip-home-country.conf /etc/geoip-allowlist.conf; do
        if [ ! -f "$config_file" ]; then
            log_error "Konfigurationsdatei fehlt: $config_file"
            ((verification_errors++))
        fi
    done
    
    # Prüfe systemd-Services
    for service in geoip-boot-restore.service geoip-update.service geoip-update.timer; do
        if ! systemctl is-enabled "$service" >/dev/null 2>&1; then
            log_error "Service nicht aktiviert: $service"
            ((verification_errors++))
        fi
    done
    
    # Prüfe Update-Skript
    if [ ! -f /usr/local/bin/update-geoip-sets ] || [ ! -x /usr/local/bin/update-geoip-sets ]; then
        log_error "Update-Skript fehlt oder ist nicht ausführbar: /usr/local/bin/update-geoip-sets"
        ((verification_errors++))
    fi
    
    # Prüfe NFTables-Sets
    local missing_sets=0
    for set in geoip_allowlist_v4 geoip_allowlist_v6 geoip_home_v4 geoip_home_v6 geoip_blocked_v4 geoip_blocked_v6; do
        if ! nft list set inet filter "$set" >/dev/null 2>&1; then
            log_warn "NFTables-Set nicht gefunden: $set"
            ((missing_sets++))
        fi
    done
    
    # Prüfe GeoIP-Chain
    if ! nft list chain inet filter geoip_check >/dev/null 2>&1; then
        log_error "GeoIP-Chain nicht gefunden: geoip_check"
        ((verification_errors++))
    fi
    
    # Ergebnis
    if [ $verification_errors -eq 0 ]; then
        if [ $missing_sets -eq 0 ]; then
            log_ok "GeoIP-System vollständig installiert und konfiguriert"
        else
            log_warn "GeoIP-System installiert, aber $missing_sets Sets sind noch leer (werden beim nächsten Update befüllt)"
        fi
        return 0
    else
        log_error "GeoIP-Verifikation fehlgeschlagen: $verification_errors Fehler gefunden"
        return 1
    fi
}

################################################################################
# ENDE MODUL GEOIP-BLOCKING-SYSTEM v5.0
################################################################################
