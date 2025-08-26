#!/bin/bash
################################################################################
#
# BIBLIOTHEK: GEOIP-HELFER-FUNKTIONEN
#
# @description: Funktionen für die Konfiguration und Verwaltung des GeoIP-Blockings.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################



# ===============================================================================
#  GeoIP Konfigurationsdateien sicher erstellen
# ===============================================================================
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
# ===============================================================================
#  GEOP-IP-SYSTEMD-TIMER ERSTELLEN (wöchentliches Update)
# ===============================================================================
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

# ===============================================================================
#  GeoIP-Blocking installieren 
# ===============================================================================
configure_geoip_system() {
    log_info "🚀 Installiere GeoIP-Blocking (nutzt vordefinierte Sets)..."
    
    # 1. Konfigs erstellen
    create_geoip_config_files
    create_geoip_systemd_timer
    
    # 2. Sets müssen nicht mehr erstellt werden, da sie in nftables.conf stehen.
    log_info "  -> Sets sind bereits in nftables.conf definiert."
    
    # 3. Chain leeren und mit sauberen, Set-basierten Regeln befüllen
    log_info "  -> Fülle Chain 'geoip_check' mit 6 Kernregeln (inkl. Countern)..."
    
    nft flush chain inet filter geoip_check
    
    nft add rule inet filter geoip_check ip saddr @geoip_allowlist_v4 counter accept comment \"Manual-Allow-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_allowlist_v6 counter accept comment \"Manual-Allow-v6\"
    nft add rule inet filter geoip_check ip saddr @geoip_home_v4 counter accept comment \"GeoIP-Allow-Home-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_home_v6 counter accept comment \"GeoIP-Allow-Home-v6\"
    nft add rule inet filter geoip_check ip saddr @geoip_blocked_v4 counter drop comment \"GeoIP-Block-v4\"
    nft add rule inet filter geoip_check ip6 saddr @geoip_blocked_v6 counter drop comment \"GeoIP-Block-v6\"
    

    
    # 4. Timer aktivieren und erstes Update sofort ausführen
    log_info "  -> Starte GeoIP-Timer und führe initiales Update aus..."
    
    # VERWENDE run_with_spinner für besseres Feedback
    run_with_spinner "Aktiviere GeoIP-Update-Timer..." "systemctl daemon-reload && systemctl enable --now geoip-update.timer"
    
    # Führe das Update-Skript direkt aus, um die Sets sofort zu befüllen
    if run_with_spinner "Führe initiales GeoIP-Update aus..." "/usr/local/bin/update-geoip-sets"; then
        log_ok "Erstes GeoIP-Update erfolgreich. Die Sets sind jetzt befüllt."
    else
        log_warn "Erstes GeoIP-Update fehlgeschlagen. Sets sind noch leer. Timer wird es erneut versuchen."
    fi
    
    log_ok "GeoIP-Blocking (Set-basiert) erfolgreich installiert und aktiviert."
}
