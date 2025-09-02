#!/bin/bash
################################################################################
#
# MODUL: SYSTEM-UPDATE & AUTOMATISIERUNG
#
# @description: Führt System-Updates durch und konfiguriert die automatische
#               Wartung via systemd-Timer.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

##
# MODUL 3: Führt ein System-Update durch und konfiguriert moderne,
#          journald-basierte automatische Updates via systemd.
##
module_system_update() {
    local TEST_MODE="$1"
    log_info "🆙 MODUL: System Update & Automatisierung (via systemd)"

    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS: Überspringe System-Update (dist-upgrade)."
        run_with_spinner "Installiere 'unattended-upgrades' für die Konfiguration..." \
            "apt-get install -y unattended-upgrades apt-listchanges >/dev/null"
    else
        run_with_spinner "Führe initiales System-Update (dist-upgrade) durch..." \
            "apt-get update -qq && apt-get dist-upgrade -y"
        apt-get install -y unattended-upgrades apt-listchanges >/dev/null
    fi

    log_info "  -> 1/3: Konfiguriere unattended-upgrades (Was soll aktualisiert werden?)..."
    local allowed_origins="      \"\\\${distro_id}:\\\${distro_codename}-security\";"
    if [ "$UPGRADE_EXTENDED" = "ja" ]; then
        allowed_origins+="\n      \"\\\${distro_id}:\\\${distro_codename}-updates\";"
    fi
    backup_and_register "/etc/apt/apt.conf.d/50unattended-upgrades"
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
// Konfiguration für unattended-upgrades
// Was wird aktualisiert? (Server-Baukasten v$SCRIPT_VERSION)
Unattended-Upgrade::Allowed-Origins {
$(echo -e "$allowed_origins")
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Mail "${NOTIFICATION_EMAIL:-root@localhost}";
Unattended-Upgrade::SyslogEnable "false"; // Wir loggen via systemd-journal
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    log_info "  -> 2/3: Deaktiviere alten apt-Timer und erstelle neue systemd-Units..."
    backup_and_register "/etc/apt/apt.conf.d/20auto-upgrades"
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
// Konfiguration für periodische apt-Aktivitäten
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::AutocleanInterval "7";

// Unattended-Upgrades werden jetzt durch unseren eigenen systemd-Timer gesteuert
APT::Periodic::Unattended-Upgrade "0";
EOF

    cat > /etc/systemd/system/unattended-upgrades-run.service << 'EOF'
[Unit]
Description=Run unattended-upgrades and log verbosely to journal
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/unattended-upgrade -d --verbose
StandardOutput=journal
StandardError=journal
User=root
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    cat > /etc/systemd/system/unattended-upgrades-run.timer << 'EOF'
[Unit]
Description=Run unattended-upgrades service daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true
[Install]
WantedBy=timers.target
EOF

    log_info "  -> 3/3: Aktiviere neuen systemd-Timer..."
    systemctl daemon-reload
    systemctl enable --now unattended-upgrades-run.timer

    log_ok "System-Updates erfolgreich auf modernen systemd-Timer umgestellt."
    log_info "  📜 Logs sind jetzt direkt im Journal verfügbar: journalctl -u unattended-upgrades-run.service"
}