#!/bin/bash
################################################################################
#
# BIBLIOTHEK: INTEGRITÄTS-MONITORING-HELFER
#
# @description: AIDE und RKHunter Setup und Konfiguration für das
#               System-Integritäts-Monitoring
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

# ===============================================================================
#                    AIDE & RKHUNTER JOURNALD-INTEGRATION
# ===============================================================================

##
# Konfiguriert AIDE durch Herunterladen des Templates und Erstellen der systemd-Units.
##
configure_aide() {
    log_info "Konfiguriere AIDE (System-Integritäts-Monitoring)..."
    
    # --- Schritt 1: Deaktiviere Standard-Timer ---
    systemctl disable --now dailyaidecheck.timer >/dev/null 2>&1 || true

    # --- Schritt 2: Verzeichnisse erstellen ---
    mkdir -p /etc/aide /var/lib/aide /var/log/aide
    chown root:root /etc/aide /var/lib/aide
    chmod 750 /etc/aide /var/lib/aide
    chown root:adm /var/log/aide
    chmod 750 /var/log/aide
   
    # --- Schritt 3: Lade Konfigurations-Template herunter ---
    download_and_process_template "aide.conf.template" "/etc/aide/aide.conf" "640" "root:root"

    # AIDE-spezifisches Log-Directory (nur als Backup)
    mkdir -p /var/log/aide
    chown root:adm /var/log/aide
    chmod 750 /var/log/aide

    # 3. Systemd Service 
    cat > /etc/systemd/system/aide-check.service << 'EOF'
[Unit]
Description=AIDE File Integrity Check
Documentation=man:aide(1)
After=multi-user.target

[Service]
Type=oneshot
User=root

# KORRIGIERT: Check if database exists, if not create it
ExecStartPre=/bin/bash -c 'if [ ! -f /var/lib/aide/aide.db ]; then /usr/bin/aide --config /etc/aide/aide.conf --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db; fi'

# KORRIGIERT: Run the integrity check with structured output
ExecStart=/usr/bin/aide --config /etc/aide/aide.conf --check

# journald-optimized output
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aide-check

# Structured logging environment
Environment="SYSTEMD_LOG_LEVEL=info"
Environment="SYSTEMD_LOG_TARGET=journal"

# Performance optimization (VPS-friendly)
TimeoutStartSec=45min
CPUQuota=40%
Nice=19
IOSchedulingClass=2
IOSchedulingPriority=7

# Security hardening
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/aide /var/log/aide /tmp

# Exit codes: AIDE-specific handling
# 0 = No changes, 1 = New files, 2 = Removed files, 3 = Changed files
# 4 = Changed and new files, 5 = Changed and removed, 6 = New and removed
# 7 = All types of changes, 14 = Error writing database
SuccessExitStatus=0 1 2 3 4 5 6 7

[Install]
# IMPORTANT: Don't enable service directly - only via timer!
WantedBy=
EOF

    # 4. Systemd Timer
    cat > /etc/systemd/system/aide-check.timer << 'EOF'
[Unit]
Description=Run AIDE integrity check daily
Documentation=man:systemd.timer(5)
Requires=aide-check.service

[Timer]
# Daily at 5:00 AM (low system load time)
OnCalendar=*-*-* 05:00:00

# Randomize up to 30 minutes (spread server load)
RandomizedDelaySec=1800

# Run even if system was down
Persistent=true

# Explicit service reference
Unit=aide-check.service

[Install]
WantedBy=timers.target
EOF

   # 5. journald-Konfiguration neu laden und systemd-Units aktivieren
    run_with_spinner "Lade systemd-Konfiguration neu..." "systemctl restart systemd-journald && systemctl daemon-reload"
    
    # --- Schritt 6: Aktiviere den neuen Timer (für zukünftige Starts) ---
    systemctl daemon-reload
    if ! run_with_spinner "Aktiviere AIDE-Timer für zukünftige Starts..." "systemctl enable aide-check.timer"; then
        log_warn "AIDE-Timer konnte nicht für den Systemstart aktiviert werden."
    fi
    
    log_ok "AIDE-Konfiguration abgeschlossen und Timer für nächsten Boot vorgemerkt."
    log_info "  📜 Logs abrufen mit: journalctl -u aide-check.service"
    log_info "  📊 Timer-Status prüfen mit: systemctl list-timers aide-check.timer"
}

##
# Konfiguriert RKHunter (Rootkit-Scanner) für die Ausführung via systemd-Timer
# und leitet die Ausgabe direkt an das journald-Log um.
##
configure_rkhunter() {
    log_info "Konfiguriere RKHunter..."
    
    # --- Schritt 1: Lade Konfigurations-Template herunter ---
    download_and_process_template "rkhunter.conf.template" "/etc/rkhunter.conf" "640" "root:root"
    
    # RKHunter-spezifische journald-Konfiguration
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/rkhunter-logging.conf << 'EOF'
# RKHunter-optimierte journald-Konfiguration
[Journal]
# RKHunter-Logs persistent speichern (wichtig für Security-Audit)
Storage=persistent

# Längere Aufbewahrung für Security-Logs
MaxRetentionSec=16week

# Komprimierung für RKHunter-Reports
Compress=yes

# Security-Logs haben Priorität - größere Limits
SystemMaxUse=350M
SystemMaxFileSize=40M

# Rate-Limiting für RKHunter-Scans anpassen
RateLimitIntervalSec=120s
RateLimitBurst=30000
EOF

    # 3. Mail nur wenn aktiviert
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ] && [ -n "${NOTIFICATION_EMAIL:-}" ]; then
        echo "MAIL-ON-WARNING=\"$NOTIFICATION_EMAIL\"" >> /etc/rkhunter.conf
        echo "MAIL_CMD=mail -s \"[rkhunter] \$(hostname)\"" >> /etc/rkhunter.conf
        log_info "Mail aktiviert für $NOTIFICATION_EMAIL"
    fi
    
    # 4. Datenbank initialisieren
    log_info "Initialisiere RKHunter-Pfade und Datenbank..."
    
    # Stelle sicher, dass alle benötigten Verzeichnisse existieren
    mkdir -p /var/lib/rkhunter/tmp
    mkdir -p /var/lib/rkhunter/db
    chown root:root /var/lib/rkhunter/tmp /var/lib/rkhunter/db
    chmod 755 /var/lib/rkhunter/tmp /var/lib/rkhunter/db
    
    # Prüfe ob kritische Pfade existieren
    local missing_paths=()
    [ ! -d /usr/share/rkhunter/scripts ] && missing_paths+=("SCRIPTDIR")
    [ ! -d /usr/share/rkhunter ] && missing_paths+=("INSTALLDIR")
    
    if [ ${#missing_paths[@]} -gt 0 ]; then
        log_error "Kritische RKHunter-Pfade fehlen: ${missing_paths[*]}"
        log_warn "RKHunter-Paket ist beschädigt oder nicht vollständig installiert"
        log_info "Lösung: sudo apt-get remove --purge rkhunter && sudo apt-get install rkhunter"
        log_warn "Überspringe RKHunter-Konfiguration..."
        return 0
    fi
    
    rkhunter --update --quiet || true
    rkhunter --propupd --quiet || true
    
    # 5. Systemd Service (journald-optimiert)
    cat > /etc/systemd/system/rkhunter-check.service << 'EOF'
[Unit]
Description=RKHunter Security Check (Rootkit Detection)
Documentation=man:rkhunter(8)
After=multi-user.target

[Service]
Type=oneshot
User=root

# Update signatures if needed
ExecStartPre=-/usr/bin/rkhunter --update --quiet

# Main security scan with structured output
ExecStart=/usr/bin/rkhunter --check --cronjob --report-warnings-only

# journald-optimized output
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rkhunter-check

# Structured logging environment
Environment="SYSTEMD_LOG_LEVEL=info"
Environment="SYSTEMD_LOG_TARGET=journal"

# Performance settings (VPS-optimized)
TimeoutStartSec=20min
CPUQuota=25%
Nice=19

# Security hardening
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rkhunter /var/log /tmp

# RKHunter-specific exit codes as success
# 0 = OK, 1 = Warnings found, 2 = Errors (but scan completed)
SuccessExitStatus=0 1 2

[Install]
# IMPORTANT: Don't enable service directly - only via timer!
WantedBy=
EOF

    # 6. Systemd Timer
    cat > /etc/systemd/system/rkhunter-check.timer << 'EOF'
[Unit]
Description=Run RKHunter security check weekly
Documentation=man:systemd.timer(5)
Requires=rkhunter-check.service

[Timer]
# Weekly on Sunday at 4:00 AM (low system load)
OnCalendar=Sun *-*-* 04:00:00

# Randomize up to 30 minutes (spread server load)
RandomizedDelaySec=1800

# Run even if system was down
Persistent=true

# Explicit service reference
Unit=rkhunter-check.service

[Install]
WantedBy=timers.target
EOF

    # 7. journald-Konfiguration neu laden und aktivieren
    systemctl restart systemd-journald
    systemctl daemon-reload
    systemctl enable --now rkhunter-check.timer
    
    log_ok "RKHunter konfiguriert (wöchentlich sonntags 4:00-4:30 Uhr, journald-optimiert)"
    log_info "Logs: journalctl -u rkhunter-check.service"
    log_info "Security-Filter: journalctl -t rkhunter-check"
    log_info "Timer-Status: systemctl list-timers rkhunter-check.timer"
}
