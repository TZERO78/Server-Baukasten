#!/bin/bash
################################################################################
#
# MODUL: SYSTEM-UPDATE & AUTOMATISIERUNG  (deterministisch, 1 Job + Reboot)
#
# @description: Führt System-Updates aus, konfiguriert unattended-upgrades und
#               richtet einen systemd-Timer ein (03:30). Optional E-Mail.
# @license:     MIT
#
################################################################################

module_system_update() {
    local TEST_MODE="$1"

    # ========================= Konfigurierbare Defaults =========================
    : "${UPGRADE_EXTENDED:=ja}"      # ja => +updates, nein => nur -security
    : "${U_U_TIME:=03:30:00}"        # Startzeit für den nächtl. Job
    : "${REBOOT_ENABLE:=ja}"         # ja|nein
    : "${REBOOT_TIME:=03:45}"        # Reboot-Fenster (HH:MM)
    : "${REBOOT_WITH_USERS:=ja}"     # ja|nein (Serverbetrieb meist: ja)

    # Optionales erweitertes Aufräumen
    : "${CLEAN_DEEP:=nein}"          # ja => apt-get clean
    : "${PURGE_RC:=nein}"            # ja => rc-Pakete per dpkg -P entfernen

    log_info "🆙 MODUL: System Update & Automatisierung (via systemd)"

    # ================================ Pakete ===================================
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS: Überspringe dist-upgrade."
        run_with_spinner "Installiere unattended-upgrades..." \
            "apt-get install -y -qq unattended-upgrades >/dev/null"
    else
        run_with_spinner "Führe dist-upgrade durch..." \
            "apt-get update -qq && apt-get dist-upgrade -y"
        apt-get install -y -qq unattended-upgrades >/dev/null
    fi

    # Helper: prüft, ob systemd-Unit existiert
    _unit_exists() { systemctl list-unit-files --all 2>/dev/null | awk '{print $1}' | grep -qx "$1"; }

    # =================== 1/3: unattended-upgrades konfigurieren =================
    log_info "  -> 1/3: Konfiguriere unattended-upgrades…"

    local allowed_origins='      "\${distro_id}:\${distro_codename}-security";
      "\${distro_id}:stable-security";'
    if [ "$UPGRADE_EXTENDED" = "ja" ]; then
        allowed_origins="${allowed_origins}
      \"\${distro_id}:\${distro_codename}-updates\";
      \"\${distro_id}:stable-updates\";"
    fi

    # Mail-Block nur, wenn global aktiviert und Ziel gesetzt (Mail-Modul kümmert sich)
    local mail_block=""
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ] && [ -n "${NOTIFICATION_EMAIL:-}" ]; then
        mail_block=$(cat <<EOF_MB
Unattended-Upgrade::Mail "${NOTIFICATION_EMAIL}";
Unattended-Upgrade::MailOnlyOnError "false";
Unattended-Upgrade::MailReport "on-change";
EOF_MB
)
    fi

    backup_and_register "/etc/apt/apt.conf.d/50unattended-upgrades"
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
// Server-Baukasten – unattended-upgrades (deterministisch, 1 Job)
Unattended-Upgrade::Allowed-Origins {
$allowed_origins
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
${mail_block}Unattended-Upgrade::SyslogEnable "false";
Unattended-Upgrade::Automatic-Reboot "$( [ "$REBOOT_ENABLE" = "ja" ] && echo true || echo false )";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_TIME}";
Unattended-Upgrade::Automatic-Reboot-WithUsers "$( [ "$REBOOT_WITH_USERS" = "ja" ] && echo true || echo false )";
EOF

    # ======== 2/3: APT Periodic deaktivieren (alles übernimmt unser Job) ========
    log_info "  -> 2/3: Deaktiviere APT-Periodic (ein Job reicht)…"
    backup_and_register "/etc/apt/apt.conf.d/20auto-upgrades"
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
// APT Periodic – deaktiviert; Listen & Cleanup übernimmt unser Service
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "0";
EOF

    # ===== 3/3: Service & Timer (update → upgrade → cleanup, klar getaktet) =====
    log_info "  -> 3/3: Erzeuge Service & Timer…"

    # Service mit Update, Upgrade und Cleanup
    backup_and_register "/etc/systemd/system/unattended-upgrades-run.service"
    cat > /etc/systemd/system/unattended-upgrades-run.service <<'EOF'
[Unit]
Description=Run unattended-upgrades (update, upgrade, cleanup) with verbose logging
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
# 1) Paketlisten aktualisieren
ExecStartPre=/usr/bin/apt-get update -qq
# 2) Upgrades (verbose ins Journal)
ExecStart=/usr/bin/unattended-upgrade -d --verbose
# 3) Aufräumen (Altpakete & Cache)
ExecStartPost=/usr/bin/apt-get -y autoremove --purge
ExecStartPost=/usr/bin/apt-get -y autoclean
StandardOutput=journal
StandardError=journal
User=root
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    # Optionalen Extra-Cleanup anhängen (Deep-Clean / rc-Pakete purgen)
    local extra_cleanup=""
    [ "$CLEAN_DEEP" = "ja" ] && extra_cleanup+=$'\nExecStartPost=/usr/bin/apt-get -y clean'
    if [ "$PURGE_RC" = "ja" ]; then
        # rc-Pakete entfernen; robust (kein Fehler, wenn leer)
        extra_cleanup+=$'\nExecStartPost=/bin/sh -c '\''
dpkg -l | awk "/^rc/ {print \\$2}" | xargs -r dpkg -P'\'''
    fi
    [ -n "$extra_cleanup" ] && printf "%s\n" "$extra_cleanup" >> /etc/systemd/system/unattended-upgrades-run.service

    # Timer (Baseline) + deterministisches Drop-in
    backup_and_register "/etc/systemd/system/unattended-upgrades-run.timer"
    cat > /etc/systemd/system/unattended-upgrades-run.timer <<'EOF'
[Unit]
Description=Run unattended-upgrades service daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true
[Install]
WantedBy=timers.target
EOF

    install -d /etc/systemd/system/unattended-upgrades-run.timer.d
    cat > /etc/systemd/system/unattended-upgrades-run.timer.d/override.conf <<EOF
[Timer]
OnCalendar=
OnCalendar=*-*-* ${U_U_TIME}
RandomizedDelaySec=0
Persistent=true
EOF

    # Fremde apt-Timer NICHT erzeugen; falls vorhanden, nur sauber deaktivieren
    if _unit_exists "apt-daily.timer"; then
        log_info "     -> Deaktiviere vorhandenen apt-daily.timer (ein Job genügt)…"
        systemctl disable --now apt-daily.timer 2>/dev/null || true
    fi
    if _unit_exists "apt-daily-upgrade.timer"; then
        log_info "     -> Deaktiviere vorhandenen apt-daily-upgrade.timer (Doppel-Logik vermeiden)…"
        systemctl disable --now apt-daily-upgrade.timer 2>/dev/null || true
    fi

    # Aktivieren
    systemctl daemon-reload
    systemctl enable --now unattended-upgrades-run.timer
    systemctl restart unattended-upgrades-run.timer || true

    log_ok "Automatisches Update-Setup abgeschlossen (1 Job + Reboot)."
    log_info "⏱  Upgrades: ${U_U_TIME}  |  Reboot: $( [ "$REBOOT_ENABLE" = "ja" ] && echo "${REBOOT_TIME}" || echo "aus")"
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ] && [ -n "${NOTIFICATION_EMAIL:-}" ]; then
        log_info "📧 Mail-Report: on-change → ${NOTIFICATION_EMAIL}"
    else
        log_info "📧 Mail-Report: deaktiviert (ENABLE_SYSTEM_MAIL!=ja oder NOTIFICATION_EMAIL leer)"
    fi
    log_info "📜 Logs: journalctl -u unattended-upgrades-run.service"
}
