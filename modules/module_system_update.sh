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
    : "${UPGRADE_BACKPORTS:=nein}"   # ja => +backports, nein => ohne
    : "${U_U_TIME:=03:30:00}"        # Startzeit für den nächtl. Job
    : "${REBOOT_ENABLE:=ja}"         # ja|nein
    : "${REBOOT_TIME:=03:45}"        # Reboot-Fenster (HH:MM)
    : "${REBOOT_WITH_USERS:=ja}"     # ja|nein (Serverbetrieb meist: ja)

    # Optionales erweitertes Aufräumen
    : "${CLEAN_DEEP:=nein}"          # ja => apt-get clean
    : "${PURGE_RC:=nein}"            # ja => rc-Pakete per dpkg -P entfernen

    log_info "🆙 MODUL: System Update & Automatisierung (via systemd)"

    # ========================= Lokale Template-Rendering-Funktion =========================
    _render_local_template() {
        local template_name="$1" output_path="$2"
        local template_file="templates/${template_name}"
        
        [ -f "$template_file" ] || { log_error "Template nicht gefunden: $template_file"; return 1; }
        
        # Export alle Variablen für envsubst
        export BACKPORTS_LINE MAIL_BLOCK REBOOT_ENABLE REBOOT_TIME REBOOT_WITH_USERS U_U_TIME
        
        envsubst < "$template_file" > "$output_path" || { 
            log_error "Template-Rendering fehlgeschlagen: $template_name"; 
            return 1; 
        }
        log_debug "Template gerendert: $template_name → $output_path"
    }

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

    # ========== Variablen-Setup für Templates ==========
    
    # Backports-Zeile generieren (nur wenn gewünscht)
    if [ "$UPGRADE_BACKPORTS" = "ja" ]; then
        BACKPORTS_LINE="    \"\${distro_id}:\${distro_codename}-backports\";"
    else
        BACKPORTS_LINE=""
    fi

    # Mail-Block generieren (nur wenn global aktiviert und Ziel gesetzt)
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ] && [ -n "${NOTIFICATION_EMAIL:-}" ]; then
        MAIL_BLOCK="Unattended-Upgrade::Mail \"${NOTIFICATION_EMAIL}\";
Unattended-Upgrade::MailOnlyOnError \"false\";
Unattended-Upgrade::MailReport \"on-change\";
"
    else
        MAIL_BLOCK=""
    fi

    # Boolean-Konvertierung für systemd (ja → true, nein → false)
    REBOOT_ENABLE=$( [ "$REBOOT_ENABLE" = "ja" ] && echo "true" || echo "false" )
    REBOOT_WITH_USERS=$( [ "$REBOOT_WITH_USERS" = "ja" ] && echo "true" || echo "false" )

    # ========== Template rendern ==========
    backup_and_register "/etc/apt/apt.conf.d/50unattended-upgrades"
    _render_local_template "50unattended-upgrades.template" "/etc/apt/apt.conf.d/50unattended-upgrades" || {
        log_error "Fehler beim Rendern von 50unattended-upgrades.template"
        return 1
    }

    # ======== 2/3: APT Periodic deaktivieren (alles übernimmt unser Job) ========
    log_info "  -> 2/3: Deaktiviere APT-Periodic (ein Job reicht)…"
    backup_and_register "/etc/apt/apt.conf.d/20auto-upgrades"
    _render_local_template "20auto-upgrades.template" "/etc/apt/apt.conf.d/20auto-upgrades" || {
        log_error "Fehler beim Rendern von 20auto-upgrades.template"
        return 1
    }

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
SuccessExitStatus=0 2
TimeoutStartSec=1h
EOF

    # Optionalen Extra-Cleanup anhängen (Deep-Clean / rc-Pakete purgen)
    local extra_cleanup=""
    [ "$CLEAN_DEEP" = "ja" ] && extra_cleanup+=$'\nExecStartPost=/usr/bin/apt-get -y clean'
    if [ "$PURGE_RC" = "ja" ]; then
        # rc-Pakete entfernen; robust (kein Fehler, wenn leer)
        extra_cleanup+=$'\nExecStartPost=/bin/sh -c '\''dpkg -l | awk "/^rc/ {print \\$2}" | xargs -r dpkg -P'\'''
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

    # Deterministisches Override (exakte Zeit, kein Zufall)
    install -d /etc/systemd/system/unattended-upgrades-run.timer.d
    cat > /etc/systemd/system/unattended-upgrades-run.timer.d/override.conf <<EOF
[Timer]
OnCalendar=
OnCalendar=*-*-* ${U_U_TIME}
RandomizedDelaySec=0
Persistent=true
EOF

    # ========== apt-Timer MASKIEREN (nicht nur disable, verhindert Reaktivierung) ==========
    log_info "     -> Maskiere apt-Timer (Doppel-Logik vermeiden)…"
    for timer_unit in apt-daily.timer apt-daily.service apt-daily-upgrade.timer apt-daily-upgrade.service; do
        if _unit_exists "$timer_unit"; then
            systemctl disable --now "$timer_unit" 2>/dev/null || true
            systemctl mask "$timer_unit" 2>/dev/null || true
            log_debug "       Maskiert: $timer_unit"
        fi
    done

    # Aktivieren unseres Jobs
    systemctl daemon-reload
    systemctl enable --now unattended-upgrades-run.timer
    systemctl restart unattended-upgrades-run.timer 2>/dev/null || true

    log_ok "Automatisches Update-Setup abgeschlossen (1 Job + Reboot)."
    log_info "⏱  Upgrades: ${U_U_TIME}  |  Reboot: $( [ "$REBOOT_ENABLE" = "true" ] && echo "${REBOOT_TIME}" || echo "aus" )"
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ] && [ -n "${NOTIFICATION_EMAIL:-}" ]; then
        log_info "📧 Mail-Report: on-change → ${NOTIFICATION_EMAIL}"
    else
        log_info "📧 Mail-Report: deaktiviert (ENABLE_SYSTEM_MAIL!=ja oder NOTIFICATION_EMAIL leer)"
    fi
    log_info "📜 Logs: journalctl -u unattended-upgrades-run.service"
    log_info "📜 Timer: systemctl list-timers unattended-upgrades-run.timer"
}
