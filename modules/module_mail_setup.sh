module_mail_setup() {
    if [ "$ENABLE_SYSTEM_MAIL" != "ja" ]; then
        log_info "📧 Systemweite E-Mail-Benachrichtigungen sind deaktiviert (übersprungen)."
        return 0
    fi

    log_info "📧 MODUL: Systemweiter E-Mail-Versand (msmtp)"
    
    run_with_spinner "Konfiguriere msmtp als sendmail-Alternative..." \
        "update-alternatives --install /usr/sbin/sendmail sendmail /usr/bin/msmtp 25 && update-alternatives --set sendmail /usr/bin/msmtp"

    local auth_setting="on"
    if [ "${SMTP_AUTH:-ja}" = "nein" ]; then
        auth_setting="off"
        log_info "  -> SMTP-Authentifizierung ist deaktiviert."
    else
        log_info "  -> SMTP-Authentifizierung ist aktiviert."
    fi
    
    local starttls_setting="off"
    if [ "${SMTP_TLS_STARTTLS:-nein}" = "ja" ]; then
        starttls_setting="on"
        log_info "  -> STARTTLS ist aktiviert."
    else
        log_info "  -> STARTTLS ist deaktiviert (direkter TLS-Modus)."
    fi
    
    log_info "  -> Schreibe msmtp-Konfiguration nach /etc/msmtprc..."
    backup_and_register "/etc/msmtprc"
    
    cat > /etc/msmtprc <<EOF
# msmtp-Konfiguration für systemweiten E-Mail-Versand
# Generiert von Server-Baukasten v$SCRIPT_VERSION am $(date)
defaults
auth           $auth_setting
tls            on
tls_starttls   $starttls_setting
tls_trust_file /etc/ssl/certs/ca-certificates.crt
syslog         on

account        default
host           $SMTP_HOST
port           $SMTP_PORT
from           $SMTP_FROM
EOF

    if [ "$auth_setting" = "on" ]; then
        if [ -n "${SMTP_USER:-}" ]; then
            echo "user            $SMTP_USER" >> /etc/msmtprc
            log_info "     - SMTP-Benutzername konfiguriert."
        fi
        if [ -n "${SMTP_PASSWORD:-}" ]; then
            echo "password        $SMTP_PASSWORD" >> /etc/msmtprc
            log_info "     - SMTP-Passwort konfiguriert."
        fi
    fi
    
    chmod 644 /etc/msmtprc
    chown root:root /etc/msmtprc
    log_ok "Sichere Dateiberechtigungen für /etc/msmtprc gesetzt."
    
    log_info "  -> Optimiere journald für E-Mail-Logs..."
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/99-mail-logging.conf <<EOF
# Optimierte journald-Konfiguration für E-Mail-Logging
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=200M
MaxRetentionSec=4week
SyncIntervalSec=60s
EOF
    
    run_with_spinner "Lade journald-Konfiguration neu..." "systemctl restart systemd-journald"
    
    log_info "  -> Teste E-Mail-Versand mit msmtp..."
    
    # KORRIGIERT: Verwende --from Parameter mit vollständiger E-Mail-Adresse
    if echo "Test-E-Mail vom Server-Baukasten auf $(hostname) am $(date)" | msmtp --debug --from="$SMTP_FROM" "$NOTIFICATION_EMAIL"; then
        log_ok "Test-E-Mail erfolgreich an $NOTIFICATION_EMAIL gesendet."
    else
        log_warn "Test-E-Mail konnte nicht gesendet werden."
        log_info "  -> Häufige Ursachen: SMTP-Credentials, Firewall, oder Provider-Einschränkungen"
        log_info "  -> Testen Sie manuell: echo 'Test' | msmtp --from='$SMTP_FROM' '$NOTIFICATION_EMAIL'"
        
        # NICHT abbrechen - Mail ist optional für das System-Setup
        log_warn "Mail-Setup abgeschlossen, aber Test fehlgeschlagen. System läuft trotzdem sicher!"
        return 0
    fi
    
    log_ok "Systemweiter E-Mail-Versand via msmtp erfolgreich eingerichtet."
    log_info "  📜 E-Mail-Logs sind im Journal verfügbar: journalctl | grep msmtp"
    log_warn "WICHTIG: Prüfe dein Postfach ($NOTIFICATION_EMAIL) auf Test-Mails!"
}