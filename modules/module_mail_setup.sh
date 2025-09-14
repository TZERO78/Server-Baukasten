#!/bin/bash
################################################################################
# MODUL: E-MAIL-SETUP - v2.1 SICHERHEITSKORRIGIERT
#
# @description: Konfiguriert msmtp für systemweiten E-Mail-Versand mit
#               sicheren Dateiberechtigungen und robuster Fehlerbehandlung
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ÄNDERUNGEN v2.1:
# - SICHERHEIT: chmod 600 statt 644 für /etc/msmtprc (Passwort-Schutz)
# - Robuste Validierung der SMTP-Variablen vor Konfiguration
# - Verbesserte Fehlerbehandlung bei update-alternatives
# - Erweiterte Logging-Konfiguration für bessere Diagnose
#
################################################################################

module_mail_setup() {
    if [ "$ENABLE_SYSTEM_MAIL" != "ja" ]; then
        log_info "📧 Systemweite E-Mail-Benachrichtigungen sind deaktiviert (übersprungen)."
        return 0
    fi

    log_info "📧 MODUL: Systemweiter E-Mail-Versand (msmtp)"

    # --- VALIDIERUNG DER SMTP-KONFIGURATION ---
    log_info "  -> Validiere SMTP-Konfiguration..."
    
    if [ -z "${SMTP_HOST:-}" ]; then
        log_error "SMTP_HOST ist nicht gesetzt!"
        log_error "Setze SMTP_HOST in der Konfigurationsdatei."
        return 1
    fi
    
    if [ -z "${SMTP_FROM:-}" ]; then
        log_error "SMTP_FROM ist nicht gesetzt!"
        log_error "Setze SMTP_FROM (Absender-E-Mail) in der Konfigurationsdatei."
        return 1
    fi
    
    if [ -z "${NOTIFICATION_EMAIL:-}" ]; then
        log_error "NOTIFICATION_EMAIL ist nicht gesetzt!"
        log_error "Setze NOTIFICATION_EMAIL (Empfänger) in der Konfigurationsdatei."
        return 1
    fi

    # Prüfe ob msmtp installiert ist
    if ! command -v msmtp >/dev/null 2>&1; then
        log_error "msmtp ist nicht installiert!"
        log_error "Führe zuerst das Install-Services-Modul aus."
        return 1
    fi

    log_ok "SMTP-Konfiguration validiert."
    log_info "  Host: $SMTP_HOST:${SMTP_PORT:-25}"
    log_info "  Von: $SMTP_FROM"
    log_info "  An: $NOTIFICATION_EMAIL"

    # --- SENDMAIL-ALTERNATIVE KONFIGURIEREN ---
    log_info "  -> Konfiguriere msmtp als sendmail-Alternative..."
    
    if ! run_with_spinner "Konfiguriere sendmail-Alternative..." \
        "update-alternatives --install /usr/sbin/sendmail sendmail /usr/bin/msmtp 25"; then
        log_error "update-alternatives fehlgeschlagen!"
        log_error "Ist msmtp korrekt installiert? Prüfe: which msmtp"
        return 1
    fi
    
    if ! update-alternatives --set sendmail /usr/bin/msmtp; then
        log_error "Setzen der sendmail-Alternative fehlgeschlagen!"
        return 1
    fi
    
    log_ok "msmtp als systemweite sendmail-Alternative konfiguriert."

    # --- SMTP-EINSTELLUNGEN AUSWERTEN ---
    local auth_setting="on"
    if [ "${SMTP_AUTH:-ja}" = "nein" ]; then
        auth_setting="off"
        log_info "  -> SMTP-Authentifizierung ist deaktiviert."
    else
        log_info "  -> SMTP-Authentifizierung ist aktiviert."
        
        # Validiere Auth-Credentials
        if [ -z "${SMTP_USER:-}" ] || [ -z "${SMTP_PASSWORD:-}" ]; then
            log_error "SMTP_AUTH=ja aber SMTP_USER oder SMTP_PASSWORD fehlen!"
            log_error "Setze beide Variablen oder deaktiviere Auth mit SMTP_AUTH=nein."
            return 1
        fi
    fi

    local starttls_setting="off"
    if [ "${SMTP_TLS_STARTTLS:-nein}" = "ja" ]; then
        starttls_setting="on"
        log_info "  -> STARTTLS ist aktiviert."
    else
        log_info "  -> STARTTLS ist deaktiviert (direkter TLS-Modus)."
    fi

    # --- MSMTP-KONFIGURATIONSDATEI ERSTELLEN ---
    log_info "  -> Schreibe sichere msmtp-Konfiguration nach /etc/msmtprc..."
    backup_and_register "/etc/msmtprc"

    cat > /etc/msmtprc <<EOF
# msmtp-Konfiguration für systemweiten E-Mail-Versand
# Generiert von Server-Baukasten v$SCRIPT_VERSION am $(date)
# WICHTIG: Diese Datei enthält Passwörter - Rechte sind auf 600 gesetzt!

defaults
auth           $auth_setting
tls            on
tls_starttls   $starttls_setting
tls_trust_file /etc/ssl/certs/ca-certificates.crt
syslog         on
timeout        30

account        default
host           $SMTP_HOST
port           ${SMTP_PORT:-25}
from           $SMTP_FROM
EOF

    # SMTP-Credentials nur bei aktivierter Authentifizierung hinzufügen
    if [ "$auth_setting" = "on" ]; then
        cat >> /etc/msmtprc <<EOF

# SMTP-Authentifizierung
user           $SMTP_USER
password       $SMTP_PASSWORD
EOF
        log_info "     - SMTP-Benutzername und Passwort konfiguriert."
    fi

    # --- SICHERE DATEIBERECHTIGUNGEN SETZEN ---
    chmod 600 /etc/msmtprc           # NUR ROOT KANN LESEN/SCHREIBEN
    chown root:root /etc/msmtprc
    log_ok "Sichere Dateiberechtigungen für /etc/msmtprc gesetzt (600 - nur root)."

    # Warnhinweis für Sicherheit
    log_info "  🔒 SICHERHEIT: /etc/msmtprc enthält SMTP-Passwort und ist nur für root lesbar."

    # --- JOURNALD FÜR E-MAIL-LOGGING OPTIMIEREN ---
    log_info "  -> Optimiere journald für E-Mail-Logs..."
    mkdir -p /etc/systemd/journald.conf.d
    
    cat > /etc/systemd/journald.conf.d/99-mail-logging.conf <<EOF
# Optimierte journald-Konfiguration für E-Mail-Logging
# Generiert von Server-Baukasten v$SCRIPT_VERSION

[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=200M
MaxRetentionSec=4week
SyncIntervalSec=60s

# E-Mail-spezifische Einstellungen
RateLimitInterval=30s
RateLimitBurst=10000
EOF

    run_with_spinner "Lade journald-Konfiguration neu..." "systemctl restart systemd-journald"
    log_ok "Journald für E-Mail-Logging optimiert."

    # --- E-MAIL-VERSAND TESTEN ---
    log_info "  -> Teste E-Mail-Versand mit msmtp..."
    log_info "     Sende Test-E-Mail an: $NOTIFICATION_EMAIL"

    # Test-E-Mail mit detaillierter Fehlerbehandlung
    local test_message="Test-E-Mail vom Server-Baukasten

Server: $(hostname -f 2>/dev/null || hostname)
Zeitpunkt: $(date)
Script-Version: $SCRIPT_VERSION

Diese E-Mail bestätigt, dass der systemweite E-Mail-Versand korrekt konfiguriert ist.

--- 
Server-Baukasten E-Mail-Test
"

    if echo "$test_message" | msmtp --debug --from="$SMTP_FROM" "$NOTIFICATION_EMAIL" 2>&1; then
        log_ok "Test-E-Mail erfolgreich an $NOTIFICATION_EMAIL gesendet."
        log_info "  📬 Prüfe dein E-Mail-Postfach auf die Test-Nachricht!"
    else
        local exit_code=$?
        log_warn "Test-E-Mail konnte nicht gesendet werden (Exit-Code: $exit_code)."
        log_info "  -> Häufige Ursachen:"
        log_info "     • Falsche SMTP-Credentials (User/Passwort)"
        log_info "     • Firewall blockiert Port ${SMTP_PORT:-25}"
        log_info "     • Provider-Einschränkungen (z.B. Port 25 gesperrt)"
        log_info "     • TLS/STARTTLS-Konfiguration passt nicht zum Server"
        log_info "  -> Manueller Test: echo 'Test' | msmtp --debug --from='$SMTP_FROM' '$NOTIFICATION_EMAIL'"
        log_info "  -> Logs prüfen: journalctl | grep msmtp"
        
        # NICHT abbrechen - Mail ist optional für das System-Setup
        log_warn "Mail-Setup abgeschlossen, aber Test fehlgeschlagen. System läuft trotzdem sicher!"
        log_info "  💡 Du kannst die Konfiguration später mit obigem Test-Befehl prüfen."
        return 0
    fi

    # --- ERFOLGS-ZUSAMMENFASSUNG ---
    log_ok "Systemweiter E-Mail-Versand via msmtp erfolgreich eingerichtet."
    log_info "--- E-MAIL-KONFIGURATION ---"
    log_info "  📧 SMTP-Server: $SMTP_HOST:${SMTP_PORT:-25}"
    log_info "  🔐 Authentifizierung: $auth_setting"
    log_info "  🔒 STARTTLS: $starttls_setting"
    log_info "  📤 Absender: $SMTP_FROM"
    log_info "  📥 Benachrichtigungen: $NOTIFICATION_EMAIL"
    log_info "--- MANAGEMENT-BEFEHLE ---"
    log_info "  E-Mail-Logs: journalctl | grep msmtp"
    log_info "  Test-Versand: echo 'Test' | msmtp --from='$SMTP_FROM' '$NOTIFICATION_EMAIL'"
    log_info "  Konfiguration: cat /etc/msmtprc (nur als root)"
    
    return 0
}

################################################################################
# ENDE MODUL E-MAIL-SETUP v2.1
################################################################################