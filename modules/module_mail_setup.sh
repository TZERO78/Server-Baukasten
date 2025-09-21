#!/bin/bash
################################################################################
# MODUL: E-MAIL-SETUP – msmtp (idempotent + Validation + optional Rollback)
#
# Zweck:
# - msmtp als systemweite sendmail-Alternative
# - Sichere Konfig (600), optional Passwort getrennt per passwordeval
# - Journald-Logging optimiert
# - Testmail optional
#
# Abhängigkeiten (extern bereitgestellt):
# - Helfer: log_info/log_warn/log_error/log_ok, run_with_spinner, backup_and_register, rollback (optional)
# - Pakete: msmtp, ca-certificates
################################################################################
#
# Dieses Modul nimmt nur Änderungen vor, wenn Inhalte sich geändert haben.
# Mehrfachaufrufe sind dadurch unkritisch.
################################################################################

# -------------------------- Hilfsfunktionen -----------------------------------
# usage: _write_if_changed <mode> <path> <outvar>; stdin=content; sets outvar=0/1
_write_if_changed() {
    local mode="$1" path="$2" outvar="$3" tmp
    tmp="$(mktemp)"
    cat >"$tmp"
    if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
        rm -f "$tmp"
        printf -v "$outvar" 0
    else
        install -D -o root -g root -m "$mode" "$tmp" "$path"
        rm -f "$tmp"
        printf -v "$outvar" 1
    fi
}

_validate_smtp_config() {
    log_info "  -> Validiere SMTP-Konfiguration…"
    if ! command -v msmtp >/dev/null 2>&1; then
        log_error "msmtp ist nicht installiert! Bitte erst Basis-/Service-Install ausführen."
        return 1
    fi
    command -v update-alternatives >/dev/null 2>&1 || {
        log_error "update-alternatives nicht verfügbar!"
        return 1
    }

    if [ -z "${SMTP_HOST:-}" ]; then log_error "SMTP_HOST fehlt."; return 1; fi
    if [ -z "${SMTP_FROM:-}" ]; then log_error "SMTP_FROM fehlt."; return 1; fi
    if [ -z "${NOTIFICATION_EMAIL:-}" ]; then log_error "NOTIFICATION_EMAIL fehlt."; return 1; fi

    # Auth prüfen
    NEED_AUTH="on"
    if [ "${SMTP_AUTH:-ja}" = "nein" ]; then
        NEED_AUTH="off"
        if [ -n "${SMTP_USER:-}" ] || [ -n "${SMTP_PASSWORD:-}" ]; then
            log_warn "SMTP_AUTH=nein, aber USER/PASSWORD gesetzt – werden ignoriert."
        fi
    else
        if [ -z "${SMTP_USER:-}" ] || [ -z "${SMTP_PASSWORD:-}" ]; then
            log_error "SMTP_AUTH=ja, aber SMTP_USER/SMTP_PASSWORD fehlen."
            return 1
        fi
    fi

    STARTTLS_SETTING="off"
    [ "${SMTP_TLS_STARTTLS:-nein}" = "ja" ] && STARTTLS_SETTING="on"

    log_ok "SMTP-Konfiguration validiert."
    log_info "  Host: ${SMTP_HOST}:${SMTP_PORT:-25}"
    log_info "  From: ${SMTP_FROM}"
    log_info "  To:   ${NOTIFICATION_EMAIL}"
    [ "$NEED_AUTH" = "on" ] && log_info "  Auth: aktiv" || log_info "  Auth: aus"
}

module_mail_setup() {
    # Früher Exit, wenn deaktiviert
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" != "ja" ]; then
        log_info "📧 Systemweite E-Mail-Benachrichtigungen sind deaktiviert (übersprungen)."
        return 0
    fi

    log_info "📧 MODUL: Systemweiter E-Mail-Versand (msmtp)"

    # Optionaler Rollback bei Fehlern, falls Helper vorhanden
    if type -t rollback >/dev/null 2>&1; then
        trap 'log_warn "Fehler im mail_setup – führe Rollback aus"; rollback || true; trap - ERR' ERR
    fi

    # Validierung (setzt NEED_AUTH/STARTTLS_SETTING)
    if ! _validate_smtp_config; then
        log_error "Validierung fehlgeschlagen."
        return 1
    fi

    umask 077

    # Passwortdatei (optional)
    local pass_line="" changed_pass=0
    if [ "$NEED_AUTH" = "on" ]; then
        backup_and_register "/etc/msmtp.pass"
        printf '%s\n' "${SMTP_PASSWORD}" | _write_if_changed 600 /etc/msmtp.pass changed_pass
        # Rechte/Owner nur setzen, wenn geändert ODER falsch
        if [ "$changed_pass" -eq 1 ] || [ "$(stat -c '%a %U:%G' /etc/msmtp.pass 2>/dev/null)" != "600 root:root" ]; then
            chmod 600 /etc/msmtp.pass && chown root:root /etc/msmtp.pass
        fi
        pass_line='passwordeval     "cat /etc/msmtp.pass"'
        [ "$changed_pass" -eq 1 ] && log_info "  -> Passwortdatei aktualisiert (/etc/msmtp.pass)."
    fi

    # user-Zeile vorbereiten (nur bei Auth)
    local need_auth_user_line=""
    [ "$NEED_AUTH" = "on" ] && need_auth_user_line="user           ${SMTP_USER}"

    # /etc/msmtprc
    backup_and_register "/etc/msmtprc"
    local changed_msmtprc=0
    _write_if_changed 600 /etc/msmtprc changed_msmtprc <<EOF
# msmtp – systemweite Konfiguration
# Generiert von Server-Baukasten ${SCRIPT_VERSION:-}
# ACHTUNG: Enthält Zugangsdaten; Rechte 600!

defaults
auth           ${NEED_AUTH}
tls            on
tls_starttls   ${STARTTLS_SETTING}
tls_trust_file /etc/ssl/certs/ca-certificates.crt
syslog         on
timeout        30

account        default
host           ${SMTP_HOST}
port           ${SMTP_PORT:-25}
from           ${SMTP_FROM}
${need_auth_user_line}
${pass_line}
EOF
    if [ "$changed_msmtprc" -eq 1 ]; then
        log_ok "  -> /etc/msmtprc aktualisiert."
    else
        log_info "  -> /etc/msmtprc unverändert."
    fi

    # journald-Logging optimieren
    backup_and_register "/etc/systemd/journald.conf.d/99-mail-logging.conf"
    local changed_journal=0
    _write_if_changed 644 /etc/systemd/journald.conf.d/99-mail-logging.conf changed_journal <<'EOF'
# Journald-Optimierung für Mail-Logs
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=200M
MaxRetentionSec=4week
SyncIntervalSec=60s
RateLimitInterval=30s
RateLimitBurst=10000
EOF
    if [ "$changed_journal" -eq 1 ]; then
        systemctl restart systemd-journald
        log_ok "  -> journald neu geladen (Mail-Logging)."
    else
        log_info "  -> journald-Konfiguration unverändert."
    fi

    # sendmail-Alternative idempotent
    if ! update-alternatives --query sendmail >/dev/null 2>&1; then
        run_with_spinner "Registriere sendmail-Alternative (msmtp)..." \
            "update-alternatives --install /usr/sbin/sendmail sendmail /usr/bin/msmtp 25"
    fi

    local current_alt
    current_alt="$(update-alternatives --query sendmail 2>/dev/null | awk -F': ' '/^Value: /{print $2}')"
    if [ "$current_alt" != "/usr/bin/msmtp" ]; then
        if update-alternatives --set sendmail /usr/bin/msmtp; then
            log_ok "  -> msmtp als sendmail gesetzt."
        else
            log_error "Konnte sendmail-Alternative nicht setzen."
            return 1
        fi
    else
        log_info "  -> sendmail zeigt bereits auf msmtp."
    fi

    # Test-Mail (optional)
    if [ "${MAIL_SETUP_SEND_TEST:-ja}" = "ja" ]; then
        # Vorab: Erreichbarkeit des SMTP-Servers TLS-sensitiv prüfen
        local extra_tls=""
        if [ "${SMTP_TLS_STARTTLS:-nein}" = "ja" ]; then
            extra_tls="--tls-starttls"
        elif [ "${SMTP_PORT:-25}" = "465" ]; then
            extra_tls="--tls"
        fi
        if ! timeout 10 msmtp --serverinfo --host="${SMTP_HOST}" --port="${SMTP_PORT:-25}" ${extra_tls} >/dev/null 2>&1; then
            log_warn "  -> SMTP-Server nicht erreichbar, überspringe Test-Mail."
        else
            log_info "  -> Sende Test-E-Mail an: ${NOTIFICATION_EMAIL}"
            local test_message="Test-E-Mail vom Server-Baukasten

Server: $(hostname -f 2>/dev/null || hostname)
Zeitpunkt: $(date)
Script-Version: ${SCRIPT_VERSION:-}

Diese E-Mail bestätigt den systemweiten E-Mail-Versand via msmtp."
            if echo "$test_message" | msmtp --debug --from="${SMTP_FROM}" "${NOTIFICATION_EMAIL}" 2>&1; then
                log_ok "  -> Test-E-Mail erfolgreich gesendet."
            else
                local ec=$?
                log_warn "  -> Test-E-Mail fehlgeschlagen (Exit-Code: $ec). System bleibt funktionsfähig."
                log_info "     Häufige Ursachen: falsche Credentials, Port-Block, TLS/STARTTLS unpassend."
                log_info "     Manuell testen: echo 'Test' | msmtp --debug --from='${SMTP_FROM}' '${NOTIFICATION_EMAIL}'"
            fi
        fi
    else
        log_info "  -> Test-E-Mail übersprungen (MAIL_SETUP_SEND_TEST!=ja)."
    fi

    # Trap aufräumen
    trap - ERR 2>/dev/null || true

    # Abschluss
    log_ok "Systemweiter E-Mail-Versand via msmtp ist eingerichtet."
    log_info "  sendmail  : $(update-alternatives --query sendmail 2>/dev/null | awk -F': ' '/^Value: /{print $2}')"
    # sauberes Abschluss-Log ohne hängendes Komma
    local _cfg="/etc/msmtprc (600)"
    [ "$NEED_AUTH" = "on" ] && _cfg="$_cfg, /etc/msmtp.pass (600)"
    log_info "  Konfig    : ${_cfg}, Journald-Logging aktiv"
    return 0
}
