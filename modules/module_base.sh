#!/bin/bash
################################################################################
#
# MODUL: BASIS-SYSTEM-SETUP
#
# @description: Grundlegende Systemkonfiguration (Hostname, Zeitzone, Locale,
#               Benutzer, Passwörter, Swap). KEINE Paket- oder Docker-Installs!
# @license:     MIT
#
################################################################################

set -Eeuo pipefail

##
# MODUL 2: Führt die grundlegende Systemkonfiguration durch.
##
module_base() {
    log_info "📦 MODUL: Basis-System-Setup"

    # --- Phase 1/5: System-Identität ------------------------------------------------
    log_info "  -> 1/5: Konfiguriere System-Identität..."
    log_debug "     Hostname alt: $(hostname -f 2>/dev/null || hostname)"

    # /etc/hosts vorbereiten (Backup nur einmal anlegen)
    if type -t backup_and_register >/dev/null 2>&1; then
        backup_and_register "/etc/hosts"
    fi

    hostnamectl set-hostname "$SERVER_HOSTNAME"
    if grep -qE '^127\.0\.1\.1' /etc/hosts; then
        sed -i -E "s|^127\.0\.1\.1.*|127.0.1.1       ${SERVER_HOSTNAME}|" /etc/hosts
    else
        echo "127.0.1.1       ${SERVER_HOSTNAME}" >> /etc/hosts
    fi
    log_ok "Hostname gesetzt auf: $SERVER_HOSTNAME"

    # Zeitzone
    timedatectl set-timezone "$TIMEZONE"
    log_ok "Zeitzone gesetzt auf: $TIMEZONE"

    # Locale
    log_debug "     Aktuelles LOCALE: ${LOCALE}"
    sed -i -E 's/^#\s*(de_DE\.UTF-8\s+UTF-8)/\1/' /etc/locale.gen
    sed -i -E 's/^#\s*(en_US\.UTF-8\s+UTF-8)/\1/' /etc/locale.gen
    run_with_spinner "Generiere Locales..." "locale-gen"
    update-locale LANG="$LOCALE"
    log_ok "System-Locale gesetzt auf: $LOCALE"

    # --- Phase 2/5: Benutzer-Management --------------------------------------------
    log_info "  -> 2/5: Konfiguriere Benutzer-Accounts..."
    echo "root:$ROOT_PASSWORD" | chpasswd
    log_ok "Root-Passwort aktualisiert."

    if ! id "$ADMIN_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$ADMIN_USER"
        log_ok "Admin-Benutzer '$ADMIN_USER' erstellt."
    else
        log_info "Admin-Benutzer '$ADMIN_USER' existiert bereits."
    fi

    echo "$ADMIN_USER:$ADMIN_PASSWORD" | chpasswd
    usermod -aG sudo "$ADMIN_USER"
    log_ok "Admin-Benutzer '$ADMIN_USER' konfiguriert und zur sudo-Gruppe hinzugefügt."

    # Temporäre, sichere NOPASSWD-Rechte für die Setup-Phase
    if ! grant_temporary_sudo_rights; then
        log_error "Konnte temporäre sudo-Rechte nicht gewähren!"
        exit 1
    fi
    log_warn "Temporäre NOPASSWD sudo-Rechte für '$ADMIN_USER' aktiviert (werden am Ende entfernt)."

    # --- Phase 3/5: (frei für spätere System-Feinheiten) ----------------------------
    # Platzhalter, falls du hier später noch Basiskonfig (ohne Paketinstall) ergänzen willst

    # --- Phase 4/5: Swap-Konfiguration ---------------------------------------------
    log_info "  -> 4/5: Konfiguriere Swap-Speicher..."
    if ! swapon --show | grep -q /swapfile; then
        run_with_spinner "Erstelle 2GB Swap-Datei..." \
            "fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile"
        if ! grep -qE '^\s*/swapfile\s' /etc/fstab; then
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi
        log_ok "Swap-Datei eingerichtet und in fstab eingetragen."
    else
        log_info "Swap-Datei existiert bereits – überspringe."
    fi

    # --- Phase 5/5: Abschluss -------------------------------------------------------
    log_ok "Modul Basis-System-Setup erfolgreich abgeschlossen."
}
