#!/bin/bash
################################################################################
#
# MODUL: SYSTEMBEREINIGUNG
#
# @description: Bereinigt alle vom Baukasten installierten Komponenten,
#               um einen definierten Ausgangszustand herzustellen.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

##
# MODUL 0: Versetzt den Server in einen ZUSTAND NAHE DER NEUINSTALLATION.
#           Entfernt alle Konfigurationen, Pakete, Benutzer und Systemzustände.
# Hinweis: Diese Funktion muss mit "trap '' ERR; set +e" am Anfang und
#           "set -e; trap 'rollback' ERR" am Ende abgesichert werden,
#           da sie absichtlich Befehle ausführt, die möglicherweise fehlschlagen.
##
module_cleanup() {
    log_info "MODUL 0: Führe LÜCKENLOSE Systembereinigung durch..."
    trap '' ERR; set +e

    # --- 1. Systemzustand sofort zurücksetzen (Firewall, Docker) ---
    log_info "  -> 1/7: Setze aktive Systemzustände zurück..."
    if command -v nft &>/dev/null; then nft flush ruleset; fi
    if command -v docker &>/dev/null; then
        # Vollständige Docker-Bereinigung
        docker stop $(docker ps -aq) >/dev/null 2>&1 || true
        docker rm $(docker ps -aq) >/dev/null 2>&1 || true
        systemctl stop docker docker.socket containerd >/dev/null 2>&1 || true
        systemctl disable docker docker.socket containerd >/dev/null 2>&1 || true
    fi
    log_ok "Aktive Firewall-Regeln und Docker-Objekte entfernt."

    # --- 2. Alle relevanten systemd-Units stoppen & deaktivieren ---
    log_info "  -> 2/7: Stoppe und deaktiviere alle Baukasten-Timer und -Services..."
    local units_to_remove=(
        "aide-check.timer" "aide-check.service" "dailyaidecheck.timer" "dailyaidecheck.service"
        "rkhunter-check.timer" "rkhunter-check.service" "geoip-update.timer" "geoip-update.service"
        "system-backup.timer" "system-backup.service" "unattended-upgrades-run.timer" "unattended-upgrades-run.service"
        "crowdsec-healthcheck.timer" "crowdsec-healthcheck.service" "mail-failure@.service" "tailscaled.service"
    )
    systemctl stop "${units_to_remove[@]}" >/dev/null 2>&1
    systemctl disable "${units_to_remove[@]}" >/dev/null 2>&1
    log_ok "Alle systemd-Units gestoppt und deaktiviert."
    
    # --- 3. Pakete deinstallieren (ALLES entfernen - unabhängig von Zielkonfiguration) ---
    log_info "  -> 3/7: Deinstalliere alle vom Baukasten installierten Pakete..."
    local packages_to_purge=(
        "aide" "rkhunter" "crowdsec" "crowdsec-firewall-bouncer-nftables" "msmtp" "msmtp-mta"
        "mailutils" "geoip-bin" "geoip-database" "ipset" "docker-ce" "docker-ce-cli"
        "containerd.io" "docker-buildx-plugin" "docker-compose-plugin" "docker-ce-rootless-extras"
        "tailscale"
    )
    apt-get purge -y "${packages_to_purge[@]}" >/dev/null 2>&1
    apt-get autoremove -y --purge >/dev/null 2>&1
    apt-get autoclean >/dev/null 2>&1
    log_ok "Alle Kernpakete deinstalliert."

    # --- 4. Alle Konfigurations-, Daten- & Skript-Dateien entfernen ---
    log_info "  -> 4/7: Entferne alle Konfigurationen, Skripte und Daten..."
    # APT-Quellen
    rm -f /etc/apt/sources.list.d/{docker,tailscale,crowdsec_crowdsec}.list
    rm -f /etc/apt/keyrings/{docker,tailscale-archive-keyring}.gpg
    # Docker-spezifische Bereinigung
    rm -rf /var/lib/docker /var/lib/containerd /etc/docker ~/.docker
    ip link delete docker0 >/dev/null 2>&1 || true
    # Sonstige Konfig & Daten
    rm -rf /etc/aide/ /var/lib/aide/
    rm -rf /etc/rkhunter.conf.d/ /etc/rkhunter.conf /var/lib/rkhunter/
    rm -rf /etc/crowdsec/ /var/lib/crowdsec/
    rm -rf /etc/nftables.d/ /etc/nftables.conf
    # systemd Unit-Dateien und Journald-Konfigs
    rm -f /etc/systemd/system/{aide-check,rkhunter-check,geoip-update,system-backup,unattended-upgrades-run,crowdsec-healthcheck,dailyaidecheck}.*
    rm -f /etc/systemd/system/mail-failure@.service
    rm -rf /etc/systemd/system/*.d/
    rm -f /etc/systemd/journald.conf.d/*
    # Sonstige Skripte und Konfigs
    rm -f /etc/geoip-*.conf /usr/local/bin/{geoip-manager,update-geoip-sets,system-backup}
    rm -f /etc/msmtprc*
    rm -f /etc/sysctl.d/99-baukasten-hardening.conf
    systemctl daemon-reload
    log_ok "Alle Konfigurationen, Skripte und Daten entfernt."

    # --- 5. Swap-Datei entfernen ---
    log_info "  -> 5/7: Entferne Swap-Datei..."
    swapoff /swapfile >/dev/null 2>&1
    rm -f /swapfile
    sed -i '\|/swapfile|d' /etc/fstab
    log_ok "Swap-Datei und fstab-Eintrag entfernt."

    # --- 6. sudo-Reste bereinigen ---
    log_info "  -> 6/7: Bereinige temporäre sudo-Einträge systemweit..."
    cleanup_all_temporary_sudo_entries

    # --- 7. Journal bereinigen ---
    log_info "  -> 7/7: Rotiere Journal-Logs für einen sauberen Start..."
    journalctl --rotate >/dev/null 2>&1
    systemctl restart systemd-journald
    log_ok "Journal-Logs wurden rotiert."

    set -e; trap 'rollback' ERR
    log_ok "Lückenlose Systembereinigung vollständig abgeschlossen."
}
