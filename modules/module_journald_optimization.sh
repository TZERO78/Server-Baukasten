#!/bin/bash
################################################################################
#
# MODUL: JOURNALD-OPTIMIERUNG
#
# @description: Optimiert die journald-Konfiguration für einen sparsamen
#               Betrieb auf Servern mit wenig Speicher.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

module_journald_optimization() {
    log_info "📜 MODUL: Zentrale Log-Verwaltung (journald)"
    
    log_info "  -> Schreibe optimierte journald-Konfigurationsdateien..."
    mkdir -p /etc/systemd/journald.conf.d
    
    backup_and_register "/etc/systemd/journald.conf"
    
    # Allgemeine Optimierungen
    cat > /etc/systemd/journald.conf.d/99-baukasten-optimization.conf <<EOF
# Optimierte journald-Konfiguration für Server-Baukasten
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=250M
RuntimeMaxUse=50M
MaxRetentionSec=3week
SystemMaxFileSize=25M
SyncIntervalSec=60s
ForwardToSyslog=no
ForwardToWall=no
RateLimitIntervalSec=60s
RateLimitBurst=10000
EOF
    
    # Längere Aufbewahrung für sicherheitskritische Logs
    cat > /etc/systemd/journald.conf.d/10-security-logging.conf <<EOF
# Längere Aufbewahrung für Security-Logs (SSH, CrowdSec, AIDE etc.)
[Journal]
MaxRetentionSec=12week
EOF
    
    run_with_spinner "Aktiviere neue journald-Konfiguration..." "systemctl restart systemd-journald"
    
    log_info "  -> Verifiziere journald-Status..."
    if systemctl is-active --quiet systemd-journald; then
        local journal_size
        journal_size=$(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[KMGT]B' || echo "Unbekannt")
        log_info "     - Aktuelle Journal-Größe: $journal_size"
        
        local boot_count
        boot_count=$(journalctl --list-boots --no-pager 2>/dev/null | wc -l || echo "Unbekannt")
        log_info "     - Verfügbare Boot-Logs: $boot_count"
        
        log_ok "journald erfolgreich optimiert und aktiv."
    else
        log_error "journald konnte nicht neu gestartet werden!"
        return 1
    fi
    
    log_info "--- Nützliche journalctl-Befehle ---"
    log_info "  Live-Logs: journalctl -f"
    log_info "  Baukasten-Logs: journalctl -t server-baukasten"
    log_info "  SSH-Logs: journalctl -u ssh"
    log_info "  Journal-Größe: journalctl --disk-usage"
    log_info "------------------------------------"
    
    log_ok "Zentrale Log-Verwaltung via journald erfolgreich konfiguriert."
}