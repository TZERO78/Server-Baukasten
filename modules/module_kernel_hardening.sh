#!/bin/bash
################################################################################
#
# MODUL: KERNEL-HÄRTUNG
#
# @description: Konfiguriert die Kernel-Sicherheitsparameter (sysctl)
#               und optimiert Dienste für VPS.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

module_kernel_hardening() {
    log_info "🧠 MODUL: Kernel-Härtung (sysctl)"
    
    backup_and_register "/etc/sysctl.conf"
    
    log_info "  -> Schreibe Konfiguration für Basis-Sicherheitsparameter..."
    cat > /etc/sysctl.d/99-baukasten-hardening.conf << 'EOF'
# Basis Kernel-Härtung
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.log_martians=1
net.ipv6.conf.default.use_tempaddr=2
# Explizites Aktivieren von IP-Forwarding für IPv4 und IPv6.
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
 
    log_info "  -> Schreibe Konfiguration für erweiterten DDoS-Schutz & VPS-Optimierung..."
    cat > /etc/sysctl.d/98-baukasten-advanced-hardening.conf << 'EOF'
# Erweiterte Kernel-Parameter für DDoS-Schutz & Stabilität
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=1800
net.ipv4.tcp_max_syn_backlog=8192
net.netfilter.nf_conntrack_max=524288
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
vm.swappiness=10
vm.dirty_ratio=15
net.core.rmem_max=16777216
net.core.wmem_max=16777216
EOF

    run_with_spinner "Wende neue Kernel-Parameter an..." "sysctl --system"
    
    log_info "  -> Verifiziere kritische Kernel-Parameter..."
    if [[ $(sysctl -n net.ipv4.ip_forward) -eq 1 ]] && [[ $(sysctl -n net.ipv6.conf.all.forwarding) -eq 1 ]]; then
        log_ok "IP-Forwarding für IPv4 und IPv6 ist erfolgreich aktiviert."
    else
        log_error "IP-Forwarding konnte nicht aktiviert werden! NAT für Docker/VPN wird nicht funktionieren."
        # return 1 # Optional: Harter Abbruch, wenn Forwarding kritisch ist
    fi

    log_info "  -> Deaktiviere unnötige Dienste (VPS-optimiert)..."
    local services_to_disable=("bluetooth" "cups" "avahi-daemon" "ModemManager" "wpa_supplicant")
    for service in "${services_to_disable[@]}"; do
        if systemctl list-units --full -all | grep -q "$service.service"; then
            run_with_spinner "Deaktiviere Dienst '$service'..." "systemctl disable --now '$service'"
        else
            log_debug "Dienst '$service' nicht gefunden, wird übersprungen."
        fi
    done
    
    log_ok "Modul Kernel-Härtung erfolgreich abgeschlossen."
}