#!/bin/bash
################################################################################
# MODUL: KERNEL-HÄRTUNG (sysctl & Dienste)
#
# Zweck:
# - Sichere Kernel-/Netzwerk-Defaults via sysctl.d Drop-in
# - Idempotent schreiben; nur anwenden, wenn geändert
# - Optional unnötige Desktop-/Notebook-Dienste deaktivieren/maskieren
# - Minimal-Verification & Warnungen bei unbekannten sysctl-Keys
#
# Abhängigkeiten (Helfer):
# - log_info/log_warn/log_error/log_ok/log_debug, run_with_spinner, backup_and_register
################################################################################

module_kernel_hardening() {
    log_info "🧠 MODUL: Kernel-Härtung (sysctl & Dienste)"

    # ------------------------------------------------------------------
    # Guardrails
    # ------------------------------------------------------------------
    if [ "$(id -u)" -ne 0 ]; then
        log_error "root-Rechte erforderlich."; return 1; fi
    command -v sysctl >/dev/null 2>&1 || { log_error "sysctl fehlt"; return 1; }

    # Optionale Schalter (ENV)
    : "${HARDEN_MASK_SERVICES:=nein}"   # ja → mask zusätzlich zu disable

    # ------------------------------------------------------------------
    # Helper: idempotent writer
    # usage: _write_if_changed <mode> <path> <outvar>; stdin=content; sets outvar=0/1
    _write_if_changed() {
        local mode="$1" path="$2" outvar="$3" tmp
        tmp="$(mktemp)"; cat >"$tmp"
        if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
            rm -f "$tmp"; printf -v "$outvar" 0
        else
            install -D -o root -g root -m "$mode" "$tmp" "$path"; rm -f "$tmp"; printf -v "$outvar" 1
        fi
    }

    # ------------------------------------------------------------------
    # Sysctl: schreiben (nur wenn geändert)
    # ------------------------------------------------------------------
    backup_and_register "/etc/sysctl.d/99-baukasten-hardening.conf"
    local changed_sysctl=0
    _write_if_changed 644 /etc/sysctl.d/99-baukasten-hardening.conf changed_sysctl <<'EOF'
# =====================================================================
# Kernel-Härtung (sysctl) – Server-Baukasten v5.3.x
# Mischung aus Best Practices & Lynis-Empfehlungen (KRNL-6000)
# =====================================================================

# --- Netzwerk / IPv4 ---
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.secure_redirects=0
# Optionale Robustheit gegen TIME-WAIT-Attacken
net.ipv4.tcp_rfc1337=1

# --- Netzwerk / IPv6 ---
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0

# --- Forwarding (für Docker/VPN)
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1

# --- Kernel-Härtung ---
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
# Zusätzliche Hardening-Optionen
kernel.randomize_va_space=2
kernel.yama.ptrace_scope=1
# verhindert kexec-basierte Reboots (optional Sicherheitsgewinn)
kernel.kexec_load_disabled=1

# --- FS-Schutz ---
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
# (falls verfügbar) reguläre Dateien strikter schützen
fs.protected_regular=2

# --- Speicher/IO/Netz-Performance (VPS-tauglich, konservativ) ---
vm.swappiness=10
vm.dirty_background_ratio=5
vm.dirty_ratio=15

net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.somaxconn=4096
net.core.netdev_max_backlog=16384

net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=1800
net.ipv4.tcp_max_syn_backlog=8192

# conntrack (nur wenn Netfilter aktiv; sonst ignoriert sysctl das)
net.netfilter.nf_conntrack_max=524288
EOF

    if [ "$changed_sysctl" -eq 1 ]; then
        run_with_spinner "Wende Kernel-Parameter an…" "sysctl --system 2>&1 | tee /run/baukasten-sysctl.log >/dev/null"
        if grep -qiE 'not found|No such file' /run/baukasten-sysctl.log; then
            log_warn "Einige sysctl-Keys wurden nicht gefunden (Kernel-Modul fehlt oder alt)."
        fi
    else
        log_info "sysctl-Konfiguration unverändert; kein Reload nötig."
    fi

    # ------------------------------------------------------------------
    # Verifikation (kritische Parameter)
    # ------------------------------------------------------------------
    local v4f v6f
    v4f="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
    v6f="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 0)"
    if [ "$v4f" = "1" ] && [ "$v6f" = "1" ]; then
        log_ok "IP-Forwarding (IPv4/IPv6) aktiv."
    else
        log_warn "IP-Forwarding nicht voll aktiv (v4=$v4f, v6=$v6f). Prüfe VPN/Docker-Bedarf."
    fi

    # ------------------------------------------------------------------
    # Dienste: deaktivieren/maskieren (nur falls vorhanden)
    # ------------------------------------------------------------------
    log_info "  -> Deaktiviere unnötige Desktop/Notebook-Dienste (falls vorhanden)…"
    local services_to_disable=(bluetooth cups avahi-daemon ModemManager wpa_supplicant)
    for svc in "${services_to_disable[@]}"; do
        if systemctl list-unit-files -t service --no-legend | awk '{print $1}' | grep -qx "${svc}.service"; then
            run_with_spinner "Disable ${svc}" "systemctl disable --now ${svc}.service >/dev/null 2>&1 || true"
            if [ "${HARDEN_MASK_SERVICES}" = "ja" ]; then
                systemctl mask ${svc}.service >/dev/null 2>&1 || true
                log_info "  -> ${svc} zusätzlich maskiert."
            fi
        else
            log_debug "Dienst '${svc}.service' nicht installiert – übersprungen."
        fi
    done

    log_ok "Kernel-Härtung abgeschlossen."
}
