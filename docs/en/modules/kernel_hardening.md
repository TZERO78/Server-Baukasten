# README – Module: `kernel_hardening` (sysctl & Services)

## Purpose
Hardens kernel and network defaults via `/etc/sysctl.d/` and disables unnecessary desktop/notebook services. Idempotent: only writes on changes and then loads `sysctl --system`. Optional masking of services.

## Prerequisites
- **Root privileges**
- **Packages:** `procps` (for `sysctl`)
- **Baukasten functions:** `log_*`, `run_with_spinner`, `backup_and_register`

## Behavior
- Writes **one** file: `/etc/sysctl.d/99-baukasten-hardening.conf`
- Only reloads on changes (`sysctl --system`) and logs to `/run/baukasten-sysctl.log`
- Verifies `ip_forward` (v4/v6) and warns on deviations
- Disables (and optionally masks) unneeded services: `bluetooth`, `cups`, `avahi-daemon`, `ModemManager`, `wpa_supplicant`

## Configuration Variables (ENV)
| Variable | Required | Example | Effect |
|---|---|---|---|
| `HARDEN_MASK_SERVICES` | No | `ja`/`nein` | In addition to `disable`, applies `mask` to the above services. Default: `nein` |

## Important sysctl Settings (Excerpt)
**IPv4**
- `net.ipv4.conf.*.rp_filter=1` – Source validation (use `2` for asymmetric routing if needed)
- `accept_redirects=0`, `secure_redirects=0`, `send_redirects=0`
- `accept_source_route=0` (all/default)
- `log_martians=1` (all & default)
- `tcp_syncookies=1`, `tcp_rfc1337=1`

**IPv6**
- `accept_redirects=0` (all/default)
- `accept_ra=0` (all/default)
- `accept_source_route=0` (all/default)
- **Forwarding:** `net.ipv6.conf.all.forwarding=1` (intentionally enabled for Docker/VPN)

**Kernel Hardening**
- `dev.tty.ldisc_autoload=0`
- `kernel.dmesg_restrict=1`, `kernel.kptr_restrict=2`, `kernel.sysrq=0`
- `kernel.unprivileged_bpf_disabled=1`, `net.core.bpf_jit_harden=2`
- `kernel.core_uses_pid=1`, `kernel.randomize_va_space=2`, `kernel.yama.ptrace_scope=1`
- Optional: `kernel.kexec_load_disabled=1` (no kexec reboot)
- **Not set:** `kernel.modules_disabled` (would globally prohibit module loading – usually impractical on VPS)

**FS Protection**
- `fs.protected_fifos=2`, `fs.protected_hardlinks=1`, `fs.protected_symlinks=1`, `fs.protected_regular=2`

**Performance (conservative, VPS-compatible)**
- `vm.swappiness=10`, `vm.dirty_background_ratio=5`, `vm.dirty_ratio=15`
- `net.core.rmem_max/wmem_max=16777216`, `somaxconn=4096`, `netdev_max_backlog=16384`
- `tcp_fin_timeout=30`, `tcp_keepalive_time=1800`, `tcp_max_syn_backlog=8192`
- `net.netfilter.nf_conntrack_max=524288` (if Netfilter is active)

## Files & Changes
- `/etc/sysctl.d/99-baukasten-hardening.conf` – central hardening parameters (644, `root:root`)

## Verification
```bash
# File found?
grep -n "baukasten-hardening" /etc/sysctl.d/*.conf

# Critical switches
sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.forwarding \
         kernel.core_uses_pid dev.tty.ldisc_autoload \
         fs.protected_fifos

# Last apply (log)
[ -f /run/baukasten-sysctl.log ] && tail -n +1 /run/baukasten-sysctl.log | sed -n '1,120p'
```

## Troubleshooting
- **Lynis deviations:**
  - `net.ipv4.conf.all.forwarding`: Lynis expects `0`. **Intentionally 1** for Docker/VPN. Alternatively, enable interface-specifically.
  - `kernel.modules_disabled`: not set – usually not practical in production.
- **Asymmetric routing:** `rp_filter=1` may drop packets → switch to `2`.
- **IPv6 RA/SLAAC required:** Set `accept_ra=1` interface-specifically or enable autoconfig.
- **Missing keys in log:** Non-critical (kernel/modules may not be present).

## Security
- Changes apply system-wide. Test before production use (VPN, overlay, Kubernetes, container runtime).
- `sysrq=0` is common on headless servers.

## Removal / Rollback
```bash
sudo rm -f /etc/sysctl.d/99-baukasten-hardening.conf
sudo sysctl --system

# Optionally unmask services
for s in bluetooth cups avahi-daemon ModemManager wpa_supplicant; do
  systemctl unmask "$s" 2>/dev/null || true
  systemctl enable --now "$s" 2>/dev/null || true
done
```

## Notes
- Module is **idempotent**: rerunning changes nothing if the content remains the same.
- Parameterization (e.g., `rp_filter` mode) can be added as needed. Open an issue/PR with your policy.
