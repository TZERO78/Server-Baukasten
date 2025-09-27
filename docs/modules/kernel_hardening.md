# README – Modul: `kernel_hardening` (sysctl & Dienste)

## Zweck
Härtet den Kernel und die Netzwerk‑Defaults über `/etc/sysctl.d/` und schaltet unnötige Desktop/Notebook‑Dienste ab. Idempotent: schreibt nur bei Änderungen und lädt sysctl dann neu. Optionales Maskieren von Diensten.

## Voraussetzungen
- **Root‑Rechte**.
- **Pakete:** `procps` (für `sysctl` – auf Debian standardmäßig da).
- **Baukasten‑Funktionen:** `log_*`, `run_with_spinner`, `backup_and_register`.

## Verhalten
- Schreibt **eine** Drop‑in‑Datei: `/etc/sysctl.d/99-baukasten-hardening.conf`.
- Lädt die Parameter mit `sysctl --system`, **nur wenn** sich Inhalte geändert haben.
- Verifiziert anschließend u. a. `ip_forward` (IPv4/IPv6) und warnt bei Abweichung.
- Deaktiviert optionale Dienste (falls installiert): `bluetooth`, `cups`, `avahi-daemon`, `ModemManager`, `wpa_supplicant`.
- Optional: maskiert diese Dienste zusätzlich, wenn `HARDEN_MASK_SERVICES=ja`.

## Konfigurationsvariablen (ENV)
| Variable | Pflicht | Beispiel | Wirkung |
|---|---|---|---|
| `HARDEN_MASK_SERVICES` | Nein | `ja`/`nein` | Zusätzlich zu `disable` ein `mask` auf die genannten Dienste setzen. Default: `nein` |

## Inhalte (`sysctl`‑Parameter – Auszug)
**Netzwerk/IPv4**
- `rp_filter=1` (Source‑Validation), `tcp_syncookies=1`
- `accept_redirects=0`, `send_redirects=0`, `secure_redirects=0`
- `icmp_echo_ignore_broadcasts=1`, `icmp_ignore_bogus_error_responses=1`
- Logging: `log_martians=1`

**Netzwerk/IPv6**
- `accept_redirects=0`, `accept_ra=0`

**Forwarding (Server mit Docker/VPN):**
- `net.ipv4.ip_forward=1`, `net.ipv6.conf.all.forwarding=1`

**Kernel‑Hardening**
- `dmesg_restrict=1`, `kptr_restrict=2`, `sysrq=0`
- `unprivileged_bpf_disabled=1`, `net.core.bpf_jit_harden=2`
- `randomize_va_space=2`, `yama.ptrace_scope=1`, `kexec_load_disabled=1`

**FS‑Schutz**
- `fs.protected_fifos=2`, `fs.protected_hardlinks=1`, `fs.protected_symlinks=1`, `fs.protected_regular=2`

**Performance (vorsichtig konservativ)**
- `vm.swappiness=10`, `vm.dirty_background_ratio=5`, `vm.dirty_ratio=15`
- `net.core.{rmem_max,wmem_max}=16777216`, `somaxconn=4096`, `netdev_max_backlog=16384`
- `tcp_fin_timeout=30`, `tcp_keepalive_time=1800`, `tcp_max_syn_backlog=8192`
- `net.netfilter.nf_conntrack_max=524288` (falls Netfilter aktiv)

## Dateien & Änderungen
**Erstellt/Ändert**
- `/etc/sysctl.d/99-baukasten-hardening.conf` – zentrale Hardening‑Parameter (644, `root:root`).

**Dienste**
- `systemctl disable --now` auf die o. g. Services (nur wenn vorhanden).
- Optional: `systemctl mask` bei `HARDEN_MASK_SERVICES=ja`.

## Verifikation
```bash
# Welche Datei wird geladen?
grep -n "baukasten-hardening" /etc/sysctl.d/*.conf

# Kritische Schalter prüfen
sysctl -n net.ipv4.ip_forward
sysctl -n net.ipv6.conf.all.forwarding
sysctl -n kernel.unprivileged_bpf_disabled
sysctl -n kernel.kptr_restrict

# Letztes sysctl-Apply (Log, falls Modul es geschrieben hat)
[ -f /run/baukasten-sysctl.log ] && tail -n +1 /run/baukasten-sysctl.log | sed -n '1,120p'

# Dienste-Status
systemctl --no-pager --full status bluetooth.service 2>/dev/null | sed -n '1,5p'
```

## Troubleshooting
- **Asymmetrisches Routing / Policy‑Routing:** `rp_filter=1` kann legitime Pakete verwerfen. In solchen Setups lieber `rp_filter=2` (loose). Quick‑Override:
  ```bash
  printf '%s\n' 'net.ipv4.conf.all.rp_filter=2' 'net.ipv4.conf.default.rp_filter=2' \
    | sudo tee /etc/sysctl.d/50-routing-override.conf && sudo sysctl --system
  ```
- **IPv6 RA erwartet (Client‑Netz):** `accept_ra=0` schaltet Router Advertisements ab. Für Client‑Interfaces ggf. Interface‑spezifisch erlauben:
  ```bash
  echo 'net.ipv6.conf.eth0.accept_ra=1' | sudo tee /etc/sysctl.d/50-ipv6-ra.conf && sudo sysctl --system
  ```
- **`nf_conntrack_max` Warnungen:** Wenn Kernel/Module fehlen, wird der Key ignoriert. Unkritisch; Log prüfen.
- **Docker/VPN funktioniert nicht:** Prüfe, ob `ip_forward` Werte **1** liefern und Firewall/NAT korrekt gesetzt ist.

## Sicherheit
- Änderungen sind systemweit. Prüfe vor produktivem Einsatz, ob Netzwerk‑Policies (VPN, Overlay, Kubernetes) betroffen sind.
- `sysrq=0` deaktiviert Notfall‑Tastenkombinationen; auf Headless‑Servern üblich.

## Entfernen / Rollback
```bash
# Datei entfernen und Werte neu laden
sudo rm -f /etc/sysctl.d/99-baukasten-hardening.conf
sudo sysctl --system

# Optional maskierte Dienste wieder freigeben
for s in bluetooth cups avahi-daemon ModemManager wpa_supplicant; do
  systemctl unmask "$s" 2>/dev/null || true
  systemctl enable --now "$s" 2>/dev/null || true
done
```

## Hinweise
- Das Modul ist **idempotent**: erneutes Ausführen ändert nichts, solange der Inhalt gleich bleibt.
- Parameterisierung (z. B. `rp_filter`‑Modus, Queue‑Größen) kann bei Bedarf ergänzt werden. Öffne gerne ein Issue/PR mit deinen Anforderungen.

