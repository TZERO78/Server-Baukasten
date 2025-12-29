# README – Modul: `kernel_hardening` (sysctl & Dienste)

## Zweck
Härtet Kernel- und Netzwerk-Defaults über `/etc/sysctl.d/` und schaltet unnötige Desktop/Notebook‑Dienste ab. Idempotent: schreibt nur bei Änderungen und lädt dann `sysctl --system`. Optionales Maskieren von Diensten.

## Voraussetzungen
- **Root‑Rechte**
- **Pakete:** `procps` (für `sysctl`)
- **Baukasten‑Funktionen:** `log_*`, `run_with_spinner`, `backup_and_register`

## Verhalten
- Schreibt **eine** Datei: `/etc/sysctl.d/99-baukasten-hardening.conf`
- Lädt nur bei Änderungen neu (`sysctl --system`) und protokolliert nach `/run/baukasten-sysctl.log`
- Verifiziert `ip_forward` (v4/v6) und warnt bei Abweichungen
- Deaktiviert (und optional maskiert) nicht benötigte Dienste: `bluetooth`, `cups`, `avahi-daemon`, `ModemManager`, `wpa_supplicant`

## Konfigurationsvariablen (ENV)
| Variable | Pflicht | Beispiel | Wirkung |
|---|---|---|---|
| `HARDEN_MASK_SERVICES` | Nein | `ja`/`nein` | Zusätzlich zu `disable` ein `mask` auf die o. g. Dienste. Default: `nein` |

## Wichtige sysctl‑Einstellungen (Auszug)
**IPv4**
- `net.ipv4.conf.*.rp_filter=1` – Source‑Validation (bei asymmetrischem Routing ggf. `2` nutzen)
- `accept_redirects=0`, `secure_redirects=0`, `send_redirects=0`
- `accept_source_route=0` (all/default)
- `log_martians=1` (all & default)
- `tcp_syncookies=1`, `tcp_rfc1337=1`

**IPv6**
- `accept_redirects=0` (all/default)
- `accept_ra=0` (all/default)
- `accept_source_route=0` (all/default)
- **Forwarding:** `net.ipv6.conf.all.forwarding=1` (bewusst an für Docker/VPN)

**Kernel‑Hardening**
- `dev.tty.ldisc_autoload=0`
- `kernel.dmesg_restrict=1`, `kernel.kptr_restrict=2`, `kernel.sysrq=0`
- `kernel.unprivileged_bpf_disabled=1`, `net.core.bpf_jit_harden=2`
- `kernel.core_uses_pid=1`, `kernel.randomize_va_space=2`, `kernel.yama.ptrace_scope=1`
- Optional: `kernel.kexec_load_disabled=1` (kein kexec‑Reboot)
- **Nicht gesetzt:** `kernel.modules_disabled` (würde Modulladen global verbieten – auf VPS meist unpraktisch)

**FS‑Schutz**
- `fs.protected_fifos=2`, `fs.protected_hardlinks=1`, `fs.protected_symlinks=1`, `fs.protected_regular=2`

**Performance (konservativ, VPS‑tauglich)**
- `vm.swappiness=10`, `vm.dirty_background_ratio=5`, `vm.dirty_ratio=15`
- `net.core.rmem_max/wmem_max=16777216`, `somaxconn=4096`, `netdev_max_backlog=16384`
- `tcp_fin_timeout=30`, `tcp_keepalive_time=1800`, `tcp_max_syn_backlog=8192`
- `net.netfilter.nf_conntrack_max=524288` (falls Netfilter aktiv)

## Dateien & Änderungen
- `/etc/sysctl.d/99-baukasten-hardening.conf` – zentrale Hardening‑Parameter (644, `root:root`)

## Verifikation
```bash
# Datei gefunden?
grep -n "baukasten-hardening" /etc/sysctl.d/*.conf

# Kritische Schalter
sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.forwarding \
         kernel.core_uses_pid dev.tty.ldisc_autoload \
         fs.protected_fifos

# Letztes Apply (Log)
[ -f /run/baukasten-sysctl.log ] && tail -n +1 /run/baukasten-sysctl.log | sed -n '1,120p'
```

## Troubleshooting
- **Lynis‑Abweichungen:**
  - `net.ipv4.conf.all.forwarding`: Lynis erwartet `0`. Für Docker/VPN **bewusst 1**. Alternativ interface‑spezifisch aktivieren.
  - `kernel.modules_disabled`: nicht gesetzt – produktiv meist nicht praktikabel.
- **Asymmetrisches Routing:** `rp_filter=1` kann Pakete verwerfen → auf `2` wechseln.
- **IPv6 RA/SLAAC benötigt:** Interface‑spezifisch `accept_ra=1` setzen oder Autokonfig aktivieren.
- **Fehlende Keys im Log:** Unkritisch (Kernel/Module ggf. nicht vorhanden).

## Sicherheit
- Änderungen gelten systemweit. Vor Produktivbetrieb prüfen (VPN, Overlay, Kubernetes, Container‑Runtime).
- `sysrq=0` ist auf Headless‑Servern üblich.

## Entfernen / Rollback
```bash
sudo rm -f /etc/sysctl.d/99-baukasten-hardening.conf
sudo sysctl --system

# Optional maskierte Dienste wieder freigeben
for s in bluetooth cups avahi-daemon ModemManager wpa_supplicant; do
  systemctl unmask "$s" 2>/dev/null || true
  systemctl enable --now "$s" 2>/dev/null || true
done
```

## Hinweise
- Modul ist **idempotent**: erneuter Lauf ändert nichts, wenn der Inhalt gleich bleibt.
- Parametrisierung (z. B. `rp_filter`‑Modus) kann bei Bedarf ergänzt werden. Eröffne ein Issue/PR mit deiner Policy.