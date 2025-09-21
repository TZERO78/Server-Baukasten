# README – Modul: `system_update` (unattended‑upgrades)

## Zweck
Einrichtung einer **deterministischen**, wartungsarmen Update‑Routine mit **einem nächtlichen Job**:
- `03:30:00`: `apt-get update` → `unattended-upgrade` → `apt-get autoremove --purge` → `apt-get autoclean`
- **03:45**: Auto‑Reboot **nur bei Bedarf** (`/var/run/reboot-required`)
- Optional: Mail‑Report (nur bei aktivierter System‑Mail)
- **APT::Periodic deaktiviert** (kein zweiter Pfad)
- **Keine** `apt-daily*` Units werden erzeugt; falls vorhanden, werden sie (idempotent) deaktiviert

Zielsysteme: Debian/Ubuntu mit systemd.

---

## Voraussetzungen
- Root‑Rechte
- Internetzugang zu APT‑Spiegeln
- `systemd` verfügbar und aktiv
- Optional für Mail: zuvor konfiguriertes **Mail‑Modul** (msmtp), `ENABLE_SYSTEM_MAIL=ja` und `NOTIFICATION_EMAIL` gesetzt

Interne Baukasten‑Funktionen, die verwendet werden:
- `log_info`, `log_warn`, `log_error`, `log_ok`
- `run_with_spinner`
- `backup_and_register`

---

## Konfigurationsvariablen (ENV)
| Variable | Werte | Standard | Wirkung |
|---|---|---|---|
| `UPGRADE_EXTENDED` | `ja`/`nein` | `ja` | `ja` = zusätzlich `…-updates` zulassen; `nein` = nur `…-security` |
| `U_U_TIME` | `HH:MM:SS` | `03:30:00` | Startzeit des nächtlichen Jobs |
| `REBOOT_ENABLE` | `ja`/`nein` | `ja` | Automatischer Neustart nach Updates (nur bei Bedarf) |
| `REBOOT_TIME` | `HH:MM` | `03:45` | Uhrzeit für Auto‑Reboot |
| `REBOOT_WITH_USERS` | `ja`/`nein` | `ja` | Reboot auch bei angemeldeten Nutzern (Headless‑Server) |
| `ENABLE_SYSTEM_MAIL` | `ja`/`nein` | – | Aktiviert Mail‑Block, wenn `ja` **und** `NOTIFICATION_EMAIL` gesetzt |
| `NOTIFICATION_EMAIL` | E‑Mail | – | Empfänger für Report; Nutzung nur, wenn Mail aktiv |
| `CLEAN_DEEP` | `ja`/`nein` | `nein` | Optional zusätzlich `apt-get clean` |
| `PURGE_RC` | `ja`/`nein` | `nein` | Optional RC‑Pakete entfernen (`dpkg -P`)

**Hinweis:** Mail‑Einstellungen werden nur gesetzt, wenn das Mail‑Modul aktiv ist.

---

## Was das Modul schreibt/ändert
**Konfigurationsdateien**
- `/etc/apt/apt.conf.d/50unattended-upgrades`
- `/etc/apt/apt.conf.d/20auto-upgrades` (alle Periodic‑Jobs auf "0")

**systemd Units**
- `/etc/systemd/system/unattended-upgrades-run.service`
- `/etc/systemd/system/unattended-upgrades-run.timer`
- Drop‑In: `/etc/systemd/system/unattended-upgrades-run.timer.d/override.conf` (setzt `U_U_TIME`, `RandomizedDelaySec=0`)

**Nicht** erzeugt: `apt-daily*` Units. Wenn vorhanden: werden deaktiviert.

---

## Ablauf im Detail
1. **Update‑Pfad**: `apt-get update -qq`
2. **Upgrade**: `unattended-upgrade -d --verbose`
3. **Cleanup**: `apt-get -y autoremove --purge` + `apt-get -y autoclean`
4. **Optional**: `apt-get -y clean` (bei `CLEAN_DEEP=ja`)
5. **Optional**: RC‑Pakete purgen (bei `PURGE_RC=ja`)
6. **Reboot-Steuerung** über `/etc/apt/apt.conf.d/50unattended-upgrades`:
   - `Automatic-Reboot` (an/aus)
   - `Automatic-Reboot-Time` (Standard: `03:45`)
   - `Automatic-Reboot-WithUsers` (Standard: `ja`)

**Mail‑Report** (nur bei aktivem Mail‑Modul):
- `Unattended-Upgrade::MailReport "on-change"` → E‑Mail bei Änderungen (inkl. "reboot required")

---

## Einbindung
1. Optional: Mail‑Modul vorher ausführen (`ENABLE_SYSTEM_MAIL=ja`, `NOTIFICATION_EMAIL` setzen)
2. Modul aufrufen:
```bash
module_system_update    # oder: module_system_update true  (TEST_MODE)
```

---

## Verifikation
```bash
# Timer prüfen (sollte exakt U_U_TIME zeigen)
systemctl list-timers | grep unattended

# Trockentest (zeigt u. a. Reboot-Hinweise)
sudo unattended-upgrade --dry-run --debug | grep -iE 'upgrade|reboot|required' -n || true

# Logs
journalctl -u unattended-upgrades-run.service -n 200 --no-pager

# Reboot-Parameter anzeigen
grep -E 'Automatic-Reboot(|-Time|-WithUsers)' /etc/apt/apt.conf.d/50unattended-upgrades
```

---

## Troubleshooting
- **Keine Journal‑Einträge sichtbar**: mit `sudo` lesen oder Nutzer in `adm`/`systemd-journal` aufnehmen.
- **Mail kommt nicht an**: Mail‑Modul prüfen; Test: `printf "Subject: test\n\nhi\n" | sendmail -v <empfänger>`.
- **Timer kollidieren/verdoppeln**: sicherstellen, dass keine `apt-daily*` Timer aktiv sind (`systemctl list-timers | grep apt-daily`).
- **Kein Reboot trotz Kernelupdate**: prüfen, ob `/var/run/reboot-required` existiert; Reboot‑Zeit korrekt?

---

## Sicherheit/Policy
- Reboot erfolgt ausschließlich, wenn das System dies anfordert.
- Zeitfenster bewusst in die Nacht gelegt; anpassen über `REBOOT_TIME`/`U_U_TIME`.
- `UPGRADE_EXTENDED=nein` für konservativen Betrieb (nur Security).

---

## Entfernen/Rollback
```bash
# Timer deaktivieren
systemctl disable --now unattended-upgrades-run.timer

# (Optional) Dateien manuell entfernen oder aus Backup wiederherstellen
# Backups liegen gemäß Baukasten-Mechanik vor (backup_and_register).
```

---

## Lizenz
MIT‑Lizenz (siehe Repository).

