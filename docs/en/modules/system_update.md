# README – Module: `system_update` (unattended‑upgrades)

## Purpose
Setup of a **deterministic**, low-maintenance update routine with **one nightly job**:
- `03:30:00`: `apt-get update` → `unattended-upgrade` → `apt-get autoremove --purge` → `apt-get autoclean`
- **03:45**: Auto‑reboot **only when needed** (`/var/run/reboot-required`)
- Optional: Mail report (only when system mail is enabled)
- **APT::Periodic disabled** (no second path)
- **No** `apt-daily*` units are created; if present, they are disabled (idempotently)

Target systems: Debian/Ubuntu with systemd.

---

## Prerequisites
- Root privileges
- Internet access to APT mirrors
- `systemd` available and active
- Optional for mail: previously configured **mail module** (msmtp), `ENABLE_SYSTEM_MAIL=ja` and `NOTIFICATION_EMAIL` set

Internal Baukasten functions used:
- `log_info`, `log_warn`, `log_error`, `log_ok`
- `run_with_spinner`
- `backup_and_register`

---

## Configuration Variables (ENV)
| Variable | Values | Default | Effect |
|---|---|---|---|
| `UPGRADE_EXTENDED` | `ja`/`nein` | `ja` | `ja` = additionally allow `…-updates`; `nein` = only `…-security` |
| `U_U_TIME` | `HH:MM:SS` | `03:30:00` | Start time of the nightly job |
| `REBOOT_ENABLE` | `ja`/`nein` | `ja` | Automatic reboot after updates (only when needed) |
| `REBOOT_TIME` | `HH:MM` | `03:45` | Time for auto-reboot |
| `REBOOT_WITH_USERS` | `ja`/`nein` | `ja` | Reboot even with logged-in users (headless server) |
| `ENABLE_SYSTEM_MAIL` | `ja`/`nein` | – | Enables mail block when `ja` **and** `NOTIFICATION_EMAIL` is set |
| `NOTIFICATION_EMAIL` | Email | – | Recipient for report; used only when mail is active |
| `CLEAN_DEEP` | `ja`/`nein` | `nein` | Optionally run additional `apt-get clean` |
| `PURGE_RC` | `ja`/`nein` | `nein` | Optionally remove RC packages (`dpkg -P`)

**Note:** Mail settings are only configured when the mail module is active.

---

## What the Module Creates/Modifies
**Configuration files**
- `/etc/apt/apt.conf.d/50unattended-upgrades`
- `/etc/apt/apt.conf.d/20auto-upgrades` (all Periodic jobs set to "0")

**systemd Units**
- `/etc/systemd/system/unattended-upgrades-run.service`
- `/etc/systemd/system/unattended-upgrades-run.timer`
- Drop‑In: `/etc/systemd/system/unattended-upgrades-run.timer.d/override.conf` (sets `U_U_TIME`, `RandomizedDelaySec=0`)

**Not** created: `apt-daily*` units. If present: they are disabled.

---

## Detailed Process Flow
1. **Update path**: `apt-get update -qq`
2. **Upgrade**: `unattended-upgrade -d --verbose`
3. **Cleanup**: `apt-get -y autoremove --purge` + `apt-get -y autoclean`
4. **Optional**: `apt-get -y clean` (when `CLEAN_DEEP=ja`)
5. **Optional**: Purge RC packages (when `PURGE_RC=ja`)
6. **Reboot control** via `/etc/apt/apt.conf.d/50unattended-upgrades`:
   - `Automatic-Reboot` (on/off)
   - `Automatic-Reboot-Time` (default: `03:45`)
   - `Automatic-Reboot-WithUsers` (default: `ja`)

**Mail report** (only with active mail module):
- `Unattended-Upgrade::MailReport "on-change"` → Email on changes (including "reboot required")

---

## Integration
1. Optional: Run mail module beforehand (`ENABLE_SYSTEM_MAIL=ja`, set `NOTIFICATION_EMAIL`)
2. Invoke module:
```bash
module_system_update    # or: module_system_update true  (TEST_MODE)
```

---

## Verification
```bash
# Check timer (should show exact U_U_TIME)
systemctl list-timers | grep unattended

# Dry run test (shows reboot hints among other things)
sudo unattended-upgrade --dry-run --debug | grep -iE 'upgrade|reboot|required' -n || true

# Logs
journalctl -u unattended-upgrades-run.service -n 200 --no-pager

# Display reboot parameters
grep -E 'Automatic-Reboot(|-Time|-WithUsers)' /etc/apt/apt.conf.d/50unattended-upgrades
```

---

## Troubleshooting
- **No journal entries visible**: read with `sudo` or add user to `adm`/`systemd-journal` group.
- **Mail not arriving**: check mail module; test: `printf "Subject: test\n\nhi\n" | sendmail -v <recipient>`.
- **Timer conflicts/duplicates**: ensure no `apt-daily*` timers are active (`systemctl list-timers | grep apt-daily`).
- **No reboot despite kernel update**: check if `/var/run/reboot-required` exists; reboot time correct?

---

## Security/Policy
- Reboot occurs exclusively when the system requests it.
- Time window deliberately set to nighttime; adjust via `REBOOT_TIME`/`U_U_TIME`.
- `UPGRADE_EXTENDED=nein` for conservative operation (security only).

---

## Removal/Rollback
```bash
# Disable timer
systemctl disable --now unattended-upgrades-run.timer

# (Optional) Manually remove files or restore from backup
# Backups exist according to Baukasten mechanism (backup_and_register).
```

---

## License
MIT License (see repository).
