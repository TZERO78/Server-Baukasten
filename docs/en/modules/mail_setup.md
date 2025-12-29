# README – Module: `mail_setup` (msmtp)

## Purpose
Sets up system-wide email sending via **msmtp** and configures it as a `sendmail` alternative. msmtp is used for its simplicity, minimal dependencies, and solid TLS support. The module applies restrictive file permissions, optimizes journald logs, and can perform a test send for verification.

## Prerequisites
- **Permissions:** Root access (writing to `/etc/`, etc.).
- **Network:** Outbound access to the SMTP server (e.g., port **587**/STARTTLS or **465**/SMTPS) must be allowed.
- **Packages:** `msmtp`, `ca-certificates`.
- **Baukasten functions:** `log_*`, `run_with_spinner`, `backup_and_register`.

## Behavior
- Executes **nothing** if `ENABLE_SYSTEM_MAIL` ≠ `ja` (global switch).
- **Validates** all `SMTP_*` variables upfront; aborts on missing required values.
- Registers `msmtp` as system-wide `sendmail` alternative via `update-alternatives`.
- Writes `/etc/msmtprc` with **permissions 600** (readable by root only).
- Stores the password in `/etc/msmtp.pass` (also **600**) when auth is active, and references it via `passwordeval`.
- Adjusts journald for longer/persistent mail logs.
- Performs an **SMTP connectivity test** before an optional test mail (TLS-sensitive: depending on ENV `--tls-starttls` or `--tls` for port 465).
- Test mail failure → **warning** with hints; setup does **not** abort.

## Configuration Variables (ENV)

| Variable | Required | Example | Description |
|---|---|---|---|
| `ENABLE_SYSTEM_MAIL` | Yes | `ja` | Enable/disable module |
| `SMTP_HOST` | Yes | `smtp.example.com` | SMTP server hostname |
| `SMTP_PORT` | No | `587` | Port (default: `25`) |
| `SMTP_FROM` | Yes | `server@example.com` | Sender address |
| `NOTIFICATION_EMAIL` | Yes | `admin@example.com` | Recipient for tests/reports |
| `SMTP_AUTH` | No | `ja`/`nein` | Authentication active (default: `ja`) |
| `SMTP_USER` | With auth | `user@example.com` | User for login |
| `SMTP_PASSWORD` | With auth | `***` | Password for login |
| `SMTP_TLS_STARTTLS` | No | `ja`/`nein` | Use STARTTLS (default: `nein`) |
| `MAIL_SETUP_SEND_TEST` | No | `ja`/`nein` | Send test mail after setup (default: `ja`) |

## Files & Changes
**Creates/Modifies**
- `/etc/msmtprc` – Main configuration (600, `root:root`).
- `/etc/msmtp.pass` – Password only (600, `root:root`, with auth only), referenced via `passwordeval` in `msmtprc`.
- `/etc/systemd/journald.conf.d/99-mail-logging.conf` – Journald drop-in.

**System Integration**
- `update-alternatives`: sets `/usr/sbin/sendmail` → `/usr/bin/msmtp`.

## Verification
```bash
# Check sendmail alternative (Value → /usr/bin/msmtp)
update-alternatives --display sendmail

# Check permissions/owner of config (root only)
ls -l /etc/msmtprc /etc/msmtp.pass

# Check journald drop-in
cat /etc/systemd/journald.conf.d/99-mail-logging.conf

# Manual test send via sendmail interface
printf "Subject: Manual Test

This is a test." | sendmail -v "$NOTIFICATION_EMAIL"

# Review send logs
journalctl | grep -i msmtp | tail -n 20
```

## Troubleshooting
- **Auth errors:** `SMTP_AUTH=ja`, but user/password incorrect; app password may be required; port 25 often blocked.
- **TLS errors:** Set `SMTP_TLS_STARTTLS` appropriately (587→STARTTLS, 465→SMTPS); is CA bundle `/etc/ssl/certs/ca-certificates.crt` current?
- **No mails:** Check DNS/firewall (host and gateway); logs with `journalctl | grep -i msmtp`.
- **Permission problem:** `msmtp` refuses if `/etc/msmtprc` or `/etc/msmtp.pass` **≠ 600**.

## Security
- Password is **not** in `/etc/msmtprc`, but in `/etc/msmtp.pass` (plaintext) and referenced via `passwordeval`.
- Both files contain sensitive data → permissions **600**, owner `root:root`.
- Exclude from unencrypted backups or remove before backups.

## Removal / Rollback
```bash
# Remove sendmail alternative (ignores error if not present)
update-alternatives --remove sendmail /usr/bin/msmtp >/dev/null 2>&1 || true

# Remove configuration
rm -f /etc/msmtprc /etc/msmtp.pass
rm -f /etc/systemd/journald.conf.d/99-mail-logging.conf

# Restart journald
systemctl restart systemd-journald
```
