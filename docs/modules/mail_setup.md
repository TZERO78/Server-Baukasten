# README – Modul: `mail_setup` (msmtp)

## Zweck
Richtet **systemweiten E‑Mail‑Versand** über `msmtp` ein und setzt es als `sendmail`‑Alternative. Sichere Dateirechte, einfache Logs, Testversand.

---

## Voraussetzungen
- Root‑Rechte
- Internetzugang zum SMTP‑Server
- Pakete: `msmtp` (wird außerhalb installiert, z. B. im Install‑Services‑Modul)

Interne Baukasten‑Funktionen: `log_*`, `run_with_spinner`, `backup_and_register`.

---

## Verhalten
- Abbruch **ohne** Änderung, wenn `ENABLE_SYSTEM_MAIL != ja`.
- Validiert: `SMTP_HOST`, `SMTP_FROM`, `NOTIFICATION_EMAIL` (fehlt ⇒ Abbruch mit Fehler).
- Setzt `msmtp` als `sendmail` via `update-alternatives`.
- Schreibt `/etc/msmtprc` mit **Rechten 600** (Passwortschutz).
- Optional Auth je nach `SMTP_AUTH`.
- Journald‑Tuning: `/etc/systemd/journald.conf.d/99-mail-logging.conf`.
- Test‑E‑Mail an `NOTIFICATION_EMAIL` (Fehlschlag bricht **nicht** das System‑Setup).

---

## Konfigurationsvariablen (ENV)
| Variable | Pflicht | Beispiel | Beschreibung |
|---|---|---|---|
| `ENABLE_SYSTEM_MAIL` | ja | `ja` | Modul aktivieren/deaktivieren |
| `SMTP_HOST` | ja | `smtp.example.com` | SMTP‑Server |
| `SMTP_PORT` | nein | `587` | Port (Default 25) |
| `SMTP_FROM` | ja | `server@example.com` | Absender‑Adresse |
| `NOTIFICATION_EMAIL` | ja | `admin@example.com` | Empfänger für Tests/Reports |
| `SMTP_AUTH` | nein | `ja`/`nein` | Authentifizierung aktiv |
| `SMTP_USER` | bei Auth | `user@example.com` | Benutzer |
| `SMTP_PASSWORD` | bei Auth | `***` | Passwort |
| `SMTP_TLS_STARTTLS` | nein | `ja`/`nein` | STARTTLS (sonst direkt TLS)

---

## Dateien/Änderungen
- `/etc/msmtprc` (600, Besitzer `root:root`)
- `update-alternatives` → `/usr/sbin/sendmail` → `/usr/bin/msmtp`
- `/etc/systemd/journald.conf.d/99-mail-logging.conf` (persistente Logs, Limits)

---

## Ausführung
```bash
module_mail_setup
```

Bei Erfolg:
- `sendmail` zeigt auf `msmtp`
- Test‑Mail wird gesendet (oder Fehlerhinweise im Log)

---

## Verifikation
```bash
# sendmail‑Pfad
update-alternatives --display sendmail | sed -n '1,20p'

# Rechte & Inhalt (nur als root)
ls -l /etc/msmtprc
sudo head -n 20 /etc/msmtprc

# Journald aktiv/persistent?
cat /etc/systemd/journald.conf.d/99-mail-logging.conf

# Testversand
printf "Subject: Test\n\nHallo" | sendmail -v "$NOTIFICATION_EMAIL"
# Logs sichten
journalctl | grep -i msmtp | tail -n 50
```

---

## Troubleshooting
- **Auth‑Fehler**: `SMTP_AUTH=ja`, User/Pass prüfen; Provider blockiert ggf. Port 25.
- **TLS‑Fehler**: `SMTP_TLS_STARTTLS` passend zum Server setzen; Zert.-Bundle: `/etc/ssl/certs/ca-certificates.crt`.
- **Keine Mails**: DNS/Firewall prüfen; Logs (`journalctl | grep msmtp`).
- **Rechteproblem**: `/etc/msmtprc` muss `600` sein.

---

## Sicherheit
- `/etc/msmtprc` enthält Zugangsdaten → **600**.
- Nur Root hat Leserechte. Keine Weitergabe der Datei in Backups ohne Verschlüsselung.

---

## Entfernen/Rollback
```bash
# sendmail‑Alternative zurücksetzen
update-alternatives --remove sendmail /usr/bin/msmtp || true

# Konfigs (optional) entfernen
rm -f /etc/msmtprc
rm -f /etc/systemd/journald.conf.d/99-mail-logging.conf
systemctl restart systemd-journald
```

---

## Hinweise
- Integration mit `unattended‑upgrades`: Mails nur, wenn `ENABLE_SYSTEM_MAIL=ja` **und** `NOTIFICATION_EMAIL` gesetzt.
- Absender kann im MTA (msmtp‑Option `from`) angepasst werden.
