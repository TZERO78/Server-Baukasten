# README – Modul: `mail_setup` (msmtp)

## Zweck

Richtet **systemweiten E‑Mail‑Versand** über `msmtp` ein und setzt es als `sendmail`‑Alternative. Konfiguriert Dateirechte, Journald-Logs und führt einen Testversand durch.

## Voraussetzungen

- **Rechte:** Root-Zugriff für die Ausführung.
- **Netzwerk:** Internetzugang zum konfigurierten SMTP-Server.
- **Pakete:** `msmtp`, `ca-certificates` (müssen extern installiert werden).
- **Baukasten-Funktionen:** `log_*`, `run_with_spinner`, `backup_and_register`.

## Verhalten

- Führt **keine** Aktion aus, wenn `ENABLE_SYSTEM_MAIL` nicht auf `ja` gesetzt ist.
- **Validiert** alle `SMTP_*`-Variablen; bricht bei fehlenden Pflichtangaben mit Fehler ab.
- Registriert und setzt `msmtp` als systemweite `sendmail`-Alternative via `update-alternatives`.
- Schreibt die Konfiguration nach `/etc/msmtprc` mit strikten **Rechten von 600**.
- Lagert das Passwort in `/etc/msmtp.pass` (ebenfalls `600`) aus, wenn Authentifizierung aktiv ist.
- Passt die Journald-Konfiguration für längere Log-Aufbewahrung an.
- Führt einen SMTP-Konnektivitäts-Test durch, bevor eine Test-Mail gesendet wird (TLS-sensitiv; je nach ENV wird `--tls-starttls` bzw. bei Port 465 `--tls` verwendet).
- Ein Fehlschlag der Test-E-Mail führt nur zu einer Warnung, **bricht aber nicht** das gesamte Setup ab.

## Konfigurationsvariablen (ENV)

| **Variable**           | **Pflicht** | **Beispiel**         | **Beschreibung**                             |
| ---------------------- | ----------- | -------------------- | -------------------------------------------- |
| `ENABLE_SYSTEM_MAIL`   | Ja          | `ja`                 | Modul aktivieren/deaktivieren                |
| `SMTP_HOST`            | Ja          | `smtp.example.com`   | SMTP-Server-Hostname                         |
| `SMTP_PORT`            | Nein        | `587`                | Port (Standard: 25)                          |
| `SMTP_FROM`            | Ja          | `server@example.com` | Absender-Adresse                             |
| `NOTIFICATION_EMAIL`   | Ja          | `admin@example.com`  | Empfänger für Tests/Reports                  |
| `SMTP_AUTH`            | Nein        | `ja`/`nein`          | Authentifizierung aktiv (Standard: `ja`)     |
| `SMTP_USER`            | Bei Auth    | `user@example.com`   | Benutzer für die Anmeldung                   |
| `SMTP_PASSWORD`        | Bei Auth    | `***`                | Passwort für die Anmeldung                   |
| `SMTP_TLS_STARTTLS`    | Nein        | `ja`/`nein`          | STARTTLS verwenden (Standard: `nein`)        |
| `MAIL_SETUP_SEND_TEST` | Nein        | `ja`/`nein`          | Test-Mail nach Setup senden (Standard: `ja`) |

## Dateien & Änderungen

- **Erstellt/Ändert:**
  - `/etc/msmtprc` (Rechte `600`, Besitzer `root:root`)
  - `/etc/msmtp.pass` (Rechte `600`, Besitzer `root:root`, nur bei Auth)
  - `/etc/systemd/journald.conf.d/99-mail-logging.conf`
- **System-Integration:**
  - `update-alternatives`: `/usr/sbin/sendmail` wird auf `/usr/bin/msmtp` gesetzt.

## Verifikation

```
# Prüfen, ob die sendmail-Alternative korrekt gesetzt ist
update-alternatives --display sendmail

# Rechte und Besitzer der Konfigurationsdateien prüfen (nur als root)
ls -l /etc/msmtprc /etc/msmtp.pass

# Inhalt der Journald-Optimierung prüfen
cat /etc/systemd/journald.conf.d/99-mail-logging.conf

# Manueller Testversand über die sendmail-Schnittstelle
printf "Subject: Manueller Test\n\nDies ist ein Test." | sendmail -v "$NOTIFICATION_EMAIL"

# Logs des manuellen Versands sichten
journalctl | grep -i msmtp | tail -n 20


```

## Troubleshooting

- **Auth-Fehler**: `SMTP_AUTH=ja`, aber User/Pass falsch; SMTP-Provider blockiert ggf. Port 25/587.
- **TLS-Fehler**: `SMTP_TLS_STARTTLS` passend zum Server setzen; Zertifikats-Bundle (`/etc/ssl/certs/ca-certificates.crt`) prüfen.
- **Keine Mails**: DNS-Auflösung oder Firewall auf dem Server/Gateway blockiert den Zugriff. Logs prüfen mit `journalctl | grep msmtp`.
- **Rechteproblem**: `msmtp` bricht ab, wenn `/etc/msmtprc` oder `/etc/msmtp.pass` nicht die Rechte `600` haben.

## Sicherheit

- Das Passwort liegt **nicht** in `/etc/msmtprc`, sondern in `/etc/msmtp.pass` (Klartext) und wird in `/etc/msmtprc` via `passwordeval` referenziert.
- Beide Dateien enthalten sensible Daten; Rechte **müssen** auf `600` und der Besitzer auf `root:root` gesetzt sein, um unbefugten Zugriff zu verhindern.
- Diese Dateien sollten aus unverschlüsselten Backups ausgeschlossen werden.

## Entfernen / Rollback

```
# sendmail-Alternative sicher entfernen (ignoriert Fehler, wenn nicht vorhanden)
update-alternatives --remove sendmail /usr/bin/msmtp >/dev/null 2>&1 || true

# Konfigurationsdateien löschen
rm -f /etc/msmtprc /etc/msmtp.pass
rm -f /etc/systemd/journald.conf.d/99-mail-logging.conf

# Journald neu starten, um die Konfigurationsänderung zu übernehmen
systemctl restart systemd-journald
```
