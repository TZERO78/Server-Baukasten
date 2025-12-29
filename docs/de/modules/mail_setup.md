# README – Modul: `mail_setup` (msmtp)

## Zweck
Richtet systemweiten E‑Mail‑Versand über **msmtp** ein und setzt es als `sendmail`‑Alternative. msmtp wird wegen Einfachheit, geringer Abhängigkeiten und solider TLS‑Unterstützung genutzt. Das Modul vergibt restriktive Dateirechte, optimiert Journald‑Logs und kann einen Testversand zur Verifikation durchführen.

## Voraussetzungen
- **Rechte:** Root‑Zugriff (Schreiben in `/etc/` etc.).
- **Netzwerk:** Ausgehender Zugriff auf den SMTP‑Server (z. B. Port **587**/STARTTLS oder **465**/SMTPS) muss erlaubt sein.
- **Pakete:** `msmtp`, `ca-certificates`.
- **Baukasten‑Funktionen:** `log_*`, `run_with_spinner`, `backup_and_register`.

## Verhalten
- Führt **nichts** aus, wenn `ENABLE_SYSTEM_MAIL` ≠ `ja` (globaler Schalter).
- **Validiert** alle `SMTP_*`‑Variablen vorab; bricht bei fehlenden Pflichtangaben ab.
- Registriert `msmtp` als systemweite `sendmail`‑Alternative via `update-alternatives`.
- Schreibt `/etc/msmtprc` mit **Rechten 600** (nur root lesbar).
- Lagert das Passwort in `/etc/msmtp.pass` (ebenfalls **600**) aus, wenn Auth aktiv ist, und referenziert es via `passwordeval`.
- Passt Journald für längere/persistente Mail‑Logs an.
- Führt vor einer optionalen Test‑Mail einen **SMTP‑Konnektivitäts‑Test** durch (TLS‑sensitiv: je nach ENV `--tls-starttls` oder bei Port 465 `--tls`).
- Fehlschlag der Test‑Mail → **Warnung** mit Hinweisen; Setup bricht **nicht** ab.

## Konfigurationsvariablen (ENV)

| Variable | Pflicht | Beispiel | Beschreibung |
|---|---|---|---|
| `ENABLE_SYSTEM_MAIL` | Ja | `ja` | Modul aktivieren/deaktivieren |
| `SMTP_HOST` | Ja | `smtp.example.com` | SMTP‑Server‑Hostname |
| `SMTP_PORT` | Nein | `587` | Port (Standard: `25`) |
| `SMTP_FROM` | Ja | `server@example.com` | Absender‑Adresse |
| `NOTIFICATION_EMAIL` | Ja | `admin@example.com` | Empfänger für Tests/Reports |
| `SMTP_AUTH` | Nein | `ja`/`nein` | Authentifizierung aktiv (Standard: `ja`) |
| `SMTP_USER` | Bei Auth | `user@example.com` | Benutzer für Anmeldung |
| `SMTP_PASSWORD` | Bei Auth | `***` | Passwort für Anmeldung |
| `SMTP_TLS_STARTTLS` | Nein | `ja`/`nein` | STARTTLS verwenden (Standard: `nein`) |
| `MAIL_SETUP_SEND_TEST` | Nein | `ja`/`nein` | Test‑Mail nach Setup senden (Standard: `ja`) |

## Dateien & Änderungen
**Erstellt/Ändert**
- `/etc/msmtprc` – Hauptkonfiguration (600, `root:root`).
- `/etc/msmtp.pass` – nur Passwort (600, `root:root`, nur bei Auth), via `passwordeval` in `msmtprc` referenziert.
- `/etc/systemd/journald.conf.d/99-mail-logging.conf` – Journald‑Drop‑in.

**System‑Integration**
- `update-alternatives`: setzt `/usr/sbin/sendmail` → `/usr/bin/msmtp`.

## Verifikation
```bash
# sendmail-Alternative prüfen (Value → /usr/bin/msmtp)
update-alternatives --display sendmail

# Rechte/Besitzer der Konfig prüfen (nur root)
ls -l /etc/msmtprc /etc/msmtp.pass

# Journald-Drop-in prüfen
cat /etc/systemd/journald.conf.d/99-mail-logging.conf

# Manueller Testversand über sendmail-Schnittstelle
printf "Subject: Manueller Test

Dies ist ein Test." | sendmail -v "$NOTIFICATION_EMAIL"

# Versand-Logs sichten
journalctl | grep -i msmtp | tail -n 20
```

## Troubleshooting
- **Auth‑Fehler:** `SMTP_AUTH=ja`, aber User/Pass falsch; ggf. App‑Passwort nötig; Port 25 oft blockiert.
- **TLS‑Fehler:** `SMTP_TLS_STARTTLS` passend setzen (587→STARTTLS, 465→SMTPS); CA‑Bundle `/etc/ssl/certs/ca-certificates.crt` aktuell?
- **Keine Mails:** DNS/Firewall prüfen (Host und Gateway); Logs mit `journalctl | grep -i msmtp`.
- **Rechteproblem:** `msmtp` verweigert, wenn `/etc/msmtprc` oder `/etc/msmtp.pass` **≠ 600**.

## Sicherheit
- Passwort liegt **nicht** in `/etc/msmtprc`, sondern in `/etc/msmtp.pass` (Klartext) und wird via `passwordeval` referenziert.
- Beide Dateien enthalten sensible Daten → Rechte **600**, Besitzer `root:root`.
- Aus unverschlüsselten Backups ausschließen oder vor Backups entfernen.

## Entfernen / Rollback
```bash
# sendmail-Alternative entfernen (ignoriert Fehler, wenn nicht vorhanden)
update-alternatives --remove sendmail /usr/bin/msmtp >/dev/null 2>&1 || true

# Konfiguration entfernen
rm -f /etc/msmtprc /etc/msmtp.pass
rm -f /etc/systemd/journald.conf.d/99-mail-logging.conf

# Journald neu starten
systemctl restart systemd-journald
```

