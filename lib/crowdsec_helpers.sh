#!/bin/bash
################################################################################
# BIBLIOTHEK: CROWDSEC-HELFER-FUNKTIONEN
################################################################################

declare -g crowdsec_config_file=""



# --- Logging-Dummies (falls global nicht geladen) ---
command -v log_info  >/dev/null || log_info()  { echo -e "ℹ️  $*"; }
command -v log_ok    >/dev/null || log_ok()    { echo -e "✅ $*"; }
command -v log_warn  >/dev/null || log_warn()  { echo -e "⚠️  $*"; }
command -v log_error >/dev/null || log_error() { echo -e "❌ $*" >&2; }
command -v log_debug >/dev/null || log_debug() { echo -e "🐞 $*"; }
command -v run_with_spinner >/dev/null || run_with_spinner(){ bash -c "$2"; }

# --- Paket-Install Helper + yq v4 sicherstellen ---
install_crowdsec_packages() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --allow-downgrades "$@" \
    || { log_error "Paketinstallation fehlgeschlagen: $*"; return 1; }
}

ensure_yq_v4() {
  if ! yq --version 2>/dev/null | grep -qi 'mikefarah/yq'; then
    install_crowdsec_packages yq || { log_error "yq v4 fehlt"; return 1; }
  fi
}

# --- Repo-Setup (Bookworm/Trixie via Debian-Repos reicht) ---
setup_crowdsec_repository() {
  apt-get update -qq || { log_error "apt update fehlgeschlagen"; return 1; }
}

## Bereinigt CrowdSec für Neuinstallation
cleanup_crowdsec() {
    log_info "Bereinige CrowdSec für Neuinstallation..."
    
    # Prüfen ob CrowdSec überhaupt installiert ist
    if ! command -v cscli >/dev/null 2>&1 && ! dpkg -l | grep -q crowdsec; then
        log_info "CrowdSec nicht installiert - überspringe Bereinigung"
        return 0
    fi
    
    # Services stoppen vor der Bereinigung (falls vorhanden)
    systemctl stop crowdsec crowdsec-firewall-bouncer crowdsec-bouncer-setonly 2>/dev/null || true
    
    # Collections explizit entfernen (nur wenn cscli verfügbar)
    if command -v cscli >/dev/null 2>&1; then
        cscli collections remove crowdsecurity/sshd 2>/dev/null || true
        cscli collections remove crowdsecurity/linux 2>/dev/null || true
        log_debug "Collections entfernt"
    fi
    
    # Pakete entfernen (falls installiert)
    apt-get remove --purge -y crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
    
    # Verzeichnisse löschen (falls vorhanden)
    [ -d /etc/crowdsec ] && rm -rf /etc/crowdsec
    [ -d /var/lib/crowdsec ] && rm -rf /var/lib/crowdsec
    [ -d /var/log/crowdsec ] && rm -rf /var/log/crowdsec
    
    # Custom systemd-Services entfernen (falls vorhanden)
    [ -f /etc/systemd/system/crowdsec-bouncer-setonly.service ] && rm -f /etc/systemd/system/crowdsec-bouncer-setonly.service
    [ -f /etc/systemd/system/crowdsec-healthcheck.service ] && rm -f /etc/systemd/system/crowdsec-healthcheck.service
    [ -f /etc/systemd/system/crowdsec-healthcheck.timer ] && rm -f /etc/systemd/system/crowdsec-healthcheck.timer
    [ -f /etc/systemd/system/nftables.service.d/crowdsec.conf ] && rm -f /etc/systemd/system/nftables.service.d/crowdsec.conf
    
    systemctl daemon-reload 2>/dev/null || true
    
    # Health-Check-Script entfernen (falls vorhanden)
    [ -f /usr/local/bin/crowdsec-healthcheck ] && rm -f /usr/local/bin/crowdsec-healthcheck
    
    # Autoremove
    apt-get autoremove -y 2>/dev/null || true
    
    log_ok "CrowdSec bereinigt"
}

ensure_crowdsec_hub_perms() {
  install -d -m0755 /var/lib/crowdsec /var/lib/crowdsec/hub /var/lib/crowdsec/data
  if getent passwd crowdsec >/dev/null 2>&1; then
    chown -R crowdsec:crowdsec /var/lib/crowdsec
  else
    chown -R root:root /var/lib/crowdsec
  fi
  chmod 0755 /var/lib/crowdsec /var/lib/crowdsec/hub /var/lib/crowdsec/data
}

set_bouncer_api_key_yq() {
  # Nutzung: set_bouncer_api_key_yq <config.yml> <keyfile>
  local conf="$1" key="$2"

  # Checks
  [ -n "$conf" ] && [ -n "$key" ] || { log_error "API-Key-Helper: Pfade fehlen"; return 1; }
  [ -s "$conf" ] || { log_error "API-Key-Helper: Config fehlt/leer: $conf"; return 1; }
  [ -s "$key"  ] || { log_error "API-Key-Helper: Key fehlt/leer: $key"; return 1; }
  command -v yq >/dev/null || { log_error "API-Key-Helper: yq nicht installiert"; return 1; }

  # Rechte härten (root only liest Key; Config für root:root lesbar)
  chown root:root "$key" "$conf" 2>/dev/null || true
  chmod 600 "$key"  2>/dev/null || true
  chmod 640 "$conf" 2>/dev/null || true

  # Key sicher eintragen (load_str + Newline strip)
  export KEYFILE="$key"
  yq e -i '.api_key = (load_str(env(KEYFILE)) | sub("\\r?\\n$"; ""))' "$conf" \
    || { log_error "API-Key-Helper: yq-Set fehlgeschlagen"; return 1; }

  # Optional: Verifizieren
  local k c
  k="$(tr -d '\r\n' < "$key")"
  c="$(yq e -r '.api_key' "$conf" 2>/dev/null)"
  [ "$k" = "$c" ] || { log_error "API-Key-Helper: Verifikation fehlgeschlagen"; return 1; }

  log_ok "API-Key in '$conf' gesetzt"
}


## Dedizierter systemd-Service für set-only Mode
create_setonly_bouncer_service() {
  log_info "  -> Erstelle dedizierten systemd-Service für set-only Mode..."
  local service_file="/etc/systemd/system/crowdsec-bouncer-setonly.service"
  local config_file="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"
  export CONFIG_FILE="$crowdsec_config_file"



  log_debug "VPS-Umgebung: Nur NFTables, kein UFW - optimal! ✅"
  local primary_interface; primary_interface="$(ip route | awk '/default/{print $5; exit}')" || true
  log_debug "Primäres Interface: ${primary_interface:-unbekannt}"

  if ! nft list table ip crowdsec >/dev/null 2>&1; then
    log_warn "CrowdSec NFTables-Struktur nicht gefunden - wird bei nächstem nftables-Reload geladen"
  fi

  # Template holen & auswerten (setzt CONFIG_FILE im Template voraus)
  download_and_process_template "crowdsec-bouncer-setonly.service.template" \
                                "$service_file" "644" "root:root"

  # Safety: cscli absolut, falls das Template es nicht schon tut
  if grep -q 'ExecStartPre=.*cscli metrics' "$service_file"; then
    sed -i 's#cscli metrics#/usr/bin/cscli metrics#g' "$service_file"
  fi

  # Bouncer-Grundwerte per yq (nur wenn Config existiert)
  if [ -s "$crowdsec_config_file" ]; then
    ensure_yq_v4 || return 1
    yq e -i '.mode = "nftables"'                       "$crowdsec_config_file"
    yq e -i '.log_level = "info"'                      "$crowdsec_config_file"
    yq e -i '.debug = false'                           "$crowdsec_config_file"
    yq e -i '.update_frequency = "30s"'                "$crowdsec_config_file"
    yq e -i '.disable_ipv6 = false'                    "$crowdsec_config_file"
    yq e -i '.nftables.ipv4.enabled = true'            "$crowdsec_config_file"
    yq e -i '.nftables.ipv6.enabled = true'            "$crowdsec_config_file"
    yq e -i '.nftables.ipv4."set-only" = true'         "$crowdsec_config_file"
    yq e -i '.nftables.ipv6."set-only" = true'         "$crowdsec_config_file"
    yq e -i '.nftables.ipv4.table = "crowdsec"'        "$crowdsec_config_file"
    yq e -i '.nftables.ipv6.table = "crowdsec6"'       "$crowdsec_config_file"
    yq e -i '.nftables.ipv4.chain = "crowdsec-chain"'  "$crowdsec_config_file"
    yq e -i '.nftables.ipv6.chain = "crowdsec6-chain"' "$crowdsec_config_file"
    yq e -i '.blacklists_ipv4 = "crowdsec-blacklists"' "$crowdsec_config_file"
    yq e -i '.blacklists_ipv6 = "crowdsec6-blacklists"' "$crowdsec_config_file"
  else
    log_warn "Bouncer-Config ($crowdsec_config_file) fehlt noch – wird später gesetzt."
  fi

  systemctl daemon-reload
  systemctl enable crowdsec-bouncer-setonly.service
  log_ok "Dedizierter set-only Service erstellt und aktiviert."
  log_info "  Service-Datei: $service_file"
  log_info "  Nutzt Sets: crowdsec-blacklists (IPv4) & crowdsec6-blacklists (IPv6)"
  log_info "  Start: systemctl start crowdsec-bouncer-setonly"
}

## Installiert nur den CrowdSec-Agent
install_crowdsec() {
  log_info "Installiere CrowdSec-Agent..."
  setup_crowdsec_repository || return 1
  install_crowdsec_packages crowdsec || return 1

    
  log_info "  -> Konfiguriere systemd-Service..."
  mkdir -p /etc/systemd/system/crowdsec.service.d
  cat > /etc/systemd/system/crowdsec.service.d/override.conf <<'EOF'
[Unit]
After=network.target
[Service]
Restart=on-failure
RestartSec=30s
EOF

  systemctl daemon-reload
  systemctl enable --now crowdsec >/dev/null 2>&1

  local wait_cmd='for i in {1..30}; do
    if systemctl is-active --quiet crowdsec && cscli metrics &>/dev/null; then exit 0; fi
    sleep 1; done; exit 1'
  if run_with_spinner "Warte auf CrowdSec-API..." "bash -c \"$wait_cmd\""; then
    log_ok "CrowdSec-Agent erfolgreich installiert und gestartet"
    return 0
  else
    log_error "CrowdSec-Agent konnte nicht gestartet werden"
    return 1
  fi

}

## Installiert nur den Firewall-Bouncer
install_crowdsec_firewall_bouncer() {
  log_info "🐾 Installiere CrowdSec-Firewall-Bouncer..."
  log_info "  -> Prüfe Voraussetzungen..."
  systemctl is-active --quiet crowdsec || { log_error "CrowdSec läuft nicht"; return 1; }
  cscli metrics >/dev/null 2>&1       || { log_error "CrowdSec API nicht erreichbar"; return 1; }
  command -v nft >/dev/null           || { log_error "nftables nicht installiert"; return 1; }

  local dir="/etc/crowdsec/bouncers"
  local base_yml="$dir/crowdsec-firewall-bouncer.yaml"
  local local_yml="$dir/crowdsec-firewall-bouncer.yaml.local"
  local keyfile="$dir/.api_key"
  mkdir -p "$dir"

  install_crowdsec_packages crowdsec-firewall-bouncer || return 1

  log_info "  -> Warte auf Bouncer-Konfigurationsdatei..."
  for i in {1..30}; do [ -s "$base_yml" ] && break; sleep 1; done
  [ -s "$base_yml" ] || { log_error "Base-Konfiguration fehlt: $base_yml"; return 1; }

  # Kopieren & yq v4 sicherstellen
  cp -f "$base_yml" "$local_yml"
  chmod 0640 "$local_yml"
  ensure_yq_v4 || return 1

  # Nur yq – keine sed-Manips an YAML
  yq e -i '.mode = "nftables"'                          "$local_yml"
  yq e -i '.log_level = "info"'                         "$local_yml"
  yq e -i '.debug = false'                              "$local_yml"
  yq e -i '.update_frequency = "30s"'                   "$local_yml"
  yq e -i '.disable_ipv6 = false'                       "$local_yml"
  yq e -i '.nftables.ipv4.enabled = true'               "$local_yml"
  yq e -i '.nftables.ipv4."set-only" = true'            "$local_yml"
  yq e -i '.nftables.ipv4.table = "crowdsec"'           "$local_yml"
  yq e -i '.nftables.ipv4.chain = "crowdsec-chain"'     "$local_yml"
  yq e -i '.blacklists_ipv4 = "crowdsec-blacklists"'    "$local_yml"
  yq e -i '.nftables.ipv6.enabled = true'               "$local_yml"
  yq e -i '.nftables.ipv6."set-only" = true'            "$local_yml"
  yq e -i '.nftables.ipv6.table = "crowdsec6"'          "$local_yml"
  yq e -i '.nftables.ipv6.chain = "crowdsec6-chain"'    "$local_yml"
  yq e -i '.blacklists_ipv6 = "crowdsec6-blacklists"'   "$local_yml"

	# API-Key erzeugen (falls fehlt)
	if [ ! -s "$keyfile" ]; then
	install -m600 /dev/null "$keyfile"
	cscli bouncers add "firewall-bouncer-$(hostname -s 2>/dev/null || echo default)" -o raw >"$keyfile" \
		|| { log_error "API-Key-Generierung fehlgeschlagen"; return 1; }
	fi

	# API-Key sicher via yq eintragen
	set_bouncer_api_key_yq "$local_yml" "$keyfile" || return 1
	log_info "     🔑 API-Key konfiguriert"

  # Config vor Enable testen
  /usr/bin/crowdsec-firewall-bouncer -c "$local_yml" -t >/dev/null 2>&1 \
    || { log_error "Bouncer-Konfiguration ungültig"; return 1; }

  # Unit + Healthcheck
  create_setonly_bouncer_service

  log_info "  -> Installiere Health-Check-System..."
  install -m755 /dev/null /usr/local/bin/crowdsec-healthcheck
  cat > /usr/local/bin/crowdsec-healthcheck <<'EOF'
#!/bin/bash
if ! cscli metrics >/dev/null 2>&1; then
  logger -t "crowdsec-healthcheck" -p daemon.warn "CrowdSec API nicht erreichbar - Restart..."
  systemctl restart crowdsec crowdsec-bouncer-setonly
fi
EOF
  cat > /etc/systemd/system/crowdsec-healthcheck.service <<'EOF'
[Unit]
Description=CrowdSec Health-Check
After=crowdsec.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/crowdsec-healthcheck
User=root
EOF
  cat > /etc/systemd/system/crowdsec-healthcheck.timer <<'EOF'
[Unit]
Description=CrowdSec Health-Check (alle 5 Min)
Requires=crowdsec-healthcheck.service
[Timer]
OnBootSec=5min
OnUnitInactiveSec=5min
Unit=crowdsec-healthcheck.service
[Install]
WantedBy=timers.target
EOF

  # nftables Reload-Integration
  mkdir -p /etc/systemd/system/nftables.service.d
  cat > /etc/systemd/system/nftables.service.d/crowdsec.conf <<'EOF'
[Service]
ExecReloadPost=/usr/bin/systemctl try-restart crowdsec-bouncer-setonly
EOF

  systemctl daemon-reload
  systemctl enable --now crowdsec-bouncer-setonly crowdsec-healthcheck.timer >/dev/null 2>&1 || true

  # Verifikation
  local ok=1
  systemctl is-active --quiet crowdsec-bouncer-setonly || ok=0
  grep -q 'set-only: true' "$local_yml" || ok=0
  [ -s "$keyfile" ] || ok=0

  if [ "$ok" = 1 ]; then
    log_ok "CrowdSec-Firewall-Bouncer erfolgreich installiert"
    log_info "  -> Set-only Mode aktiv, Health-Check alle 5 Min."
    return 0
  else
    log_error "Bouncer-Installation unvollständig"
    return 1
  fi
}

## SSH-Policy Tuning
tune_crowdsec_ssh_policy() {
  local bantime="${CROWDSEC_BANTIME:-4h}"
  log_info "  -> Passe CrowdSec SSH-Policy an (Ban-Dauer: ${bantime})..."

  # Standard? Dann nix tun.
  [ "$bantime" = "4h" ] && { log_info "Standard 4h – nichts zu tun."; return 0; }

  # (Optional) simples Format-Guarding – anpassen, falls du andere Units zulassen willst
  if ! [[ "$bantime" =~ ^[0-9]+(s|m|h|d|w)$ ]]; then
    log_error "Ungültiges Ban-Dauer-Format: '$bantime' (erwartet z.B. 30m, 4h, 1d, 1w)"
    return 1
  fi

  # Root benötigt
  if [ "$(id -u)" -ne 0 ]; then
    log_error "SSH-Policy-Tuning benötigt root-Rechte."
    return 1
  fi

  # Zielpfad
  local dir="/etc/crowdsec/profiles.d"
  local dst="$dir/99-custom-ssh-duration.yaml"

  # Verzeichnis anlegen (fail-fast, damit set -e gewollt greift)
  install -o root -g root -m0755 -d "$dir"

  # Atomar schreiben: erst tmp, dann mit korrekten Rechten "install"-kopieren
  local tmp
  tmp="$(mktemp)" || { log_error "mktemp fehlgeschlagen"; return 1; }
  cat >"$tmp" <<EOF
name: custom_ssh_ban_duration
description: "Override default ssh ban duration"
filters:
  - "decision.scenario starts_with 'crowdsecurity/sshd-'"
decisions:
  - type: ban
    duration: "${bantime}"
on_success: break
EOF

  install -o root -g root -m0640 "$tmp" "$dst"
  rm -f "$tmp"

  log_ok "Custom SSH-Profile mit Ban-Dauer '${bantime}' erstellt: $dst"

  # CrowdSec neu laden, damit das Profil greift
  systemctl reload crowdsec 2>/dev/null || systemctl restart crowdsec
}


## Komplett-Stack (Agent + Bouncer)
install_crowdsec_stack() {
  log_info "⚙️  Installiere und konfiguriere den CrowdSec-Stack..."
  
  cleanup_crowdsec 

 
  if install_crowdsec && install_crowdsec_firewall_bouncer; then
    tune_crowdsec_ssh_policy
    log_ok "CrowdSec-Stack erfolgreich installiert"
    return 0
  else
    log_error "CrowdSec-Stack Installation fehlgeschlagen"
    return 1
  fi
}
