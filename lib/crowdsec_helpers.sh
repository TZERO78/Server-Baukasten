#!/bin/bash
################################################################################
#
#  CROWDSEC-HELFER (modern, simpel, yq v4)
#
#  Zweck: Installation & Konfiguration von CrowdSec (LAPI) + Firewall-Bouncer
#         im nftables "set-only"-Modus. Fokus auf Debian Bookworm & Trixie.
#         Minimal invasiv, idempotent, robuste Warte- und Health-Checks.
#
#  Abhängigkeiten (aus dem Baukasten):
#    - log_info/log_ok/log_warn/log_error/log_debug
#    - run_with_spinner (optional; sonst normaler Aufruf)
#    - detect_os_version
#    - ensure_default_release_regex, apt_wait_for_locks (für apt)
#
#  Hinweis: yq = Go-Version v4 (Keys mit Bindestrich IMMER quoten: ."set-only")
#
################################################################################

# -----------------------------------------------------------------------------
# Hilfsfunktionen: Falls nicht vorhanden, Dummy-Implementierungen
# -----------------------------------------------------------------------------
command -v log_info  >/dev/null || log_info()  { echo -e "ℹ️  $*"; }
command -v log_ok    >/dev/null || log_ok()    { echo -e "✅ $*"; }
command -v log_warn  >/dev/null || log_warn()  { echo -e "⚠️  $*"; }
command -v log_error >/dev/null || log_error() { echo -e "❌ $*" >&2; }
command -v log_debug >/dev/null || log_debug() { echo -e "🐞 $*"; }

command -v run_with_spinner >/dev/null || run_with_spinner(){ bash -c "$2"; }

# detect_os_version muss im Projekt vorhanden sein; Minimal-Fallback:
command -v detect_os_version >/dev/null || detect_os_version(){
  local id="debian" ver="unknown" code="unknown"
  if [ -r /etc/os-release ]; then . /etc/os-release; id=${ID:-debian}; ver=${VERSION_ID:-unknown}; code=${VERSION_CODENAME:-unknown}; fi
  echo "$id $ver $code"
}

# -----------------------------------------------------------------------------
# Paketinstallation (simpel): nur fehlende Pakete installieren
# -----------------------------------------------------------------------------
_is_installed(){
  dpkg-query -W -f='${Status}\n' "$1" 2>/dev/null | grep -qx 'install ok installed'
}

install_packages_safe(){
  local pkgs=("$@")
  [ ${#pkgs[@]} -gt 0 ] || { log_debug "install_packages_safe: nix zu tun"; return 0; }

  local missing=() p
  for p in "${pkgs[@]}"; do
    _is_installed "$p" || missing+=("$p")
  done
  [ ${#missing[@]} -gt 0 ] || { log_ok "Alle gewünschten Pakete sind bereits installiert."; return 0; }

  local _id _ver _code; read -r _id _ver _code <<<"$(detect_os_version)"
  command -v ensure_default_release_regex >/dev/null && ensure_default_release_regex "$_code" || true
  command -v apt_wait_for_locks          >/dev/null && apt_wait_for_locks || true

  log_info "Installiere Pakete: ${missing[*]}"
  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --allow-downgrades "${missing[@]}"; then
    log_error "Paketinstallation fehlgeschlagen: ${missing[*]}"
    return 1
  fi

  # CrowdSec-Basics gleich sichern, falls crowdsec dabei war
  if printf '%s\n' "${missing[@]}" | grep -qx 'crowdsec'; then
    ensure_crowdsec_basics || true
  fi
  log_ok "Pakete installiert."
}

# -----------------------------------------------------------------------------
# CrowdSec-Basisdateien/-pfade minimal sicherstellen (idempotent)
# -----------------------------------------------------------------------------
ensure_crowdsec_basics(){
  local etc="/etc/crowdsec"
  install -d -m0755 "$etc" /var/lib/crowdsec/data /var/log/crowdsec "$etc/hub"

  if [ ! -f "$etc/config.yaml" ]; then
    if   [ -f /usr/share/doc/crowdsec/examples/config.yaml ]; then
      cp /usr/share/doc/crowdsec/examples/config.yaml "$etc/config.yaml"
    elif [ -f /usr/share/crowdsec/config/config.yaml ]; then
      cp /usr/share/crowdsec/config/config.yaml "$etc/config.yaml"
    else
      cat >"$etc/config.yaml" <<'EOF'
common:
  daemonize: true
  log_level: info
config_paths:
  acquis: /etc/crowdsec/acquis.yaml
  data_dir: /var/lib/crowdsec/data
  hub_dir: /etc/crowdsec/hub
  simulation_path: /etc/crowdsec/simulation.yaml
cscli:
  output: human
db_config:
  type: sqlite
  db_path: /var/lib/crowdsec/data/crowdsec.db
api:
  server:
    listen_uri: 127.0.0.1:8080
    profiles_path: /etc/crowdsec/profiles.yaml
    online_api_credentials_path: /etc/crowdsec/online_api_credentials.yaml
    use_forwarded_for_headers: false
EOF
    fi
  fi

  for f in acquis.yaml profiles.yaml simulation.yaml online_api_credentials.yaml; do
    [ -e "$etc/$f" ] || install -m0640 /dev/null "$etc/$f"
  done

  chown -R root:root "$etc"
  chmod 0640 "$etc"/*.yaml 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# OS-abhängige Installation (Trixie IMMER Debian-Repo, kein packagecloud)
# -----------------------------------------------------------------------------
install_crowdsec_for_trixie(){
  log_info "  -> Installiere CrowdSec aus Debian-Trixie-Repos..."
  install_packages_safe crowdsec crowdsec-firewall-bouncer
  log_ok   "CrowdSec aus Debian-Trixie-Repos installiert"
}

install_crowdsec_for_bookworm(){
  log_info "  -> Installiere CrowdSec für Bookworm..."
  if [ "${CROWDSEC_USE_OFFICIAL_REPO:-true}" = "true" ]; then
    log_info "     📦 Nutze offizielle Bookworm-Repos"
    install_packages_safe crowdsec crowdsec-firewall-bouncer
  else
    log_info "     📦 Nutze externes packagecloud.io Repository"
    setup_crowdsec_external_repository
    install_packages_safe crowdsec crowdsec-firewall-bouncer
  fi
  log_ok "CrowdSec für Bookworm installiert"
}

install_crowdsec_by_detected_os(){
  local os_id os_version os_code
  read -r os_id os_version os_code < <(detect_os_version)
  os_id="${os_id,,}"; os_code="${os_code,,}"; os_id="${os_id//[[:space:]]/}"; os_code="${os_code//[[:space:]]/}"
  log_info "  -> Erkannter Host: id='${os_id}' version='${os_version}' codename='${os_code}'"

  case "${os_id}:${os_code}" in
    debian:trixie)
      log_info "Debian Trixie erkannt – verwende offizielle Debian-Pakete."
      install_crowdsec_for_trixie ;;
    debian:bookworm)
      log_info "Debian Bookworm erkannt."
      install_crowdsec_for_bookworm ;;
    debian:*)
      log_warn "Debian unbekannter Codename '${os_code}' – nutze Fallback (externes Repo)."
      setup_crowdsec_external_repository
      install_packages_safe crowdsec crowdsec-firewall-bouncer ;;
    *)
      log_warn "Nicht-Debian/unknown OS '${os_id}' – Fallback (externes Repo)."
      setup_crowdsec_external_repository
      install_packages_safe crowdsec crowdsec-firewall-bouncer ;;
  esac
}

# Optional: externes packagecloud-Repo einrichten (für Fallback/Bookworm neueste)
setup_crowdsec_external_repository(){
  if [ -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then
    log_debug "CrowdSec-Repository bereits eingerichtet"; return 0; fi
  log_info "     -> Füge CrowdSec APT-Repository hinzu..."
  local script="/tmp/crowdsec-install.sh"
  if ! curl -fsSL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh -o "$script"; then
    log_error "Download des CrowdSec-Repo-Skripts fehlgeschlagen"; return 1; fi
  if ! grep -q "packagecloud" "$script"; then
    log_error "Ungültiges CrowdSec-Repo-Skript"; rm -f "$script"; return 1; fi
  if run_with_spinner "Richte APT-Repo ein und aktualisiere..." "bash '$script' && apt-get update -qq"; then
    log_ok "Externes CrowdSec-Repository eingerichtet"
  else
    log_error "Repository-Setup fehlgeschlagen"; rm -f "$script"; return 1; fi
  rm -f "$script"
}

# -----------------------------------------------------------------------------
# nftables: Sets für set-only Bouncer bereitstellen
# -----------------------------------------------------------------------------
ensure_nftables_sets(){
  log_info "  -> Stelle NFTables-Sets sicher..."
  if ! nft list set ip crowdsec crowdsec-blacklists >/dev/null 2>&1; then
    nft add table ip crowdsec 2>/dev/null || true
    nft add set ip crowdsec crowdsec-blacklists '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
    log_debug "IPv4-Set crowdsec-blacklists erstellt"
  else
    log_debug "IPv4-Set crowdsec-blacklists bereits vorhanden"
  fi
  if ! nft list set ip6 crowdsec6 crowdsec6-blacklists >/dev/null 2>&1; then
    nft add table ip6 crowdsec6 2>/dev/null || true
    nft add set ip6 crowdsec6 crowdsec6-blacklists '{ type ipv6_addr; flags interval; }' 2>/dev/null || true
    log_debug "IPv6-Set crowdsec6-blacklists erstellt"
  else
    log_debug "IPv6-Set crowdsec6-blacklists bereits vorhanden"
  fi
  log_ok "NFTables-Sets verfügbar"
}

# -----------------------------------------------------------------------------
# Bouncer-YAML via yq (Go v4) konfigurieren (set-only)
# -----------------------------------------------------------------------------
configure_bouncer_with_yq(){
  log_info "  -> Konfiguriere Bouncer-YAML mit yq (set-only)..."
  if ! command -v yq >/dev/null 2>&1; then
    log_info "  -> Installiere yq..."; install_packages_safe yq || { log_error "yq-Install fehlgeschlagen"; return 1; }
  fi

  local dir="/etc/crowdsec/bouncers"
  local base="$dir/crowdsec-firewall-bouncer.yaml"
  local localf="$dir/crowdsec-firewall-bouncer.yaml.local"
  local keyfile="$dir/.api_key"

  [ -d "$dir" ] || install -d -m0755 "$dir"
  if [ ! -f "$localf" ] || [ "$base" -nt "$localf" ]; then
    cp "$base" "$localf" 2>/dev/null || install -m0640 /dev/null "$localf"
  fi

  if [ ! -s "$keyfile" ]; then
    install -o root -g root -m600 /dev/null "$keyfile"
    local bname="firewall-bouncer-$(hostname -s 2>/dev/null || echo default)"
    if ! cscli bouncers add "$bname" -o raw >"$keyfile"; then
      log_error "API-Key-Generierung fehlgeschlagen"; return 1; fi
    log_debug "API-Key generiert ($bname)"
  fi
  local api_key; api_key=$(tr -d '\n\r' <"$keyfile")

  # YAML setzen (Bindestrich-Keys quoten)
  API_KEY="$api_key" yq e -i '.api_key = env(API_KEY)' "$localf"
  yq e -i '.mode = "nftables"'            "$localf"
  yq e -i '.log_level = "info"'           "$localf"
  yq e -i '.update_frequency = "30s"'     "$localf"
  yq e -i '.disable_ipv6 = false'          "$localf"

  yq e -i '.nftables.ipv4.enabled = true'           "$localf"
  yq e -i '.nftables.ipv4."set-only" = true'       "$localf"
  yq e -i '.nftables.ipv4.table = "crowdsec"'      "$localf"
  yq e -i '.nftables.ipv4.chain = "crowdsec-chain"'"$localf"
  yq e -i '.blacklists_ipv4 = "crowdsec-blacklists"'"$localf"

  yq e -i '.nftables.ipv6.enabled = true'           "$localf"
  yq e -i '.nftables.ipv6."set-only" = true'       "$localf"
  yq e -i '.nftables.ipv6.table = "crowdsec6"'     "$localf"
  yq e -i '.nftables.ipv6.chain = "crowdsec6-chain"'"$localf"
  yq e -i '.blacklists_ipv6 = "crowdsec6-blacklists"'"$localf"

  if /usr/bin/crowdsec-firewall-bouncer -c "$localf" -t >/dev/null 2>&1; then
    log_ok "Bouncer-Konfiguration gültig"
  else
    log_error "Bouncer-Konfiguration fehlerhaft"; return 1
  fi
}

# -----------------------------------------------------------------------------
# Systemd-Unit für set-only Bouncer + Healthcheck
# -----------------------------------------------------------------------------
create_setonly_bouncer_service(){
  log_info "  -> Erstelle systemd-Service (set-only)..."
  local service="/etc/systemd/system/crowdsec-bouncer-setonly.service"
  local config="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"

  cat >"$service" <<EOF
[Unit]
Description=CrowdSec Firewall Bouncer (Set-Only Mode)
After=network-online.target crowdsec.service nftables.service
Wants=network-online.target crowdsec.service nftables.service
ConditionPathExists=$config

[Service]
Type=simple
ExecStartPre=/bin/bash -c 'until cscli metrics >/dev/null 2>&1; do sleep 2; done'
ExecStartPre=/usr/bin/crowdsec-firewall-bouncer -c $config -t
ExecStart=/usr/bin/crowdsec-firewall-bouncer -c $config
Restart=on-failure
RestartSec=15s
TimeoutStartSec=60
TimeoutStopSec=30
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/log /var/run
Environment=BOUNCER_MODE=set-only
Environment=BOUNCER_DISABLE_METRICS=true
Environment=BOUNCER_LOG_LEVEL=info
SyslogIdentifier=crowdsec-bouncer-setonly

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl disable --now crowdsec-firewall-bouncer.service 2>/dev/null || true
  systemctl enable crowdsec-bouncer-setonly.service
  log_ok "Service crowdsec-bouncer-setonly eingerichtet"
}

# -----------------------------------------------------------------------------
# Bouncer-Gesamtsetup (nach laufender LAPI)
# -----------------------------------------------------------------------------
setup_crowdsec_bouncer(){
  log_info "🐾 Setup CrowdSec Bouncer..."
  for _ in {1..30}; do
    if systemctl is-active --quiet crowdsec && cscli metrics >/dev/null 2>&1; then
      configure_bouncer
      return $?
    fi
    sleep 1
  done
  log_error "CrowdSec-Service oder API nicht verfügbar - Bouncer-Setup übersprungen"
  return 1
}

configure_bouncer(){
  log_info "🐾 Konfiguriere CrowdSec-Bouncer (nftables set-only)..."
  command -v nft >/dev/null || { log_error "nftables nicht installiert"; return 1; }
  command -v yq  >/dev/null || { log_error "yq nicht installiert"; return 1; }

  ensure_nftables_sets
  configure_bouncer_with_yq
  create_setonly_bouncer_service

  # Healthcheck + Timer
  install -m755 /dev/null /usr/local/bin/crowdsec-healthcheck
  cat > /usr/local/bin/crowdsec-healthcheck <<'EOF'
#!/bin/bash
set -euo pipefail
if ! cscli metrics >/dev/null 2>&1; then
  logger -t "crowdsec-healthcheck" -p daemon.warn "CrowdSec API down - restart..."
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
Description=CrowdSec Health-Check Timer
[Timer]
OnBootSec=5min
OnUnitInactiveSec=5min
Unit=crowdsec-healthcheck.service
[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now crowdsec-healthcheck.timer >/dev/null 2>&1 || true

  # Verifikation (set-only Flag & API-Key-Datei)
  local localf="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"
  yq e '.nftables.ipv4."set-only"' "$localf" | grep -q "true" || { log_error "Set-only Modus nicht aktiviert"; return 1; }
  [ -s "/etc/crowdsec/bouncers/.api_key" ] || { log_error "API-Key-Datei fehlt/leer"; return 1; }
  log_ok "CrowdSec-Bouncer erfolgreich konfiguriert (set-only aktiv)"
}

# -----------------------------------------------------------------------------
# Hauptfunktion: komplette Installation + Start + Bouncer-Setup
# -----------------------------------------------------------------------------
install_crowdsec_stack(){
  log_info "⚙️  Installiere CrowdSec-Stack..."

  install_crowdsec_by_detected_os || { log_error "CrowdSec-Installation fehlgeschlagen"; return 1; }

  # Minimal sicherstellen, falls nach Purge o.ä. Basisdateien fehlen
  ensure_crowdsec_basics

  # CrowdSec-Service robuster starten & warten
  log_info "  -> Aktiviere CrowdSec-Dienste und warte auf die API..."
  systemctl daemon-reload
  systemctl enable --now crowdsec >/dev/null 2>&1 || true

  local wait_cmd='
    for i in {1..45}; do
      if systemctl is-active --quiet crowdsec && cscli metrics >/dev/null 2>&1; then exit 0; fi
      sleep 2
    done
    exit 1'
  if ! run_with_spinner "Warte auf CrowdSec-API (bis zu 90s)..." "bash -c \"$wait_cmd\""; then
    log_error "CrowdSec-Agent konnte nicht gestartet werden oder die API antwortet nicht"
    return 1
  fi
  log_ok "CrowdSec-Agent ist erfolgreich gestartet und API ist erreichbar"

  # Jetzt Bouncer-Setup
  setup_crowdsec_bouncer
}

# -----------------------------------------------------------------------------
# Optional: SSH-Policy Tuning
# -----------------------------------------------------------------------------
tune_crowdsec_ssh_policy(){
  local bantime="${CROWDSEC_BANTIME:-4h}"
  log_info "  -> Passe CrowdSec SSH-Policy an (Ban-Dauer: ${bantime})..."
  if [ "$bantime" = "4h" ]; then
    log_info "Standard CrowdSec SSH-Ban-Dauer ('4h') wird verwendet"
    return 0
  fi
  install -d -m0755 /etc/crowdsec/profiles.d/
  local f="/etc/crowdsec/profiles.d/99-custom-ssh-duration.yaml"
  cat > "$f" <<EOF
name: custom_ssh_ban_duration
description: "Override default ssh ban duration"
filters:
  - "decision.scenario starts_with 'crowdsecurity/sshd-'"
decisions:
  - type: ban
    duration: "${bantime}"
on_success: break
EOF
  chmod 0640 "$f" 2>/dev/null || true
  log_ok "Custom SSH-Profile mit Ban-Dauer '${bantime}' erstellt"
}
