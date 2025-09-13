#!/bin/bash
################################################################################
#
# BIBLIOTHEK: CROWDSEC-HELFER-FUNKTIONEN (MODERNISIERT, BEST PRACTICE)
#
# @description: Installation & Konfiguration von CrowdSec (LAPI) und
#               Firewall-Bouncer im nftables "set-only"-Modus für Debian
#               Bookworm (12) & Trixie (13).
# @author:      Markus F. (TZERO78) & KI-Assistent
# @license:     MIT
#
################################################################################

set -o errexit
set -o pipefail
set -o nounset

# ---- Hilfsfunktionen (Platzhalter; im Baukasten vorhanden) -------------------
log_info()  { echo -e "ℹ️  $*"; }
log_ok()    { echo -e "✅ $*"; }
log_warn()  { echo -e "⚠️  $*"; }
log_error() { echo -e "❌ $*" >&2; }
log_debug() { echo -e "🐞 $*"; }

run_with_spinner() { bash -c "$2"; }   # vereinfachter Platzhalter
install_packages_safe() { DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; }

# ------------------------------------------------------------------------------
# SETUP-HOOK: nach LAPI-Start den Bouncer einrichten (robust mit Retry)
# ------------------------------------------------------------------------------
setup_crowdsec_bouncer() {
  log_info "🐾 Setup CrowdSec Bouncer..."
  # bis zu 30s auf LAPI warten (gegen Race-Conditions)
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

################################################################################
# INSTALLATION NACH DIST
################################################################################

install_crowdsec_for_trixie() {
  log_info "  -> Installiere CrowdSec aus offiziellen Trixie-Repositories..."
  install_packages_safe crowdsec crowdsec-firewall-bouncer
  log_ok "CrowdSec aus offiziellen Debian-Repositories installiert"
}

install_crowdsec_for_bookworm() {
  log_info "  -> Installiere CrowdSec für Bookworm..."
  if [ "${CROWDSEC_USE_OFFICIAL_REPO:-true}" = "true" ]; then
    log_info "     📦 Nutze offizielle Bookworm-Repositories"
    install_packages_safe crowdsec crowdsec-firewall-bouncer
  else
    log_info "     📦 Nutze externes packagecloud.io Repository (neueste Version)"
    setup_crowdsec_external_repository
    install_packages_safe crowdsec crowdsec-firewall-bouncer
  fi
  log_ok "CrowdSec für Bookworm installiert"
}

setup_crowdsec_external_repository() {
  if [ -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then
    log_debug "CrowdSec-Repository bereits eingerichtet"
    return 0
  fi
  log_info "     -> Füge CrowdSec APT-Repository hinzu..."
  local install_script="/tmp/crowdsec-install.sh"
  if ! curl -fsSL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh -o "$install_script"; then
    log_error "Download des CrowdSec-Repository-Scripts fehlgeschlagen"
    return 1
  fi
  if ! grep -q "packagecloud" "$install_script"; then
    log_error "Ungültiges CrowdSec-Installationsskript"
    rm -f "$install_script"
    return 1
  fi
  if run_with_spinner "Richte APT-Repository ein und aktualisiere..." "bash '$install_script' && apt-get update -qq"; then
    log_ok "Externes CrowdSec-Repository erfolgreich eingerichtet"
  else
    log_error "Repository-Setup fehlgeschlagen"
    rm -f "$install_script"
    return 1
  fi
  rm -f "$install_script"
}

################################################################################
# BOUNCER-KONFIG (yq v4, nftables set-only)
################################################################################

configure_bouncer_with_yq() {
  log_info "  -> Konfiguriere NFTables-Modus mit yq (YAML-sicher)..."

  # yq sicherstellen (Go-Version)
  if ! command -v yq >/dev/null 2>&1; then
    log_info "  -> Installiere 'yq'..."
    install_packages_safe yq || { log_error "yq-Installation fehlgeschlagen"; return 1; }
  fi

  local dir="/etc/crowdsec/bouncers"
  local base_yml="$dir/crowdsec-firewall-bouncer.yaml"
  local local_yml="$dir/crowdsec-firewall-bouncer.yaml.local"
  local keyfile="$dir/.api_key"

  # Base-Config kopieren (idempotent)
  if [ ! -f "$local_yml" ] || [ "$base_yml" -nt "$local_yml" ]; then
    cp "$base_yml" "$local_yml"
    log_debug "Base-Config kopiert"
  fi

  # API-Key (eindeutiger Name je Host vermeidet Duplikate)
  if [ ! -s "$keyfile" ]; then
    install -o root -g root -m600 /dev/null "$keyfile"
    local bname="firewall-bouncer-$(hostname -s 2>/dev/null || echo default)"
    if ! cscli bouncers add "$bname" -o raw >"$keyfile"; then
      log_error "API-Key-Generierung fehlgeschlagen!"
      return 1
    fi
    log_debug "API-Key generiert ($bname)"
  fi
  local api_key; api_key=$(tr -d '\n\r' < "$keyfile")

  # YAML setzen (Bindestrich-Keys IMMER quoten)
  yq eval -i '.mode = "nftables"' "$local_yml"
  yq eval -i '.log_level = "info"' "$local_yml"
  yq eval -i '.update_frequency = "30s"' "$local_yml"
  yq eval -i '.disable_ipv6 = false' "$local_yml"
  yq eval -i '.api_key = strenv(API_KEY)' --env API_KEY="$api_key" "$local_yml"

  # IPv4
  yq eval -i '.nftables.ipv4.enabled = true' "$local_yml"
  yq eval -i '.nftables.ipv4."set-only" = true' "$local_yml"
  yq eval -i '.nftables.ipv4.table = "crowdsec"' "$local_yml"
  yq eval -i '.nftables.ipv4.chain = "crowdsec-chain"' "$local_yml"
  yq eval -i '.blacklists_ipv4 = "crowdsec-blacklists"' "$local_yml"

  # IPv6
  yq eval -i '.nftables.ipv6.enabled = true' "$local_yml"
  yq eval -i '.nftables.ipv6."set-only" = true' "$local_yml"
  yq eval -i '.nftables.ipv6.table = "crowdsec6"' "$local_yml"
  yq eval -i '.nftables.ipv6.chain = "crowdsec6-chain"' "$local_yml"
  yq eval -i '.blacklists_ipv6 = "crowdsec6-blacklists"' "$local_yml"

  log_info "     🔧 NFTables set-only Mode konfiguriert"
  log_info "     🎯 IPv4: crowdsec/crowdsec-blacklists"
  log_info "     🎯 IPv6: crowdsec6/crowdsec6-blacklists"

  # Validate
  log_info "  -> Teste Konfiguration..."
  if /usr/bin/crowdsec-firewall-bouncer -c "$local_yml" -t >/dev/null 2>&1; then
    log_ok "Bouncer-Konfiguration ist gültig"
    return 0
  else
    log_error "Konfiguration fehlerhaft!"
    log_info "Config-Datei: $local_yml"
    return 1
  fi
}

ensure_nftables_sets() {
    log_info "  -> Stelle NFTables-Sets sicher..."

    # IPv4
    if ! nft list set ip crowdsec crowdsec-blacklists >/dev/null 2>&1; then
        nft add table ip crowdsec 2>/dev/null || true
        nft add set ip crowdsec crowdsec-blacklists '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
        log_debug "IPv4-Set crowdsec-blacklists erstellt"
    else
        log_debug "IPv4-Set crowdsec-blacklists bereits vorhanden"
    fi

    # IPv6  (Fix: /dev/null)
    if ! nft list set ip6 crowdsec6 crowdsec6-blacklists >/dev/null 2>&1; then
        nft add table ip6 crowdsec6 2>/dev/null || true
        nft add set ip6 crowdsec6 crowdsec6-blacklists '{ type ipv6_addr; flags interval; }' 2>/dev/null || true
        log_debug "IPv6-Set crowdsec6-blacklists erstellt"
    else
        log_debug "IPv6-Set crowdsec6-blacklists bereits vorhanden"
    fi

    log_ok "NFTables-Sets verfügbar"
}
create_setonly_bouncer_service() {
  log_info "  -> Erstelle dedizierten systemd-Service für set-only Mode..."

  local service_file="/etc/systemd/system/crowdsec-bouncer-setonly.service"
  local config_file="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"

  cat > "$service_file" <<EOF
[Unit]
Description=CrowdSec Firewall Bouncer (Set-Only Mode) - Server-Baukasten
Documentation=https://docs.crowdsec.net/docs/bouncers/firewall/
After=network-online.target multi-user.target crowdsec.service nftables.service
Wants=network-online.target crowdsec.service nftables.service
ConditionPathExists=$config_file

[Service]
Type=simple
User=root
Group=root

# Warte bis CrowdSec API verfügbar ist
ExecStartPre=/bin/bash -c 'until cscli metrics >/dev/null 2>&1; do sleep 2; done'

# Konfiguration testen
ExecStartPre=/usr/bin/crowdsec-firewall-bouncer -c $config_file -t

# Haupt-Service starten
ExecStart=/usr/bin/crowdsec-firewall-bouncer -c $config_file

# Robuster Restart bei Problemen
Restart=on-failure
RestartSec=15s
StartLimitBurst=3
StartLimitIntervalSec=300

# Timeouts
TimeoutStartSec=60
TimeoutStopSec=30

# Sicherheits-Härtung
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/log /var/run

# Umgebung (set-only hat i.d.R. keine eigenen Metriken)
Environment=BOUNCER_MODE=set-only
Environment=BOUNCER_DISABLE_METRICS=true
Environment=BOUNCER_LOG_LEVEL=info
StandardOutput=journal
StandardError=journal
SyslogIdentifier=crowdsec-bouncer-setonly

[Install]
WantedBy=multi-user.target
EOF

  # Original-Service deaktivieren (falls vorhanden)
  if systemctl is-enabled crowdsec-firewall-bouncer.service >/dev/null 2>&1; then
    systemctl stop crowdsec-firewall-bouncer.service 2>/dev/null || true
    systemctl disable crowdsec-firewall-bouncer.service 2>/dev/null || true
  fi

  systemctl daemon-reload
  systemctl enable crowdsec-bouncer-setonly.service

  log_ok "Dedizierter set-only Service erstellt und aktiviert"
  log_info "  Service-Datei: $service_file"
  log_info "  Nutzt Sets: crowdsec-blacklists (IPv4) & crowdsec6-blacklists (IPv6)"
}

################################################################################
# HAUPTFUNKTION: komplette Installation + Konfiguration
################################################################################

install_crowdsec_stack() {
  log_info "⚙️  Installiere und konfiguriere den CrowdSec-Stack..."

  # 1) Debian-Version ermitteln
  local debian_version
  debian_version=$(lsb_release -cs 2>/dev/null || { . /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-unknown}"; })
  log_info "  -> Erkannte Debian-Version: $debian_version"

  case "$debian_version" in
    "trixie")   install_crowdsec_for_trixie ;;
    "bookworm") install_crowdsec_for_bookworm ;;
    *)          log_warn "Unbekannte/Unsupported Debian-Version: $debian_version"
                log_info "Fallback: Verwende externes Repository..."
                setup_crowdsec_external_repository
                install_packages_safe crowdsec crowdsec-firewall-bouncer ;;
  esac

  # 2) systemd-Verhalten (netzabhängiger Start der LAPI)
  log_info "  -> Konfiguriere CrowdSec für netzwerkabhängigen Start..."
  mkdir -p /etc/systemd/system/crowdsec.service.d
  cat > /etc/systemd/system/crowdsec.service.d/override.conf <<'EOF'
[Unit]
After=network.target
[Service]
Restart=on-failure
RestartSec=30s
EOF

  # 3) LAPI-Installation verifizieren/reparieren
  log_info "  -> Validiere CrowdSec-Installation..."
  if [ ! -f "/etc/crowdsec/config.yaml" ] || [ ! -d "/etc/crowdsec" ]; then
    log_warn "CrowdSec-Konfiguration fehlt - repariere Installation..."
    systemctl stop crowdsec 2>/dev/null || true
    if ! run_with_spinner "Repariere CrowdSec-Installation..." "apt-get remove --purge -y crowdsec >/dev/null 2>&1 || true && DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec >/dev/null 2>&1"; then
      log_error "CrowdSec-Reparatur fehlgeschlagen"
      return 1
    fi
    log_ok "CrowdSec-Installation repariert"
  fi

  # 4) LAPI starten & warten
  log_info "  -> Aktiviere CrowdSec-Dienste und warte auf die API..."
  systemctl daemon-reload
  systemctl enable --now crowdsec >/dev/null 2>&1

  local wait_cmd='
    for i in {1..45}; do
      if [ -f "/etc/crowdsec/config.yaml" ] && systemctl is-active --quiet crowdsec && cscli metrics &>/dev/null; then
        exit 0
      fi
      sleep 2
    done
    exit 1'
  if ! run_with_spinner "Warte auf CrowdSec-API (bis zu 90s)..." "bash -c \"$wait_cmd\""; then
    log_error "CrowdSec-Agent konnte nicht gestartet werden oder die API antwortet nicht"
    log_info "Debug-Auszug:"
    (systemctl status crowdsec --no-pager -l 2>/dev/null || true)
    (ls -la /etc/crowdsec/ 2>/dev/null || true)
    return 1
  fi
  log_ok "CrowdSec-Agent ist erfolgreich gestartet und API ist erreichbar"

  # 5) Jetzt erst: Bouncer-Setup
  setup_crowdsec_bouncer
}

################################################################################
# OPTIONALES TUNING: SSH-Policy
################################################################################

tune_crowdsec_ssh_policy() {
  log_info "  -> Passe CrowdSec SSH-Policy an (Ban-Dauer: ${CROWDSEC_BANTIME})..."
  if [ "${CROWDSEC_BANTIME:-4h}" != "4h" ]; then
    mkdir -p /etc/crowdsec/profiles.d/
    local custom_profile="/etc/crowdsec/profiles.d/99-custom-ssh-duration.yaml"
    if [ ! -f "$custom_profile" ] || ! grep -q "duration: \"${CROWDSEC_BANTIME}\"" "$custom_profile"; then
      cat > "$custom_profile" <<EOF
name: custom_ssh_ban_duration
description: "Override default ssh ban duration"
filters:
  - "decision.scenario starts_with 'crowdsecurity/sshd-'"
decisions:
  - type: ban
    duration: "${CROWDSEC_BANTIME}"
on_success: break
EOF
      log_ok "Custom SSH-Profile mit Ban-Dauer '${CROWDSEC_BANTIME}' erstellt"
    else
      log_debug "Custom SSH-Profile bereits korrekt"
    fi
  else
    log_info "Standard CrowdSec SSH-Ban-Dauer ('4h') wird verwendet"
  fi
}

################################################################################
# KERN-FUNKTION: Bouncer-Integration
################################################################################

configure_bouncer() {
  log_info "🐾 Konfiguriere CrowdSec-Bouncer (NFTables-Integration)..."

  # Voraussetzungen
  if ! command -v nft >/dev/null 2>&1; then log_error "NFTables nicht installiert!"; return 1; fi
  if ! command -v yq  >/dev/null 2>&1; then log_error "yq nicht verfügbar!"; return 1; fi

  # Mini-Retry auf LAPI (zusätzliche Robustheit)
  for _ in {1..20}; do
    if cscli metrics >/dev/null 2>&1; then break; fi
    sleep 1
  done
  if ! cscli metrics >/dev/null 2>&1; then
    log_error "CrowdSec API ist nicht erreichbar"
    return 1
  fi

  # Bouncer-Install valide?
  local dir="/etc/crowdsec/bouncers"
  local base_yml="$dir/crowdsec-firewall-bouncer.yaml"
  if [ ! -d "$dir" ]; then
    log_warn "Bouncer-Verzeichnis fehlt - reinstalliere Bouncer-Paket..."
    if ! run_with_spinner "Reinstalliere Bouncer-Paket..." "apt-get remove --purge -y crowdsec-firewall-bouncer >/dev/null 2>&1 || true && DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer >/dev/null 2>&1"; then
      log_error "Bouncer-Reinstallation fehlgeschlagen"; return 1; fi
    log_ok "Bouncer-Paket reinstalliert"
  fi
  if [ ! -f "$base_yml" ]; then
    log_error "Base-Konfigurationsdatei nicht gefunden: $base_yml"; return 1; fi

  # nftables-Sets & YAML
  ensure_nftables_sets
  configure_bouncer_with_yq

  # Unit + Healthcheck
  create_setonly_bouncer_service

  install -m755 /dev/null /usr/local/bin/crowdsec-healthcheck
  cat > /usr/local/bin/crowdsec-healthcheck <<'EOF'
#!/bin/bash
set -euo pipefail
if ! cscli metrics >/dev/null 2>&1; then
  logger -t "crowdsec-healthcheck" -p daemon.warn "CrowdSec API nicht erreichbar - starte Services neu..."
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

  systemctl daemon-reload
  if run_with_spinner "Aktiviere Set-Only-Bouncer und Health-Check..." "systemctl enable --now crowdsec-bouncer-setonly crowdsec-healthcheck.timer"; then
    # Verifikation
    local verification_passed=true
    local local_yml="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"

    if ! systemctl is-active --quiet crowdsec-bouncer-setonly; then
      systemctl start crowdsec-bouncer-setonly || true
      sleep 5
      systemctl is-active --quiet crowdsec-bouncer-setonly || { log_error "Service konnte nicht gestartet werden!"; verification_passed=false; }
    fi

    yq eval '.nftables.ipv4."set-only"' "$local_yml" | grep -q "true" || { log_error "Set-only Modus nicht aktiviert!"; verification_passed=false; }
    [ -s "/etc/crowdsec/bouncers/.api_key" ] || { log_error "API-Key-Datei fehlt oder ist leer"; verification_passed=false; }

    if [ "$verification_passed" = true ]; then
      log_ok "CrowdSec-Bouncer erfolgreich konfiguriert (set-only aktiv)"
      log_info "  -> Health-Check läuft alle 5 Minuten"
      return 0
    else
      log_error "Bouncer-Konfiguration unvollständig!"
      return 1
    fi
  else
    log_error "Services konnten nicht gestartet werden"
    return 1
  fi
}
