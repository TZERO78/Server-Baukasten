#!/bin/bash
################################################################################
#
# BIBLIOTHEK: CROWDSEC-HELFER-FUNKTIONEN (MODERNISIERT, yq v4)
#
# @description: Installation und Konfiguration des CrowdSec-Agenten + Firewall-
#               Bouncer im "set-only"-Modus mit NFTables. Unterstützt Debian
#               Bookworm & Trixie. Robuste API-Checks, Healthcheck-Timer.
# @author:      Markus F. (TZERO78) & KI
# @repository:  https://github.com/TZERO78/Server-Baukasten
# @license:     MIT
#
################################################################################

##
# Setup CrowdSec-Bouncer (erst nach laufender CrowdSec-API)
##
setup_crowdsec_bouncer() {
    log_info "🐾 Setup CrowdSec Bouncer..."
    # bis zu 30s warten, bis LAPI läuft
    for i in {1..30}; do
        if systemctl is-active --quiet crowdsec && cscli metrics >/dev/null 2>&1; then
            configure_bouncer
            return $?
        fi
        sleep 1
    done
    log_error "CrowdSec-Service oder API nicht verfügbar - Bouncer-Setup übersprungen"
    return 1
}

##
# Installiert CrowdSec für Debian Trixie aus offiziellen Repositories
##
install_crowdsec_for_trixie() {
    log_info "  -> Installiere CrowdSec aus offiziellen Trixie-Repositories..."
    install_packages_safe crowdsec crowdsec-firewall-bouncer
    
    # Bekannter Debian-Paket-Bug: Config-Dateien fehlen manchmal
    if [ ! -f "/etc/crowdsec/config.yaml" ] || [ ! -d "/etc/crowdsec" ]; then
        log_warn "Debian-Paket-Bug erkannt - führe Cleanup-Neuinstallation durch..."
        apt-get remove --purge crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
        rm -rf /etc/crowdsec /var/lib/crowdsec 2>/dev/null || true
        install_packages_safe crowdsec crowdsec-firewall-bouncer
        
        if [ ! -f "/etc/crowdsec/config.yaml" ]; then
            log_error "CrowdSec-Installation fehlgeschlagen - auch nach Cleanup"
            return 1
        fi
        log_ok "CrowdSec nach Cleanup erfolgreich installiert"
    else
        log_ok "CrowdSec aus offiziellen Debian-Repositories installiert"
    fi
}

##
# Installiert CrowdSec für Debian Bookworm (mit Wahlmöglichkeit)
##
install_crowdsec_for_bookworm() {
    log_info "  -> Installiere CrowdSec für Bookworm..."
    
    if [ "${CROWDSEC_USE_OFFICIAL_REPO:-true}" = "true" ]; then
        log_info "     📦 Nutze offizielle Bookworm-Repositories (v1.4.6-6~deb12u1)"
        install_packages_safe crowdsec crowdsec-firewall-bouncer
    else
        log_info "     📦 Nutze externes packagecloud.io Repository (neueste Version)"
        setup_crowdsec_external_repository
        install_packages_safe crowdsec crowdsec-firewall-bouncer
    fi
    
    # Bekannter Debian-Paket-Bug: Config-Dateien fehlen manchmal
    if [ ! -f "/etc/crowdsec/config.yaml" ] || [ ! -d "/etc/crowdsec" ]; then
        log_warn "Debian-Paket-Bug erkannt - führe Cleanup-Neuinstallation durch..."
        apt-get remove --purge crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
        rm -rf /etc/crowdsec /var/lib/crowdsec 2>/dev/null || true
        
        # Nochmal mit derselben Methode installieren
        if [ "${CROWDSEC_USE_OFFICIAL_REPO:-true}" = "true" ]; then
            install_packages_safe crowdsec crowdsec-firewall-bouncer
        else
            setup_crowdsec_external_repository
            install_packages_safe crowdsec crowdsec-firewall-bouncer
        fi
        
        if [ ! -f "/etc/crowdsec/config.yaml" ]; then
            log_error "CrowdSec-Installation fehlgeschlagen - auch nach Cleanup"
            return 1
        fi
        log_ok "CrowdSec nach Cleanup erfolgreich installiert"
    else
        log_ok "CrowdSec für Bookworm installiert"
    fi
}

# nutzt detect_os_version(): gibt "os_id os_version os_codename" aus
install_crowdsec_by_detected_os() {
  local os_id os_version os_codename
  # robust lesen + normalisieren (lowercase, whitespace raus)
  read -r os_id os_version os_codename < <(detect_os_version)
  os_id="${os_id,,}"; os_codename="${os_codename,,}"
  os_id="${os_id//[[:space:]]/}"; os_codename="${os_codename//[[:space:]]/}"

  log_info "  -> Erkannter Host: id='${os_id}' version='${os_version}' codename='${os_codename}'"

  case "${os_id}:${os_codename}" in
    debian:trixie)
      log_info "Debian Trixie erkannt – nutze **offizielle Debian-Pakete** (kein externes Repo)."
      install_crowdsec_for_trixie
      ;;

    debian:bookworm)
      log_info "Debian Bookworm erkannt."
      install_crowdsec_for_bookworm    # darf optional externes Repo nutzen, je nach Flag in deiner Funktion
      ;;

    debian:*)
      log_warn "Debian, aber unbekannter Codename: '${os_codename}' – nutze Fallback (externes Repo)."
      setup_crowdsec_external_repository
      install_packages_safe crowdsec crowdsec-firewall-bouncer
      ;;

    *)
      log_warn "Nicht-Debian oder unbekanntes OS ('${os_id}'). Versuche Fallback über externes Repo."
      setup_crowdsec_external_repository
      install_packages_safe crowdsec crowdsec-firewall-bouncer
      ;;
  esac
}

##
# Externes CrowdSec-Repo einrichten
##
setup_crowdsec_external_repository() {
    if [ -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then
        log_debug "CrowdSec-Repository bereits vorhanden"
        return 0
    fi
    log_info "     -> Füge CrowdSec APT-Repository hinzu..."
    local script="/tmp/crowdsec-install.sh"
    if ! curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh -o "$script"; then
        log_error "Download des CrowdSec-Repo-Skripts fehlgeschlagen"
        return 1
    fi
    if ! grep -q "packagecloud" "$script"; then
        log_error "CrowdSec-Repo-Skript ungültig"
        rm -f "$script"; return 1
    fi
    if run_with_spinner "Richte APT-Repo ein..." "bash '$script' && apt-get update -qq"; then
        log_ok "CrowdSec-Repository eingerichtet"
    else
        log_error "CrowdSec-Repository-Setup fehlgeschlagen"
        rm -f "$script"; return 1
    fi
    rm -f "$script"
}

##
# NFTables-Sets erstellen
##
ensure_nftables_sets() {
    log_info "  -> Stelle NFTables-Sets sicher..."
    if ! nft list set ip crowdsec crowdsec-blacklists >/dev/null 2>&1; then
        nft add table ip crowdsec 2>/dev/null || true
        nft add set ip crowdsec crowdsec-blacklists '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
        log_debug "IPv4-Set erstellt"
    fi
    if ! nft list set ip6 crowdsec6 crowdsec6-blacklists >/dev/null 2>&1; then
        nft add table ip6 crowdsec6 2>/dev/null || true
        nft add set ip6 crowdsec6 crowdsec6-blacklists '{ type ipv6_addr; flags interval; }' 2>/dev/null || true
        log_debug "IPv6-Set erstellt"
    fi
    log_ok "NFTables-Sets verfügbar"
}

##
# Bouncer YAML mit yq v4 konfigurieren
##
configure_bouncer_with_yq() {
    log_info "  -> Konfiguriere Bouncer YAML..."
    local dir="/etc/crowdsec/bouncers"
    local base="$dir/crowdsec-firewall-bouncer.yaml"
    local localf="$dir/crowdsec-firewall-bouncer.yaml.local"
    local keyfile="$dir/.api_key"

    # Config kopieren
    [ ! -f "$localf" ] || [ "$base" -nt "$localf" ] && cp "$base" "$localf"

    # API-Key erzeugen
    if [ ! -s "$keyfile" ]; then
        install -o root -g root -m600 /dev/null "$keyfile"
        local bname="firewall-bouncer-$(hostname -s)"
        cscli bouncers add "$bname" -o raw >"$keyfile" || { log_error "API-Key fehlgeschlagen"; return 1; }
    fi
    local api_key; api_key=$(tr -d '\n\r' <"$keyfile")

    # Werte setzen (mit Quotes für set-only)
    API_KEY="$api_key" yq e -i '.api_key = env(API_KEY)' "$localf"
    yq e -i '.mode = "nftables"' "$localf"
    yq e -i '.log_level = "info"' "$localf"
    yq e -i '.update_frequency = "30s"' "$localf"
    yq e -i '.disable_ipv6 = false' "$localf"

    yq e -i '.nftables.ipv4.enabled = true' "$localf"
    yq e -i '.nftables.ipv4."set-only" = true' "$localf"
    yq e -i '.nftables.ipv4.table = "crowdsec"' "$localf"
    yq e -i '.nftables.ipv4.chain = "crowdsec-chain"' "$localf"
    yq e -i '.blacklists_ipv4 = "crowdsec-blacklists"' "$localf"

    yq e -i '.nftables.ipv6.enabled = true' "$localf"
    yq e -i '.nftables.ipv6."set-only" = true' "$localf"
    yq e -i '.nftables.ipv6.table = "crowdsec6"' "$localf"
    yq e -i '.nftables.ipv6.chain = "crowdsec6-chain"' "$localf"
    yq e -i '.blacklists_ipv6 = "crowdsec6-blacklists"' "$localf"

    /usr/bin/crowdsec-firewall-bouncer -c "$localf" -t >/dev/null 2>&1 \
        && log_ok "Bouncer-Config gültig" || { log_error "Bouncer-Config fehlerhaft"; return 1; }
}

##
# Systemd-Service für Set-Only-Bouncer
##
create_setonly_bouncer_service() {
    log_info "  -> Erstelle Systemd-Service für Bouncer..."
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

##
# Hauptinstallation CrowdSec + Bouncer
##
install_crowdsec_stack() {
    log_info "⚙️  Installiere CrowdSec-Stack..."
	set -x # Debugging an
    # OS erkennen und CrowdSec installieren
    install_crowdsec_by_detected_os || {
        log_error "CrowdSec-Installation fehlgeschlagen"
        return 1
    }

    # CrowdSec Service fixen
    mkdir -p /etc/systemd/system/crowdsec.service.d
    cat >/etc/systemd/system/crowdsec.service.d/override.conf <<EOF
[Unit]
After=network.target
[Service]
Restart=on-failure
RestartSec=30s
EOF

    # CrowdSec starten
    systemctl daemon-reload
    systemctl enable --now crowdsec >/dev/null 2>&1
    local wait='for i in {1..45}; do if systemctl is-active --quiet crowdsec && cscli metrics >/dev/null 2>&1; then exit 0; fi; sleep 2; done; exit 1'
    run_with_spinner "Warte auf CrowdSec-API..." "bash -c \"$wait\"" || { log_error "CrowdSec-Start fehlgeschlagen"; return 1; }

    log_ok "CrowdSec läuft"
    setup_crowdsec_bouncer
}

##
# Bouncer konfigurieren (mit Healthcheck-Timer)
##
configure_bouncer() {
    log_info "🐾 Konfiguriere Bouncer..."
    ensure_nftables_sets
    configure_bouncer_with_yq
    create_setonly_bouncer_service

    # Healthcheck
    install -m755 /dev/null /usr/local/bin/crowdsec-healthcheck
    cat >/usr/local/bin/crowdsec-healthcheck <<'EOF'
#!/bin/bash
set -euo pipefail
if ! cscli metrics >/dev/null 2>&1; then
  logger -t "crowdsec-healthcheck" -p daemon.warn "CrowdSec API down - restart..."
  systemctl restart crowdsec crowdsec-bouncer-setonly
fi
EOF
    cat >/etc/systemd/system/crowdsec-healthcheck.service <<'EOF'
[Unit]
Description=CrowdSec Health-Check
After=crowdsec.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/crowdsec-healthcheck
User=root
EOF
    cat >/etc/systemd/system/crowdsec-healthcheck.timer <<'EOF'
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
    systemctl enable --now crowdsec-healthcheck.timer
    log_ok "Healthcheck-Timer aktiv"
}
