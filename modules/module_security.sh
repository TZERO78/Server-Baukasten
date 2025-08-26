#!/bin/bash
################################################################################
#
# MODUL: SICHERHEITS-ARCHITEKTUR
#
# @description: Konfiguriert die mehrschichtige Sicherheitsarchitektur des Servers
#               (SSH, Firewall, IPS, GeoIP, Integritäts-Monitoring).
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################
module_security() {
    local TEST_MODE="$1"
    log_info "🔒 MODUL: Sicherheits-Architektur (Multi-Layer)"

    # Die Reihenfolge ist wichtig: Von der Basis-Härtung über die Firewall bis zur Überwachung.
    
    setup_basic_security
    
    # Diese Funktion installiert nftables, generiert die config und startet den Service.
    setup_firewall_infrastructure
    
    setup_intrusion_prevention
    
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        setup_geoip_protection
    else
        log_info "GeoIP-Blocking ist deaktiviert und wird übersprungen."
    fi
    
    setup_integrity_monitoring "$TEST_MODE"
    
    verify_security_layers
    
    log_ok "Modul Sicherheits-Architektur erfolgreich abgeschlossen."
}

##
# Stellt iptables auf nft-Backend um und sichert den nftables-Dienst ab.
##
setup_iptables_nft_backend() {
    log_info "🔗 Stelle iptables auf NFT-Backend um..."
    
    # IPv4 + IPv6 iptables auf NFT umstellen
    run_with_spinner "Konfiguriere iptables-nft..." \
        "update-alternatives --set iptables /usr/sbin/iptables-nft && \
         update-alternatives --set ip6tables /usr/sbin/ip6tables-nft"
    
    # Kurze Verifikation
    if iptables --version 2>/dev/null | grep -q "nf_tables"; then
        log_ok "iptables nutzt jetzt nf_tables-Backend"
    else
        log_warn "iptables-nft Verifikation fehlgeschlagen"
    fi

    # --- NEU: systemd Drop-in für nftables.service ---
    log_info "🛡️  Sichere den nftables-Dienst gegen unbeabsichtigtes Leeren ab..."
    
    local override_dir="/etc/systemd/system/nftables.service.d"
    local override_file="$override_dir/override.conf"

    # Verzeichnis erstellen
    mkdir -p "$override_dir"

    # Drop-in-Datei schreiben. Verhindert, dass 'systemctl stop nftables' die Regeln löscht.
    # Dies ist ein wichtiges Sicherheitsmerkmal, besonders in Produktionsumgebungen.
    cat > "$override_file" <<'EOF'
[Service]
# Standard ExecStop neutralisieren, um das Leeren der Regeln zu verhindern
ExecStop=
ExecStop=/bin/true
# Definiere einen sauberen Reload-Befehl
ExecReload=/usr/sbin/nft -f /etc/nftables.conf
EOF

    log_ok "systemd Drop-in-Datei '$override_file' erstellt."

    # systemd neu laden, um die Änderung zu übernehmen
    run_with_spinner "Lade systemd-Konfiguration neu..." "systemctl daemon-reload"
}

##
# Konfiguriert Basis-Sicherheitsmaßnahmen wie SSH-Härtung und AppArmor.
##
setup_basic_security() {
    log_info "🔐 MODUL: Basis-Sicherheit (SSH + AppArmor)"
    
    # --- SSH-Härtung ---
    log_info "  -> Konfiguriere SSH-Sicherheit..."
    backup_and_register "/etc/ssh/sshd_config"
    
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        mkdir -p "/home/$ADMIN_USER/.ssh"
        echo "$SSH_PUBLIC_KEY" > "/home/$ADMIN_USER/.ssh/authorized_keys"
        chown -R "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
        chmod 700 "/home/$ADMIN_USER/.ssh" && chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
        log_ok "SSH Public Key für '$ADMIN_USER' wurde installiert."
    fi
    
    set_config_value "/etc/ssh/sshd_config" "Port" "$SSH_PORT"
    set_config_value "/etc/ssh/sshd_config" "PasswordAuthentication" "yes"
    set_config_value "/etc/ssh/sshd_config" "PermitRootLogin" "no"
    set_config_value "/etc/ssh/sshd_config" "PubkeyAuthentication" "yes"
    
    if [ "$OS_ID" = "ubuntu" ]; then
        log_info "  -> Wende Ubuntu-spezifischen SSH-Socket-Fix an..."
        systemctl disable --now ssh.socket >/dev/null 2>&1 || true
        systemctl enable --now ssh.service >/dev/null 2>&1 || true
    fi
    
    # Verwende den Spinner für Aktionen mit spürbarer Dauer
    if ! run_with_spinner "SSH-Dienst neu starten..." "systemctl restart ssh"; then
        log_warn "Neustart des SSH-Dienstes ist fehlgeschlagen. Überprüfe den Status manuell."
    else
        log_ok "SSH auf Port $SSH_PORT gehärtet und neu gestartet."
    fi

    # --- AppArmor ---
    log_info "  -> Aktiviere AppArmor (Mandatory Access Control)..."
    run_with_spinner "AppArmor-Dienst aktivieren..." "systemctl enable --now apparmor"
    run_with_spinner "AppArmor-Profile in den 'enforce'-Modus setzen..." "aa-enforce /etc/apparmor.d/*"
    log_ok "AppArmor aktiviert und Profile in den enforce-Modus versetzt."
    
    log_ok "Modul Basis-Sicherheit erfolgreich abgeschlossen."
}
##
# Installiert und konfiguriert die NFTables-Firewall-Infrastruktur.
##
setup_firewall_infrastructure() {
    log_info "🔥 MODUL: Firewall-Infrastruktur (NFTables)"
    
    # Installation von NFTables mit Feedback
    run_with_spinner "Installiere NFTables..." "apt-get install -y nftables"
    
    # Die Funktion generate_nftables_config hat bereits eigene, passende log_* Aufrufe
    generate_nftables_config
    
    # Aktiviere und starte den NFTables-Service
    if ! run_with_spinner "Aktiviere NFTables-Service..." "systemctl enable --now nftables"; then
        log_error "NFTables-Service konnte nicht gestartet werden. Firewall ist NICHT aktiv."
        return 1
    fi
    
    # KRITISCH: Lade die generierte Konfiguration zur Laufzeit!
    if ! run_with_spinner "Lade generierte Firewall-Konfiguration..." "nft -f /etc/nftables.conf"; then
        log_error "Generierte NFTables-Konfiguration konnte nicht geladen werden!"
        return 1
    fi
    
    # Finale Überprüfung, ob die Regeln geladen sind
    if nft list tables &>/dev/null; then
        log_ok "Firewall-Infrastruktur ist bereit und die Regeln sind aktiv."
        
        # BONUS: Verifikation der kritischen Komponenten
        if nft list chain inet filter geoip_check &>/dev/null; then
            log_ok "GeoIP-Chain erfolgreich geladen und bereit."
        else
            log_warn "GeoIP-Chain nicht gefunden - GeoIP-Blocking wird möglicherweise Probleme haben."
        fi
    else
        log_error "NFTables-Regeln konnten nicht geladen werden. Firewall ist NICHT aktiv."
        return 1
    fi
}
##
# Installiert und konfiguriert das Intrusion Prevention System (CrowdSec).
##
setup_intrusion_prevention() {
    log_info "🛡️ MODUL: Intrusion Prevention System (CrowdSec)"
    
    # Die Funktion install_crowdsec_stack sollte ihre eigenen log_* Aufrufe haben.
    install_crowdsec_stack
    
    log_info "  -> Konfiguriere SSH-Schutz-Policies..."
    # Die Funktion tune_crowdsec_ssh_policy hat ebenfalls eigene log_* Aufrufe.
    tune_crowdsec_ssh_policy
    
    # Installiere die notwendigen Collections mit Feedback
    run_with_spinner "Installiere CrowdSec Collections (sshd, linux)..." \
        "cscli collections install crowdsecurity/sshd crowdsecurity/linux > /dev/null 2>&1"
    
    # Finale Überprüfung der CrowdSec-Dienste
    log_info "  -> Überprüfe CrowdSec-Service-Status..."
    if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
        log_ok "CrowdSec IPS ist aktiv und in die Firewall integriert."
    else
        log_warn "Ein oder mehrere CrowdSec-Dienste laufen nicht. Bitte manuell prüfen mit: systemctl status crowdsec crowdsec-firewall-bouncer"
    fi
}
##
# Installiert und konfiguriert die geografische Bedrohungsabwehr (GeoIP).
##
setup_geoip_protection() {
    log_info "🌍 MODUL: Geografische Bedrohungsabwehr (GeoIP)"

    log_info "  -> Validiere GeoIP-Konfiguration..."
    if ! is_valid_country_list "$BLOCKED_COUNTRIES"; then
        log_error "Ungültige Ländercodes in der Blocklist: $BLOCKED_COUNTRIES"
        log_warn "GeoIP-Blocking wird übersprungen!"
        return 1
    fi
    if [ -n "$HOME_COUNTRY" ] && ! is_valid_country_code "$HOME_COUNTRY"; then
        log_error "Ungültiger Ländercode für das Heimatland: $HOME_COUNTRY"
        log_warn "GeoIP-Blocking wird übersprungen!"
        return 1
    fi
    if echo "$BLOCKED_COUNTRIES" | grep -wq "$HOME_COUNTRY"; then
        log_warn "KONFLIKT: Heimatland ($HOME_COUNTRY) wurde in der Blocklist gefunden!"
        BLOCKED_COUNTRIES=$(echo "$BLOCKED_COUNTRIES" | sed "s/\b$HOME_COUNTRY\b//g" | tr -s ' ' | sed 's/^ *//; s/ *$//')
        log_ok "Heimatland wurde automatisch aus der Blocklist entfernt."
        log_info "     Bereinigte Blocklist: $BLOCKED_COUNTRIES"
    fi
    
    # Die aufgerufene Funktion `configure_geoip_system` sollte ihr eigenes, detailliertes Logging haben.
    configure_geoip_system
    
    # Warte auf die Erstellung der 'geoip_check'-Chain durch das Neuladen der Firewall
    local wait_cmd="
        local retries=30;
        while ! nft list chain inet filter geoip_check &>/dev/null; do
            ((retries--));
            if [ \$retries -le 0 ]; then exit 1; fi;
            sleep 1;
        done"
    
    if run_with_spinner "Warte auf Erstellung der GeoIP-Firewall-Chain..." "$wait_cmd"; then
        log_ok "GeoIP-Chain 'geoip_check' wurde erfolgreich in der Firewall erstellt."
    else
        log_warn "GeoIP-Chain konnte nicht sofort verifiziert werden. Dies kann bei hoher Systemlast normal sein."
    fi
    
    log_ok "Geografische Bedrohungsabwehr ist konfiguriert."
    log_info "  🏠 Geschütztes Heimatland: $HOME_COUNTRY"
    log_info "  🚫 Blockierte Länder: $BLOCKED_COUNTRIES"
    log_info "  📊 Verwaltung mit: geoip-manager status"
}

##
# MODUL: Installiert, konfiguriert und initialisiert das
#        System-Integritäts-Monitoring (AIDE & RKHunter).
##
setup_integrity_monitoring() {
    local TEST_MODE="$1"
    log_info "📊 MODUL: System-Integritäts-Monitoring"

    # TEST-MODUS: Dieses Modul ist sehr zeitaufwändig und wird daher komplett übersprungen.
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS: Überspringe Integritäts-Monitoring komplett (AIDE & RKHunter)."
        return 0
    fi

    # --- Schritt 1/4: Basispakete installieren ---
    log_info "  -> 1/4: Installiere Basispakete..."
    run_with_spinner "Installiere aide & rkhunter..." "apt-get install -y aide rkhunter"

    # --- Schritt 2/4: Tools konfigurieren (legt .conf-Dateien und Timer an) ---
    log_info "  -> 2/4: Konfiguriere AIDE und RKHunter..."
    configure_aide
    configure_rkhunter

    # --- Schritt 3/4: Datenbanken einmalig initialisieren ---
    log_info "  -> 3/4: Initialisiere Datenbanken (dies kann einige Minuten dauern)..."
    if run_with_spinner "Initialisiere AIDE-Datenbank..." "/usr/bin/aide --config /etc/aide/aide.conf --init"; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        log_ok "AIDE-Datenbank erfolgreich initialisiert."
    else
        log_warn "AIDE-Initialisierung fehlgeschlagen. Der Timer wird es später erneut versuchen."
    fi
    
    run_with_spinner "Aktualisiere RKHunter-Properties..." "rkhunter --propupd --quiet || true"

    # --- Schritt 4/4: Timer für den regulären Betrieb starten ---
    log_info "  -> 4/4: Starte die Timer für die regelmäßigen Scans..."
    if ! run_with_spinner "Starte AIDE-Timer..." "systemctl start aide-check.timer"; then
        log_warn "AIDE-Timer konnte nicht gestartet werden."
    fi
    if ! run_with_spinner "Starte RKHunter-Timer..." "systemctl start rkhunter-check.timer"; then
        log_warn "RKHunter-Timer konnte nicht gestartet werden."
    fi

    log_ok "Integritäts-Monitoring konfiguriert und Timer gestartet."
}

##
# Verifiziert die korrekte Funktion aller installierten Sicherheitsschichten.
# @return int Anzahl der erkannten kritischen Fehler.
##
verify_security_layers() {
    log_info "🔍 MODUL: Verifikation der Sicherheitsarchitektur"
    
    # WICHTIG: Deaktiviere set -e für Verifikation, damit das Skript bei Fehlern nicht abbricht
    local old_errexit=$(set +o | grep errexit)
    set +e
    
    local security_status=0 # Zählt kritische Fehler
    
    # --- LAYER 1: BASIS-FIREWALL (NFTables + Core-Security) ---
    log_info "  -> Teste Layer 1: Basis-Firewall..."
    if systemctl is-active --quiet nftables; then
        log_ok "Layer 1: NFTables-Service ist aktiv."
    else
        log_error "Layer 1: NFTables-Service ist NICHT aktiv!"
        ((security_status++))
    fi

    local input_policy=$(nft list chain inet filter input 2>/dev/null | grep "policy" | awk '{print $NF}' | tr -d ';' || echo "unbekannt")
    if [ "$input_policy" = "drop" ]; then
        log_ok "Layer 1: Firewall Drop-Policy ist aktiv."
    else
        log_error "Layer 1: Firewall Policy ist NICHT 'drop' (sondern '$input_policy')."
        ((security_status++))
    fi

    local ssh_port="${SSH_PORT:-22}"
    if systemctl is-active --quiet ssh && ss -tln | grep -q ":$ssh_port "; then
        log_ok "Layer 1: SSH-Service ist aktiv auf Port $ssh_port."
    else
        log_error "Layer 1: SSH-Service hat ein Problem oder Port $ssh_port ist nicht erreichbar."
        ((security_status++))
    fi
        
    # --- LAYER 2: CROWDSEC IPS ---
    log_info "  -> Teste Layer 2: CrowdSec IPS..."
    if command -v crowdsec >/dev/null 2>&1; then
        if systemctl is-active --quiet crowdsec; then
            log_ok "Layer 2: CrowdSec-Engine ist aktiv."
        else
            log_error "Layer 2: CrowdSec-Engine ist NICHT aktiv!"
            ((security_status++))
        fi
        
        if systemctl is-active --quiet crowdsec-firewall-bouncer; then
            log_ok "Layer 2: CrowdSec-Bouncer ist aktiv."
        else
            log_error "Layer 2: CrowdSec-Bouncer ist NICHT aktiv!"
            ((security_status++))
        fi
        
        if nft list table ip crowdsec >/dev/null 2>&1; then
            log_ok "Layer 2: CrowdSec-NFTables-Integration (IPv4) ist aktiv."
        else
            log_error "Layer 2: CrowdSec-NFTables-Integration (IPv4) fehlt!"
            ((security_status++))
        fi

        if nft list table ip6 crowdsec6 >/dev/null 2>&1; then
            log_ok "Layer 2: CrowdSec-NFTables-Integration (IPv6) ist aktiv."
        else
            log_warn "Layer 2: CrowdSec-NFTables-Integration (IPv6) fehlt."
        fi
    else
        log_info "Layer 2: CrowdSec ist nicht installiert (übersprungen)."
    fi
    
    # --- LAYER 3: GEOIP-BLOCKING ---
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        log_info "  -> Teste Layer 3: GeoIP-Blocking..."
        log_info "     Detaillierte GeoIP-Verifikation mit: geoip-manager status"
        
        if systemctl is-active --quiet geoip-update.timer; then
            log_ok "Layer 3: GeoIP-Timer ist aktiv."
        else
            log_error "Layer 3: GeoIP-Timer ist NICHT aktiv!"
            ((security_status++))
        fi
        
        if nft list chain inet filter geoip_check >/dev/null 2>&1; then
            log_ok "Layer 3: GeoIP-Chain existiert in der Firewall."
        else
            log_error "Layer 3: GeoIP-Chain fehlt in der Firewall!"
            ((security_status++))
        fi
    else
        log_info "  -> Teste Layer 3: GeoIP-Blocking... (übersprungen, da deaktiviert)."
    fi

    # --- LAYER 4: SSH-HÄRTUNG & APPARMOR ---
    log_info "  -> Teste Layer 4: SSH-Härtung & AppArmor..."
    if systemctl is-active --quiet ssh; then
        log_ok "Layer 4: SSH-Service ist aktiv."
    else
        log_error "Layer 4: SSH-Service ist NICHT aktiv!"
        ((security_status++))
    fi
    
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
        log_ok "Layer 4: SSH-Root-Login ist deaktiviert."
    else
        log_warn "Layer 4: SSH-Root-Login ist noch aktiv."
    fi
    
    if systemctl is-active --quiet apparmor; then
        local enforced_profiles=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
        log_ok "Layer 4: AppArmor ist aktiv ($enforced_profiles Profile im enforce mode)."
    else
        log_error "Layer 4: AppArmor ist NICHT aktiv!"
        ((security_status++))
    fi

    # --- ABSCHLUSS-BEWERTUNG ---
    echo "" # Leere Zeile für die Lesbarkeit
    if [ "$security_status" -eq 0 ]; then
        log_ok "Alle Sicherheits-Checks bestanden. Die Multi-Layer-Security-Architektur ist vollständig funktional."
    elif [ "$security_status" -le 2 ]; then
        log_warn "$security_status kleinere Sicherheitsproblem(e) erkannt. System ist grundsätzlich sicher."
    else
        log_error "$security_status kritische(s) Sicherheitsproblem(e) erkannt. Bitte die Ausgabe oben prüfen!"
    fi
    
    # set -e wieder aktivieren
    eval "$old_errexit"
    
    return $security_status
}



# ===============================================================================
#          MODULARE & DYNAMISCHE NFTABLES-GENERIERUNG
# ===============================================================================

##
# Erkennt den aktuellen Systemzustand (Netzwerk-Interfaces, aktive Dienste wie Docker/Tailscale).
# @return string Ein String mit erkannten Werten zur Verwendung mit 'source'.
##
detect_system_state() {
    local primary_interface=""
    if command -v ip &>/dev/null; then
        primary_interface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -n1)
    fi
    if [ -z "$primary_interface" ]; then
        primary_interface=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1)
    fi
    if [ -z "$primary_interface" ]; then
        primary_interface=$(ls /sys/class/net/ | grep -E '^(eth|ens|enp)' | head -n1)
    fi
    
    local docker_active="false"
    local docker_interface_exists="false"
    if systemctl is-active --quiet docker && command -v docker &>/dev/null; then
        docker_active="true"
        if ip link show docker0 &>/dev/null; then
            docker_interface_exists="true"
        fi
    fi
    
    local tailscale_active="false"
    local tailscale_interface=""
    if command -v tailscale &>/dev/null && tailscale status &>/dev/null; then
        tailscale_active="true"
        tailscale_interface=$(ip link show | grep -E '^[0-9]+: tailscale[0-9]*:' | head -n1 | cut -d: -f2 | tr -d ' ')
        if [ -z "$tailscale_interface" ]; then
            tailscale_interface="tailscale0"
        fi
    fi
    
    cat <<EOF
PRIMARY_INTERFACE="$primary_interface"
DOCKER_ACTIVE="$docker_active"
DOCKER_INTERFACE_EXISTS="$docker_interface_exists"
TAILSCALE_ACTIVE="$tailscale_active"
TAILSCALE_INTERFACE="$tailscale_interface"
EOF
}

# ===============================================================================
#          MODULARE & DYNAMISCHE NFTABLES-GENERIERUNG (FINAL v3.2)
#
#   Dieser Block implementiert die Best Practice für nftables:
#   - /etc/nftables.conf ist nur noch ein minimalistischer Lader.
#   - Die eigentlichen Regeln liegen in /etc/nftables.d/
#   - Dies verhindert Konflikte mit Docker und anderen Diensten.
# ===============================================================================

##
# Generiert die GeoIP-Set-Definitionen in der Regeldatei.
##
generate_geoip_sets_section() {
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        cat << 'GEOIP_SETS'
    # GeoIP-Sets für die geografische Filterung
    set geoip_blocked_v4 { type ipv4_addr; flags interval; }
    set geoip_blocked_v6 { type ipv6_addr; flags interval; }
    set geoip_home_v4 { type ipv4_addr; flags interval; }
    set geoip_home_v6 { type ipv6_addr; flags interval; }
    set geoip_allowlist_v4 { type ipv4_addr; flags interval; }
    set geoip_allowlist_v6 { type ipv6_addr; flags interval; }

    # GeoIP-Chain, in die gesprungen wird
    chain geoip_check {}
GEOIP_SETS
    fi
}

##
# Generiert die 'jump'-Regel zur GeoIP-Chain.
##
generate_geoip_jump_section() {
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        cat << 'EOF'
        # STUFE 3: Geografische Filterung
        jump geoip_check comment "GeoIP-Filter"
EOF
    fi
}

##
# Erlaubt eingehenden Traffic von der Tailscale-Schnittstelle.
##
generate_tailscale_input_section() {
    if [ "$TAILSCALE_ACTIVE" = "true" ] && [ -n "$TAILSCALE_INTERFACE" ]; then
        cat << EOF
        iifname "$TAILSCALE_INTERFACE" accept comment "Input vom Tailscale-Interface"
EOF
    fi
}

##
# Konfiguriert das Forwarding für Tailscale (z.B. Subnet-Routing).
##
generate_tailscale_forward_section() {
    if [ "$TAILSCALE_ACTIVE" = "true" ] && [ -n "$TAILSCALE_INTERFACE" ]; then
        cat << EOF
        # Erlaube Traffic vom VPN in andere Netze und etablierte Antworten
        iifname "$TAILSCALE_INTERFACE" accept comment "Forward vom Tailscale-Interface"
        oifname "$TAILSCALE_INTERFACE" ct state related,established accept comment "Forward-Antworten an Tailscale"
EOF
    fi
}

##
# Generiert die NAT-Regel für Tailscale (Subnet-Routing / Exit-Node).
##
generate_tailscale_nat_section() {
    # Diese Funktion wird nur aufgerufen, wenn Tailscale aktiv ist.
    cat << EOF
        oifname "$PRIMARY_INTERFACE" iifname "$TAILSCALE_INTERFACE" masquerade comment "Tailscale NAT für Subnet-Routing/Exit-Node"
EOF
}

##
# NEU: Schreibt die eigentlichen Baukasten-Regeln in eine separate Datei.
##
generate_baukasten_rules_file() {
    log_info "  -> Erstelle Baukasten-Regeldatei in /etc/nftables.d/..."
    local rules_file="/etc/nftables.d/10-server-baukasten.conf"

    # System-Zustand für Variablen wie TAILSCALE_ACTIVE etc. ermitteln
    local system_state; system_state=$(detect_system_state); source <(echo "$system_state")

    # Schreibe die Filter-Regeln
    cat > "$rules_file" <<EOF
# =============================================================================
# SERVER-BAUKASTEN BASIS-REGELN (v4.0)
# =============================================================================

# Haupt-Filtertabelle für den Baukasten
table inet filter {
$(generate_geoip_sets_section)

    # -------------------------------------------------------------------------
    # INPUT-CHAIN: Eingehender Traffic zum Server selbst (Priority 10)
    # -------------------------------------------------------------------------
    chain input {
        type filter hook input priority 10; policy drop;

        # STUFE 1: Erlaubte etablierte und ungültige Verbindungen
        ct state established,related accept comment "Aktive Verbindungen"
        ct state invalid drop comment "Ungültige Pakete"

        # STUFE 2: Vertrauenswürdige Quellen (Loopback, VPN)
        iifname "lo" accept comment "Loopback"
$(generate_tailscale_input_section)

$(generate_geoip_jump_section)

        # STUFE 4: Explizit freigegebene öffentliche Dienste
        tcp dport ${SSH_PORT} accept comment "SSH-Zugang"
        ip protocol icmp accept comment "IPv4 Ping"
        ip6 nexthdr ipv6-icmp accept comment "IPv6 Ping"
    }

    # -------------------------------------------------------------------------
    # FORWARD-CHAIN: Traffic zwischen Interfaces (Priority 10)
    # -------------------------------------------------------------------------
    chain forward {
        type filter hook forward priority 10; policy drop;
        ct state established,related accept comment "Aktive Forward-Verbindungen"
$(generate_tailscale_forward_section)
    }

    # -------------------------------------------------------------------------
    # OUTPUT-CHAIN: Ausgehender Traffic vom Server (Priority 10)
    # -------------------------------------------------------------------------
    chain output {
        type filter hook output priority 10; policy accept;
    }
}
EOF

    # --- Hänge die separate NAT-Tabelle NUR für Tailscale an ---
    if [ "${ACCESS_MODEL:-2}" = "1" ] && [ "$TAILSCALE_ACTIVE" = "true" ] && [ -n "$TAILSCALE_INTERFACE" ]; then
        cat >> "$rules_file" <<EOF
# =============================================================================
# NAT-TABELLE (NUR für Tailscale Subnet Routing / Exit Node)
# =============================================================================
table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
$(generate_tailscale_nat_section)
    }
}
table ip6 nat {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
$(generate_tailscale_nat_section)
    }
}
EOF
        log_info "  -> NAT-Regeln für Tailscale wurden zur Regeldatei hinzugefügt."
    fi
}


##
# FINAL (v4.0): Erstellt die modulare Grundstruktur für nftables.
##
generate_nftables_config() {
    log_info "🔥 Erstelle modulare NFTables-Konfiguration (produktionssicher)..."

    # 1. Sicherstellen, dass das Verzeichnis für modulare Regeln existiert
    mkdir -p /etc/nftables.d

    # 2. Die Haupt-Konfigurationsdatei wird zu einem simplen Lader
    cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f

# ==========================================================================
# SERVER-BAUKASTEN HAUPT-KONFIGURATION (v4.0)
# ==========================================================================
# Diese Datei ist nur der Lader. Die eigentlichen Regeln liegen in
# /etc/nftables.d/ und werden von dort eingebunden.
#
# Dieses Setup verhindert Konflikte mit Diensten wie Docker, CrowdSec etc.
# ==========================================================================

# Leere die Konfiguration nur EINMALIG bei einem kompletten Neustart des
# nftables.service, um einen sauberen Zustand zu garantieren.
# Bei einem 'reload' wird dies NICHT ausgeführt, was Docker schützt.
flush ruleset

# Lade alle Konfigurations-Snippets aus dem .d Verzeichnis
include "/etc/nftables.d/*.conf"
EOF

    # 3. Erstelle unsere eigene, detaillierte Regel-Datei
    generate_baukasten_rules_file

    log_ok "Modulare NFTables-Struktur erfolgreich erstellt."

    # 4. Syntax-Validierung (nft prüft die Hauptdatei inklusive aller includes)
    if ! nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
        log_error "SYNTAX-FEHLER in der generierten NFTables-Konfiguration!"
        return 1
    fi
    log_ok "Syntax-Validierung der gesamten Konfiguration erfolgreich."
}