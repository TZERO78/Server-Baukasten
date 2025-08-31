#!/bin/bash
################################################################################
#
# BIBLIOTHEK: FIREWALL-HELFER-FUNKTIONEN (v4.2)
#
# @description: Modulare NFTables-Konfiguration basierend auf CONFIG, nicht Systemzustand
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
################################################################################

##
# Stellt iptables auf nft-Backend um und sichert den nftables-Dienst ab.
# Lädt Kernel-Module intelligent, basierend auf der Kernel-Unterstützung.
##
setup_iptables_nft_backend() {
    log_info "🔗 Konfiguriere Firewall-Backend (iptables-nft & Module)..."
    
    # --- 1. Installation sicherstellen ---
    run_with_spinner "Installiere iptables-Pakete..." \
        "apt-get install -y iptables ip6tables netfilter-persistent iptables-persistent"

    # --- 2. Kernel-Module intelligent laden & registrieren ---
    log_info "  -> Prüfe und lade benötigte Kernel-Module..."
    
    # Wir definieren die Module getrennt nach IPv4 und IPv6
    local base_modules=("nf_nat" "nft_masq" "nft_nat")
    local ipv6_nat_modules=("ip6table_nat" "ip6t_MASQUERADE")
    
    # Die /etc/modules-load.d/-Datei wird jetzt schrittweise aufgebaut
    local modules_conf="/etc/modules-load.d/99-server-baukasten-nat.conf"
    echo "# Automatisch generiert vom Server-Baukasten" > "$modules_conf"
    echo "# Basis-Module für NAT" >> "$modules_conf"
    printf '%s\n' "${base_modules[@]}" >> "$modules_conf"

    # Basis-Module immer laden
    for module in "${base_modules[@]}"; do
        modprobe "$module" 2>/dev/null || true
    done

    # IPv6-NAT-Module nur laden, wenn vom Kernel unterstützt
    if [ "$(check_ipv6_nat_kernel)" = "true" ]; then
        log_info "  -> IPv6-NAT-Unterstützung im Kernel gefunden. Lade entsprechende Module..."
        echo "# IPv6-NAT-Module (vom Kernel unterstützt)" >> "$modules_conf"
        printf '%s\n' "${ipv6_nat_modules[@]}" >> "$modules_conf"

        for module in "${ipv6_nat_modules[@]}"; do
            if modprobe "$module" 2>/dev/null; then
                log_ok "Kernel-Modul '$module' geladen."
            else
                log_debug "Konnte '$module' nicht laden, obwohl Support erkannt wurde."
            fi
        done
    else
        log_warn "Keine IPv6-NAT-Unterstützung im Kernel erkannt. Überspringe IPv6-NAT-Module."
    fi

    # --- 3. IPv4 + IPv6 iptables auf NFT umstellen ---
    run_with_spinner "Konfiguriere iptables-nft..." \
        "update-alternatives --set iptables /usr/sbin/iptables-nft && \
         update-alternatives --set ip6tables /usr/sbin/ip6tables-nft"
    
    # --- 4. Verifikation ---
    if iptables --version 2>/dev/null | grep -q "nf_tables"; then
        log_ok "iptables nutzt jetzt nf_tables-Backend"
    else
        log_warn "iptables-nft Verifikation fehlgeschlagen"
    fi

    # --- 5. systemd Drop-in für nftables.service ---
    log_info "  -> Sichere den nftables-Dienst gegen unbeabsichtigtes Leeren ab..."
    
    local override_dir="/etc/systemd/system/nftables.service.d"
    local override_file="$override_dir/override.conf"

    mkdir -p "$override_dir"

    cat > "$override_file" <<'EOF'
[Service]
# Standard ExecStop neutralisieren, um das Leeren der Regeln zu verhindern
ExecStop=
ExecStop=/bin/true
# Definiere einen sauberen Reload-Befehl
ExecReload=/usr/sbin/nft -f /etc/nftables.conf
EOF

    log_ok "systemd Drop-in-Datei '$override_file' erstellt."
    run_with_spinner "Lade systemd-Konfiguration neu..." "systemctl daemon-reload"
}

# ===============================================================================
#          MODULARE NFTABLES-GENERIERUNG (v4.2) - CONFIG-BASIERT
# ===============================================================================

##
# Erstellt die Basis-Filter-Regeln (Loopback, established, etc.)
##
generate_base_filter_rules() {
    local rules_file="/etc/nftables.d/10-base-filter.conf"
    log_info "  -> Erstelle Basis-Filter-Regeln..."
    
    cat > "$rules_file" <<'EOF'
# =============================================================================
# BASIS-FILTER-REGELN (Kern-Sicherheit)
# =============================================================================

table inet filter {
    # -------------------------------------------------------------------------
    # INPUT-CHAIN: Eingehender Traffic zum Server selbst (Priority -1)
    # -------------------------------------------------------------------------
    chain input {
        type filter hook input priority -1; policy drop;

        # STUFE 1: Erlaubte etablierte und ungültige Verbindungen
        ct state established,related accept comment "Aktive Verbindungen"
        ct state invalid drop comment "Ungültige Pakete"

        # STUFE 2: Vertrauenswürdige Quellen (Loopback)
        iifname "lo" accept comment "Loopback"
        
        # Weitere Regeln werden von anderen Modulen hinzugefügt
    }

    # -------------------------------------------------------------------------
    # FORWARD-CHAIN: Traffic zwischen Interfaces (Priority -1)
    # -------------------------------------------------------------------------
    chain forward {
        type filter hook forward priority -1; policy drop;
        ct state established,related accept comment "Aktive Forward-Verbindungen"
        
        # Weitere Forward-Regeln werden von anderen Modulen hinzugefügt
    }

    # -------------------------------------------------------------------------
    # OUTPUT-CHAIN: Ausgehender Traffic vom Server (Priority -1)
    # -------------------------------------------------------------------------
    chain output {
        type filter hook output priority -1; policy accept;
    }
}
EOF
}

##
# Erstellt die GeoIP-Regeln und Sets (basierend auf CONFIG)
##
generate_geoip_rules() {
  [ "${ENABLE_GEOIP_BLOCKING:-nein}" != "ja" ] && return 0

  local f="/etc/nftables.d/20-geoip.conf"
  log_info "  -> Erstelle GeoIP-Blocking-Regeln..."

  cat > "$f" <<'EOF'
# =============================================================================
# GEOIP-BLOCKING (append to existing table/chain)
# =============================================================================

# Sets
add set inet filter geoip_blocked_v4 { type ipv4_addr; flags interval; }
add set inet filter geoip_blocked_v6 { type ipv6_addr; flags interval; }
add set inet filter geoip_home_v4    { type ipv4_addr; flags interval; }
add set inet filter geoip_home_v6    { type ipv6_addr; flags interval; }
add set inet filter geoip_allowlist_v4 { type ipv4_addr; flags interval; }
add set inet filter geoip_allowlist_v6 { type ipv6_addr; flags interval; }

# GeoIP-Chain
add chain inet filter geoip_check
add rule  inet filter geoip_check ip  saddr @geoip_allowlist_v4 counter accept comment "Manual-Allow-v4"
add rule  inet filter geoip_check ip6 saddr @geoip_allowlist_v6 counter accept comment "Manual-Allow-v6"
add rule  inet filter geoip_check ip  saddr @geoip_home_v4     counter accept comment "GeoIP-Allow-Home-v4"
add rule  inet filter geoip_check ip6 saddr @geoip_home_v6     counter accept comment "GeoIP-Allow-Home-v6"
add rule  inet filter geoip_check ip  saddr @geoip_blocked_v4  counter drop    comment "GeoIP-Block-v4"
add rule  inet filter geoip_check ip6 saddr @geoip_blocked_v6  counter drop    comment "GeoIP-Block-v6"

# Jump in die bestehende input-Chain
add rule  inet filter input jump geoip_check comment "GeoIP-Filter"
EOF
}


##
# Erstellt die Tailscale-VPN-Regeln.
# - Akzeptiert den Interface-Namen als Parameter.
# - Erstellt die Datei nur, wenn sie aufgerufen wird.
##
generate_tailscale_rules() {
    local tailscale_interface="$1"

    # Guard Clause: Funktion bricht ab, wenn kein Interface-Name übergeben wird.
    if [ -z "$tailscale_interface" ]; then
        log_error "generate_tailscale_rules: Kein Interface-Name übergeben!"
        return 1
    fi
    
    local rules_file="/etc/nftables.d/30-tailscale.conf"
    local rules_content=""

    # --- 1. Inhalt für die Regel-Datei sammeln ---
    rules_content+="# Erlaube eingehenden Verkehr ZUM SERVER selbst von der Tailscale-Schnittstelle.\n"
    rules_content+="add rule inet filter input iifname \"$tailscale_interface\" accept comment \"Input vom Tailscale-Interface\"\n\n"
    
    rules_content+="# Erlaube etablierte ANTWORTEN, die VOM SERVER INS VPN gehen (wichtig für Subnet-Routing).\n"
    rules_content+="add rule inet filter forward oifname \"$tailscale_interface\" ct state related,established accept comment \"Forward-Antworten an Tailscale\"\n"

    # --- 2. Datei schreiben ---
    log_info "  -> Erstelle Tailscale-VPN-Regeln für Interface '$tailscale_interface'..."
    printf "# =============================================================================\n" > "$rules_file"
    printf "# TAILSCALE-VPN REGELN (dynamisch für Interface: %s)\n" "$tailscale_interface" >> "$rules_file"
    printf "# =============================================================================\n\n" >> "$rules_file"
    printf "%b" "$rules_content" >> "$rules_file"
}

##
# Erstellt die Docker-Container-Regeln.
# - Akzeptiert Docker- und Tailscale-Interface-Namen als Parameter.
# - Schreibt inaktive Regeln als Kommentar, um die Konfiguration transparent zu machen.
##
generate_docker_rules() {
    local docker_interface="$1"
    local tailscale_interface="$2" # Dieser Parameter kann leer sein

    # Guard Clause: Funktion bricht ab, wenn der Docker-Interface-Name fehlt.
    if [ -z "$docker_interface" ]; then
        log_error "generate_docker_rules: Kein Docker-Interface übergeben!"
        return 1
    fi
    
    local rules_file="/etc/nftables.d/40-docker.conf"
    local rules_content=""

    # --- 1. Inhalt basierend auf den Parametern sammeln ---
    
    # Bedingte Logik für die Brücke zwischen Tailscale und Docker
    if [ -n "$tailscale_interface" ]; then
        # Tailscale-Interface wurde übergeben -> Schreibe die aktiven Regeln
        rules_content+="# VPN <-> Container Kommunikation (AKTIV)\n"
        rules_content+="add rule inet filter forward iifname \"$tailscale_interface\" oifname \"$docker_interface\" accept comment \"Tailscale zu Docker\"\n"
        rules_content+="add rule inet filter forward iifname \"$docker_interface\" oifname \"$tailscale_interface\" ct state related,established accept comment \"Docker-Antworten an Tailscale\"\n\n"
    else
        # Kein Tailscale-Interface übergeben -> Schreibe die Regeln als auskommentiertes Beispiel
        rules_content+="# VPN <-> Container Kommunikation (INAKTIV, da Tailscale nicht konfiguriert/aktiv ist)\n"
        rules_content+="# add rule inet filter forward iifname \"tailscale0\" oifname \"$docker_interface\" accept comment \"Tailscale zu Docker\"\n"
        rules_content+="# add rule inet filter forward iifname \"$docker_interface\" oifname \"tailscale0\" ct state related,established accept comment \"Docker-Antworten an Tailscale\"\n\n"
    fi
    
    # Regel für die Kommunikation von Containern untereinander (immer aktiv)
    rules_content+="# Docker-interne Container-Kommunikation\n"
    rules_content+="add rule inet filter forward iifname \"$docker_interface\" oifname \"$docker_interface\" accept comment \"Docker-interne Kommunikation\"\n"

    # --- 2. Datei schreiben ---
    log_info "  -> Erstelle/Aktualisiere Docker-Regeln (40-docker.conf)..."
    printf "# =============================================================================\n" > "$rules_file"
    printf "# DOCKER-CONTAINER REGELN\n" >> "$rules_file"
    printf "# Diese Datei wird automatisch vom Server-Baukasten generiert.\n" >> "$rules_file"
    printf "# =============================================================================\n\n" >> "$rules_file"
    printf "%b" "$rules_content" >> "$rules_file"
}

##
# Erstellt die Service-Regeln (SSH, ICMP, etc.)
##
generate_service_rules() {
    local rules_file="/etc/nftables.d/50-services.conf"
    log_info "  -> Erstelle Service-Regeln (SSH, ICMP)..."
    
    cat > "$rules_file" <<EOF
# =============================================================================
# ÖFFENTLICHE DIENSTE
# =============================================================================

# Ergänze die input-Chain um öffentliche Dienste
add rule inet filter input tcp dport ${SSH_PORT:-22} accept comment "SSH-Zugang"
add rule inet filter input ip protocol icmp accept comment "IPv4 Ping"
add rule inet filter input ip6 nexthdr ipv6-icmp accept comment "IPv6 Ping"
EOF
}

##
# Erstellt die NAT-Regeln intelligent und nur wenn nötig.
# IPv6-NAT-Regeln werden nur erstellt, wenn der Kernel sie unterstützt.
##
generate_nat_rules() {
    # Guard Clause: Funktion nur ausführen, wenn NAT laut Config benötigt wird.
    if [ "${ACCESS_MODEL:-2}" != "1" ] || [ "$TAILSCALE_ACTIVE" != "true" ] || [ -z "$PRIMARY_INTERFACE" ]; then
        return 0
    fi
    
    local rules_content=""
    
    # --- IPv4-NAT (wird immer erstellt, wenn die Funktion läuft) ---
    rules_content+="# IPv4 NAT-Tabelle für Tailscale Subnet-Routing / Exit-Node\n"
    rules_content+="add table ip nat\n"
    rules_content+="add chain ip nat postrouting { type nat hook postrouting priority 100; policy accept; }\n"
    rules_content+="add rule ip nat postrouting oifname \"$PRIMARY_INTERFACE\" iifname \"$TAILSCALE_INTERFACE\" masquerade comment \"Tailscale IPv4 NAT\"\n"

    # --- IPv6-NAT (wird nur erstellt, wenn vom Kernel unterstützt) ---
    if [ "$(check_ipv6_nat_kernel)" = "true" ]; then
        rules_content+="\n# IPv6 NAT-Tabelle (vom Kernel unterstützt)\n"
        rules_content+="add table ip6 nat\n"
        rules_content+="add chain ip6 nat postrouting { type nat hook postrouting priority 100; policy accept; }\n"
        rules_content+="add rule ip6 nat postrouting oifname \"$PRIMARY_INTERFACE\" iifname \"$TAILSCALE_INTERFACE\" masquerade comment \"Tailscale IPv6 NAT\"\n"
        log_debug "IPv6-NAT-Regeln werden hinzugefügt."
    else
        log_warn "IPv6-NAT wird übersprungen (keine Kernel-Unterstützung)."
        rules_content+="\n# IPv6 NAT übersprungen (keine Kernel-Unterstützung)\n"
    fi

    # --- Datei schreiben (nur wenn es Inhalt gibt) ---
    if [ -n "$rules_content" ]; then
        local rules_file="/etc/nftables.d/90-nat.conf"
        log_info "  -> Erstelle NAT-Regeln für Tailscale..."
        
        printf "# =============================================================================\n" > "$rules_file"
        printf "# NAT-REGELN (Tailscale Subnet Routing / Exit Node)\n" >> "$rules_file"
        printf "# =============================================================================\n\n" >> "$rules_file"
        printf "%b" "$rules_content" >> "$rules_file"
    fi
}

##
# HAUPT-FUNKTION: Erstellt die modulare NFTables-Konfiguration (CONFIG-BASIERT)
##
generate_nftables_config() {
    log_info "🔥 Erstelle modulare NFTables-Konfiguration (v4.2 - Config-basiert)..."

    # 1. Sicherstellen, dass das Verzeichnis existiert
    mkdir -p /etc/nftables.d

    # 2. Erkenne das primäre Interface für NAT-Regeln
    if [ -z "${PRIMARY_INTERFACE:-}" ]; then
        PRIMARY_INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -n1)
        [ -z "$PRIMARY_INTERFACE" ] && PRIMARY_INTERFACE="eth0"
        export PRIMARY_INTERFACE
        log_info "  -> Primäres Interface erkannt: $PRIMARY_INTERFACE"
    fi

    # 3. Erstelle alle Regel-Module basierend auf CONFIG
    generate_base_filter_rules
    
    # Nur aktivierte Features werden erstellt
    [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ] && generate_geoip_rules
    ## [ "${ACCESS_MODEL:-2}" = "1" ] && generate_tailscale_rules im Netzwerk-Modul
    ## [ "${SERVER_ROLE:-2}" = "1" ] generate_docker_rules im Container-Modul
    [ "${ACCESS_MODEL:-2}" = "1" ] && generate_nat_rules
    
    # Service-Regeln werden immer erstellt
    generate_service_rules

    # 4. Die Haupt-Konfigurationsdatei (dynamisch mit nur existierenden Dateien)
    log_info "  -> Erstelle dynamische Haupt-Konfiguration..."
    cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f

# ==========================================================================
# SERVER-BAUKASTEN HAUPT-KONFIGURATION (v5.0)
# ==========================================================================
# Config-basierte modulare Struktur
# Generiert am: $(date '+%Y-%m-%d %H:%M:%S')
# ==========================================================================

# AKTIVE FEATURES:
# Server-Rolle:        ${SERVER_ROLE:-2} (1=Docker-Host, 2=Einfach)
# Zugriffs-Modell:     ${ACCESS_MODEL:-2} (1=VPN-only, 2=Öffentlich) 
# GeoIP-Blocking:      ${ENABLE_GEOIP_BLOCKING:-nein}
# Primary Interface:   ${PRIMARY_INTERFACE:-unbekannt}

# Leere die Konfiguration nur bei kompletter Neuinstallation
flush ruleset
include "/etc/nftables.d/*.conf"
EOF

    log_ok "Modulare NFTables-Konfiguration erstellt."

    # 7. Syntax-Validierung
    if ! nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
        log_error "SYNTAX-FEHLER in der modularen NFTables-Konfiguration!"
        log_info "Debug-Info: Teste einzelne Module..."
        for conf_file in /etc/nftables.d/*.conf; do
            if [ -f "$conf_file" ]; then
                if nft -c -f "$conf_file" >/dev/null 2>&1; then
                    log_ok "  ✅ $(basename "$conf_file") - Syntax OK"
                else
                    log_error "  ❌ $(basename "$conf_file") - SYNTAX-FEHLER!"
                fi
            fi
        done
        return 1
    fi
    log_ok "Syntax-Validierung aller Module erfolgreich."
}
