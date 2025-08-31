#!/bin/bash
################################################################################
#
# BIBLIOTHEK: FIREWALL-HELFER-FUNKTIONEN (v4.3) - KORRIGIERT
#
# @description: Modulare NFTables-Konfiguration mit korrekten Prioritäten
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# WICHTIGE ÄNDERUNGEN v4.3:
# - Priority-Fix: Nutze 'filter' statt '-1' (verhindert Docker/CrowdSec-Konflikte)
# - flush ruleset aktiviert (löscht alte Chains korrekt)
# - Bessere Kommentierung aller Config-Dateien
# - IPv6-NAT Kernel-Check implementiert
################################################################################

##
# Prüft, ob der Kernel IPv6-NAT unterstützt (mit praktischem Test)
# @return string "true" oder "false"
##
check_ipv6_nat_kernel() {
    log_debug "IPv6-NAT: Starte umfassende Kernel-Support-Prüfung..."
    
    # TEST 1: Kernel-Konfiguration prüfen
    local kconfig="/boot/config-$(uname -r)"
    if [ -f "$kconfig" ] && grep -q 'CONFIG_NF_NAT_MASQUERADE_IPV6=y\|CONFIG_IP6_NF_TARGET_MASQUERADE=y' "$kconfig"; then
        log_debug "IPv6-NAT: Kernel-Config zeigt Support (CONFIG gefunden)."
    else
        log_debug "IPv6-NAT: Kernel-Config zeigt keinen expliziten Support."
    fi
    
    # TEST 2: Modul-Verfügbarkeit prüfen
    if modinfo ip6t_MASQUERADE &>/dev/null; then
        log_debug "IPv6-NAT: Modul ip6t_MASQUERADE ist verfügbar."
        if modprobe ip6t_MASQUERADE 2>/dev/null; then
            log_debug "IPv6-NAT: Modul ip6t_MASQUERADE erfolgreich geladen."
        else
            log_debug "IPv6-NAT: Modul ip6t_MASQUERADE konnte nicht geladen werden."
        fi
    else
        log_debug "IPv6-NAT: Modul ip6t_MASQUERADE nicht gefunden."
    fi
    
    # TEST 3: Praktischer Funktions-Test (KRITISCH!)
    # Dies ist der ultimative Test - wenn das funktioniert, ist IPv6-NAT definitiv verfügbar
    log_debug "IPv6-NAT: Führe praktischen Funktionstest durch..."
    
    # Verwende harmlose Test-Regel in OUTPUT-Chain (sicher, kollidiert mit nichts)
    local test_successful=false
    local cleanup_needed=false
    
    # Versuche Test-Regel zu erstellen
    if ip6tables -t nat -A OUTPUT -p tcp --dport 59999 -j DNAT --to-destination [::1]:59999 >/dev/null 2>&1; then
        log_debug "IPv6-NAT: Test-Regel erfolgreich erstellt."
        test_successful=true
        cleanup_needed=true
    else
        log_debug "IPv6-NAT: Test-Regel konnte nicht erstellt werden."
        # Prüfe ob es ein ip6tables-Problem oder ein NAT-Problem ist
        if ip6tables -t filter -L OUTPUT >/dev/null 2>&1; then
            log_debug "IPv6-NAT: ip6tables funktioniert, aber NAT-Tabelle nicht verfügbar."
        else
            log_debug "IPv6-NAT: Grundlegendes ip6tables-Problem."
        fi
    fi
    
    # Cleanup der Test-Regel (falls erfolgreich erstellt)
    if [ "$cleanup_needed" = true ]; then
        if ip6tables -t nat -D OUTPUT -p tcp --dport 59999 -j DNAT --to-destination [::1]:59999 >/dev/null 2>&1; then
            log_debug "IPv6-NAT: Test-Regel erfolgreich entfernt."
        else
            log_warn "IPv6-NAT: Test-Regel konnte nicht entfernt werden (nicht kritisch)."
            # Versuche Fallback-Cleanup
            ip6tables -t nat -F OUTPUT >/dev/null 2>&1 || true
        fi
    fi
    
    # Endergebnis basierend auf praktischem Test
    if [ "$test_successful" = true ]; then
        log_debug "IPv6-NAT: Praktischer Test erfolgreich - IPv6-NAT ist voll funktional."
        echo "true"
    else
        log_debug "IPv6-NAT: Praktischer Test fehlgeschlagen - IPv6-NAT nicht verfügbar."
        echo "false"
    fi
}

##
# Stellt iptables auf nft-Backend um und sichert den nftables-Dienst ab.
# Lädt Kernel-Module intelligent, basierend auf der Kernel-Unterstützung.
##
setup_iptables_nft_backend() {
    log_info "🔗 Konfiguriere Firewall-Backend (iptables-nft & Module)..."
    
    # --- 1. Installation sicherstellen ---
    run_with_spinner "Installiere NFTables und iptables-Pakete..." \
        "apt-get install -y iptables netfilter-persistent iptables-persistent"

    # --- 2. Kernel-Module intelligent laden & registrieren ---
    log_info "  -> Prüfe und lade benötigte Kernel-Module..."
    
    # Module-Definition: Basis-Module werden immer geladen
    local base_modules=("nf_nat" "nft_masq" "nft_nat")
    # IPv6-NAT-Module nur wenn Kernel-Support vorhanden
    local ipv6_nat_modules=("ip6table_nat" "ip6t_MASQUERADE")
    
    # Erstelle Module-Config für automatisches Laden beim Boot
    local modules_conf="/etc/modules-load.d/99-server-baukasten-nat.conf"
    echo "# Automatisch generiert vom Server-Baukasten" > "$modules_conf"
    echo "# Basis-Module für NAT (IPv4 immer erforderlich)" >> "$modules_conf"
    printf '%s\n' "${base_modules[@]}" >> "$modules_conf"

    # Basis-Module sofort laden
    for module in "${base_modules[@]}"; do
        if modprobe "$module" 2>/dev/null; then
            log_ok "Basis-Modul '$module' geladen."
        else
            log_debug "Basis-Modul '$module' konnte nicht geladen werden (möglicherweise bereits integriert)."
        fi
    done

    # IPv6-NAT-Module nur bei Kernel-Support
    if [ "$(check_ipv6_nat_kernel)" = "true" ]; then
        log_info "  -> IPv6-NAT-Unterstützung im Kernel gefunden. Lade entsprechende Module..."
        echo "" >> "$modules_conf"
        echo "# IPv6-NAT-Module (vom Kernel unterstützt)" >> "$modules_conf"
        printf '%s\n' "${ipv6_nat_modules[@]}" >> "$modules_conf"

        for module in "${ipv6_nat_modules[@]}"; do
            if modprobe "$module" 2>/dev/null; then
                log_ok "IPv6-Modul '$module' geladen."
            else
                log_debug "IPv6-Modul '$module' konnte nicht geladen werden."
            fi
        done
    else
        log_warn "Keine IPv6-NAT-Unterstützung im Kernel erkannt. Überspringe IPv6-NAT-Module."
        echo "" >> "$modules_conf"
        echo "# IPv6-NAT-Module übersprungen (keine Kernel-Unterstützung)" >> "$modules_conf"
    fi

    # --- 3. iptables auf NFT-Backend umstellen (KRITISCH für Docker-Kompatibilität) ---
    run_with_spinner "Stelle iptables auf nft-Backend um..." \
        "update-alternatives --set iptables /usr/sbin/iptables-nft && \
         update-alternatives --set ip6tables /usr/sbin/ip6tables-nft"
    
    # --- 4. Verifikation des Backends ---
    if iptables --version 2>/dev/null | grep -q "nf_tables"; then
        log_ok "iptables nutzt jetzt nf_tables-Backend (Docker-kompatibel)"
    else
        log_error "iptables-nft Umstellung fehlgeschlagen! Docker wird Probleme haben."
        return 1
    fi

    # --- 5. systemd Drop-in für nftables.service (Sicherheit) ---
    log_info "  -> Sichere nftables-Service gegen versehentliches Leeren..."
    
    local override_dir="/etc/systemd/system/nftables.service.d"
    local override_file="$override_dir/override.conf"
    
    mkdir -p "$override_dir"
    cat > "$override_file" <<'EOF'
[Service]
# SICHERHEIT: Verhindere versehentliches Leeren der Firewall-Regeln
# Standard 'systemctl stop nftables' würde alle Regeln löschen
ExecStop=
ExecStop=/bin/true

# Sauberer Reload-Befehl für Konfigurationsänderungen
ExecReload=/usr/sbin/nft -f /etc/nftables.conf
EOF

    log_ok "nftables-Service gegen versehentliches Leeren gesichert."
    run_with_spinner "Lade systemd-Konfiguration neu..." "systemctl daemon-reload"
}

# ===============================================================================
#          MODULARE NFTABLES-GENERIERUNG (v4.3) - KORRIGIERT
# ===============================================================================

##
# Erstellt das Firewall-Grundgerüst mit korrekten Prioritäten.
# KORRIGIERT: Integriert GeoIP direkt in die Basis-Tabelle!
##
generate_base_filter_rules() {
    local server_role="$1"
    local rules_file="/etc/nftables.d/10-base-filter.conf"
    
    log_info "  -> Erstelle Firewall-Grundgerüst mit integriertem GeoIP..."
    
    # Docker-Chains nur erstellen wenn Docker-Host konfiguriert
    local docker_chains=""
    if [ "$server_role" = "1" ]; then
        log_debug "SERVER_ROLE=1: Erstelle leere DOCKER-Chains als Platzhalter."
        docker_chains="    # Leere DOCKER-Chain - wird von Docker-Engine befüllt
    chain DOCKER { }"
    fi

    # GeoIP-Sets nur erstellen wenn aktiviert
    local geoip_sets=""
    local geoip_chain=""
    local geoip_jump=""
    
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        log_debug "ENABLE_GEOIP_BLOCKING=ja: Erstelle GeoIP-Sets und Chain."
        geoip_sets="
    # =========================================================================
    # GEOIP-SETS (Geografisches Blocking)
    # =========================================================================
    # IPv4 und IPv6 Sets für Länder-basierte Filterung
    # Sets werden von update-geoip-sets Script mit IP-Listen befüllt
    
    set geoip_blocked_v4 { 
        type ipv4_addr; 
        flags interval; 
        comment \"Blockierte Länder IPv4: ${BLOCKED_COUNTRIES:-Keine}\"; 
    }
    
    set geoip_blocked_v6 { 
        type ipv6_addr; 
        flags interval; 
        comment \"Blockierte Länder IPv6: ${BLOCKED_COUNTRIES:-Keine}\"; 
    }
    
    set geoip_home_v4 { 
        type ipv4_addr; 
        flags interval; 
        comment \"Heimatland IPv4 (geschützt): ${HOME_COUNTRY:-Nicht gesetzt}\"; 
    }
    
    set geoip_home_v6 { 
        type ipv6_addr; 
        flags interval; 
        comment \"Heimatland IPv6 (geschützt): ${HOME_COUNTRY:-Nicht gesetzt}\"; 
    }
    
    set geoip_allowlist_v4 { 
        type ipv4_addr; 
        flags interval; 
        comment \"Manuelle IPv4-Freigaben (geoip-manager)\"; 
    }
    
    set geoip_allowlist_v6 { 
        type ipv6_addr; 
        flags interval; 
        comment \"Manuelle IPv6-Freigaben (geoip-manager)\"; 
    }"

        geoip_chain="
    # =========================================================================
    # GEOIP-CHECK-CHAIN (Geografische Filterung)
    # =========================================================================
    chain geoip_check { 
        comment \"GeoIP-Länder-Filter\"; 
        
        # PRIORITÄTEN (Reihenfolge ist KRITISCH!):
        # 1. Manuelle Allowlist (höchste Priorität)
        ip  saddr @geoip_allowlist_v4 counter accept comment \"Manual-Allow-v4\"
        ip6 saddr @geoip_allowlist_v6 counter accept comment \"Manual-Allow-v6\"
        
        # 2. Heimatland-Schutz (wird nie blockiert)  
        ip  saddr @geoip_home_v4     counter accept comment \"GeoIP-Allow-Home-v4\"
        ip6 saddr @geoip_home_v6     counter accept comment \"GeoIP-Allow-Home-v6\"
        
        # 3. Blockierte Länder (niedrigste Priorität)
        ip  saddr @geoip_blocked_v4  counter drop   comment \"GeoIP-Block-v4\"
        ip6 saddr @geoip_blocked_v6  counter drop   comment \"GeoIP-Block-v6\"
        
        # Nicht in Sets = wird durchgelassen (implizit)
    }"

        geoip_jump="        
        # STUFE 4: Geografische Filterung (falls aktiviert)
        jump geoip_check comment \"GeoIP-Länder-Filter\""
    fi

    cat > "$rules_file" <<EOF
# =============================================================================
# BASIS-FIREWALL-REGELN MIT INTEGRIERTEM GEOIP (v4.3) - KORRIGIERT
# =============================================================================
# Komplette Firewall-Basis mit allen Features in einer Datei
# 
# KONFIGURATION:
# - Server-Rolle: $server_role (1=Docker, 2=Einfach)
# - GeoIP-Blocking: ${ENABLE_GEOIP_BLOCKING:-nein}
# - SSH-Port: ${SSH_PORT:-22}
#
# WICHTIG: Priority 'filter' verhindert Konflikte mit Docker/CrowdSec
# =============================================================================

# NAT-Tabellen (IPv4 und IPv6) für Docker und VPN
table ip nat {
$docker_chains
}

table ip6 nat {
$docker_chains  
}

# HAUPT-FILTER-TABELLE mit allen integrierten Features
table inet filter {
$docker_chains$geoip_sets$geoip_chain

    # -------------------------------------------------------------------------
    # INPUT-CHAIN: Eingehender Traffic ZUM SERVER
    # -------------------------------------------------------------------------
    chain input {
        type filter hook input priority filter; policy drop;
        
        # STUFE 1: Vertrauenswürdige Verbindungen
        ct state established,related accept comment "Aktive/verwandte Verbindungen"
        ct state invalid drop comment "Ungültige/korrupte Pakete"
        iifname "lo" accept comment "Loopback-Interface"
$geoip_jump
        
        # STUFE 5: Öffentliche Services (SSH, ICMP)
        tcp dport ${SSH_PORT:-22} accept comment "SSH-Server (Port ${SSH_PORT:-22})"
        ip protocol icmp accept comment "IPv4 Ping (ICMP)"
        ip6 nexthdr ipv6-icmp accept comment "IPv6 Ping (ICMPv6)"
    }

    # -------------------------------------------------------------------------
    # FORWARD-CHAIN: Traffic ZWISCHEN Interfaces
    # -------------------------------------------------------------------------
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept comment "Aktive Forward-Verbindungen"
    }

    # -------------------------------------------------------------------------  
    # OUTPUT-CHAIN: Ausgehender Traffic VOM SERVER
    # -------------------------------------------------------------------------
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF

    log_ok "Basis-Firewall mit integriertem GeoIP erstellt."
}

##
# GeoIP wird jetzt direkt in generate_base_filter_rules() integriert!
# Diese Funktion ist nicht mehr nötig.
##

##
# Erstellt die Tailscale-VPN-Regeln
# Parameter: Interface-Name (z.B. "tailscale0")
##
generate_tailscale_rules() {
    local tailscale_interface="$1"

    if [ -z "$tailscale_interface" ]; then
        log_error "generate_tailscale_rules: Kein Interface-Name übergeben!"
        return 1
    fi
    
    local rules_file="/etc/nftables.d/30-tailscale.conf"
    log_info "  -> Erstelle Tailscale-VPN-Regeln für Interface '$tailscale_interface'..."

    cat > "$rules_file" <<EOF
# =============================================================================
# TAILSCALE-VPN REGELN (Server-Baukasten v4.3)
# =============================================================================
# Sichere VPN-Verbindungen über Tailscale
#
# KONFIGURATION:
# - Tailscale-Interface: $tailscale_interface
# - Primäres Interface: ${PRIMARY_INTERFACE:-nicht gesetzt}
#
# FUNKTIONSWEISE:
# 1. INPUT: Erlaube allen Traffic VOM VPN ZUM Server
# 2. FORWARD: Erlaube VPN-Traffic zu anderen Netzen (Subnet-Routing)
# 3. NAT: Erstellt separaten NAT-Bereich (90-nat.conf)
# =============================================================================

# INPUT-Regeln: Traffic ZUM Server über VPN
# Tailscale ist vertrauenswürdig - erlaube allen Traffic
add rule inet filter input iifname "$tailscale_interface" accept comment "VPN-Input: Tailscale zu Server"

# FORWARD-Regeln: Traffic DURCH den Server (Subnet-Routing/Exit-Node)
# Erlaube VPN-Clients den Zugriff auf andere Netzwerke durch den Server
add rule inet filter forward iifname "$tailscale_interface" accept comment "VPN-Forward: Von Tailscale zu anderen Netzen"

# Erlaube Antwort-Traffic zurück ins VPN
add rule inet filter forward oifname "$tailscale_interface" ct state related,established accept comment "VPN-Forward: Antworten zurück an Tailscale"

# HINWEISE:
# - NAT-Regeln für Internet-Zugang: siehe 90-nat.conf
# - Docker-Integration: siehe 40-docker.conf  
# - Tailscale kümmert sich um interne Verschlüsselung und Routing
EOF

    log_ok "Tailscale-VPN-Regeln für Interface '$tailscale_interface' erstellt."
}

##
# Erstellt die Docker-Container-Regeln
# Parameter: Docker-Interface, Optional: Tailscale-Interface
##
generate_docker_rules() {
    local docker_interface="$1" 
    local tailscale_interface="$2"  # Optional

    if [ -z "$docker_interface" ]; then
        log_error "generate_docker_rules: Kein Docker-Interface übergeben!"
        return 1
    fi
    
    local rules_file="/etc/nftables.d/40-docker.conf"
    log_info "  -> Erstelle Docker-Container-Regeln..."

    cat > "$rules_file" <<EOF
# =============================================================================
# DOCKER-CONTAINER REGELN (Server-Baukasten v4.3)
# =============================================================================
# Netzwerk-Regeln für Docker-Container
#
# KONFIGURATION:
# - Docker-Interface: $docker_interface
# - Tailscale-Interface: ${tailscale_interface:-nicht konfiguriert}
#
# WICHTIG: Docker erstellt seine eigenen iptables-Regeln zusätzlich!
# Diese NFTables-Regeln ergänzen Docker's automatische Regeln.
# =============================================================================

EOF

    # Tailscale <-> Docker Integration (falls Tailscale aktiv)
    if [ -n "$tailscale_interface" ]; then
        cat >> "$rules_file" <<EOF
# VPN <-> CONTAINER INTEGRATION (AKTIV)
# Erlaube VPN-Clients den direkten Zugriff auf Container
add rule inet filter forward iifname "$tailscale_interface" oifname "$docker_interface" accept comment "VPN zu Docker-Container"
add rule inet filter forward iifname "$docker_interface" oifname "$tailscale_interface" ct state related,established accept comment "Container-Antworten an VPN"

EOF
    else
        cat >> "$rules_file" <<EOF
# VPN <-> CONTAINER INTEGRATION (INAKTIV)  
# Tailscale nicht konfiguriert - VPN-Container-Regeln sind deaktiviert
# Beispiel für manuelle Aktivierung:
# add rule inet filter forward iifname "tailscale0" oifname "$docker_interface" accept comment "VPN zu Docker-Container"
# add rule inet filter forward iifname "$docker_interface" oifname "tailscale0" ct state related,established accept comment "Container-Antworten an VPN"

EOF
    fi

    cat >> "$rules_file" <<EOF
# CONTAINER-INTERNE KOMMUNIKATION
# Container müssen untereinander kommunizieren können (Docker-Networks)
add rule inet filter forward iifname "$docker_interface" oifname "$docker_interface" accept comment "Docker-Container untereinander"

# HINWEISE:
# - Docker erstellt automatisch zusätzliche iptables-Regeln für Port-Forwarding
# - Diese NFTables-Regeln laufen parallel und ergänzen Docker's Regeln
# - Für Container-Zugriff von außen: siehe Docker-Dokumentation für Port-Mapping
# - Container-zu-Internet: siehe Docker's NAT-Regeln (automatisch)
EOF

    log_ok "Docker-Container-Regeln erstellt."
}

##
# Erstellt die Service-Regeln (SSH, ICMP, etc.)
# Diese Regeln werden IMMER erstellt (öffentliche Grunddienste)
##
generate_service_rules() {
    local rules_file="/etc/nftables.d/50-services.conf"
    log_info "  -> Erstelle öffentliche Service-Regeln..."
    
    cat > "$rules_file" <<EOF
# =============================================================================
# ÖFFENTLICHE DIENSTE (Server-Baukasten v4.3)  
# =============================================================================
# Grundlegende Server-Dienste die öffentlich erreichbar sein müssen
#
# KONFIGURATION:
# - SSH-Port: ${SSH_PORT:-22}
# - Zugriffs-Modell: ${ACCESS_MODEL:-2} (1=VPN-only, 2=öffentlich)
#
# HINWEIS: Bei VPN-only Modell sind diese Services nur Fallback/Notfall
# =============================================================================

# SSH-ZUGANG
# KRITISCH: Ohne SSH-Zugang ist der Server nicht mehr verwaltbar!
add rule inet filter input tcp dport ${SSH_PORT:-22} accept comment "SSH-Server (Port ${SSH_PORT:-22})"

# ICMP/PING (IPv4 und IPv6)  
# Ermöglicht Netzwerk-Diagnose und Erreichbarkeits-Tests
add rule inet filter input ip protocol icmp accept comment "IPv4 Ping (ICMP)"
add rule inet filter input ip6 nexthdr ipv6-icmp accept comment "IPv6 Ping (ICMPv6)"

# ZUSÄTZLICHE SERVICES
# Weitere öffentliche Services können hier hinzugefügt werden:
# add rule inet filter input tcp dport 80 accept comment "HTTP-Server" 
# add rule inet filter input tcp dport 443 accept comment "HTTPS-Server"
# add rule inet filter input tcp dport 9443 accept comment "Portainer Web-UI"

# SICHERHEITSHINWEISE:
# - SSH sollte mit Key-basierter Authentifizierung gesichert werden
# - Bei VPN-Modell: SSH über Tailscale nutzen, öffentlichen SSH sperren
# - Zusätzliche Ports nur öffnen wenn wirklich benötigt
# - Rate-Limiting für SSH wird von CrowdSec übernommen
EOF

    log_ok "Öffentliche Service-Regeln erstellt."
}

##
# Erstellt die NAT-Regeln für Tailscale (nur wenn benötigt)
# Unterstützt IPv6-NAT nur bei Kernel-Support
##
generate_nat_rules() {
    # Nur NAT erstellen wenn VPN-Modell und Tailscale aktiv
    if [ "${ACCESS_MODEL:-2}" != "1" ] || [ -z "${TAILSCALE_INTERFACE:-}" ] || [ -z "${PRIMARY_INTERFACE:-}" ]; then
        log_debug "NAT-Regeln werden übersprungen (VPN nicht aktiv oder Interfaces fehlen)."
        return 0
    fi
    
    local rules_file="/etc/nftables.d/90-nat.conf"
    log_info "  -> Erstelle NAT-Regeln für Tailscale Subnet-Routing..."

    cat > "$rules_file" <<EOF
# =============================================================================
# NAT-REGELN FÜR TAILSCALE (Server-Baukasten v4.3)
# =============================================================================
# Network Address Translation für VPN-Exit-Node und Subnet-Routing
#
# KONFIGURATION:
# - Tailscale-Interface: ${TAILSCALE_INTERFACE}
# - Primäres Interface: ${PRIMARY_INTERFACE}
# - IPv6-NAT-Support: $(check_ipv6_nat_kernel)
#
# FUNKTIONSWEISE:
# - VPN-Clients können über diesen Server ins Internet
# - Server fungiert als "Exit Node" für das Tailscale-Netzwerk
# =============================================================================

# IPv4 NAT-TABELLE (wird immer erstellt)
# Alle IPv4-Pakete die vom VPN kommen und ins Internet gehen werden maskiert
add table ip nat { comment "IPv4 NAT für Tailscale"; }
add chain ip nat postrouting { type nat hook postrouting priority 100; policy accept; comment "IPv4 NAT Postrouting"; }
add rule ip nat postrouting oifname "${PRIMARY_INTERFACE}" iifname "${TAILSCALE_INTERFACE}" masquerade comment "Tailscale IPv4 NAT (Exit Node)"

EOF

    # IPv6 NAT nur bei Kernel-Support
    if [ "$(check_ipv6_nat_kernel)" = "true" ]; then
        cat >> "$rules_file" <<EOF
# IPv6 NAT-TABELLE (Kernel-Support vorhanden)  
# IPv6-NAT ist weniger üblich, aber für vollständige Exit-Node-Funktionalität
add table ip6 nat { comment "IPv6 NAT für Tailscale"; }
add chain ip6 nat postrouting { type nat hook postrouting priority 100; policy accept; comment "IPv6 NAT Postrouting"; }  
add rule ip6 nat postrouting oifname "${PRIMARY_INTERFACE}" iifname "${TAILSCALE_INTERFACE}" masquerade comment "Tailscale IPv6 NAT (Exit Node)"

EOF
        log_debug "IPv6-NAT-Regeln hinzugefügt (Kernel-Support vorhanden)."
    else
        cat >> "$rules_file" <<EOF
# IPv6 NAT-TABELLE (ÜBERSPRUNGEN)
# Kernel unterstützt kein IPv6-NAT - wird übersprungen
# Falls benötigt: Kernel mit CONFIG_IP6_NF_TARGET_MASQUERADE kompilieren

EOF
        log_warn "IPv6-NAT übersprungen (keine Kernel-Unterstützung)."
    fi

    cat >> "$rules_file" <<EOF
# USAGE NOTES:
# - Diese NAT-Regeln machen den Server zum Exit-Node
# - VPN-Clients können über diese Server-IP ins Internet
# - Hilfreich für Umgehung von Geo-Blocking oder zensierter Internet-Zugänge
# - Performance-Impact: Minimal für normale Nutzung
EOF

    log_ok "NAT-Regeln für Tailscale erstellt."
}

##
# HAUPT-FUNKTION: Erstellt die BASIS-NFTables-Konfiguration (ohne VPN/Docker)
# VPN/Docker-Regeln werden später dynamisch hinzugefügt via activate_*_rules()
##
generate_nftables_config() {
    log_info "🔥 Erstelle BASIS-NFTables-Konfiguration (v4.3 - Zweistufig)..."

    # 1. Verzeichnis für modulare Regeln sicherstellen
    mkdir -p /etc/nftables.d
    
    # Alte Regel-Dateien löschen für sauberen Neuanfang
    rm -f /etc/nftables.d/*.conf

    # 2. Primäres Interface für NAT-Regeln ermitteln (falls nicht gesetzt)
    if [ -z "${PRIMARY_INTERFACE:-}" ]; then
        PRIMARY_INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -n1)
        [ -z "$PRIMARY_INTERFACE" ] && PRIMARY_INTERFACE="eth0"
        export PRIMARY_INTERFACE
        log_info "  -> Primäres Interface erkannt: $PRIMARY_INTERFACE"
    fi

    # 3. BASIS-Regel-Module erstellen (ohne VPN/Docker-spezifische Teile)
    log_info "  -> Erstelle BASIS-Module..."
    
    # Basis-Regeln werden IMMER erstellt (inkl. GeoIP wenn aktiviert)
    generate_base_filter_rules "$SERVER_ROLE"
    log_info "    ✅ Basis-Firewall mit GeoIP erstellt"

    # 4. Haupt-Konfigurationsdatei erstellen
    log_info "  -> Erstelle Haupt-Konfiguration (BASIS-Setup)..."
    
    cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f

# ==========================================================================
# SERVER-BAUKASTEN BASIS-KONFIGURATION (v4.3) - ZWEISTUFIG
# ==========================================================================
# 
# KONZEPT: Zweistufiges Setup
# 1. BASIS-Setup: Grundlegende Firewall + GeoIP
# 2. DYNAMISCH: VPN/Docker-Regeln werden später hinzugefügt
#
# Generiert am: $(date '+%Y-%m-%d %H:%M:%S')
# ==========================================================================

# AKTIVE BASIS-KONFIGURATION:
# Server-Rolle:        ${SERVER_ROLE:-2} (1=Docker-Host, 2=Einfacher Server)
# Zugriffs-Modell:     ${ACCESS_MODEL:-2} (1=VPN-only, 2=Öffentlich zugänglich)
# GeoIP-Blocking:      ${ENABLE_GEOIP_BLOCKING:-nein}
# SSH-Port:            ${SSH_PORT:-22}
# Primary Interface:   ${PRIMARY_INTERFACE:-auto-detect}

# DYNAMISCHE MODULE (werden später hinzugefügt):
# - Tailscale-VPN:     via activate_tailscale_rules() nach module_network
# - Docker-Container:  via activate_docker_rules() nach module_container

# KRITISCH: Lösche alle alten Regeln für sauberen Neustart!
flush ruleset

# Lade BASIS-Module
include "/etc/nftables.d/*.conf"

# ==========================================================================
# HINWEISE FÜR ZWEISTUFIGES SETUP:
# ==========================================================================
# 
# 🔧 BASIS-FIREWALL (jetzt aktiv):
#   - Grundlegende Input/Forward/Output Chains
#   - GeoIP-Blocking (falls aktiviert)  
#   - SSH + ICMP Zugang
#   - Drop-Policy für nicht-explizit erlaubten Traffic
#
# 🚀 DYNAMISCHE ERWEITERUNGEN (werden später hinzugefügt):
#   - activate_tailscale_rules() nach Tailscale-Installation
#   - activate_docker_rules() nach Docker-Installation
#   - Regeln werden in bestehende Chains eingefügt
#
# 🔍 STATUS PRÜFEN:
#   - Aktuelle Regeln: nft list ruleset
#   - Einzelne Chains: nft list chain inet filter input
#   - Counters: nft list chain inet filter geoip_check
#
# ==========================================================================
EOF

    log_ok "BASIS-Konfiguration mit detaillierter Dokumentation erstellt."

    # 5. Syntax-Validierung der BASIS-Konfiguration
    log_info "  -> Führe Syntax-Validierung der BASIS-Config durch..."
    
    # Teste Basis-Modul einzeln
    if [ -f "/etc/nftables.d/10-base-filter.conf" ]; then
        if nft -c -f "/etc/nftables.d/10-base-filter.conf" >/dev/null 2>&1; then
            log_ok "  ✅ 10-base-filter.conf - Syntax OK"
        else
            log_error "  ❌ 10-base-filter.conf - SYNTAX-FEHLER!"
            return 1
        fi
    fi
    
    # Teste Haupt-Konfiguration  
    if nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
        log_ok "  ✅ Haupt-Konfiguration - Syntax OK"
    else
        log_error "  ❌ Haupt-Konfiguration - SYNTAX-FEHLER!"
        return 1
    fi

    # 6. Status-Zusammenfassung
    log_ok "BASIS-NFTables-Konfiguration erfolgreich erstellt!"
    log_info "--- BASIS-MODULE AKTIV ---"
    log_info "  📁 Haupt-Config: /etc/nftables.conf"
    log_info "  📁 Basis-Filter: /etc/nftables.d/10-base-filter.conf"
    
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        log_info "  🌍 GeoIP-Blocking: Integriert (${BLOCKED_COUNTRIES:-Keine} blockiert)"
    else
        log_info "  🌍 GeoIP-Blocking: Deaktiviert"
    fi
    
    log_info "--- DYNAMISCHE ERWEITERUNGEN (später) ---"
    log_info "  🔗 Tailscale-VPN: Wird nach module_network hinzugefügt"
    log_info "  🐳 Docker-Container: Wird nach module_container hinzugefügt"
    log_info "  🔧 Laden mit: systemctl reload nftables"
    
    return 0
}

##
# NEU: Erstellt nur die Basis-Service-Regeln (ohne VPN/Docker-spezifische Teile)  
# Zusätzliche Services können später hinzugefügt werden
##
generate_base_service_rules() {
    local rules_file="/etc/nftables.d/50-base-services.conf"
    log_info "  -> Erstelle BASIS-Service-Regeln (SSH, ICMP)..."
    
    cat > "$rules_file" <<EOF
# =============================================================================
# BASIS-DIENSTE (Server-Baukasten v4.3) - Grundlegende Services
# =============================================================================
# Services die IMMER verfügbar sein müssen, unabhängig von VPN/Container-Setup
#
# KONFIGURATION:
# - SSH-Port: ${SSH_PORT:-22}
# - Zugriffs-Modell: ${ACCESS_MODEL:-2} (wird später bei VPN-Setup berücksichtigt)
#
# HINWEIS: Diese Regeln sind bereits in 10-base-filter.conf integriert
#          Diese Datei ist nur für eventuelle Erweiterungen da
# =============================================================================

# SSH-ZUGANG (bereits in Basis-Config definiert, hier nur als Referenz)
# tcp dport ${SSH_PORT:-22} accept comment "SSH-Server"

# ICMP/PING (bereits in Basis-Config definiert, hier nur als Referenz)  
# ip protocol icmp accept comment "IPv4 Ping"
# ip6 nexthdr ipv6-icmp accept comment "IPv6 Ping"

# ZUSÄTZLICHE SERVICES können hier hinzugefügt werden:
# Beispiele:
# tcp dport 80 accept comment "HTTP-Server"
# tcp dport 443 accept comment "HTTPS-Server" 
# tcp dport 9443 accept comment "Portainer Web-UI (falls öffentlich)"

# SICHERHEITSHINWEISE:
# - SSH sollte mit Key-basierter Authentifizierung gesichert werden
# - Bei VPN-Modell sollten öffentliche Ports minimal gehalten werden
# - Rate-Limiting wird von CrowdSec übernommen
# - Zusätzliche Ports nur öffnen wenn wirklich benötigt

# STATUS:
# Diese Datei enthält derzeit keine aktiven Regeln - alle Basis-Services
# sind bereits in 10-base-filter.conf integriert für bessere Performance.
EOF

    log_ok "BASIS-Service-Regeln (Platzhalter) erstellt."
}

##
# Aktiviert Tailscale-Regeln dynamisch (wird vom Netzwerk-Modul aufgerufen)
# KORRIGIERT: Erweitert bestehende Chains statt neue zu erstellen
##
activate_tailscale_rules() {
    local tailscale_interface="$1"
    
    if [ -z "$tailscale_interface" ]; then
        log_error "activate_tailscale_rules: Kein Interface-Name übergeben!"
        return 1
    fi
    
    log_info "🔗 Aktiviere Tailscale-Regeln für Interface '$tailscale_interface'..."
    
    # Setze Umgebungsvariablen für NAT-Regeln
    export TAILSCALE_INTERFACE="$tailscale_interface"
    export TAILSCALE_ACTIVE="true"
    
    # Erstelle 30-tailscale.conf mit ERWEITERTEN Regeln (nicht neuen Tabellen!)
    local rules_file="/etc/nftables.d/30-tailscale.conf"
    cat > "$rules_file" <<EOF
# =============================================================================
# TAILSCALE-VPN REGELN (dynamisch hinzugefügt) - v4.3
# =============================================================================
# Diese Regeln werden NACH der Tailscale-Installation dynamisch hinzugefügt
# 
# Interface: $tailscale_interface
# Status: Aktiviert am $(date)
# =============================================================================

# ERWEITERE die bestehende input-Chain um VPN-Zugang
insert rule inet filter input position 0 iifname "$tailscale_interface" accept comment "VPN-Input: Tailscale"

# ERWEITERE die bestehende forward-Chain um VPN-Forwarding  
insert rule inet filter forward position 0 iifname "$tailscale_interface" accept comment "VPN-Forward: Von Tailscale"
insert rule inet filter forward position 1 oifname "$tailscale_interface" ct state related,established accept comment "VPN-Forward: Zu Tailscale"
EOF
    
    # Falls VPN-Modell: Erstelle auch NAT-Regeln
    if [ "${ACCESS_MODEL:-2}" = "1" ]; then
        generate_nat_rules  # Diese Funktion erstellt 90-nat.conf
    fi
    
    # Lade die Konfiguration neu um die neuen Regeln zu aktivieren
    if systemctl reload nftables >/dev/null 2>&1; then
        log_ok "Tailscale-Firewall-Regeln erfolgreich aktiviert."
        
        # Verifikation
        if nft list chain inet filter input 2>/dev/null | grep -q "tailscale"; then
            log_ok "  ✅ Tailscale-Input-Regeln sind aktiv"
        else
            log_warn "  ⚠️  Tailscale-Input-Regeln nicht sichtbar"
        fi
        
    else
        log_error "Fehler beim Laden der Tailscale-Regeln!"
        return 1
    fi
}

##
# Aktiviert Docker-Regeln dynamisch (wird vom Container-Modul aufgerufen)  
# KORRIGIERT: Erweitert bestehende Chains statt neue zu erstellen
##
activate_docker_rules() {
    local docker_interface="$1"
    local tailscale_interface="${2:-}"  # Optional
    
    if [ -z "$docker_interface" ]; then
        log_error "activate_docker_rules: Kein Docker-Interface übergeben!"
        return 1
    fi
    
    log_info "🐳 Aktiviere Docker-Regeln für Interface '$docker_interface'..."
    
    # Erstelle 40-docker.conf mit ERWEITERTEN Regeln
    local rules_file="/etc/nftables.d/40-docker.conf"
    cat > "$rules_file" <<EOF
# =============================================================================
# DOCKER-CONTAINER REGELN (dynamisch hinzugefügt) - v4.3
# =============================================================================
# Diese Regeln werden NACH der Docker-Installation dynamisch hinzugefügt
#
# Docker-Interface: $docker_interface
# Tailscale-Interface: ${tailscale_interface:-nicht konfiguriert}
# Status: Aktiviert am $(date)
# =============================================================================

# Docker-Container untereinander (immer benötigt)
insert rule inet filter forward position 0 iifname "$docker_interface" oifname "$docker_interface" accept comment "Docker-Container untereinander"
EOF

    # Tailscale <-> Docker Integration (falls verfügbar)
    if [ -n "$tailscale_interface" ]; then
        cat >> "$rules_file" <<EOF

# VPN <-> CONTAINER INTEGRATION (AKTIV)
insert rule inet filter forward position 0 iifname "$tailscale_interface" oifname "$docker_interface" accept comment "VPN zu Docker-Container"  
insert rule inet filter forward position 1 iifname "$docker_interface" oifname "$tailscale_interface" ct state related,established accept comment "Container-Antworten an VPN"
EOF
        log_info "  -> VPN-Container-Integration aktiviert"
    else
        cat >> "$rules_file" <<EOF

# VPN <-> CONTAINER INTEGRATION (INAKTIV - Tailscale nicht verfügbar)
# insert rule inet filter forward iifname "tailscale0" oifname "$docker_interface" accept comment "VPN zu Docker-Container"
# insert rule inet filter forward iifname "$docker_interface" oifname "tailscale0" ct state related,established accept comment "Container-Antworten an VPN"
EOF
    fi
    
    # Lade die Konfiguration neu
    if systemctl reload nftables >/dev/null 2>&1; then
        log_ok "Docker-Firewall-Regeln erfolgreich aktiviert."
        
        # Verifikation
        if nft list chain inet filter forward 2>/dev/null | grep -q "docker"; then
            log_ok "  ✅ Docker-Forward-Regeln sind aktiv"
        else
            log_warn "  ⚠️  Docker-Forward-Regeln nicht sichtbar"
        fi
        
    else  
        log_error "Fehler beim Laden der Docker-Regeln!"
        return 1
    fi
}

##
# Debugging-Funktion: Zeigt den aktuellen Firewall-Status
##
debug_firewall_status() {
    log_info "🔍 FIREWALL-STATUS DIAGNOSE:"
    
    # 1. Service-Status
    echo "--- SERVICE-STATUS ---"
    systemctl is-active nftables && echo "✅ nftables: AKTIV" || echo "❌ nftables: INAKTIV"
    systemctl is-active crowdsec >/dev/null 2>&1 && echo "✅ crowdsec: AKTIV" || echo "❌ crowdsec: INAKTIV"  
    systemctl is-active docker >/dev/null 2>&1 && echo "✅ docker: AKTIV" || echo "❌ docker: INAKTIV"
    
    # 2. Tabellen-Übersicht
    echo -e "\n--- NFTABLES TABELLEN ---"
    nft list tables 2>/dev/null || echo "❌ Keine NFTables geladen"
    
    # 3. Chain-Übersicht  
    echo -e "\n--- WICHTIGE CHAINS ---"
    nft list chain inet filter input >/dev/null 2>&1 && echo "✅ inet filter input" || echo "❌ inet filter input"
    nft list chain inet filter forward >/dev/null 2>&1 && echo "✅ inet filter forward" || echo "❌ inet filter forward"
    nft list chain inet filter geoip_check >/dev/null 2>&1 && echo "✅ geoip_check" || echo "❌ geoip_check"
    
    # 4. Interface-Status
    echo -e "\n--- INTERFACE-STATUS ---" 
    ip link show docker0 >/dev/null 2>&1 && echo "✅ docker0 Interface" || echo "❌ docker0 Interface"
    ip link show tailscale0 >/dev/null 2>&1 && echo "✅ tailscale0 Interface" || echo "❌ tailscale0 Interface"
    
    # 5. Modul-Dateien
    echo -e "\n--- KONFIGURATIONSMODULE ---"
    for conf_file in /etc/nftables.d/*.conf; do
        if [ -f "$conf_file" ]; then
            echo "✅ $(basename "$conf_file")"
        fi
    done
    
    echo -e "\n--- ENDE DIAGNOSE ---"
}

################################################################################
# ENDE DER FIREWALL-HELFER-BIBLIOTHEK v4.3
################################################################################
