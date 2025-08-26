#!/bin/bash
################################################################################
#
# BIBLIOTHEK: FIREWALL-HELFER-FUNKTIONEN
#
# @description: Funktionen für die Konfiguration und Generierung der NFTables-Regeln.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

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