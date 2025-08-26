#!/bin/bash
################################################################################
#
# UI-HELPER-FUNKTIONEN
#
# @description: Funktionen für die Benutzeroberfläche und Konsolenausgabe.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

# Farben für die Ausgabe
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'

##
# Fragt den Benutzer nach einer Ja/Nein-Antwort und speichert das Ergebnis.
# @param string $1 Die Frage, die dem Benutzer gestellt wird.
# @param string $2 Der Name der Variable, in der das Ergebnis ('ja'/'nein') gespeichert wird.
# @param string $3 Der Standardwert ('ja' oder 'nein').
##
prompt_for_yes_no() {
    local prompt="$1" var_name="$2" default="$3"
    local answer
    while true; do
        read -p "$(echo -e "${CYAN}›${NC}") $prompt (ja/nein, Standard: $default, Enter für Standard): " answer
        if [ -z "$answer" ]; then answer="$default"; fi
        
        case "$answer" in
            [jJ]|[yY]|[jJ][aA]|[yY][eE][sS] ) eval "$var_name='ja'"; break;;
            [nN]|[nN][eE][iI][nN]|[nN][oO] ) eval "$var_name='nein'"; break;;
            * ) echo -e "${RED}  Bitte mit 'ja' oder 'nein' antworten.${NC}";;
        esac
    done
}

##
# Gibt einen formatierten Header für einen Abschnitt in der Konsole aus.
# @param string $1 Schrittnummer (z.B. "1").
# @param string $2 Titel des Abschnitts.
# @param string $3 Icon für den Abschnitt.
##
print_section_header() {
    local step="$1" title="$2" icon="$3"
    local padding_size=$((60 - ${#title} - ${#step}))
    local padding; printf -v padding '%*s' $padding_size
    echo -e "\n${BLUE}┌─────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│ ${icon}   SCHRITT ${step}:   ${title}${padding}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────────────┘${NC}"
}

##
# Gibt einen formatierten Header für einen Block in der Zusammenfassung aus.
# @param string $1 Titel des Headers.
# @param string $2 Farbvariable (z.B. "GREEN").
##
print_summary_header() {
    local title="$1" color="$2"
    echo -e "\n${!color}--- $title ---${NC}"
}

##
# Gibt einen formatierten Eintrag (Label: Wert) in der Zusammenfassung aus.
# @param string $1 Das Label.
# @param string $2 Der Wert.
# @param string $3 Optionale Farbvariable (Standard: CYAN).
##
print_summary_entry() {
    local label="$1" value="$2" color="${3:-$CYAN}"
    printf "   %-28s %b\n" "$label:" "${color}${value}${NC}"
}

##
# Gibt einen formatierten Tipp in der Zusammenfassung aus.
# @param string $1 Der Tipp-Text.
##
print_summary_tip() {
    local tip="$1"
    echo -e "   ${BLUE}💡 $1${NC}"
}

##
# Gibt eine formatierte Warnung in der Zusammenfassung aus.
# @param string $1 Der Warnhinweis.
##
print_summary_warning() {
    local warning="$1"
    echo -e "   ${YELLOW}⚠️  $1${NC}"
}

##
# Gibt die Fingerprints der SSH-Host-Schlüssel aus.
##
print_ssh_host_keys() {
    echo -e "   ${BLUE}Server Host-Key Fingerprints:${NC}"
    for key_file in /etc/ssh/ssh_host_*_key.pub; do
        if [ -f "$key_file" ]; then
            local fingerprint
            fingerprint=$(ssh-keygen -l -f "$key_file" | awk '{print $2}')
            print_summary_entry "  > $(basename "$key_file" .pub)" "$fingerprint" "$CYAN"
        fi
    done
}

##
# Zeigt eine praxisorientierte Zusammenfassung mit den wichtigsten Informationen
# und den nächsten Schritten für den Administrator an.
##
show_summary() {
    local server_ip
    server_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "Unbekannt")
    
    echo -e "${GREEN}🎉 Server-Setup erfolgreich abgeschlossen! 🎉${NC}\n"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ZUGANGS-INFORMATIONEN (kritisch für nächste Schritte)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "ZUGANGS-INFORMATIONEN" "GREEN"
    print_summary_entry "Server" "${SERVER_HOSTNAME:-$(hostname)} ($server_ip)"
    print_summary_entry "SSH-Befehl" "ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$server_ip"
    print_summary_entry "Admin-User" "${ADMIN_USER:-admin} (sudo-Berechtigung)"
    
    # SSH-Key-Status (wichtig für Sicherheit)
    if [ -n "${SSH_PUBLIC_KEY:-}" ]; then
        print_summary_entry "SSH-Key" "✅ Konfiguriert"
        print_ssh_host_keys
        print_summary_tip "SSH-Key ist aktiv - Passwort-Login kann deaktiviert werden"
    else
        print_summary_entry "SSH-Key" "❌ Nicht konfiguriert"
        print_summary_warning "SSH-Key nach erstem Login einrichten!"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TAILSCALE VPN (falls konfiguriert - wichtig für sicheren Zugang)
    # ═══════════════════════════════════════════════════════════════════════════
    if [ "${ACCESS_MODEL:-}" = "1" ] && command -v tailscale >/dev/null 2>&1; then
        print_summary_header "TAILSCALE VPN-ZUGANG" "PURPLE"
        local tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "")
        local tailscale_status=$(tailscale status --json 2>/dev/null | grep -o '"Online":[^,]*' | cut -d: -f2 || echo "false")
        
        if [ -n "$tailscale_ip" ] && [ "$tailscale_status" = "true" ]; then
            print_summary_entry "VPN-Status" "✅ Verbunden"
            print_summary_entry "VPN-IP" "$tailscale_ip"
            print_summary_entry "SSH via VPN" "ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$tailscale_ip"
            print_summary_tip "VPN ist aktiv - sicherster Zugangsweg!"
        else
            print_summary_entry "VPN-Status" "⚠️ Nicht verbunden"
            print_summary_warning "Tailscale-Autorisierung abschließen!"
            print_summary_tip "Befehl: sudo tailscale up"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # DOCKER-INFORMATIONEN (falls installiert - wichtig für Container-Verwaltung)
    # ═══════════════════════════════════════════════════════════════════════════
    if [ "${SERVER_ROLE:-}" = "1" ] || systemctl is-active --quiet docker 2>/dev/null; then
        print_summary_header "DOCKER-CONTAINER" "CYAN"
        
        if systemctl is-active --quiet docker; then
            print_summary_entry "Docker-Status" "✅ Aktiv"
            
            # Docker-Netzwerk-Info (wichtig für Container-Konfiguration)
            local docker_network=$(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || echo "Standard")
            print_summary_entry "Docker-Netz" "$docker_network"
            
            # Portainer (wichtig für Web-Management)
            if [ "${INSTALL_PORTAINER:-}" = "ja" ]; then
                local portainer_ip="${PORTAINER_FINAL_IP:-127.0.0.1}"
                local portainer_status="❌ Nicht erreichbar"
                
                if docker ps --filter name=portainer --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
                    portainer_status="✅ Läuft"
                fi
                
                print_summary_entry "Portainer" "$portainer_status"
                print_summary_entry "Portainer-URL" "https://$portainer_ip:9443"
                
                if [ "$portainer_ip" = "127.0.0.1" ]; then
                    print_summary_tip "SSH-Tunnel: ssh -L 9443:localhost:9443 ${ADMIN_USER:-admin}@$server_ip"
                fi
            fi
            
            # Watchtower (Auto-Updates)
            if [ "${INSTALL_WATCHTOWER:-}" = "ja" ] && docker ps --filter name=watchtower --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
                print_summary_entry "Auto-Updates" "✅ Watchtower aktiv (täglich 04:00)"
            fi
            
        else
            print_summary_entry "Docker-Status" "❌ Problem"
            print_summary_warning "Docker-Service prüfen: systemctl status docker"
        fi
    fi
    # ═══════════════════════════════════════════════════════════════════════════
    # AUTOMATISCHE WARTUNG (systemd-Timer - komplett automatisch)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "AUTOMATISCHE WARTUNG (SYSTEMD-TIMER)" "YELLOW"

    # Finde alle Timer
    local all_timers=$(systemctl list-unit-files --type=timer 2>/dev/null | grep "\.timer" | awk '{print $1}' | sort)

    local active_count=0
    local total_count=0

    # Durchlaufe alle gefundenen Timer
    while read -r timer_name; do
        if [ -n "$timer_name" ]; then
            ((total_count++))
            
            # Timer-Name formatieren (ohne .timer, Bindestriche zu Leerzeichen)
            local display_name=$(echo "$timer_name" | sed 's/\.timer$//' | sed 's/-/ /g')
            
            if systemctl is-active --quiet "$timer_name" 2>/dev/null; then
                ((active_count++))
                local next_run=$(systemctl list-timers "$timer_name" --no-pager 2>/dev/null | grep "$timer_name" | awk '{print $1, $2}' | head -1 || echo "Unbekannt")
                print_summary_entry "$display_name" "✅ Aktiv (Nächster: $next_run)"
            else
                print_summary_entry "$display_name" "❌ Inaktiv"
            fi
        fi
    done <<< "$all_timers"

    if [ "${ENABLE_GEOIP_BLOCKING:-}" = "ja" ]; then
        print_summary_header "GEOIP BLOCKING" "YELLOW"
        print_summary_entry "Status & Statistiken" "geoip-manager status"
        print_summary_entry "Manuelles Update" "geoip-manager update"
        print_summary_entry "Logs anzeigen" "geoip-manager logs"
        print_summary_tip "Blockierte Länder: ${BLOCKED_COUNTRIES:-Keine}"
        print_summary_tip "Geschütztes Heimatland: ${HOME_COUNTRY:-Keines}"
    fi

    # Zusammenfassung
    print_summary_entry "Timer Status" "$active_count von $total_count aktiv"
    print_summary_tip "Alle Timer: systemctl list-timers"

    # ═══════════════════════════════════════════════════════════════════════════
    # SOFORT-AKTIONEN (Was jetzt gemacht werden muss)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "SOFORT-AKTIONEN (IN DIESER REIHENFOLGE)" "RED"
    
    echo -e "    ${RED}1. SSH-ZUGANG TESTEN (KRITISCH!)${NC}"
    echo -e "       ${CYAN}ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$server_ip${NC}"
    if [ -n "$tailscale_ip" ]; then
        echo -e "       ${PURPLE}Oder via VPN: ssh -p ${SSH_PORT:-22} ${ADMIN_USER:-admin}@$tailscale_ip${NC}"
    fi
    echo ""
    
    echo -e "    ${RED}2. SSH-SICHERHEIT MAXIMIEREN${NC}"
    if [ -z "${SSH_PUBLIC_KEY:-}" ]; then
        echo -e "       ${YELLOW}• SSH-Key einrichten (empfohlen!)${NC}"
        echo -e "       ${YELLOW}• Dann PasswordAuthentication no setzen${NC}"
    else
        print_summary_tip "SSH-Key bereits konfiguriert"
    fi
    echo ""
    
    echo -e "    ${RED}3. ROOT-ZUGANG SPERREN${NC}"
    echo -e "       ${CYAN}sudo passwd -l root${NC}"
    echo ""
    
    echo -e "    ${RED}4. SYSTEM NEUSTARTEN${NC}"
    echo -e "       ${CYAN}sudo reboot${NC}"
    echo ""
    
    # ═══════════════════════════════════════════════════════════════════════════
    # VERIFIKATIONS-BEFEHLE (für Kontrolle nach Neustart)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "VERIFIKATION NACH NEUSTART" "BLUE"
    echo -e "    ${BLUE}Firewall:${NC} sudo nft list ruleset | head -20"
    echo -e "    ${BLUE}Services:${NC} systemctl status ssh nftables"
    if command -v crowdsec >/dev/null 2>&1; then
        echo -e "    ${BLUE}IPS:${NC} systemctl status crowdsec"
    fi
    echo -e "    ${BLUE}Updates:${NC} systemctl list-timers"
    echo -e "    ${BLUE}Logs:${NC} journalctl -f"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # WICHTIGE DATEIEN & BEFEHLE (für spätere Verwaltung)
    # ═══════════════════════════════════════════════════════════════════════════
    print_summary_header "WICHTIGE DATEIEN & BEFEHLE" "PURPLE"
    print_summary_entry "Setup-Log" "$LOG_FILE"
    print_summary_entry "SSH-Config" "/etc/ssh/sshd_config"
    print_summary_entry "Firewall-Config" "/etc/nftables.conf"
    
    if [ "${ENABLE_GEOIP_BLOCKING:-}" = "ja" ]; then
        print_summary_entry "GeoIP-Management" "geoip-manager status"
    fi
    
    if systemctl is-active --quiet docker 2>/dev/null; then
        print_summary_entry "Docker-Container" "docker ps -a"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FOOTER mit kritischen Hinweisen
    # ═══════════════════════════════════════════════════════════════════════════
    echo ""
    echo -e "${RED}⚠️  KRITISCH: Teste SSH-Zugang BEVOR du das Terminal schließt!${NC}"
    echo -e "${YELLOW}💡 Bei Problemen: Rescue-Mode des VPS-Providers nutzen${NC}"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}   🚀 Server bereit für Finalisierung! Folge den Sofort-Aktionen oben.        ${NC}"
    echo -e "${BLUE}   📊 Setup-Details: $LOG_FILE${NC}"
    echo -e "${BLUE}   ⏰ Setup abgeschlossen: $(date '+%d.%m.%Y %H:%M')${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
}

##
## Zeigt die Hilfe-Informationen für das Skript an.
##
show_usage() {
    print_section_header "HELP" "SERVER-BAUKASTEN v$SCRIPT_VERSION" "🏗️"
    echo -e "${BLUE}    Ein umfassendes Bash-Skript zur automatisierten Härtung und Konfiguration   ${NC}"
    echo -e "${BLUE}         von neuen Debian 12 / Ubuntu 22.04+ Servern nach höchsten Standards.     ${NC}"
    echo ""
    
    # Verwendung
    print_summary_header "VERWENDUNG" "GREEN"
    print_summary_entry "Standard-Ausführung" "sudo ./serverbaukasten.sh -c config.conf"
    print_summary_entry "Schneller Testlauf" "sudo ./serverbaukasten.sh -t -c config.conf"
    
    # Optionen
    print_summary_header "OPTIONEN" "CYAN"
    print_summary_entry "-c FILE" "Pfad zur Konfigurationsdatei (Pflicht)."
    print_summary_entry "-t" "Test-Modus (überspringt langsame Operationen)."
    print_summary_entry "-v" "Verbose-Modus (detaillierte Ausgaben)."
    print_summary_entry "-d" "Debug-Modus (maximale Ausgaben)."
    print_summary_entry "-h" "Zeigt diese Hilfe an."

    # Haupt-Features
    print_summary_header "HAUPT-FEATURES" "PURPLE"
    print_summary_entry "Sicherheits-Basis" "NFTables, CrowdSec, AIDE, RKHunter, Kernel-Härtung"
    print_summary_entry "Unsichtbarer Zugang" "Vollständige Integration von Tailscale VPN"
    print_summary_entry "Automatisierung" "Updates & Wartung via moderner systemd-Timer"
    print_summary_entry "Container-Ready" "Gehärtete Docker-Installation (optional)"
    
    # Wichtigste Schritte nach dem Setup
    print_summary_header "WICHTIGSTE SCHRITTE NACH DEM SETUP" "YELLOW"
    echo -e "  ${PURPLE}1.${NC} SSH-Zugang in einem **neuen Terminal** testen."
    echo -e "  ${PURPLE}2.${NC} Passwort-Login deaktivieren (falls SSH-Key genutzt)."
    echo -e "  ${PURPLE}3.${NC} Root-Konto sperren: ${CYAN}sudo passwd -l root${NC}"
    echo -e "  ${PURPLE}4.${NC} Server neustarten: ${CYAN}sudo reboot${NC}"
    echo -e "  ${PURPLE}5.${NC} GeoIP-Listen laden: ${CYAN}sudo geoip-manager update${NC}"
    
    # Footer
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}   🌐 Vollständige Doku: https://github.com/TZERO78/Server-Baukasten            ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
}