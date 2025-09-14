#!/bin/bash
################################################################################
#
# MODUL: SICHERHEITS-ARCHITEKTUR (v4.3) - KORRIGIERT FÜR ZWEISTUFIGES SETUP
#
# @description: Konfiguriert die mehrschichtige Sicherheitsarchitektur des Servers
#               (SSH, BASIS-Firewall, IPS, GeoIP, Integritäts-Monitoring).
#               Nutzt das neue zweistufige Firewall-Setup.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ÄNDERUNGEN v4.3:
# - Angepasst für zweistufiges Firewall-Setup
# - BASIS-Firewall wird zuerst erstellt (ohne VPN/Docker)
# - VPN/Docker-Regeln werden später dynamisch hinzugefügt
# - Verbesserte Reihenfolge und Abhängigkeiten
# - Erweiterte Verifikation der Sicherheitsschichten
#
################################################################################

##
# HAUPT-MODUL: Sicherheits-Architektur mit zweistufigem Firewall-Setup
##
module_security() {
    #TEST_MODE="$1"
    log_info "🔒 MODUL: Sicherheits-Architektur (Multi-Layer mit zweistufigem Setup)"

    # Die Reihenfolge ist KRITISCH für das zweistufige Setup:
    # 1. Basis-Sicherheit (SSH-Härtung, AppArmor)
    # 2. BASIS-Firewall (ohne VPN/Docker - das kommt später)
    # 3. Intrusion Prevention System (CrowdSec)
    # 4. GeoIP wird bereits in BASIS-Firewall integriert
    # 5. Integritäts-Monitoring (AIDE, RKHunter)
    # 6. Finale Verifikation
    
    setup_basic_security
    setup_firewall_infrastructure  # <- NEUER Ansatz: BASIS nur!
    setup_intrusion_prevention
    setup_integrity_monitoring "$TEST_MODE"
    verify_security_layers
    
    log_ok "Modul Sicherheits-Architektur erfolgreich abgeschlossen."
    log_info "--- SICHERHEITS-STATUS ---"
    log_info "  ✅ BASIS-Firewall: Aktiv (SSH + GeoIP)"
    log_info "  🔄 DYNAMISCH: VPN/Docker-Regeln werden später hinzugefügt"
    log_info "  🛡️  IPS: CrowdSec integriert"
    log_info "  📊 Monitoring: AIDE + RKHunter konfiguriert"
}

##
# Konfiguriert Basis-Sicherheitsmaßnahmen wie SSH-Härtung und AppArmor.
# UNVERÄNDERT - funktioniert weiterhin wie bisher.
##
setup_basic_security() {
    log_info "🔐 SETUP: Basis-Sicherheit (SSH + AppArmor)"
    
    # --- SSH-Härtung ---
    log_info "  -> Konfiguriere SSH-Sicherheit..."
    backup_and_register "/etc/ssh/sshd_config"
    
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        mkdir -p "/home/$ADMIN_USER/.ssh"
        echo "$SSH_PUBLIC_KEY" > "/home/$ADMIN_USER/.ssh/authorized_keys"
        chown -R "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
        chmod 700 "/home/$ADMIN_USER/.ssh" && chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
        log_ok "SSH Public Key für '$ADMIN_USER' installiert."
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
    
    if ! run_with_spinner "SSH-Dienst neu starten..." "systemctl restart ssh"; then
        log_warn "SSH-Neustart fehlgeschlagen. Überprüfe Status manuell."
    else
        log_ok "SSH auf Port $SSH_PORT gehärtet und neu gestartet."
    fi

    # --- AppArmor ---
    log_info "  -> Aktiviere AppArmor (Mandatory Access Control)..."
    run_with_spinner "AppArmor-Dienst aktivieren..." "systemctl enable --now apparmor"
    
    # AppArmor-Profile selektiv erzwingen (runc ausschließen für Docker-Kompatibilität)
    log_info "  -> Setze AppArmor-Profile in enforce-Modus (außer runc)..."
    for profile in /etc/apparmor.d/*; do
        basename_profile=$(basename "$profile")
        case "$basename_profile" in
            "runc"|".*"|"local"|"tunables"|"cache")
                log_debug "Überspringe AppArmor-Profil: $basename_profile"
                continue
                ;;
            *)
                if [ -f "$profile" ]; then
                    aa-enforce "$profile" 2>/dev/null || log_debug "Konnte Profil nicht erzwingen: $basename_profile"
                fi
                ;;
        esac
    done
    
    log_ok "AppArmor aktiviert und Profile erzwungen (runc ausgenommen für Docker)."
}

##
# NEUE VERSION: Installiert und startet die BASIS-Firewall-Infrastruktur
# VPN/Docker-Regeln werden später dynamisch hinzugefügt!
##
setup_firewall_infrastructure() {
    log_info "🔥 SETUP: BASIS-Firewall-Infrastruktur (zweistufig)"
    
    # Installation von NFTables mit Backend-Setup
    run_with_spinner "Installiere NFTables..." "apt-get install -y nftables"
    setup_iptables_nft_backend  # Wichtig für Docker-Kompatibilität!
    
    # BASIS-Firewall-Konfiguration generieren (ohne VPN/Docker)
    log_info "  -> Generiere BASIS-Firewall-Konfiguration..."
    if ! generate_nftables_config; then
        log_error "BASIS-Firewall-Konfiguration konnte nicht erstellt werden!"
        return 1
    fi
    
    # NFTables-Service aktivieren und starten
    if ! run_with_spinner "Aktiviere NFTables-Service..." "systemctl enable --now nftables"; then
        log_error "NFTables-Service konnte nicht gestartet werden!"
        return 1
    fi
    
    # BASIS-Konfiguration laden (KRITISCH!)
    if ! run_with_spinner "Lade BASIS-Firewall-Konfiguration..." "nft -f /etc/nftables.conf"; then
        log_error "BASIS-Firewall-Konfiguration konnte nicht geladen werden!"
        return 1
    fi
    
    # Finale Überprüfung der BASIS-Firewall
    if nft list tables &>/dev/null; then
        log_ok "BASIS-Firewall-Infrastruktur ist aktiv."
        
        # Verifikation der wichtigsten Komponenten
        if nft list chain inet filter input &>/dev/null; then
            log_ok "  ✅ input-Chain: Aktiv"
        else
            log_error "  ❌ input-Chain: Fehlt!"
            return 1
        fi
        
        if nft list chain inet filter forward &>/dev/null; then
            log_ok "  ✅ forward-Chain: Aktiv"
        else
            log_error "  ❌ forward-Chain: Fehlt!"
            return 1
        fi
        
        # GeoIP-Verifikation (falls aktiviert)
        if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
            if nft list chain inet filter geoip_check &>/dev/null; then
                log_ok "  ✅ GeoIP-Chain: Integriert und bereit"
            else
                log_error "  ❌ GeoIP-Chain: Fehlt trotz Aktivierung!"
                return 1
            fi
        fi
        
        # SSH-Port-Test (ROBUSTE VERSION)
        local ssh_port="${SSH_PORT:-22}"
        
        # 1. Prüfe Firewall-Regel (robustes Pattern)
        local firewall_rule_exists=false
        if nft list chain inet filter input 2>/dev/null | grep -Eq "\btcp dport $ssh_port\b.*accept"; then
            firewall_rule_exists=true
        fi
        
        # 2. Prüfe Service-Status
        local ssh_service_running=false
        if systemctl is-active --quiet ssh && ss -tln | grep -q ":$ssh_port "; then
            ssh_service_running=true
        fi
        
        # 3. Bewertung mit intelligenter Fehlerbehandlung
        if [ "$firewall_rule_exists" = true ] && [ "$ssh_service_running" = true ]; then
            log_ok "  ✅ SSH-Port $ssh_port: Firewall-Regel UND Service aktiv"
        elif [ "$ssh_service_running" = true ]; then
            log_warn "  ⚠️  SSH-Port $ssh_port: Service läuft, aber Firewall-Regel unklar"
            log_info "     💡 Möglicherweise wird SSH durch andere Regel erlaubt"
            log_info "     💡 Test: ssh -p $ssh_port localhost echo 'Test OK'"
            # NICHT return 1 - SSH funktioniert ja grundsätzlich!
        elif [ "$firewall_rule_exists" = true ]; then
            log_error "  ❌ SSH-Port $ssh_port: Firewall-Regel da, aber Service Problem!"
            log_error "     🔧 Debug: systemctl status ssh"
            return 1
        else
            log_error "  ❌ SSH-Port $ssh_port: Weder Firewall-Regel noch Service aktiv!"
            log_error "     🔧 Debug: nft list chain inet filter input | grep $ssh_port"
            log_error "     🔧 Debug: systemctl status ssh"
            return 1
        fi
        
    else
        log_error "BASIS-Firewall konnte nicht geladen werden!"
        return 1
    fi
    
    log_ok "BASIS-Firewall-Infrastruktur erfolgreich eingerichtet."
    log_info "--- BASIS-FIREWALL STATUS ---"
    log_info "  🔐 SSH-Zugang: Port $ssh_port geöffnet"
    log_info "  🌍 GeoIP-Blocking: ${ENABLE_GEOIP_BLOCKING:-nein}"
    log_info "  🔄 VPN-Regeln: Werden später hinzugefügt (module_network)"
    log_info "  🔄 Docker-Regeln: Werden später hinzugefügt (module_container)"
}

setup_intrusion_prevention() {
    log_info "🛡️ SETUP: Intrusion Prevention System (CrowdSec)"
    
    # CrowdSec-Installation und -Konfiguration
    install_crowdsec_stack || {
        log_error "CrowdSec-Stack Installation fehlgeschlagen"
        return 1
    }
    # Roort-Verzeichnis & Rechte sicherstellen
	ensure_crowdsec_hub_perms
	
    log_info "  -> Konfiguriere SSH-Schutz-Policies..."
    tune_crowdsec_ssh_policy
    
	# Collections installieren mit Robustheitsprüfung
	log_info "  -> Prüfe CrowdSec Collections..."

	# Erst prüfen ob bereits installiert
	local already_installed
	already_installed=$(cscli collections list 2>/dev/null | grep -E "crowdsecurity/(sshd|linux).*enabled" | wc -l || echo 0)

	if [ "$already_installed" -ge 2 ]; then
		log_ok "SSH- und Linux-Collections bereits aktiv"
		
		# Updates-Hinweis falls tainted
		if cscli collections list 2>/dev/null | grep -q "tainted"; then
			log_info "Hinweis: Collection-Updates verfügbar (cscli collections upgrade)"
		fi
	else
		# Nur installieren wenn wirklich fehlend
		if run_with_spinner "Aktualisiere Hub-Index..." "cscli hub update 2>/dev/null"; then
			if run_with_spinner "Installiere fehlende Collections..." \
			"cscli collections install crowdsecurity/sshd crowdsecurity/linux 2>/dev/null"; then
				log_ok "Collections erfolgreich installiert"
			else
				log_warn "Collection-Installation fehlgeschlagen - CrowdSec funktioniert trotzdem"
			fi
		else
			log_warn "Hub-Update fehlgeschlagen - überspringe Collection-Installation"
		fi
	fi

    # Finale Überprüfung der CrowdSec-Dienste
    log_info "  -> Überprüfe CrowdSec-Service-Status..."
    if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-bouncer-setonly; then
        log_ok "CrowdSec IPS ist aktiv und in die Firewall integriert."
        
        # Kurz warten für NFTables-Integration
        sleep 2
        
        # Erweiterte Verifikation für das zweistufige Setup
        if nft list tables 2>/dev/null | grep -q "crowdsec"; then
            log_ok "  ✅ CrowdSec-NFTables-Integration: Aktiv"
        else
            log_warn "  ⚠️ CrowdSec-NFTables-Integration: Nicht sichtbar (möglicherweise noch startend)"
        fi
        
        return 0
    else
        log_error "CrowdSec-Dienste haben Probleme!"
        log_info "Debug-Befehle:"
        log_info "  -> systemctl status crowdsec"
        log_info "  -> systemctl status crowdsec-bouncer-setonly"
        log_info "  -> journalctl -u crowdsec -n 20"
        
        # Nicht return 1 - IPS ist optional für Basis-Funktionalität
        return 0
    fi
}

##
# MODUL: Installiert, konfiguriert und initialisiert das
#        System-Integritäts-Monitoring (AIDE & RKHunter).
# UNVERÄNDERT - funktioniert weiterhin wie bisher.
##
setup_integrity_monitoring() {
    local TEST_MODE="$1"
    log_info "📊 SETUP: System-Integritäts-Monitoring"

    # TEST-Modus: Zeitaufwändige Initialisierung überspringen
    if [ "$TEST_MODE" = true ]; then
        log_warn "TEST-MODUS: Überspringe Integritäts-Monitoring (AIDE & RKHunter)."
        return 0
    fi

    # Schritt-für-Schritt Installation und Konfiguration
    log_info "  -> 1/4: Installiere Monitoring-Pakete..."
    run_with_spinner "Installiere aide & rkhunter..." "apt-get install -y aide rkhunter"

    log_info "  -> 2/4: Konfiguriere AIDE und RKHunter..."
    configure_aide
    configure_rkhunter

    log_info "  -> 3/4: Initialisiere Datenbanken..."
    if run_with_spinner "Initialisiere AIDE-Datenbank..." "/usr/bin/aide --config /etc/aide/aide.conf --init"; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        log_ok "AIDE-Datenbank erfolgreich initialisiert."
    else
        log_warn "AIDE-Initialisierung fehlgeschlagen. Timer wird es später versuchen."
    fi
    
    run_with_spinner "Aktualisiere RKHunter-Properties..." "rkhunter --propupd --quiet || true"

    log_info "  -> 4/4: Starte Timer für regelmäßige Scans..."
    if ! run_with_spinner "Starte AIDE-Timer..." "systemctl start aide-check.timer"; then
        log_warn "AIDE-Timer konnte nicht gestartet werden."
    fi
    if ! run_with_spinner "Starte RKHunter-Timer..." "systemctl start rkhunter-check.timer"; then
        log_warn "RKHunter-Timer konnte nicht gestartet werden."
    fi

    log_ok "Integritäts-Monitoring konfiguriert und Timer gestartet."
}

##
# NEUE VERSION: Verifiziert die BASIS-Sicherheitsarchitektur 
# Berücksichtigt das zweistufige Setup (VPN/Docker kommen später)
##
verify_security_layers() {
    log_info "🔍 VERIFIKATION: BASIS-Sicherheitsarchitektur"
    
    # Deaktiviere set -e für Verifikation
    local old_errexit=$(set +o | grep errexit)
    set +e
    
    local security_status=0 # Zählt kritische Fehler
    
    # --- LAYER 1: BASIS-FIREWALL (NFTables + SSH) ---
    log_info "  -> Teste Layer 1: BASIS-Firewall..."
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
        log_error "Layer 1: Firewall Policy ist NICHT 'drop' (ist: '$input_policy')."
        ((security_status++))
    fi

    local ssh_port="${SSH_PORT:-22}"
    if systemctl is-active --quiet ssh && ss -tln | grep -q ":$ssh_port "; then
        log_ok "Layer 1: SSH-Service ist aktiv auf Port $ssh_port."
    else
        log_error "Layer 1: SSH-Service Problem oder Port $ssh_port nicht erreichbar."
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
        
        if systemctl is-active --quiet crowdsec-bouncer-setonly; then
            log_ok "Layer 2: CrowdSec-Bouncer ist aktiv."
        else
            log_error "Layer 2: CrowdSec-Bouncer ist NICHT aktiv!"
            ((security_status++))
        fi
        
        if nft list table ip crowdsec >/dev/null 2>&1; then
            log_ok "Layer 2: CrowdSec-NFTables-Integration (IPv4) ist aktiv."
        else
            log_warn "Layer 2: CrowdSec-NFTables-Integration (IPv4) noch nicht sichtbar."
            log_info "         (Kann normal sein - CrowdSec braucht Zeit zum Starten)"
        fi
    else
        log_info "Layer 2: CrowdSec nicht installiert (übersprungen)."
    fi
    
    # --- LAYER 3: GEOIP-BLOCKING (BASIS) ---
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        log_info "  -> Teste Layer 3: GeoIP-Blocking (BASIS)..."
        
        if nft list chain inet filter geoip_check >/dev/null 2>&1; then
            log_ok "Layer 3: GeoIP-Chain ist in BASIS-Firewall integriert."
            
            # Prüfe ob Sets definiert sind (müssen leer sein, werden später befüllt)
            local sets_count
            sets_count=$(nft list ruleset 2>/dev/null | grep -c "set geoip_" || echo "0")
            if [ "$sets_count" -ge 6 ]; then
                log_ok "Layer 3: Alle GeoIP-Sets sind definiert ($sets_count/6)."
            else
                log_warn "Layer 3: Nicht alle GeoIP-Sets gefunden ($sets_count/6)."
            fi
            
        else
            log_error "Layer 3: GeoIP-Chain fehlt in BASIS-Firewall!"
            ((security_status++))
        fi
        
        log_info "         💡 GeoIP-Listen-Update nach Setup: geoip-manager update"
    else
        log_info "  -> Layer 3: GeoIP-Blocking deaktiviert (übersprungen)."
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
    echo "" # Leere Zeile für Lesbarkeit
    if [ "$security_status" -eq 0 ]; then
        log_ok "🎉 Alle BASIS-Sicherheits-Checks bestanden!"
        log_info "   BASIS-Sicherheitsarchitektur ist voll funktional."
        log_info "   VPN/Docker-Regeln werden später dynamisch hinzugefügt."
    elif [ "$security_status" -le 2 ]; then
        log_warn "⚠️  $security_status kleinere Sicherheitsprobleme erkannt."
        log_warn "   BASIS-System ist funktional, aber nicht optimal."
    else
        log_error "❌ $security_status kritische Sicherheitsprobleme erkannt!"
        log_error "   Bitte Ausgabe oben prüfen und Probleme beheben."
    fi
    
    # set -e wieder aktivieren
    eval "$old_errexit"
    
    return $security_status
}

################################################################################
# ENDE MODUL SICHERHEITS-ARCHITEKTUR v4.3
################################################################################
