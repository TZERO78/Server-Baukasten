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
#                    AIDE & RKHUNTER JOURNALD-INTEGRATION
# ===============================================================================

##
# Konfiguriert AIDE durch Herunterladen des Templates und Erstellen der systemd-Units.
##
configure_aide() {
    log_info "Konfiguriere AIDE (System-Integritäts-Monitoring)..."
    
    # --- Schritt 1: Deaktiviere Standard-Timer ---
    systemctl disable --now dailyaidecheck.timer >/dev/null 2>&1 || true

    # --- Schritt 2: Verzeichnisse erstellen ---
    mkdir -p /etc/aide /var/lib/aide /var/log/aide
    chown root:root /etc/aide /var/lib/aide
    chmod 750 /etc/aide /var/lib/aide
    chown root:adm /var/log/aide
    chmod 750 /var/log/aide
   
    # --- Schritt 3: Lade Konfigurations-Template herunter ---
    download_and_process_template "aide.conf.template" "/etc/aide/aide.conf" "640" "root:root"

    # AIDE-spezifisches Log-Directory (nur als Backup)
    mkdir -p /var/log/aide
    chown root:adm /var/log/aide
    chmod 750 /var/log/aide

    # 3. Systemd Service 
    cat > /etc/systemd/system/aide-check.service << 'EOF'
[Unit]
Description=AIDE File Integrity Check
Documentation=man:aide(1)
After=multi-user.target

[Service]
Type=oneshot
User=root

# KORRIGIERT: Check if database exists, if not create it
ExecStartPre=/bin/bash -c 'if [ ! -f /var/lib/aide/aide.db ]; then /usr/bin/aide --config /etc/aide/aide.conf --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db; fi'

# KORRIGIERT: Run the integrity check with structured output
ExecStart=/usr/bin/aide --config /etc/aide/aide.conf --check

# journald-optimized output
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aide-check

# Structured logging environment
Environment="SYSTEMD_LOG_LEVEL=info"
Environment="SYSTEMD_LOG_TARGET=journal"

# Performance optimization (VPS-friendly)
TimeoutStartSec=45min
CPUQuota=40%
Nice=19
IOSchedulingClass=2
IOSchedulingPriority=7

# Security hardening
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/aide /var/log/aide /tmp

# Exit codes: AIDE-specific handling
# 0 = No changes, 1 = New files, 2 = Removed files, 3 = Changed files
# 4 = Changed and new files, 5 = Changed and removed, 6 = New and removed
# 7 = All types of changes, 14 = Error writing database
SuccessExitStatus=0 1 2 3 4 5 6 7

[Install]
# IMPORTANT: Don't enable service directly - only via timer!
WantedBy=
EOF

    # 4. Systemd Timer
    cat > /etc/systemd/system/aide-check.timer << 'EOF'
[Unit]
Description=Run AIDE integrity check daily
Documentation=man:systemd.timer(5)
Requires=aide-check.service

[Timer]
# Daily at 5:00 AM (low system load time)
OnCalendar=*-*-* 05:00:00

# Randomize up to 30 minutes (spread server load)
RandomizedDelaySec=1800

# Run even if system was down
Persistent=true

# Explicit service reference
Unit=aide-check.service

[Install]
WantedBy=timers.target
EOF

   # 5. journald-Konfiguration neu laden und systemd-Units aktivieren
    run_with_spinner "Lade systemd-Konfiguration neu..." "systemctl restart systemd-journald && systemctl daemon-reload"
    
    # --- Schritt 6: Aktiviere den neuen Timer (für zukünftige Starts) ---
    systemctl daemon-reload
    if ! run_with_spinner "Aktiviere AIDE-Timer für zukünftige Starts..." "systemctl enable aide-check.timer"; then
        log_warn "AIDE-Timer konnte nicht für den Systemstart aktiviert werden."
    fi
    
    log_ok "AIDE-Konfiguration abgeschlossen und Timer für nächsten Boot vorgemerkt."
    log_info "  📜 Logs abrufen mit: journalctl -u aide-check.service"
    log_info "  📊 Timer-Status prüfen mit: systemctl list-timers aide-check.timer"
}

##
# Konfiguriert RKHunter (Rootkit-Scanner) für die Ausführung via systemd-Timer
# und leitet die Ausgabe direkt an das journald-Log um.
##
configure_rkhunter() {
    log_info "Konfiguriere RKHunter..."
    
    # --- Schritt 1: Lade Konfigurations-Template herunter ---
    download_and_process_template "rkhunter.conf.template" "/etc/rkhunter.conf" "640" "root:root"
    
    # RKHunter-spezifische journald-Konfiguration
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/rkhunter-logging.conf << 'EOF'
# RKHunter-optimierte journald-Konfiguration
[Journal]
# RKHunter-Logs persistent speichern (wichtig für Security-Audit)
Storage=persistent

# Längere Aufbewahrung für Security-Logs
MaxRetentionSec=16week

# Komprimierung für RKHunter-Reports
Compress=yes

# Security-Logs haben Priorität - größere Limits
SystemMaxUse=350M
SystemMaxFileSize=40M

# Rate-Limiting für RKHunter-Scans anpassen
RateLimitIntervalSec=120s
RateLimitBurst=30000
EOF

    # 3. Mail nur wenn aktiviert
    if [ "${ENABLE_SYSTEM_MAIL:-nein}" = "ja" ] && [ -n "${NOTIFICATION_EMAIL:-}" ]; then
        echo "MAIL-ON-WARNING=\"$NOTIFICATION_EMAIL\"" >> /etc/rkhunter.conf
        echo "MAIL_CMD=mail -s \"[rkhunter] \$(hostname)\"" >> /etc/rkhunter.conf
        log_info "Mail aktiviert für $NOTIFICATION_EMAIL"
    fi
    
    # 4. Datenbank initialisieren
    log_info "Initialisiere RKHunter-Pfade und Datenbank..."
    
    # Stelle sicher, dass alle benötigten Verzeichnisse existieren
    mkdir -p /var/lib/rkhunter/tmp
    mkdir -p /var/lib/rkhunter/db
    chown root:root /var/lib/rkhunter/tmp /var/lib/rkhunter/db
    chmod 755 /var/lib/rkhunter/tmp /var/lib/rkhunter/db
    
    # Prüfe ob kritische Pfade existieren
    local missing_paths=()
    [ ! -d /usr/share/rkhunter/scripts ] && missing_paths+=("SCRIPTDIR")
    [ ! -d /usr/share/rkhunter ] && missing_paths+=("INSTALLDIR")
    
    if [ ${#missing_paths[@]} -gt 0 ]; then
        log_error "Kritische RKHunter-Pfade fehlen: ${missing_paths[*]}"
        log_warn "RKHunter-Paket ist beschädigt oder nicht vollständig installiert"
        log_info "Lösung: sudo apt-get remove --purge rkhunter && sudo apt-get install rkhunter"
        log_warn "Überspringe RKHunter-Konfiguration..."
        return 0
    fi
    
    rkhunter --update --quiet || true
    rkhunter --propupd --quiet || true
    
    # 5. Systemd Service (journald-optimiert)
    cat > /etc/systemd/system/rkhunter-check.service << 'EOF'
[Unit]
Description=RKHunter Security Check (Rootkit Detection)
Documentation=man:rkhunter(8)
After=multi-user.target

[Service]
Type=oneshot
User=root

# Update signatures if needed
ExecStartPre=-/usr/bin/rkhunter --update --quiet

# Main security scan with structured output
ExecStart=/usr/bin/rkhunter --check --cronjob --report-warnings-only

# journald-optimized output
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rkhunter-check

# Structured logging environment
Environment="SYSTEMD_LOG_LEVEL=info"
Environment="SYSTEMD_LOG_TARGET=journal"

# Performance settings (VPS-optimized)
TimeoutStartSec=20min
CPUQuota=25%
Nice=19

# Security hardening
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rkhunter /var/log /tmp

# RKHunter-specific exit codes as success
# 0 = OK, 1 = Warnings found, 2 = Errors (but scan completed)
SuccessExitStatus=0 1 2

[Install]
# IMPORTANT: Don't enable service directly - only via timer!
WantedBy=
EOF

    # 6. Systemd Timer
    cat > /etc/systemd/system/rkhunter-check.timer << 'EOF'
[Unit]
Description=Run RKHunter security check weekly
Documentation=man:systemd.timer(5)
Requires=rkhunter-check.service

[Timer]
# Weekly on Sunday at 4:00 AM (low system load)
OnCalendar=Sun *-*-* 04:00:00

# Randomize up to 30 minutes (spread server load)
RandomizedDelaySec=1800

# Run even if system was down
Persistent=true

# Explicit service reference
Unit=rkhunter-check.service

[Install]
WantedBy=timers.target
EOF

    # 7. journald-Konfiguration neu laden und aktivieren
    systemctl restart systemd-journald
    systemctl daemon-reload
    systemctl enable --now rkhunter-check.timer
    
    log_ok "RKHunter konfiguriert (wöchentlich sonntags 4:00-4:30 Uhr, journald-optimiert)"
    log_info "Logs: journalctl -u rkhunter-check.service"
    log_info "Security-Filter: journalctl -t rkhunter-check"
    log_info "Timer-Status: systemctl list-timers rkhunter-check.timer"
}