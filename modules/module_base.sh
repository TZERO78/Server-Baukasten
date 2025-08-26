#!/bin/bash
################################################################################
#
# MODUL: BASIS-SYSTEM-SETUP
#
# @description: Führt die grundlegende Systemkonfiguration durch,
#               wie Hostname, Zeitzone, Benutzer, Pakete und Swap.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

##
# MODUL 2: Führt die grundlegende Systemkonfiguration durch.
# Setzt Hostname, Zeitzone, Locale, Benutzer, Passwörter und installiert Kernpakete.
##
module_base() {
    log_info "📦 MODUL: Basis-System-Setup"
    
    # --- Phase 1/7: System-Identität ---
    log_info "  -> 1/7: Konfiguriere System-Identität..."
    hostnamectl set-hostname "$SERVER_HOSTNAME"
    sed -i "/127.0.1.1/c\127.0.1.1       $SERVER_HOSTNAME" /etc/hosts
    log_ok "Hostname gesetzt auf: $SERVER_HOSTNAME"
    
    timedatectl set-timezone "$TIMEZONE"
    log_ok "Zeitzone gesetzt auf: $TIMEZONE"
    
    sed -i -E 's/^#\s*(de_DE.UTF-8\s+UTF-8)/\1/' /etc/locale.gen
    sed -i -E 's/^#\s*(en_US.UTF-8\s+UTF-8)/\1/' /etc/locale.gen
    run_with_spinner "Generiere Locales..." "locale-gen"
    update-locale LANG="$LOCALE"
    log_ok "System-Locale gesetzt auf: $LOCALE"
    
    # --- Phase 2/7: Benutzer-Management ---
    log_info "  -> 2/7: Konfiguriere Benutzer-Accounts..."
    echo "root:$ROOT_PASSWORD" | chpasswd
    log_ok "Root-Passwort aktualisiert."

    if ! id "$ADMIN_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$ADMIN_USER"
        log_ok "Admin-Benutzer '$ADMIN_USER' erstellt."
    else
        log_info "Admin-Benutzer '$ADMIN_USER' existiert bereits."
    fi

    echo "$ADMIN_USER:$ADMIN_PASSWORD" | chpasswd
    usermod -aG sudo "$ADMIN_USER"
    log_ok "Admin-Benutzer '$ADMIN_USER' konfiguriert und zur sudo-Gruppe hinzugefügt."

    # SICHERE sudo-Rechte-Vergabe:
    if ! grant_temporary_sudo_rights; then
        log_error "Konnte temporäre sudo-Rechte nicht gewähren!"
        exit 1
    fi
    log_warn "Temporäre NOPASSWD sudo-Rechte für '$ADMIN_USER' aktiviert (werden am Ende entfernt)."

    # --- Phase 3/7: Kern-Pakete ---
    log_info "  -> 3/7: Installiere Kern-Pakete..."
    export DEBIAN_FRONTEND=noninteractive
    readonly APT_OPTIONS="-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
    
    local packages_to_install=()
    packages_to_install+=("sudo" "nano" "vim" "curl" "wget" "gpg" "ca-certificates" "software-properties-common" "apt-transport-https") # System
    packages_to_install+=("htop" "tree" "unzip" "git" "rsync" "screen" "tmux" "net-tools" "bind9-dnsutils" "tcpdump" "jq" "lsof" "file" "psmisc") # Admin
    packages_to_install+=("aide" "rkhunter" "apparmor" "apparmor-utils" "libipc-system-simple-perl") # Security
    
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        log_info "  -> Füge GeoIP-Pakete zur Installationsliste hinzu..."
        packages_to_install+=("ipset" "geoip-database" "geoip-bin")
    fi
    if [ "$ENABLE_SYSTEM_MAIL" = "ja" ]; then
        log_info "  -> Füge Mail-Pakete zur Installationsliste hinzu..."
        echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections
        packages_to_install+=("msmtp" "msmtp-mta" "mailutils")
    fi

    run_with_spinner "Installiere ${#packages_to_install[@]} Basis-Pakete..." "apt-get install $APT_OPTIONS ${packages_to_install[*]}"
    
    if ! run_with_spinner "Installiere zusätzliche AppArmor-Profile..." "timeout 60 apt-get install $APT_OPTIONS apparmor-profiles-extra"; then
        log_warn "Installation der AppArmor-Profile übersprungen (Timeout)."
    fi

    # --- Phase 4/7: Mail-System Konfiguration ---
    if [ "$ENABLE_SYSTEM_MAIL" = "ja" ]; then
        log_info "  -> 4/7: Konfiguriere Mail-System..."
        update-alternatives --install /usr/sbin/sendmail sendmail /usr/bin/msmtp 25
        update-alternatives --set sendmail /usr/bin/msmtp
        log_ok "msmtp als systemweite sendmail-Alternative konfiguriert."
    else
        log_info "  -> 4/7: Mail-System-Konfiguration übersprungen (deaktiviert)."
    fi
    
    # --- Phase 5/7: Swap-Konfiguration ---
    log_info "  -> 5/7: Konfiguriere Swap-Speicher..."
    if ! swapon --show | grep -q /swapfile; then
        run_with_spinner "Erstelle 2GB Swap-Datei..." \
            "fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile"
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    else
        log_info "Swap-Datei existiert bereits."
    fi
    
    # --- Phase 6/7: Docker-Setup (falls Container-Server) ---
    if [ "$SERVER_ROLE" = "1" ]; then
        log_info "  -> 6/7: Installiere Docker-Engine..."
        
        install -m 0755 -d /etc/apt/keyrings
        if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
            run_with_spinner "Füge Docker GPG-Schlüssel hinzu..." \
                "curl -fsSL https://download.docker.com/linux/$OS_ID/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
        fi
        
        if [ ! -f /etc/apt/sources.list.d/docker.list ]; then
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS_ID $OS_VERSION_CODENAME stable" > /etc/apt/sources.list.d/docker.list
            run_with_spinner "Aktualisiere Paketlisten für Docker Repository..." "apt-get update -qq"
            log_ok "Docker Repository hinzugefügt."
        fi
        
        local docker_packages=("docker-ce" "docker-ce-cli" "containerd.io" "docker-buildx-plugin" "docker-compose-plugin")
        run_with_spinner "Installiere Docker-Pakete..." "apt-get install -y ${docker_packages[*]}"
        
        usermod -aG docker "$ADMIN_USER"
        log_ok "'$ADMIN_USER' zur Docker-Gruppe hinzugefügt."
        
        systemctl disable --now docker >/dev/null 2>&1 || true
        log_info "Docker-Engine installiert (Service wird später konfiguriert)."
        # Konfiguriere iptables-nft Backend für Docker-Kompatibilität
        setup_iptables_nft_backend
    else
        log_info "  -> 6/7: Docker-Setup übersprungen (Einfacher Server)."
    fi

    # --- Phase 7/7: Modulare Komponenten bereitstellen ---
    log_info "  -> 7/7: Stelle benötigte modulare Komponenten bereit..."
    
    # GeoIP-Komponenten (falls aktiviert)
    if [ "${ENABLE_GEOIP_BLOCKING:-nein}" = "ja" ]; then
        log_info "     -> GeoIP-Komponenten..."
        
        # geoip-manager installieren
        if run_with_spinner "Download geoip-manager..." "curl -fsSL '$COMPONENTS_BASE_URL/geoip-manager' -o '/usr/local/bin/geoip-manager'"; then
            chmod 750 "/usr/local/bin/geoip-manager"
            chown root:sudo "/usr/local/bin/geoip-manager"
        else
            log_error "geoip-manager Download fehlgeschlagen!"
        fi
        
        # update-geoip-sets installieren
        if run_with_spinner "Download update-geoip-sets..." "curl -fsSL '$COMPONENTS_BASE_URL/update-geoip-sets' -o '/usr/local/bin/update-geoip-sets'"; then
            chmod 750 "/usr/local/bin/update-geoip-sets"
            chown root:sudo "/usr/local/bin/update-geoip-sets"
        else
            log_error "update-geoip-sets Download fehlgeschlagen!"
        fi
    fi
    
    # Weitere Komponenten direkt hier hinzufügen:
    # if [ "$SERVER_ROLE" = "1" ]; then
    #     log_info "     -> Docker-Komponenten..."
    #     if run_with_spinner "Download docker-setup.sh..." "curl -fsSL '$COMPONENTS_BASE_URL/docker-setup.sh' -o '/usr/local/bin/docker-setup.sh'"; then
    #         chmod 770 "/usr/local/bin/docker-setup.sh"
    #         chown root:sudo "/usr/local/bin/docker-setup.sh"
    #     fi
    # fi

   log_ok "Modul Basis-System-Setup erfolgreich abgeschlossen."  
}