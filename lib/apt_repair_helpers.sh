#!/bin/bash
##
## APT-Reparatur und Provider-Detection Helper
## Behandelt provider-spezifische APT-Probleme und repariert defekte Quellen
## 
## @author Server-Baukasten
## @version 1.0.0
##

##
## Erkennt VPS-Provider anhand verschiedener Merkmale
## @return string Provider-Name oder "generic"
##
detect_vps_provider() {
    local provider="generic"
    
    log_debug "  -> Starte VPS-Provider-Detection..."
    
    # IONOS (1&1)
    if grep -qi "ionos\|1und1\|1and1" /etc/resolv.conf 2>/dev/null || \
       [ -d /etc/apt/mirrors ]; then
        provider="ionos"
        log_info "  -> IONOS/1&1 VPS erkannt"
        log_debug "    - Mirror-Verzeichnis: $([ -d /etc/apt/mirrors ] && echo 'vorhanden' || echo 'nicht vorhanden')"
    
    # Hetzner
    elif grep -qi "hetzner\|your-server\.de" /etc/resolv.conf 2>/dev/null || \
         grep -qi "hetzner" /etc/hostname 2>/dev/null || \
         [ -f /etc/hetzner ]; then
        provider="hetzner"
        log_info "  -> Hetzner VPS erkannt"
    
    # DigitalOcean
    elif curl -s --connect-timeout 2 http://169.254.169.254/metadata/v1/id 2>/dev/null | grep -q "droplet"; then
        provider="digitalocean"
        log_info "  -> DigitalOcean Droplet erkannt"
    
    # OVH/OVHcloud
    elif grep -qi "ovh\|kimsufi\|soyoustart" /etc/resolv.conf 2>/dev/null || \
         [ -f /etc/ovh-release ]; then
        provider="ovh"
        log_info "  -> OVH/Kimsufi/SoYouStart VPS erkannt"
    
    # Contabo
    elif grep -qi "contabo" /etc/resolv.conf 2>/dev/null || \
         hostname -f 2>/dev/null | grep -qi "contabo"; then
        provider="contabo"
        log_info "  -> Contabo VPS erkannt"
    
    # Scaleway
    elif [ -f /etc/scw-release ] || \
         grep -qi "scaleway" /etc/resolv.conf 2>/dev/null; then
        provider="scaleway"
        log_info "  -> Scaleway VPS erkannt"
    
    # Linode
    elif grep -qi "linode" /etc/resolv.conf 2>/dev/null || \
         [ -f /etc/linode ]; then
        provider="linode"
        log_info "  -> Linode VPS erkannt"
    
    # AWS EC2
    elif curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null | grep -q "ami-id"; then
        provider="aws"
        log_info "  -> AWS EC2 Instance erkannt"
    
    # Vultr
    elif curl -s --connect-timeout 2 http://169.254.169.254/v1.json 2>/dev/null | grep -q "instanceid"; then
        provider="vultr"
        log_info "  -> Vultr VPS erkannt"
    
    # Netcup
    elif grep -qi "netcup" /etc/resolv.conf 2>/dev/null || \
         hostname -f 2>/dev/null | grep -qi "netcup"; then
        provider="netcup"
        log_info "  -> Netcup VPS erkannt"
    
    # Google Cloud
    elif curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" \
         http://metadata.google.internal/computeMetadata/v1/instance/id 2>/dev/null; then
        provider="gcp"
        log_info "  -> Google Cloud Platform erkannt"
    
    # Azure
    elif curl -s --connect-timeout 2 -H "Metadata: true" \
         "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | grep -q "azEnvironment"; then
        provider="azure"
        log_info "  -> Microsoft Azure erkannt"
    else
        log_debug "  -> Kein spezifischer Provider erkannt, nutze generic"
    fi
    
    echo "$provider"
}

##
## Wendet provider-spezifische APT-Fixes an
## @param string $1 Provider-Name
##
apply_provider_apt_fixes() {
    local provider="${1:-generic}"
    
    log_debug "  -> Wende Provider-APT-Fixes an für: $provider"
    
    case "$provider" in
        ionos)
            # IONOS Mirror-Listen und Configs entfernen
            [ -d /etc/apt/mirrors ] && rm -rf /etc/apt/mirrors/*.list 2>/dev/null && \
                log_debug "    - IONOS Mirror-Listen entfernt"
            rm -f /etc/apt/apt.conf.d/99ionos* 2>/dev/null
            ;;
            
        hetzner)
            # Hetzner-spezifische Repositories entfernen
            rm -f /etc/apt/sources.list.d/hetzner* 2>/dev/null
            sed -i '/mirror\.hetzner\.de/d' /etc/apt/sources.list 2>/dev/null
            log_debug "    - Hetzner-Mirror entfernt"
            ;;
            
        ovh)
            # OVH-Mirror durch offizielle ersetzen
            sed -i 's|http://.*\.ovh\.net/debian|http://deb.debian.org/debian|g' /etc/apt/sources.list 2>/dev/null
            rm -f /etc/apt/sources.list.d/ovh* 2>/dev/null
            ;;
            
        contabo|netcup)
            # Oft veraltete Images
            rm -f /etc/apt/apt.conf.d/*${provider}* 2>/dev/null
            ;;
            
        aws|gcp|azure)
            # Cloud-Provider Mirror entfernen
            sed -i 's|http://.*\.ec2\.archive\.ubuntu\.com|http://archive.ubuntu.com|g' /etc/apt/sources.list 2>/dev/null
            sed -i 's|http://.*\.amazonaws\.com/debian|http://deb.debian.org/debian|g' /etc/apt/sources.list 2>/dev/null
            ;;
    esac
    
    # Allgemeine Bereinigung
    apply_general_apt_cleanup
}

##
## Führt allgemeine APT-Bereinigungen durch
##
apply_general_apt_cleanup() {
    log_debug "  -> Führe allgemeine APT-Bereinigungen durch..."
    
    # CD/DVD Quellen entfernen
    sed -i '/^deb cdrom:/d' /etc/apt/sources.list 2>/dev/null
    
    # Veraltete Mirror-Einträge entfernen
    sed -i '/^#.*mirror\./d' /etc/apt/sources.list 2>/dev/null
    
    # Proxy-Configs entfernen wenn nicht benötigt
    if [ -z "${HTTP_PROXY}${http_proxy}" ]; then
        rm -f /etc/apt/apt.conf.d/*proxy* 2>/dev/null
    fi
    
    # Defekte Lock-Files entfernen
    if [ -f /var/lib/dpkg/lock-frontend ]; then
        rm -f /var/lib/dpkg/lock-frontend 2>/dev/null
        rm -f /var/lib/dpkg/lock 2>/dev/null
        dpkg --configure -a 2>/dev/null
    fi
}

##
## Erkennt OS-Version und Codename
## @return array (os_id os_version os_codename)
##
detect_os_version() {
    local os_id="unknown"
    local os_version="unknown"
    local os_codename="unknown"
    
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        os_id="${ID:-unknown}"
        os_version="${VERSION_ID:-unknown}"
        os_codename="${VERSION_CODENAME:-unknown}"
    fi
    
    # Fallback für Debian
    if [ "$os_codename" = "unknown" ] && [ -f /etc/debian_version ]; then
        local deb_version=$(cat /etc/debian_version)
        case "${deb_version%%.*}" in
            13) os_codename="trixie" ;;
            12) os_codename="bookworm" ;;
            11) os_codename="bullseye" ;;
            10) os_codename="buster" ;;
            9)  os_codename="stretch" ;;
            *)  os_codename="stable" ;;
        esac
    fi
    
    echo "$os_id $os_version $os_codename"
}

##
## Generiert sources.list für Debian
## @param string $1 Codename
## @param string $2 Protokoll (http/https)
##
generate_debian_sources() {
    local codename="${1:-stable}"
    local protocol="${2:-http}"
    
    cat << EOF
# Debian $codename - Official Repositories
# Generated by Server-Baukasten on $(date)
# Provider: ${VPS_PROVIDER:-unknown}

deb ${protocol}://deb.debian.org/debian/ ${codename} main contrib non-free non-free-firmware
deb ${protocol}://deb.debian.org/debian/ ${codename}-updates main contrib non-free non-free-firmware
deb ${protocol}://security.debian.org/debian-security ${codename}-security main contrib non-free non-free-firmware

# Backports (optional, uncomment if needed)
#deb ${protocol}://deb.debian.org/debian/ ${codename}-backports main contrib non-free non-free-firmware

# Source packages (optional, uncomment if needed)
#deb-src ${protocol}://deb.debian.org/debian/ ${codename} main contrib non-free non-free-firmware
EOF
}

##
## Generiert sources.list für Ubuntu
## @param string $1 Codename
## @param string $2 Protokoll (http/https)
##
generate_ubuntu_sources() {
    local codename="${1:-focal}"
    local protocol="${2:-http}"
    
    cat << EOF
# Ubuntu $codename - Official Repositories
# Generated by Server-Baukasten on $(date)
# Provider: ${VPS_PROVIDER:-unknown}

deb ${protocol}://archive.ubuntu.com/ubuntu/ ${codename} main restricted universe multiverse
deb ${protocol}://archive.ubuntu.com/ubuntu/ ${codename}-updates main restricted universe multiverse
deb ${protocol}://security.ubuntu.com/ubuntu/ ${codename}-security main restricted universe multiverse

# Backports (optional, uncomment if needed)
#deb ${protocol}://archive.ubuntu.com/ubuntu/ ${codename}-backports main restricted universe multiverse

# Partner repository (optional, uncomment if needed)
#deb ${protocol}://archive.canonical.com/ubuntu ${codename} partner

# Source packages (optional, uncomment if needed)
#deb-src ${protocol}://archive.ubuntu.com/ubuntu/ ${codename} main restricted universe multiverse
EOF
}

##
## Hauptfunktion: Repariert APT-Quellen wenn nötig
## @return int 0=Erfolg, 1=Fehler
##
fix_apt_sources_if_needed() {
    log_info "  -> Prüfe und repariere APT-Quellen..."
    
    # Provider erkennen und Fixes anwenden
    local provider
    provider=$(detect_vps_provider)
    export VPS_PROVIDER="$provider"
    apply_provider_apt_fixes "$provider"
    
    # OS erkennen
    read -r os_id os_version os_codename <<< "$(detect_os_version)"
    log_debug "    - OS: $os_id $os_version ($os_codename)"
    
    # Prüfungen
    local needs_fix=false
    
    if [ ! -f /etc/apt/sources.list ] || ! grep -qE "^deb\s+" /etc/apt/sources.list 2>/dev/null; then
        needs_fix=true
        log_warn "  -> APT-Quellen fehlen oder sind ungültig"
    fi
    
    if ! apt-cache policy 2>/dev/null | grep -qE "o=(Debian|Ubuntu)"; then
        needs_fix=true
        log_warn "  -> Keine offiziellen Repositories verfügbar"
    fi
    
    # Reparatur wenn nötig
    if [ "$needs_fix" = true ]; then
        # Backup
        [ -f /etc/apt/sources.list ] && cp /etc/apt/sources.list \
            "/etc/apt/sources.list.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Sources generieren
        case "$os_id" in
            debian)
                generate_debian_sources "$os_codename" "http" > /etc/apt/sources.list
                ;;
            ubuntu)
                generate_ubuntu_sources "$os_codename" "http" > /etc/apt/sources.list
                ;;
            *)
                log_error "  -> OS '$os_id' nicht unterstützt"
                return 1
                ;;
        esac
        
        # Update und HTTPS
        apt-get update
        
        if apt-get install -y apt-transport-https ca-certificates 2>/dev/null; then
            # Auf HTTPS umstellen
            sed -i 's|http://|https://|g' /etc/apt/sources.list
            apt-get update
        fi
        
        log_ok "✅ APT-Quellen repariert"
    else
        log_ok "  -> APT-Quellen sind funktionsfähig"
    fi
    
    return 0
}