#!/bin/bash
################################################################################
#
# MODUL: APT-QUELLEN-ANPASSUNG
#
# @description: Stellt sicher, dass die APT-Quellen auf sichere HTTPS-Verbindungen
#               umgestellt sind.
# @author:      Markus F. (TZERO78) & KI-Assistenten
# @repository:  https://github.com/TZERO78/Server-Baukasten
#
# ------------------------------------------------------------------------------
# Dieses Skript ist ein Modul des Server-Baukastens und steht unter der MIT-Lizenz.
#
################################################################################

##
# MODUL 1: Stellt die APT-Quellen auf sichere HTTPS-Verbindungen um.
##
module_fix_apt_sources() {
    log_info "MODUL 1: APT-Quellen auf HTTPS umstellen${NC}"
    backup_and_register "/etc/apt/sources.list"
    cat > /etc/apt/sources.list << EOF
deb https://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware
deb https://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
deb https://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
EOF
    rm -f /etc/apt/sources.list.d/debian.sources
    log_ok "APT-Quellen auf HTTPS umgestellt.${NC}"
}