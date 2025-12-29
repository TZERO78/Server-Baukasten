# 🏗️ Server-Baukasten

> 🇩🇪 **[Deutsche Dokumentation / German Documentation](docs/de/README.md)**

<!-- Badges -->
[![Release](https://img.shields.io/github/v/release/TZERO78/Server-Baukasten)](https://github.com/TZERO78/Server-Baukasten/releases)
[![License](https://img.shields.io/github/license/TZERO78/Server-Baukasten)](LICENSE)
[![Debian](https://img.shields.io/badge/Debian-12%20|%2013-red?logo=debian)](https://www.debian.org)
[![Last Commit](https://img.shields.io/github/last-commit/TZERO78/Server-Baukasten)](https://github.com/TZERO78/Server-Baukasten/commits/main)

Fully automated hardening and configuration for Debian and Ubuntu servers according to modern, battle-tested security standards. **Successfully tested on Debian 12 (Bookworm) and the upcoming Debian 13 (Trixie).**

**Modular server hardening for Linux with NFTables, CrowdSec, GeoIP blocking, and Docker integration.**

Pragmatic starter hardening for home servers & small VPS. A Bash script that equips a fresh Debian/Ubuntu server with a configurable security architecture in ~20 minutes.

## Why Bash instead of Ansible/Puppet?

Conscious decision for simplicity:

- **No Dependencies:** Runs immediately on any standard server
- **Fully transparent:** Every line of code is comprehensible
- **Target audience:** Home users and VPS tinkerers, not enterprise admins
- **Learning effect:** You see exactly what gets configured
- **Portability:** Works anywhere Bash is available

Ansible is technically "cleaner," but oversized for the target audience. This script is meant to be fast and understandable, not perfect.

## 📐 Concept

The Server-Baukasten is a pragmatic starter tool with three core principles:

### 1. Solid Security Foundation
The script implements multiple baseline protection layers: NFTables firewall, CrowdSec IPS, GeoIP blocking, and kernel hardening (as far as possible on VPS - no kernel modules or filesystem changes). It's not a complete enterprise system, but provides a secure starting point for your own projects.

### 2. Simplicity over Perfection
Deliberately developed as a simple Bash script - transparent, comprehensible, without external dependencies. The code has been extensively commented and documented with the help of AI. You retain full control and understand every step.

### 3. Reproducible Setup
Server configuration via config file. Enables identical, hardened server setups - once for the virtual machine for testing and secondly on the real VPS for production. The script is not yet fully idempotent - this will be improved gradually.

### 4. Modern Technology Decisions
Deliberately chose current standards instead of legacy tools:
- **NFTables** instead of iptables (modern packet filtering)
- **CrowdSec** instead of Fail2ban (community-based threat intelligence)
- **systemd-timer** instead of cron (better integration and logging)
- **journald** instead of logrotate (structured logging with automatic rotation)
- **Docker** with iptables-nft backend (hybrid solution for compatibility)

Pragmatic mix for security tools:
- **AIDE & RKHunter** remain in use, as modern alternatives (OSSEC, Wazuh) require their own databases and are oversized for home servers
- **AppArmor** as proven MAC system - simpler than SELinux, more effective than nothing

## ⚠️ What it is NOT

A fully automatic enterprise solution. It creates the secure foundation - for specific services you need to work manually. You can adapt the script to your needs at any time.

**Note:** The script is not perfect and certainly has small bugs here and there that I'm naturally trying to fix! Feedback and bug reports are always welcome.

## 🎯 Goal

Automated setup of a secure, production-ready Linux server with:

- Hardened firewall (NFTables)
- Intrusion Prevention System (CrowdSec)
- Container support (Docker)
- VPN integration (Tailscale)
- GeoIP blocking
- Automatic security updates

## ✨ Features

### Security
- **NFTables Firewall** with dynamic rule management
- **CrowdSec IPS** with community threat intelligence
- **GeoIP Blocking** for unwanted countries
- **SSH Hardening** with key-only auth and brute-force protection
- **AppArmor** Mandatory Access Control
- **AIDE & RKHunter** for integrity checking
- **Kernel Hardening** via sysctl

### Automation
- **Unattended-Upgrades** for automatic security updates
- **Automatic Backup Strategy** before critical changes
- **Self-Healing APT** repairs broken package sources
- **Provider Detection** automatically recognizes VPS providers

### Container & Services
- **Docker Engine** with secure configuration
- **Portainer CE** for container management
- **Watchtower** for automatic container updates
- **Tailscale VPN** integration

## 📜 Version History & Changes

All detailed changes for each version, including new features and bugfixes, are carefully documented in the [**CHANGELOG.md**](CHANGELOG.md).

## 📋 System Requirements

### Supported Operating Systems
| OS | Version | Status |
|-----|---------|---------|
| Debian | 13 (Trixie) | ✅ Fully tested |
| Debian | 12 (Bookworm) | ✅ Fully tested |
| Debian | 11 (Bullseye) | ⚠️ Should work |
| Ubuntu | 22.04/24.04 | ⚠️ Untested |

### Tested VPS Providers
| Provider | Status | Notes |
|----------|--------|-------------|
| IONOS | ✅ Tested | Mirror lists are automatically repaired |
| Others | ⚠️ Untested | Theoretical support available |

### Minimum Requirements
- 2 GB RAM
- 10 GB disk space
- Root access
- Internet connection

## 🚀 Installation

### Quick Start

```bash
# 1. Login as root
sudo -i

# 2. Create working directory
mkdir -p /opt/scripts && cd /opt/scripts

# 3. Clone repository
git clone https://github.com/TZERO78/Server-Baukasten.git
cd Server-Baukasten

# 4. Customize configuration
cp standard.conf my-server.conf
nano my-server.conf

# 5. Start installation
./serverbaukasten.sh -c my-server.conf
```

### Alternative: Direct Installation via curl

```bash
mkdir -p /opt/scripts && cd /opt/scripts
curl -fsSL https://raw.githubusercontent.com/TZERO78/Server-Baukasten/main/install.sh | bash
cd server-baukasten
cp standard.conf my-server.conf
nano my-server.conf
./serverbaukasten.sh -c my-server.conf
```

## ⚙️ Configuration

### Important Configuration Parameters

```bash
# Basic settings
SERVER_HOSTNAME="my-server"
ADMIN_USER="administrator"
TIMEZONE="Europe/Berlin"
LOCALE="de_DE.UTF-8"

# Security
SSH_PORT="6262"  # Non-standard SSH port
ACCESS_MODEL="1"  # 1=VPN-Only, 2=Public
ENABLE_GEOIP_BLOCKING="ja"
BLOCKED_COUNTRIES="CN RU KP IR"
HOME_COUNTRY="DE"

# Services
SERVER_ROLE="1"  # 1=Docker server, 2=Simple server
INSTALL_PORTAINER="ja"
INSTALL_WATCHTOWER="ja"

# Tailscale VPN (optional)
TAILSCALE_AUTH_KEY=""  # From Tailscale Admin Console
```

[Complete Configuration Documentation](docs/en/CONFIGURATION.md)

## 📊 Modules

The script is modular. Each module has (or will have) its own README under `docs/en/modules/`.

| Module | Description | Docs |
|---|---|---|
| `module_base` | System basic configuration (NTP, locale, user, basics) | [docs/en/modules/base.md](docs/en/modules/base.md) |
| `module_security` | Firewall (nftables), SSH hardening, CrowdSec | [docs/en/modules/security.md](docs/en/modules/security.md) |
| `module_network` | Network & VPN (e.g., WireGuard) | [docs/en/modules/network.md](docs/en/modules/network.md) |
| `module_container` | Install Docker/Moby & basic setup | [docs/en/modules/container.md](docs/en/modules/container.md) |
| `module_deploy_containers` | Deploy container stacks (Compose etc.) | [docs/en/modules/deploy_containers.md](docs/en/modules/deploy_containers.md) |
| `module_geoip` | Country-based blocking (GeoIP sets) | [docs/en/modules/geoip.md](docs/en/modules/geoip.md) |
| `module_install_services` | Install basic services/tools | [docs/en/modules/install_services.md](docs/en/modules/install_services.md) |
| `module_journald_optimization` | journald persistent + limits/rotation | [docs/en/modules/journald_optimization.md](docs/en/modules/journald_optimization.md) |
| `module_kernel_hardening` | Kernel/sysctl hardening | [docs/en/modules/kernel_hardening.md](docs/en/modules/kernel_hardening.md) |
| `module_mail_setup` | System-wide mail via msmtp | [docs/en/modules/mail_setup.md](docs/en/modules/mail_setup.md) |
| `module_prepare_install` | Preparations (repos, keys, checks) | [docs/en/modules/prepare_install.md](docs/en/modules/prepare_install.md) |
| `module_cleanup` | Clean up legacy/packages | [docs/en/modules/cleanup.md](docs/en/modules/cleanup.md) |
| `module_system_update` | Template-based unattended-upgrades (Debian 12/13) | [docs/en/modules/system_update.md](docs/en/modules/system_update.md) |
| `module_verify_setup` | Final verification/system checks | [docs/en/modules/verify_setup.md](docs/en/modules/verify_setup.md) |

## 🛠️ Usage

### Basic Commands

```bash
# Normal installation
./serverbaukasten.sh -c config.conf

# Debug mode
./serverbaukasten.sh -d -c config.conf

# Test mode (fast, without time-intensive operations)
./serverbaukasten.sh -t -c config.conf

# Show help
./serverbaukasten.sh -h
```

### After Installation

```bash
# Check status
sudo systemctl status

# Display firewall rules
sudo nft list ruleset

# CrowdSec status
sudo cscli metrics

# GeoIP manager
sudo geoip-manager status

# Docker status (if installed)
sudo docker ps
```

## 🔒 Security Concept

### Defense in Depth
The script implements multiple security layers:

1. **Perimeter Protection**: GeoIP blocking, rate limiting
2. **Network Security**: NFTables firewall, VPN-only access option
3. **Attack Detection**: CrowdSec IPS with community threat intelligence
4. **System Hardening**: SSH hardening, kernel parameters (as far as possible on VPS)
5. **Monitoring**: AIDE, RKHunter, systemd-journald

### Automatic Updates
- Security updates via unattended-upgrades
- Container updates via Watchtower (optional)
- CrowdSec threat intelligence updates

**Note**: Email notifications are configurable but optional.

## 📝 Maintenance

### Check Logs
```bash
# System logs
journalctl -xe

# CrowdSec logs
journalctl -u crowdsec

# Docker logs
docker logs <container>
```

### Backup
The script occasionally creates backups before critical changes:
- APT sources.list (before repair)
- Other system files as needed

**⚠️ Security Note**: Config files are NOT backed up because they contain passwords in plain text! Keep your config file safe and encrypted.

**Important**: Make a manual system backup before installation!

## 🐛 Troubleshooting

### APT Problems
Automatically detected and repaired (v5.2+)

### SSH Access Lost
1. Use VPS provider console
2. Temporarily disable firewall: `nft flush ruleset`
3. Check SSH port: `grep Port /etc/ssh/sshd_config`

### Docker Problems
```bash
systemctl restart docker
docker system prune -a  # Caution: Deletes all unused data
```

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request

### Testing on Other Providers

Especially wanted: Tests on
- Hetzner
- DigitalOcean
- AWS/Azure
- Other Debian/Ubuntu versions

Please open an [Issue](https://github.com/TZERO78/Server-Baukasten/issues) with your experiences.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## 👥 Authors

- **Markus F. (TZERO78)** - *Initial work*
- **AI Assistants** - *Code optimization*

## 🙏 Acknowledgments

### Inspiration & Knowledge Sources
- **Christian** (ion.it/Apfelcast) for Linux security inspiration
- **ct3003** for practical server tips
- **Dennis Schröder** (Raspberry Pi Cloud/ipv64.net) for ideas and education
- **Geek Freaks** for Docker best practices

### Open Source Projects
- [CrowdSec](https://www.crowdsec.net/) for the community-based IPS
- [Tailscale](https://tailscale.com/) for the simple mesh VPN
- [NFTables](https://netfilter.org/projects/nftables/) for modern packet filtering
- The Debian/Linux Community

## ⚠️ Disclaimer

This script makes profound system changes.
- **Always make a backup first**
- **Try it in a test environment first**
- **No guarantee for production systems**

The author assumes no liability for damages or data loss.

## 📞 Support

- [Issues](https://github.com/TZERO78/Server-Baukasten/issues) for bug reports
- [Discussions](https://github.com/TZERO78/Server-Baukasten/discussions) for questions

---

<div align="center">

**[Documentation](docs/en/) | [Changelog](CHANGELOG.md) | [Configuration](docs/en/CONFIGURATION.md) | [Wiki](../../wiki)**

🇩🇪 [Deutsche Version](docs/de/README.md)

Made with ❤️ in Germany

</div>
