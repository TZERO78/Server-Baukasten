# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.3.3] - 2025-12-29

### Changed
- **Documentation restructured to bilingual format** (English/German)
  - Root README.md now in English for international reach
  - German documentation preserved in `docs/de/`
  - English documentation in `docs/en/`
  - Bidirectional language navigation with flag links
  - All internal links updated for new structure

### Added
- **English translations** of all core documentation
  - Main README.md fully translated
  - CHANGELOG.md translated to English (single file)
  - Module documentation: system_update, kernel_hardening, mail_setup
- **Placeholder files** for future documentation (13 German + 13 English)
  - CONFIGURATION.md placeholders in both languages
  - 12 module documentation placeholders per language
- **Documentation assets directory** (`docs/images/`) for shared resources

### Documentation
- 32 total documentation files (16 German + 15 English + 1 images README)
- Consistent structure and formatting across both languages
- All technical terms, code examples, and commands preserved identically
- Professional translation maintaining technical accuracy

## [5.3.2] - 2025-10-05

### Fixed
- **CRITICAL: APT::Default-Release Regex Bug** - Function `ensure_default_release_regex()` completely removed (`lib/apt_repair_helpers.sh`)
  - Prevented APT functionality on Debian 13 through invalid regex values
  - File `/etc/apt/apt.conf.d/00-default-release` is no longer created

- **CRITICAL: Unattended-upgrades blocked all security updates on Debian 13** (`modules/module_system_update.sh`)
  - Extended Allowed-Origins with `stable-security` and `stable-updates`
  - Debian 13 uses both archive naming conventions (Suite + Codename)
  - Previously blocked critical packages like `libssl3t64`, `openssl`, `linux-image-amd64`

- **ERR-Trap Handling made more robust** - Replaced 40 occurrences of `((var++))` with `var=$((var + 1))`
  - Moved filter cases in `handle_error()` to the beginning
  - Prevents spurious ERR-trap triggers during arithmetic operations
  - Affects 8 files (serverbaukasten.sh, 4 modules, 3 libs, install.sh)

### Added
- **VERSION file** as single source of truth for version number
  - `lib/constants.sh` loads version dynamically from VERSION file
  - `install.sh` loads version from GitHub

### Security
- Automatic security updates now work correctly on Debian 13
- APT system fully functional

### Compatibility
- Debian 13 (Trixie) - fully tested
- Debian 12/11 - backward compatible

### Additional Information
- Detailed bug description and workaround: GitHub Issue #[4]
- Tested on: Debian 13.1 (Trixie), IONOS VPS
- Reported by: @TZERO78

## [5.3.1] - 2025-09-21

### Changed
- `modules/module_mail_setup.sh`: comprehensively revised (idempotent, TLS-aware)
  - Validation of SMTP variables; optional rollback (if `rollback` present)
  - `/etc/msmtprc` (600) with `user` + `passwordeval` via `/etc/msmtp.pass` (600)
  - Journald drop-in for mail logs
  - TLS-sensitive reachability check (`--serverinfo` with `--tls-starttls`/`--tls`) before optional test mail
  - `update-alternatives` only set when necessary (sendmail → msmtp)
- `modules/module_system_update.sh`: Redesign to **1-job flow** (deterministic)
  - 03:30: `apt-get update` → `unattended-upgrade -d` → `apt-get autoremove --purge` → `apt-get autoclean`
  - **Auto-Reboot** only when needed at **03:45** (`Automatic-Reboot`, `Automatic-Reboot-Time`, `Automatic-Reboot-WithUsers`)
  - **APT::Periodic completely disabled** (`Update-Package-Lists`, `AutocleanInterval`, `Unattended-Upgrade` set to `"0"`)
  - **No** `apt-daily*` units generated; if present, only disable them
  - Timer deterministic via drop-in (`RandomizedDelaySec=0`, `Persistent=true`)

### Docs
- `docs/modules/mail_setup.md`: Module README
- `docs/modules/system_update.md`: Module README

### Security
- Mail module: no plaintext secrets in `/etc/msmtprc` (using `passwordeval`), strict permissions (600)

### Behavior
- Mail reports only if `ENABLE_SYSTEM_MAIL=ja` **and** `NOTIFICATION_EMAIL` set
- Test mail only if SMTP server is reachable

### Migration
- Check if old `apt-daily*` timers are active and disable them if necessary:
  - `systemctl disable --now apt-daily.timer apt-daily-upgrade.timer` (if present)
  - `systemctl disable --now apt-daily.timer apt-daily-upgrade.timer` (if present)



## [5.3] - 2025-09-14

### Added
- **Controlled Execution:** A new `execute_step` engine in the main script controls and logs each individual setup step.
- **Idempotent Design:** Introduction of `idempotent_helpers` to allow the script to be safely executed multiple times.
- **Modular Blueprint:** A new `module_base.sh` serves as a standardized template for all modules.
- **Secure Configuration Management:** `config_helpers.sh` for robust and secure reading of configuration files.
- **Self-Healing Mechanisms:** `apt_repairs_helper.sh` automatically detects and fixes common `apt` issues.
- **Professional Error Handling:** A global `trap` mechanism with intelligent error evaluation and rollback capability.
- **Final Self-Verification:** A `module_verify` checks the correct installation and integration of all components at the end of setup.

### Changed
- **Architecture Refactoring:** Complete transition from a single script to a modular framework (`/lib`, `/modules`).
- **Role of Main Script:** `serverbaukasten.sh` now acts as a central "conductor" that only controls the workflow.

### Fixed
- Numerous minor bugfixes and stability improvements throughout the script to increase robustness.

### Tested
- **Debian 13 (Trixie):** Full functionality was successfully verified on a VPS with the upcoming Debian 13. The script is thus future-proof for the next Debian release.

## [5.2.1] - 2025-09-12

### Added
- **Modular Config System**: New `config_helper.sh` and `validation_helpers.sh` for better code organization
- **Secret Management**: Optional `*_FILE` variables for secure password handling from files
- **Log Masking**: Automatic redaction of passwords and tokens in debug output (`***redacted***`)
- **Extended Conditional Logic**: `!=` operator for WHEN rules in config validation
- **Debug Mode**: Comprehensive debug output with `DEBUG=1` for better troubleshooting
- **Windows Compatibility**: UTF-8 BOM removal in addition to CRLF normalization
- **Automatic Canonicalization**: Country codes are automatically converted to uppercase

### Changed
- **Breaking Change**: `SSH_PORT` default changed from 22 to 2222 for better security (>1024)
- Config validation now with modular rule engine and conditional validation
- `resolve_secret()` as no-op function - does nothing if `*_FILE` variables are missing
- `cond_met()` now supports both `=` and `!=` operators
- Robust defaults are set before validation (reduces configuration errors)

### Fixed
- Config injection protection through stricter character and syntax checking
- GeoIP home country conflict resolution optimized
- Debug fallback for `log_debug()` if not globally defined

### Security
- **Command Injection Protection**: Extended filtering of suspicious characters in config files
- **Secret Files**: Secure handling with `umask 077` and permission checking
- **Log Security**: Sensitive data is automatically masked in logs

### Documentation
- Comprehensive best practice examples for secret management in config file
- Step-by-step guide for secure password handling
- Extended scenario examples with security focus

### Technical Details
- New helper functions: `is_choice_1_2()`, `is_yes_no()`, `is_secret_var()`
- Config normalization in separate function with temporary files
- Validation rules as array-based system for better maintainability

### Tested on
- ✅ Debian 12 with various config combinations
- ✅ Windows-created config files (CRLF, UTF-8 BOM)
- ✅ Secret files and plaintext passwords

## [5.2.0] - 2025-09-12

### Added
- **VPS Provider Detection**: Automatic detection of 11+ providers (IONOS, Hetzner, DigitalOcean, OVH, Contabo, Scaleway, Linode, AWS, Azure, GCP, Vultr, Netcup)
- **APT Sources Repair**: Automatic fixing of broken sources.list on fresh VPS installations
- **Provider-specific Fixes**:
  - IONOS: Mirror list removal
  - Hetzner: Outdated mirror cleanup
  - OVH: Mirror replacement with official sources
- **Windows Line Break Cleanup**: Automatic CRLF→LF conversion for config files
- **Retry Logic**: Intelligent retry attempts for APT operations
- **Extended Debug Output**: Detailed error diagnostics for better troubleshooting
- **apt_repair_helpers.sh**: New helper module for APT repair and provider detection

### Fixed
- IONOS Debian 12 mirror list issues
- Empty sources.list on fresh VPS installations
- Missing GPG package on minimal installations
- APT lock handling during concurrent processes
- Missing base packages are automatically reinstalled

### Changed
- `pre_flight_checks()` now checks APT sources for known problem providers
- Improved error handling and recovery mechanisms
- Modular structure with separate apt_repair_helpers
- Config files are NO longer backed up for security reasons (plaintext passwords)

### Tested on
- ✅ IONOS VPS with Debian 12 (bookworm)
- ⚠️ Other provider/OS combinations are theoretically supported but untested

### Known Limitations
- Script is not yet fully idempotent
- Email notifications not fully implemented

## [5.1.0] - 2024-12-01

### Note
This is the beginning of changelog documentation. Earlier versions were not documented.

### Core Features (Summary)
- **Security**:
  - NFTables firewall with modular configuration
  - CrowdSec IPS integration with community threat intelligence
  - GeoIP blocking for country-based filtering
  - SSH hardening with key-only authentication
  - AppArmor mandatory access control
  - AIDE & RKHunter for integrity checking
  - Kernel hardening via sysctl (as far as possible on VPS)

- **Automation**:
  - Unattended-upgrades for automatic security updates
  - Systemd timers instead of cron for better integration
  - Journald instead of logrotate for structured logging

- **Container & Services**:
  - Docker Engine with iptables-nft backend
  - Portainer CE for container management
  - Watchtower for automatic container updates
  - Tailscale VPN integration

- **Technology Stack**:
  - NFTables instead of iptables
  - CrowdSec instead of Fail2ban
  - systemd-timer instead of cron
  - journald instead of logrotate

### Supported Systems
- Debian 11 (Bullseye)
- Debian 12 (Bookworm)
- Ubuntu 20.04/22.04 (theoretical)

## Version History before 5.1.0

Earlier versions of Server-Baukasten were not documented in a changelog.
The project was developed over several months and continuously improved.

---

## Legend

- `Added` for new features
- `Changed` for changes to existing functionality
- `Deprecated` for features that will soon be removed
- `Removed` for removed features
- `Fixed` for bug fixes
- `Security` for security updates
