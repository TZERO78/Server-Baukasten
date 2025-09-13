#!/bin/bash
################################################################################
# IDEMPOTENT HELPERS (Server-Baukasten)
# Kleine Ensure-/Guard-Funktionen für wiederholbare, nebenwirkungsarme Aktionen.
# MIT © Markus F. (TZERO78) & KI-Assistenten
################################################################################
set -Eeuo pipefail

# ── Log-Fallbacks (werden vom globalen log_helper überschrieben) ──────────────
if ! command -v log_info >/dev/null 2>&1; then
  log_info()  { echo -e "\033[0;36mℹ️  $*\033[0m"; }
  log_ok()    { echo -e "\033[0;32m✅ $*\033[0m"; }
  log_warn()  { echo -e "\033[1;33m⚠️  $*\033[0m"; }
  log_error() { echo -e "\033[0;31m❌ $*\033[0m" >&2; }
fi
if ! command -v log_debug >/dev/null 2>&1; then
  log_debug() { [ "${DEBUG:-false}" = "true" ] && echo -e "\033[0;90m🐞  $*\033[0m" >&2 || true; }
fi

# ── Globales Verhalten ────────────────────────────────────────────────────────
: "${DEBIAN_FRONTEND:=noninteractive}"
: "${APT_LISTCHANGES_FRONTEND:=none}"
: "${DRYRUN:=no}"

_run() {
  if [ "$DRYRUN" = "yes" ]; then
    log_info "[DRY] $*"
    return 0
  fi
  "$@"
}

# ── APT/DPKG ──────────────────────────────────────────────────────────────────
ensure_dpkg_unlocked() {
  log_debug "dpkg/apt: entferne Locks & repariere evtl. abgebrochene Vorgänge"
  _run rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock 2>/dev/null || true
  _run dpkg --configure -a >/dev/null 2>&1 || true
  _run apt-get -y -f install >/dev/null 2>&1 || true
}

# robuster als „update once“: mit Heuristik & Retries
apt_update_retry() {
  local tries=0 max=3
  local out="/tmp/.sbk_apt_update.log"
  while (( tries < max )); do
    ((tries++))
    log_debug "apt-get update Versuch $tries/$max"
    if _run apt-get update -y >"$out" 2>&1; then
      _run install -d -m 755 /run >/dev/null 2>&1 || true
      _run touch /run/.sbk_apt_updated
      log_debug "apt-get update: erfolgreich"
      return 0
    fi
    if grep -q "Could not get lock" "$out"; then
      log_warn "apt ist gesperrt – warte 10s"
      sleep 10
    elif grep -q "NO_PUBKEY" "$out"; then
      log_warn "fehlende GPG-Keys – versuche apt-key update"
      _run apt-key update >/dev/null 2>&1 || true
    fi
    sleep 5
  done
  log_error "apt-get update nach $max Versuchen fehlgeschlagen"; return 1
}

pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }

ensure_packages_present() {
  local need=() p
  for p in "$@"; do
    if ! dpkg -s "$p" >/dev/null 2>&1; then
      need+=("$p")
    fi
  done
  if ((${#need[@]})); then
    log_info "install: ${need[*]}"
    apt_update_retry
    _run apt-get install -y "${need[@]}" >/dev/null 2>&1 || true
  else
    log_debug "alle benötigten Pakete bereits installiert"
  fi
}

ensure_packages_absent() {
  local did=0 p
  for p in "$@"; do
    if pkg_installed "$p"; then
      log_info "purge: $p"
      _run apt-get -y purge "$p" >/dev/null 2>&1 || true
      did=1
    fi
  done
  if [ $did -eq 1 ]; then
    _run apt-get -y autoremove --purge >/dev/null 2>&1 || true
    _run apt-get autoclean >/dev/null 2>&1 || true
  fi
}

# ── systemd Units ─────────────────────────────────────────────────────────────
unit_active()  { systemctl is-active  "$1" >/dev/null 2>&1; }
unit_enabled() { systemctl is-enabled "$1" >/dev/null 2>&1; }

ensure_unit_stopped_disabled_masked() {
  local u
  for u in "$@"; do
    unit_active  "$u" && { log_info "stop: $u";    _run systemctl stop "$u" >/dev/null 2>&1 || true; }
    unit_enabled "$u" && { log_info "disable: $u"; _run systemctl disable "$u" >/dev/null 2>&1 || true; }
    _run systemctl mask "$u" >/dev/null 2>&1 || true
    log_debug "unit masked: $u"
  done
  _run systemctl reset-failed >/dev/null 2>&1 || true
}

ensure_unit_started_enabled() {
  local u
  for u in "$@"; do
    _run systemctl unmask "$u"  >/dev/null 2>&1 || true
    unit_enabled "$u" || { log_info "enable: $u"; _run systemctl enable "$u" >/dev/null 2>&1 || true; }
    unit_active  "$u" || { log_info "start:  $u"; _run systemctl start  "$u" >/devnull 2>&1 || true; }
  done
}

# ── Dateien/Verzeichnisse ────────────────────────────────────────────────────
ensure_dir() {
  local d="$1" mode="${2:-750}" owner="${3:-root:root}"
  if [ ! -d "$d" ]; then
    log_info "mkdir: $d"
    _run install -d -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$d"
  else
    log_debug "dir existiert: $d"
  fi
}

ensure_file_absent() {
  local f; for f in "$@"; do
    [ -e "$f" ] || continue
    log_info "rm: $f"; _run rm -f "$f" || true
  done
}

ensure_symlink() {
  local target="$1" link="$2"
  if [ ! -L "$link" ] || [ "$(readlink -f "$link")" != "$(readlink -f "$target")" ]; then
    log_info "symlink: $link -> $target"
    _run ln -sfn "$target" "$link"
  else
    log_debug "symlink korrekt: $link"
  fi
}

ensure_permissions() {
  local path="$1" mode="$2" owner="${3:-}"
  [ -e "$path" ] || return 0
  local cur_mode cur_owner
  cur_mode=$(stat -c %a "$path") || true
  if [ "$cur_mode" != "$mode" ]; then
    log_info "chmod $mode: $path"; _run chmod "$mode" "$path"
  fi
  if [ -n "$owner" ]; then
    cur_owner=$(stat -c %U:%G "$path") || true
    if [ "$cur_owner" != "$owner" ]; then
      log_info "chown $owner: $path"; _run chown "$owner" "$path"
    fi
  fi
}

ensure_line_in_file() {
  local file="$1" line="$2" match_re="${3:-}"
  touch "$file"
  if [ -n "$match_re" ]; then
    if ! grep -Eq "$match_re" "$file"; then
      log_info "append: $file → $line"
      _run sh -c "printf '%s\n' '$line' >> '$file'"
    else
      log_debug "Zeile bereits vorhanden (Regex match): $file"
    fi
  else
    if ! grep -Fxq "$line" "$file"; then
      log_info "append: $file → $line"
      _run sh -c "printf '%s\n' '$line' >> '$file'"
    else
      log_debug "Zeile bereits vorhanden (exakt): $file"
    fi
  fi
}

# ── Netz/Kernel/Sysctl ───────────────────────────────────────────────────────
ensure_sysctl_kv() {
  local key="$1" val="$2" dropin="${3:-/etc/sysctl.d/99-baukasten-hardening.conf}"
  ensure_dir "$(dirname "$dropin")" 755
  local need_reload=false

  if [ "$(sysctl -n "$key" 2>/dev/null || echo)" != "$val" ]; then
    log_info "sysctl -w $key=$val"
    _run sysctl -w "$key=$val" >/dev/null 2>&1 || true
  else
    log_debug "sysctl Laufzeitwert OK: $key=$val"
  fi

  if ! grep -Eq "^\s*${key}\s*=\s*${val}\s*$" "$dropin" 2>/dev/null; then
    log_info "persist: $dropin → $key=$val"
    _run sh -c "printf '%s\n' '${key}=${val}' >> '$dropin'"
    need_reload=true
  else
    log_debug "sysctl persistenter Wert OK: $dropin ($key=$val)"
  fi

  $need_reload && { log_info "sysctl --system"; _run sysctl --system >/dev/null 2>&1 || true; }
}

ensure_module_loaded() {
  local mod="$1"
  lsmod | awk '{print $1}' | grep -Fxq "$mod" && { log_debug "Kernelmodul aktiv: $mod"; return 0; }
  log_info "modprobe $mod"; _run modprobe "$mod" || true
}

# ── Firewall-Utilities ───────────────────────────────────────────────────────
iptables_minimal_flush() {
  local t
  for t in iptables ip6tables; do
    command -v "$t" >/dev/null 2>&1 || continue
    _run "$t" -F >/dev/null 2>&1 || true
    _run "$t" -t nat -F >/dev/null 2>&1 || true
    _run "$t" -t mangle -F >/dev/null 2>&1 || true
  done
  log_debug "iptables: Minimal-Flush durchgeführt"
}

ensure_ufw_disabled() {
  command -v ufw >/dev/null 2>&1 || { log_debug "UFW nicht installiert"; return 0; }
  local status; status=$(ufw status 2>/dev/null | awk '/Status:/{print $2}')
  if [ "$status" = "active" ]; then
    log_warn "UFW deaktivieren…"
    _run ufw --force disable >/dev/null 2>&1 || true
    iptables_minimal_flush
  else
    log_debug "UFW bereits inaktiv"
  fi
}

# ── Benutzer/Gruppen ─────────────────────────────────────────────────────────
ensure_user_exists() {
  local name="$1" uid="${2:-}" gid="${3:-}" home="${4:-/home/$1}" shell="${5:-/bin/bash}"
  if ! id -u "$name" >/dev/null 2>&1; then
    log_info "useradd: $name"
    local args=("-m" "-d" "$home" "-s" "$shell")
    [ -n "$uid" ] && args+=("-u" "$uid")
    [ -n "$gid" ] && { getent group "$gid" >/dev/null 2>&1 || _run groupadd "$gid"; args+=("-g" "$gid"); }
    _run useradd "${args[@]}" "$name"
  else
    log_debug "User existiert bereits: $name"
  fi
}

ensure_user_absent() {
  local name="$1"
  id -u "$name" >/dev/null 2>&1 || { log_debug "User nicht vorhanden: $name"; return 0; }
  log_info "userdel: $name"
  _run userdel -r "$name" >/dev/null 2>&1 || true
}

ensure_sudoers_dropin() {
  local name="$1" drop="/etc/sudoers.d/$1" content="$2"
  ensure_dir /etc/sudoers.d 755 root:root
  if [ ! -f "$drop" ] || ! cmp -s <(printf '%s\n' "$content") "$drop"; then
    log_info "sudoers.d: $drop"
    _run sh -c "printf '%s\n' '$content' > '$drop'"
    _run chmod 440 "$drop"
    _run visudo -cf "$drop" >/dev/null 2>&1 || log_warn "sudoers Drop-In '$drop' konnte nicht validiert werden"
  else
    log_debug "sudoers Drop-In OK: $drop"
  fi
}

pause_if_debug() {
  [ "${DEBUG:-false}" = "true" ] || return 0
  read -r -p "Weiter mit Enter… " _ || true
}
