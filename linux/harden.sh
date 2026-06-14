#!/usr/bin/env bash
set -Eeuo pipefail

MODE="audit"
BACKUP_ROOT="/var/backups/automation-hardening"
ALLOW_SSH="${ALLOW_SSH:-OpenSSH}"

usage() {
  echo "Usage: $0 [--mode audit|plan|apply] [--rollback BACKUP_DIR]"
}

log() { printf '[%s] %s\n' "$1" "$2"; }
run() {
  if [[ "$MODE" == "plan" ]]; then
    printf '[PLAN]'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

configure_firewalld_ssh() {
  local rule=$ALLOW_SSH
  if [[ "$rule" == "OpenSSH" ]]; then
    rule=ssh
  fi
  if [[ "$rule" =~ ^[0-9]+/(tcp|udp)$ ]]; then
    run firewall-cmd --permanent --add-port="$rule"
  else
    run firewall-cmd --permanent --add-service="$rule"
  fi
}

rollback() {
  local source=$1
  [[ $EUID -eq 0 ]] || { log ERROR "Rollback requires root"; exit 2; }
  [[ -d "$source" ]] || { log ERROR "Backup directory not found: $source"; exit 2; }
  [[ -f "$source/sshd_config" ]] && install -m 600 "$source/sshd_config" /etc/ssh/sshd_config
  sshd -t
  log PASS "Configuration restored from $source"
}

ROLLBACK=""
while (($#)); do
  case "$1" in
    --mode) MODE=${2:-}; shift 2 ;;
    --rollback) ROLLBACK=${2:-}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
[[ "$MODE" =~ ^(audit|plan|apply)$ ]] || { usage; exit 2; }
[[ -z "$ROLLBACK" ]] || { rollback "$ROLLBACK"; exit 0; }
if [[ "$MODE" == "apply" && $EUID -ne 0 ]]; then
  log ERROR "Apply mode requires root"
  exit 2
fi

failures=0
check() {
  local id=$1 title=$2; shift 2
  if "$@"; then log PASS "$id $title"; else log FAIL "$id $title"; failures=$((failures + 1)); fi
}

sshd_value() { sshd -T 2>/dev/null | awk -v key="$1" '$1 == key {print $2; exit}'; }
check_root_login() { [[ "$(sshd_value permitrootlogin)" == "no" ]]; }
check_empty_passwords() { [[ "$(sshd_value permitemptypasswords)" == "no" ]]; }
check_firewall() {
  if command -v ufw >/dev/null; then ufw status 2>/dev/null | grep -q '^Status: active';
  elif command -v firewall-cmd >/dev/null; then firewall-cmd --state 2>/dev/null | grep -q running;
  else return 1; fi
}
check_updates() {
  if command -v apt-get >/dev/null; then [[ -z "$(apt-get -s upgrade 2>/dev/null | awk '/^Inst / {print; exit}')" ]];
  elif command -v dnf >/dev/null; then dnf -q check-update >/dev/null 2>&1;
  else return 0; fi
}

check LINUX-FW-001 "Host firewall is active" check_firewall
if command -v sshd >/dev/null; then
  check LINUX-SSH-001 "SSH root login is disabled" check_root_login
  check LINUX-SSH-002 "SSH empty passwords are disabled" check_empty_passwords
else
  log SKIP "LINUX-SSH SSH server is not installed"
fi
check LINUX-PATCH-001 "No package upgrades are pending" check_updates

if [[ "$MODE" != "audit" ]]; then
  timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  backup="$BACKUP_ROOT/$timestamp"
  if [[ "$MODE" == "apply" ]]; then
    install -d -m 700 "$backup"
  else
    log PLAN "Create backup directory $backup"
  fi

  if command -v apt-get >/dev/null; then
    run apt-get update
    run apt-get upgrade -y
    command -v ufw >/dev/null || run apt-get install -y ufw
  elif command -v dnf >/dev/null; then
    run dnf upgrade -y
    command -v firewall-cmd >/dev/null || run dnf install -y firewalld
  fi

  if command -v ufw >/dev/null; then
    run ufw default deny incoming
    run ufw default allow outgoing
    run ufw allow "$ALLOW_SSH"
    run ufw --force enable
  elif command -v firewall-cmd >/dev/null; then
    run systemctl enable --now firewalld
    configure_firewalld_ssh
    run firewall-cmd --reload
  fi

  config=/etc/ssh/sshd_config
  if [[ -f "$config" ]]; then
    if [[ "$MODE" == "apply" ]]; then cp -p "$config" "$backup/sshd_config"; fi
    for setting in "PermitRootLogin no" "PermitEmptyPasswords no"; do
      key=${setting%% *}
      if grep -Eqi "^[[:space:]#]*${key}[[:space:]]" "$config"; then
        run sed -Ei "s|^[[:space:]#]*${key}[[:space:]].*|${setting}|I" "$config"
      elif [[ "$MODE" == "plan" ]]; then
        log PLAN "Append '$setting' to $config"
      else
        printf '%s\n' "$setting" >> "$config"
      fi
    done
    if [[ "$MODE" == "apply" ]]; then
      if ! sshd -t; then cp -p "$backup/sshd_config" "$config"; log ERROR "Invalid SSH config; restored backup"; exit 2; fi
      systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    fi
  fi
fi

((failures == 0)) || exit 1
