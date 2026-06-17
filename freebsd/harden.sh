#!/bin/sh
# FreeBSD Hardening Script - audit/plan/apply
set -u

MODE="audit"
FAIL=0
SSHD_CFG="/etc/ssh/sshd_config"
RC_CONF="/etc/rc.conf"

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    *) echo "Usage: $0 --mode audit|plan|apply"; exit 1 ;;
  esac
done

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAIL=1; }
plan() { echo "[PLAN] $1"; }
skip() { echo "[SKIP] $1"; }

# FBSD-FW-001: PF firewall enabled
check_pf() {
  ID="FBSD-FW-001"
  if grep -qE '^pf_enable="?YES"?' "$RC_CONF" 2>/dev/null && pfctl -si >/dev/null 2>&1; then
    pass "$ID: PF firewall is enabled"
  else
    case "$MODE" in
      audit) fail "$ID: PF firewall is not enabled" ;;
      plan)  plan "$ID: Will enable PF in rc.conf and start service" ;;
      apply)
        if ! grep -qE '^pf_enable=' "$RC_CONF" 2>/dev/null; then
          echo 'pf_enable="YES"' >> "$RC_CONF"
        else
          sed -i '' 's/^pf_enable=.*/pf_enable="YES"/' "$RC_CONF"
        fi
        service pf start >/dev/null 2>&1
        pass "$ID: PF firewall enabled (applied)"
        ;;
    esac
  fi
}

# FBSD-SSH-001: SSH root login disabled
check_ssh_root() {
  ID="FBSD-SSH-001"
  if grep -qE '^\s*PermitRootLogin\s+no' "$SSHD_CFG" 2>/dev/null; then
    pass "$ID: SSH root login disabled"
  else
    case "$MODE" in
      audit) fail "$ID: SSH root login not disabled" ;;
      plan)  plan "$ID: Will set PermitRootLogin no in sshd_config" ;;
      apply)
        if grep -qE '^\s*#?\s*PermitRootLogin' "$SSHD_CFG" 2>/dev/null; then
          sed -i '' 's/^#*\s*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CFG"
        else
          echo "PermitRootLogin no" >> "$SSHD_CFG"
        fi
        pass "$ID: SSH root login disabled (applied)"
        ;;
    esac
  fi
}

# FBSD-SSH-002: SSH empty passwords disabled
check_ssh_empty_pw() {
  ID="FBSD-SSH-002"
  if grep -qE '^\s*PermitEmptyPasswords\s+no' "$SSHD_CFG" 2>/dev/null; then
    pass "$ID: SSH empty passwords disabled"
  else
    case "$MODE" in
      audit) fail "$ID: SSH empty passwords not disabled" ;;
      plan)  plan "$ID: Will set PermitEmptyPasswords no in sshd_config" ;;
      apply)
        if grep -qE '^\s*#?\s*PermitEmptyPasswords' "$SSHD_CFG" 2>/dev/null; then
          sed -i '' 's/^#*\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CFG"
        else
          echo "PermitEmptyPasswords no" >> "$SSHD_CFG"
        fi
        pass "$ID: SSH empty passwords disabled (applied)"
        ;;
    esac
  fi
}

# FBSD-PATCH-001: Security patches
check_patches() {
  ID="FBSD-PATCH-001"
  if [ "$MODE" = "plan" ]; then
    plan "$ID: Will check for available security patches"
    return
  fi
  if command -v freebsd-update >/dev/null 2>&1; then
    if freebsd-update fetch 2>/dev/null | grep -q "No updates needed"; then
      pass "$ID: No security patches available"
    else
      case "$MODE" in
        audit) fail "$ID: Security patches available" ;;
        apply) skip "$ID: Patches available (manual install recommended)" ;;
      esac
    fi
  else
    skip "$ID: freebsd-update not available"
  fi
}

check_pf
check_ssh_root
check_ssh_empty_pw
check_patches

exit $FAIL
