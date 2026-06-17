#!/bin/sh
set -u

MODE="audit"
FAIL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

pass() { printf "[PASS] %s\n" "$1"; }
fail() { printf "[FAIL] %s\n" "$1"; FAIL=1; }
plan() { printf "[PLAN] %s\n" "$1"; }
skip() { printf "[SKIP] %s\n" "$1"; }

# ALPINE-USER-001: Non-root user exists
check_user() {
  if awk -F: '$3 >= 1000 && $1 != "nobody" {found=1} END {exit !found}' /etc/passwd 2>/dev/null; then
    pass "ALPINE-USER-001: Non-root user exists"
  else
    case "$MODE" in
      apply)
        adduser -D -s /bin/sh appuser 2>/dev/null
        pass "ALPINE-USER-001: Created non-root user 'appuser'"
        ;;
      plan) plan "ALPINE-USER-001: Would create non-root user 'appuser'" ;;
      *) fail "ALPINE-USER-001: No non-root user exists" ;;
    esac
  fi
}

# ALPINE-PKG-001: No vulnerable packages
check_packages() {
  if ! command -v apk >/dev/null 2>&1; then
    skip "ALPINE-PKG-001: apk not available"
    return
  fi
  vuln=$(apk audit --system 2>/dev/null)
  if [ -z "$vuln" ]; then
    pass "ALPINE-PKG-001: No vulnerable packages"
  else
    case "$MODE" in
      apply)
        apk upgrade --no-cache 2>/dev/null
        pass "ALPINE-PKG-001: Upgraded vulnerable packages"
        ;;
      plan) plan "ALPINE-PKG-001: Would upgrade vulnerable packages" ;;
      *) fail "ALPINE-PKG-001: Vulnerable packages found" ;;
    esac
  fi
}

# ALPINE-FS-001: Read-only root filesystem
check_rootfs() {
  if mount | grep 'on / ' | grep -q '\bro\b'; then
    pass "ALPINE-FS-001: Root filesystem is read-only"
  else
    case "$MODE" in
      plan) plan "ALPINE-FS-001: Would require read-only root filesystem (container config)" ;;
      *) fail "ALPINE-FS-001: Root filesystem is not read-only" ;;
    esac
  fi
}

# ALPINE-SHELL-001: No unnecessary shell accounts
check_shells() {
  shell_users=$(awk -F: '$7 ~ /\/bin\/sh/ && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
  if [ -z "$shell_users" ]; then
    pass "ALPINE-SHELL-001: No unnecessary shell accounts"
  else
    case "$MODE" in
      plan) plan "ALPINE-SHELL-001: Would review shell accounts: $shell_users" ;;
      *) fail "ALPINE-SHELL-001: Accounts with /bin/sh: $shell_users" ;;
    esac
  fi
}

check_user
check_packages
check_rootfs
check_shells

exit $FAIL
