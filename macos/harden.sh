#!/usr/bin/env bash
set -Eeuo pipefail

MODE="audit"
while (($#)); do
  case "$1" in
    --mode) MODE=${2:-}; shift 2 ;;
    -h|--help) echo "Usage: $0 [--mode audit|plan|apply]"; exit 0 ;;
    *) exit 2 ;;
  esac
done
[[ "$MODE" =~ ^(audit|plan|apply)$ ]] || exit 2
[[ "$(uname -s)" == "Darwin" ]] || { echo "[ERROR] macOS is required"; exit 2; }
[[ "$MODE" != "apply" || $EUID -eq 0 ]] || { echo "[ERROR] Apply mode requires root"; exit 2; }

failures=0
report() { if "$3"; then echo "[PASS] $1 $2"; else echo "[FAIL] $1 $2"; failures=$((failures + 1)); fi; }
run() { if [[ "$MODE" == "plan" ]]; then printf '[PLAN]'; printf ' %q' "$@"; printf '\n'; else "$@"; fi; }

firewall_on() { /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -qi enabled; }
gatekeeper_on() { spctl --status | grep -qi enabled; }
updates_on() { softwareupdate --schedule | grep -qi on; }
guest_off() { [[ "$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo 0)" != "1" ]]; }
filevault_on() { fdesetup status | grep -q 'FileVault is On'; }

report MACOS-FW-001 "Application firewall is enabled" firewall_on
report MACOS-GK-001 "Gatekeeper is enabled" gatekeeper_on
report MACOS-PATCH-001 "Automatic update checks are enabled" updates_on
report MACOS-AUTH-001 "Guest account is disabled" guest_off
report MACOS-DISK-001 "FileVault is enabled" filevault_on

if [[ "$MODE" != "audit" ]]; then
  run /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
  run /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
  run spctl --master-enable
  run softwareupdate --schedule on
  run sysadminctl -guestAccount off
  if ! filevault_on; then echo "[MANUAL] MACOS-DISK-001 Enable FileVault with an approved recovery-key escrow process"; fi
fi
((failures == 0)) || exit 1
