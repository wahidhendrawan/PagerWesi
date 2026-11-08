#!/usr/bin/env bash
set -Eeuo pipefail

MODE="audit"
OUTPUT=""
while (($#)); do
  case "$1" in
    --mode) MODE=${2:-}; shift 2 ;;
    --output) OUTPUT=${2:-}; shift 2 ;;
    -h|--help) echo "Usage: $0 [--mode audit|plan|apply] [--output FINDINGS.json]"; exit 0 ;;
    *) exit 2 ;;
  esac
done
[[ "$MODE" =~ ^(audit|plan|apply)$ ]] || exit 2
[[ "$(uname -s)" == "Darwin" ]] || { echo "[ERROR] macOS is required"; exit 2; }
[[ "$MODE" != "apply" || $EUID -eq 0 ]] || { echo "[ERROR] Apply mode requires root"; exit 2; }

failures=0
findings=()
json_str() {  # shortcut: escapes quotes, backslashes and line breaks only; these strings never carry other control characters
  local s=${1//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/ }; s=${s//$'\r'/}; s=${s//$'\t'/ }
  printf '%s' "$s"
}
record() {  # control_id title status severity evidence remediation (same shape as windows/harden.ps1 -OutputPath)
  findings+=("$(printf '  {"control_id": "%s", "title": "%s", "status": "%s", "severity": "%s", "resource": "host:%s", "evidence": "%s", "remediation": "%s"}' \
    "$(json_str "$1")" "$(json_str "$2")" "$3" "$4" "$(json_str "$(hostname)")" "$(json_str "$5")" "$(json_str "$6")")")
}
write_findings() {
  [[ -n "$OUTPUT" ]] || return 0
  {
    printf '[\n'
    local i
    for i in "${!findings[@]}"; do
      if (( i > 0 )); then printf ',\n'; fi
      printf '%s' "${findings[$i]}"
    done
    printf '\n]\n'
  } > "$OUTPUT"
}
report() {
  local id=$1 title=$2 severity=$3 remediation=$4 fn=$5
  if "$fn"; then
    echo "[PASS] $id $title"; record "$id" "$title" pass "$severity" "" "$remediation"
  else
    echo "[FAIL] $id $title"; record "$id" "$title" fail "$severity" "" "$remediation"; failures=$((failures + 1))
  fi
}
run() { if [[ "$MODE" == "plan" ]]; then printf '[PLAN]'; printf ' %q' "$@"; printf '\n'; else "$@"; fi; }

firewall_on() { /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -qi enabled; }
gatekeeper_on() { spctl --status | grep -qi enabled; }
updates_on() { softwareupdate --schedule | grep -qi on; }
guest_off() { [[ "$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo 0)" != "1" ]]; }
filevault_on() { fdesetup status | grep -q 'FileVault is On'; }

report MACOS-FW-001 "Application firewall is enabled" high "Enable the application firewall and stealth mode." firewall_on
report MACOS-GK-001 "Gatekeeper is enabled" high "Run spctl --master-enable." gatekeeper_on
report MACOS-PATCH-001 "Automatic update checks are enabled" medium "Run softwareupdate --schedule on." updates_on
report MACOS-AUTH-001 "Guest account is disabled" high "Run sysadminctl -guestAccount off." guest_off
report MACOS-DISK-001 "FileVault is enabled" high "Enable FileVault with an approved recovery-key escrow process." filevault_on

if [[ "$MODE" != "audit" ]]; then
  run /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
  run /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
  run spctl --master-enable
  run softwareupdate --schedule on
  run sysadminctl -guestAccount off
  if ! filevault_on; then echo "[MANUAL] MACOS-DISK-001 Enable FileVault with an approved recovery-key escrow process"; fi
fi
write_findings
((failures == 0)) || exit 1
