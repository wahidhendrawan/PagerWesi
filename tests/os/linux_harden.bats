#!/usr/bin/env bats

@test "linux help is non-mutating and documents execution modes" {
  run bash linux/harden.sh --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"audit|plan|apply"* ]]
  [[ "$output" == *"--rollback"* ]]
}

@test "linux rejects an invalid execution mode" {
  run bash linux/harden.sh --mode invalid
  [ "$status" -eq 2 ]
}

@test "macOS script contains a platform guard" {
  run grep -F 'Darwin' macos/harden.sh
  [ "$status" -eq 0 ]
}

@test "linux --output writes findings as JSON in the windows/harden.ps1 shape" {
  out="$BATS_TMPDIR/pagerwesi-findings-$$.json"
  run bash linux/harden.sh --mode audit --output "$out"
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
  python3 - "$out" <<'PY'
import json, sys
findings = json.load(open(sys.argv[1]))
keys = {"control_id", "title", "status", "severity", "resource", "evidence", "remediation"}
assert all(keys <= f.keys() for f in findings), findings
assert {"LINUX-FW-001", "LINUX-SSH-001", "LINUX-SSH-002", "LINUX-PATCH-001"} <= {f["control_id"] for f in findings}
assert all(f["status"] in {"pass", "fail", "skip"} and f["severity"] in {"medium", "high", "critical"} for f in findings)
assert all(f["resource"].startswith("host:") for f in findings)
PY
  rm -f "$out"
}
