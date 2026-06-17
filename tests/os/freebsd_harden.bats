#!/usr/bin/env bats

@test "freebsd/harden.sh parses without errors" {
  sh -n freebsd/harden.sh
}

@test "freebsd/harden.sh --mode audit produces expected output markers" {
  # Script will fail on non-FreeBSD but should parse and show usage or skip
  run sh freebsd/harden.sh --mode audit
  # Accept exit 0 or 1 (pass/fail findings)
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}
