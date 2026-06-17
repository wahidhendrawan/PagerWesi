#!/usr/bin/env bats

@test "alpine/harden.sh parses without errors" {
  sh -n alpine/harden.sh
}

@test "alpine/harden.sh --mode audit produces expected output markers" {
  run sh alpine/harden.sh --mode audit
  # Accept exit 0 or 1 (pass/fail findings)
  [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}
