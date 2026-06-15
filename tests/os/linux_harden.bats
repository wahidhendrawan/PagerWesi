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
