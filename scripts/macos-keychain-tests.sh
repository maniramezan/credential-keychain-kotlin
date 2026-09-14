#!/usr/bin/env bash
set -euo pipefail
# A temporary default keychain lets unsigned test executables use isolated credentials.
# Only run on macOS; every change to the user's default keychain is restored on exit.
original=$(security default-keychain -d user | sed -e 's/^[[:space:]]*"//' -e 's/"$//')
directory=$(mktemp -d)
keychain="$directory/credential-keychain-tests.keychain-db"
password=$(openssl rand -hex 24)
cleanup() {
  security default-keychain -d user -s "$original" || true
  security delete-keychain "$keychain" || true
  rm -rf "$directory"
}
trap cleanup EXIT
security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$password" "$keychain"
security default-keychain -d user -s "$keychain"
export CREDENTIAL_KEYCHAIN_INTEGRATION=1
"$@"
