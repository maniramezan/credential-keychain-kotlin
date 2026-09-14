#!/usr/bin/env bash
set -euo pipefail
# Run inside dbus-run-session. The keyring lives only in this disposable directory.
export XDG_DATA_HOME
XDG_DATA_HOME=$(mktemp -d)
cleanup() {
  gnome-keyring-daemon --quit || true
  rm -rf "$XDG_DATA_HOME"
}
trap cleanup EXIT
# An empty password unlocks only this isolated CI keyring. No real credentials are used.
printf '\n' | gnome-keyring-daemon --unlock --components=secrets
export CREDENTIAL_KEYCHAIN_INTEGRATION=1
"$@"
