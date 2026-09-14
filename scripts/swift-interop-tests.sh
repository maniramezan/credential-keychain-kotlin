#!/usr/bin/env bash
set -euo pipefail
# Run after assembling the verification consumer on an ARM macOS host.
root=$(cd "$(dirname "$0")/.." && pwd)
frameworks="$root/verification/consumer/build/bin/macosArm64/debugFramework"
output="$root/verification/consumer/build/swift-verification"
mkdir -p "$output"
xcrun swiftc -module-cache-path "$output/module-cache" \
  -F "$frameworks" -framework KeychainConsumer \
  -Xlinker -rpath -Xlinker "$frameworks" \
  "$root/verification/consumer/SwiftInterop.swift" -o "$output/interop-test"
"$output/interop-test"
