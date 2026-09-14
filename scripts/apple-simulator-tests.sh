#!/usr/bin/env bash
set -euo pipefail
# Runs verification/apple-harness/Harness.swift inside an iOS simulator app so the library uses the
# data-protection keychain, which Kotlin/Native test executables and unsigned macOS processes cannot.
# Run on macOS after assembling the verification consumer. A disposable simulator is created and
# always deleted; existing simulators are not touched.
root=$(cd "$(dirname "$0")/.." && pwd)
harness="$root/verification/apple-harness"
frameworks="$root/verification/consumer/build/bin/iosSimulatorArm64/debugFramework"
output="$root/verification/consumer/build/apple-simulator"
bundle_id="com.maniramezan.credentialkeychain.harness"
app="$output/Harness.app"

if [ ! -d "$frameworks/KeychainConsumer.framework" ]; then
  echo "Missing $frameworks/KeychainConsumer.framework; assemble verification/consumer first." >&2
  exit 1
fi
rm -rf "$output"
mkdir -p "$app/Frameworks"
min_os=$(/usr/libexec/PlistBuddy -c 'Print :MinimumOSVersion' "$frameworks/KeychainConsumer.framework/Info.plist" 2>/dev/null || echo "15.0")
sed -e "s/@BUNDLE_ID@/$bundle_id/" -e "s/@MIN_OS@/$min_os/" "$harness/Info.plist" > "$app/Info.plist"
sed -e "s/@BUNDLE_ID@/$bundle_id/g" "$harness/entitlements.plist" > "$output/entitlements.plist"
cp -R "$frameworks/KeychainConsumer.framework" "$app/Frameworks/"

# Simulator apps carry entitlements in __TEXT,__entitlements and an ad-hoc signature, as Xcode builds them.
xcrun -sdk iphonesimulator swiftc -target "arm64-apple-ios${min_os}-simulator" \
  -module-cache-path "$output/module-cache" \
  -F "$frameworks" -framework KeychainConsumer \
  -Xlinker -rpath -Xlinker @executable_path/Frameworks \
  -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __entitlements -Xlinker "$output/entitlements.plist" \
  "$harness/Harness.swift" -o "$app/Harness"
codesign --force --sign - "$app/Frameworks/KeychainConsumer.framework"
codesign --force --sign - "$app"

# Pick the newest available iOS runtime and a device type already available for it.
read -r runtime device_type < <(xcrun simctl list devices available -j | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
ios = [(key, items) for key, items in devices.items() if ".SimRuntime.iOS-" in key and items]
key, items = max(ios, key=lambda entry: [int(part) for part in entry[0].rsplit("iOS-", 1)[1].split("-")])
iphone = next(item for item in items if "iPhone" in item["name"])
print(key, iphone["deviceTypeIdentifier"])
')
device=$(xcrun simctl create "credential-keychain-harness" "$device_type" "$runtime")
cleanup() {
  xcrun simctl shutdown "$device" >/dev/null 2>&1 || true
  xcrun simctl delete "$device" >/dev/null 2>&1 || true
}
trap cleanup EXIT

xcrun simctl boot "$device"
xcrun simctl bootstatus "$device" -b >/dev/null
xcrun simctl install "$device" "$app"
container=$(xcrun simctl get_app_container "$device" "$bundle_id" app)

# spawn runs the signed binary in the simulator and forwards its output here.
set +e
xcrun simctl spawn "$device" "$container/Harness" 2>&1 | tr -d '\r' | tee "$output/harness.log"
spawn_status=${PIPESTATUS[0]}
set -e
if [ "$spawn_status" -ne 0 ] || ! grep -qx 'HARNESS-PASS' "$output/harness.log"; then
  echo "Apple simulator harness failed (exit $spawn_status); see $output/harness.log" >&2
  exit 1
fi
