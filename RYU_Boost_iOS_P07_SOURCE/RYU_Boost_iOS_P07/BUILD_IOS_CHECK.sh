#!/usr/bin/env bash
# Compile/link check only. No signing, installation or deployment.
set -euo pipefail
cd "$(dirname "$0")"
mode=${1:-wireguard}
case "$mode" in
  wireguard) spec=project.yml;;
  openvpn) spec=project-openvpn.yml;;
  *) echo 'Usage: bash BUILD_IOS_CHECK.sh [wireguard|openvpn]' >&2; exit 2;;
esac
out="$PWD/build-check/$mode"
mkdir -p "$out"
# Keep only this build's logs; never read device profiles or credentials.
exec > >(tee "$out/build.log") 2>&1
stage=preflight
trap 'rc=$?; printf "stage=%s\nexit=%s\n" "$stage" "$rc" > "$out/status.txt"' EXIT
bash CHECK_BUILD_ENV.sh
stage=offline
bash TEST_OFFLINE.sh
stage=generate
xcodegen generate --spec "$spec"
project="$PWD/RYUBoost.xcodeproj"
packages="$out/SourcePackages"
derived="$out/DerivedData"
stage=resolve
xcodebuild -resolvePackageDependencies -project "$project" -scheme RYUBoost -clonedSourcePackagesDirPath "$packages" -derivedDataPath "$derived"
lock="$project/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"
if [[ -f "$lock" ]]; then cp "$lock" "$out/Package.resolved"; fi
stage=bridge
bridge="$packages/checkouts/wireguard-apple/Sources/WireGuardKitGo"
test -f "$bridge/Makefile" || { echo 'WireGuardKitGo checkout missing'; exit 3; }
libdir="$out/bridge-lib"
mkdir -p "$libdir"
git -C "$bridge" rev-parse HEAD > "$out/wireguard-revision.txt"
make -C "$bridge" build ARCHS=arm64 PLATFORM_NAME=iphoneos SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)" DESTDIR="$libdir" BUILDDIR="$out/go-temp" DEPLOYMENT_TARGET_CLANG_FLAG_NAME=miphoneos-version-min DEPLOYMENT_TARGET_CLANG_ENV_NAME=IPHONEOS_DEPLOYMENT_TARGET IPHONEOS_DEPLOYMENT_TARGET=17.0
stage=link
xcrun lipo -verify_arch arm64 "$libdir/libwg-go.a"
xcodebuild -project "$project" -scheme RYUBoost -configuration Debug -destination 'generic/platform=iOS' -sdk iphoneos -derivedDataPath "$derived" -clonedSourcePackagesDirPath "$packages" -disableAutomaticPackageResolution CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO ARCHS=arm64 ONLY_ACTIVE_ARCH=NO ENABLE_BITCODE=NO "LIBRARY_SEARCH_PATHS=\$(inherited) \"$libdir\"" build
stage=verify
app="$derived/Build/Products/Debug-iphoneos/RYUBoost.app"
test -d "$app/PlugIns/RYUTunnel.appex"
test -f "$app/RYUBoost"
test -f "$app/PlugIns/RYUTunnel.appex/RYUTunnel"
xcrun lipo -verify_arch arm64 "$app/RYUBoost"
xcrun lipo -verify_arch arm64 "$app/PlugIns/RYUTunnel.appex/RYUTunnel"
stage=compiled_unsigned
echo 'PASS: app + extension linked; unsigned, not installable or tested on device.'
