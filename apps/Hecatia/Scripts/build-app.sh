#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
configuration=${1:-debug}

case "$configuration" in
  debug|release) ;;
  *)
    echo "usage: $0 [debug|release]" >&2
    exit 2
    ;;
esac

. "$script_dir/env.sh"

swift build --package-path "$project_dir" --configuration "$configuration"

binary_path="$project_dir/.build/$configuration/Hecatia"
app_dir="$project_dir/dist/Hecatia.app"
contents_dir="$app_dir/Contents"

rm -rf "$app_dir"
mkdir -p "$contents_dir/MacOS" "$contents_dir/Resources"
cp "$binary_path" "$contents_dir/MacOS/Hecatia"

# The linked SDK version, which SwiftPM gets wrong for our purposes.
#
# macOS gates behaviour on the `sdk` field of LC_BUILD_VERSION, not on the
# deployment target beside it. `swift build` writes the deployment target into
# both — `minos 14.0, sdk 14.0` — so everything it produces runs in macOS 14
# compatibility mode: no Liquid Glass, and the *old* focus behaviour. Xcode
# writes `minos 14.0, sdk 27.0` and gets neither.
#
# That is not a cosmetic difference. The same source, built both ways, passes
# every focus check one way and fails nine of them the other, and for a whole
# session this script's bundle was the one being measured while the app people
# run was the one being reported broken. `vtool` restamps it so the two agree.
sdk_version=$(xcrun --sdk macosx --show-sdk-version)
minimum=$(plutil -extract LSMinimumSystemVersion raw "$project_dir/App/Info.plist")
vtool -set-build-version macos "$minimum" "$sdk_version" \
  -replace -output "$contents_dir/MacOS/Hecatia" "$contents_dir/MacOS/Hecatia"
cp "$project_dir/App/Info.plist" "$contents_dir/Info.plist"

# The SDK stamps Xcode writes and a plain copy does not.
#
# macOS reads DTSDKName/DTPlatformVersion to decide whether a bundle was built
# against the current SDK, and gates behaviour on it: without them the app gets
# the compatibility appearance — no Liquid Glass — *and* the compatibility
# focus behaviour. Measured, the same source built both ways behaves
# differently, and this script's bundle passed every focus check while Xcode's
# failed nine of them. A test target that is not the shipped one is worse than
# no test target.
sdk_version=$(xcrun --sdk macosx --show-sdk-version)
sdk_build=$(xcrun --sdk macosx --show-sdk-build-version)
sdk_name=macosx$sdk_version
xcode_build=$(xcodebuild -version 2>/dev/null | sed -n 's/^Build version //p')
machine_build=$(sw_vers -buildVersion)

set_key() {
  plutil -replace "$1" -string "$2" "$contents_dir/Info.plist" 2>/dev/null \
    || plutil -insert "$1" -string "$2" "$contents_dir/Info.plist"
}

set_key DTSDKName "$sdk_name"
set_key DTSDKBuild "$sdk_build"
set_key DTPlatformName macosx
set_key DTPlatformVersion "$sdk_version"
set_key DTPlatformBuild "$sdk_build"
set_key DTCompiler com.apple.compilers.llvm.clang.1_0
set_key BuildMachineOSBuild "$machine_build"
[ -n "$xcode_build" ] && set_key DTXcodeBuild "$xcode_build"
plutil -replace CFBundleSupportedPlatforms -json '["MacOSX"]' "$contents_dir/Info.plist" 2>/dev/null \
  || plutil -insert CFBundleSupportedPlatforms -json '["MacOSX"]' "$contents_dir/Info.plist"

if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$app_dir" >/dev/null
fi

echo "$app_dir"
