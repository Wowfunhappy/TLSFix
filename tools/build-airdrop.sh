#!/bin/bash
# Optional Mavericks-only payload; the universal engine never links these frameworks.
set -euo pipefail
export LC_ALL=C
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$DIR/build/airdrop"
ST="$DIR/build/stage/usr/share/aquatransport"
BOOT_ST="$DIR/build/stage/Library/LaunchDaemons"
mkdir -p "$BUILD" "$ST" "$BOOT_ST"
rm -rf "$ST/airdrop"
rm -f "$ST/org.aquatransport.bootstrap.plist"
find "$DIR/build/stage" -name .DS_Store -delete
mkdir -p "$ST/airdrop"
ARCHIVE="$DIR/deps/libev-4.33.tar.gz"
[ "$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')" = 507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea ]
if [ ! -f "$BUILD/libev-4.33/.libs/libev.a" ]; then
  tar xzf "$ARCHIVE" -C "$BUILD"
  (cd "$BUILD/libev-4.33"; CFLAGS='-arch x86_64 -mmacosx-version-min=10.9 -O2' ./configure --disable-shared --enable-static > configure.log; make -j4 > build.log)
fi
make -C "$DIR/deps/owl" BUILD="$BUILD/owl" \
  CFLAGS='-arch x86_64 -mmacosx-version-min=10.9 -Wall -Wextra -O2 -MMD -MP' \
  LDFLAGS='-arch x86_64 -mmacosx-version-min=10.9' \
  INCLUDES="-I$DIR/deps/owl/src -I$DIR/deps/owl/radiotap -I$DIR/deps/owl/daemon -I$BUILD/libev-4.33" \
  LIBS="-lpcap $BUILD/libev-4.33/.libs/libev.a -framework Foundation -framework CoreWLAN -framework SystemConfiguration"
SOURCES="$DIR/src/mac/airdrop"
printf '_AQAirDropInstalled\n' > "$BUILD/exports.txt"
FLAGS=(-arch x86_64 -mmacosx-version-min=10.9 -O2 -fobjc-arc -fblocks -fvisibility=hidden -Wall -Wextra)
clang "${FLAGS[@]}" -dynamiclib "$SOURCES/AQAirDrop.m" "$DIR/deps/fishhook/fishhook.c" \
  -framework Foundation -framework CFNetwork -Wl,-exported_symbols_list,"$BUILD/exports.txt" \
  -install_name /usr/share/aquatransport/aquatransport_airdrop.dylib -o "$ST/aquatransport_airdrop.dylib"
clang "${FLAGS[@]}" "$SOURCES/AQHelper.m" "$SOURCES/AQWiFiLease.m" \
  -framework Foundation -framework CoreWLAN -framework SystemConfiguration -o "$ST/airdrop/org.aquatransport.airdrop"
bootstrap_slices=()
for arch in x86_64 i386; do
  bootstrap="$BUILD/aquatransport-bootstrap-$arch"
  clang -arch "$arch" -mmacosx-version-min=10.6 -O2 -fblocks -Wall -Wextra \
    "$DIR/src/mac/aquatransport_bootstrap.m" "$DIR/src/mac/aquatransport_config.c" \
    -framework Foundation -framework CoreWLAN -o "$bootstrap"
  bootstrap_slices+=("$bootstrap")
done
lipo -create "${bootstrap_slices[@]}" -output "$ST/aquatransport-bootstrap"
clang "${FLAGS[@]}" "$SOURCES/ad_ble_wake.m" -framework Foundation -framework IOBluetooth -o "$ST/airdrop/ad_ble_wake"
cp "$BUILD/owl/owl" "$ST/airdrop/owl"
cp "$SOURCES/org.aquatransport.airdrop.plist" "$ST/airdrop/"
cp "$DIR/src/mac/org.aquatransport.bootstrap.plist" "$BOOT_ST/"
for image in "$ST/aquatransport_airdrop.dylib" "$ST/airdrop/org.aquatransport.airdrop" "$ST/airdrop/ad_ble_wake" "$ST/airdrop/owl"; do
  lipo -info "$image" | grep -q "is architecture: x86_64$"
  if otool -L "$image" | tail -n +2 | grep -E '/Users/|/usr/local/|SIMBL|ModernAirDrop'; then
    echo "AirDrop payload has an external development dependency: $image"; exit 1
  fi
done
lipo -info "$ST/aquatransport-bootstrap" | grep -q 'Architectures in the fat file: .* are: x86_64 i386[[:space:]]*$'
find "$DIR/build/stage" -name .DS_Store -delete
echo 'Built standalone Mavericks AirDrop payload.'
