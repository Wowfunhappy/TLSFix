#!/bin/bash
# Optional Mavericks-only payload; the universal engine never links these frameworks.
set -euo pipefail
export LC_ALL=C
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$DIR/build/airdrop"
ST="$DIR/build/stage/usr/share/aquatransport"
mkdir -p "$BUILD" "$ST/airdrop/Licenses"
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
  -framework Foundation -framework CoreWLAN -framework SystemConfiguration -o "$ST/airdrop/radio-helper"
clang "${FLAGS[@]}" "$SOURCES/ad_ble_wake.m" -framework Foundation -framework IOBluetooth -o "$ST/airdrop/ad_ble_wake"
cp "$BUILD/owl/owl" "$ST/airdrop/owl"
cp "$DIR/deps/owl/COPYING" "$ST/airdrop/Licenses/OWL-GPLv3.txt"
cp "$DIR/deps/owl/radiotap/COPYING" "$ST/airdrop/Licenses/radiotap.txt"
cp "$BUILD/libev-4.33/LICENSE" "$ST/airdrop/Licenses/libev.txt"
cp "$SOURCES/org.aquatransport.airdrop.plist" "$ST/airdrop/"
# Ship the exact modified OWL source and libev source alongside their binaries.
COPYFILE_DISABLE=1 tar --exclude=.DS_Store --exclude='._*' --exclude=.git -czf "$ST/airdrop/owl-source.tar.gz" -C "$DIR/deps" owl
cp "$ARCHIVE" "$ST/airdrop/"
for image in "$ST/aquatransport_airdrop.dylib" "$ST/airdrop/radio-helper" "$ST/airdrop/ad_ble_wake" "$ST/airdrop/owl"; do
  lipo -info "$image" | grep -q "is architecture: x86_64$"
  if otool -L "$image" | tail -n +2 | grep -E '/Users/|/usr/local/|SIMBL|ModernAirDrop'; then
    echo "AirDrop payload has an external development dependency: $image"; exit 1
  fi
done
echo 'Built standalone Mavericks AirDrop payload.'
