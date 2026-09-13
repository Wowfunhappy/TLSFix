#!/bin/bash
# Offline only: synthetic URLs and native GeoServices serialization, no accounts.
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
LIB="$DIR/build/stage/usr/share/aquatransport/aquatransport.dylib"
CONF=$(mktemp -d /tmp/aquatransport-maps-test.XXXXXX)
trap 'rm -rf "$CONF"' EXIT
mkdir -p build/maps
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.9 tools/mapsprobe.m \
    -framework Foundation -framework CFNetwork -o build/maps/mapsprobe
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.9 tools/mapsprobe.m \
    -framework Foundation -framework CFNetwork -F/System/Library/PrivateFrameworks \
    -framework GeoServices -o build/maps/mapsprobe-startup
for a in x86_64 i386; do
    : > "$CONF/flags.txt"
    for mode in urls private-urls eta; do
        AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/maps/mapsprobe "$mode" "build/maps/$mode-$a.json"
    done
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/maps/mapsprobe-startup eta "build/maps/eta-startup-$a.json"
    printf 'disable-maps-fixes\n' > "$CONF/flags.txt"
    for mode in disabled-urls disabled-private-urls disabled-eta; do
        AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/maps/mapsprobe "$mode" "build/maps/$mode-$a.json"
    done
done
GSA_CC="${AQUATRANSPORT_GSA_CC:-$DIR/build/gsa-toolchain/bin/clang}"
"$GSA_CC" -arch x86_64 -mmacosx-version-min=10.9 -fobjc-gc tools/mapsprobe.m \
    -framework Foundation -framework CFNetwork -o build/maps/mapsprobe-gc
: > "$CONF/flags.txt"
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/maps/mapsprobe-gc urls build/maps/urls-gc.json
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/maps/mapsprobe-gc private-urls build/maps/private-urls-gc.json
printf 'disable-maps-fixes\n' > "$CONF/flags.txt"
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/maps/mapsprobe-gc disabled-urls build/maps/disabled-urls-gc.json
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/maps/mapsprobe-gc disabled-private-urls build/maps/disabled-private-urls-gc.json
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 tools/mapsloadprobe.c -o build/maps/mapsloadprobe
: > "$CONF/flags.txt"
for a in x86_64 i386; do
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/maps/mapsloadprobe
done
python tools/maps-check.py build/maps
