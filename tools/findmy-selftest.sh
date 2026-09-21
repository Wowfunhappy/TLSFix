#!/bin/bash
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
CONF=$(mktemp -d /tmp/aquatransport-findmy-test.XXXXXX)
trap 'rm -rf "$CONF"' EXIT
: > "$CONF/flags.txt"
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.9 tools/findmyprobe.m -framework Foundation -o build/findmyprobe
for mode in enabled disabled; do
    for a in x86_64 i386; do
        if [ "$mode" = disabled ]; then
            printf 'disable-icloud-gsa\n' > "$CONF/flags.txt"
            AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$DIR/build/stage/usr/share/aquatransport/aquatransport.dylib" arch -"$a" build/findmyprobe disabled
        else
            AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$DIR/build/stage/usr/share/aquatransport/aquatransport.dylib" arch -"$a" build/findmyprobe
        fi
    done
done
