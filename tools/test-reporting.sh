#!/bin/bash
# No installation, public network, keychain changes, or external server needed.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$DIR/build/reporting-test"
ENGINE="${1:-$DIR/build/stage/usr/share/aquatransport/aquatransport_engine.dylib}"
mkdir -p "$OUT/startup" "$OUT/runtime"
printf 'reportingprobe\nreportingpolicy\n' > "$OUT/startup/disabled.txt"
printf 'debug\n' > "$OUT/runtime/flags.txt"
: > "$OUT/exports.txt"
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 \
    -Wno-deprecated-declarations -I"$DIR/build/openssl/include" \
    "$DIR/tools/reportingpolicy.c" -framework Security -framework CoreFoundation \
    -o "$OUT/reportingpolicy"
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 \
    -Wno-deprecated-declarations -I"$DIR/build/openssl/include" \
    "$DIR/tools/reportingprobe.c" "$DIR/build/openssl/lib/libssl.a" \
    "$DIR/build/openssl/lib/libcrypto.a" -framework Security -framework CoreFoundation \
    -Wl,-exported_symbols_list,"$OUT/exports.txt" -o "$OUT/reportingprobe"
for arch in x86_64 i386; do
    echo "== $arch =="
    AQUATRANSPORT_DIR="$OUT/startup" /usr/bin/arch -"$arch" "$OUT/reportingpolicy"
    AQUATRANSPORT_DIR="$OUT/startup" /usr/bin/arch -"$arch" \
        "$OUT/reportingprobe" "$ENGINE" "$OUT/runtime"
done
