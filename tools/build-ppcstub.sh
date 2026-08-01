#!/bin/bash
# Builds the PowerPC no-op slice. MUST run on Mac OS X 10.6 with Xcode 3.2.6 installed --
# that is the last Xcode with PowerPC codegen, and clang on 10.9 has no ppc backend at all
# ("No available targets are compatible with this triple").
#
# The result is vendored at deps/ppcstub/aquatransport-ppc.dylib so build-macos.sh can lipo it in
# on machines that cannot produce it. Rebuild only if src/mac/ppcstub.c changes.
#
#   scp src/mac/ppcstub.c tools/build-ppcstub.sh user@snowleopard:/tmp/
#   ssh user@snowleopard 'cd /tmp && ./build-ppcstub.sh'
#   scp user@snowleopard:/tmp/aquatransport-ppc.dylib deps/ppcstub/
#
# See src/mac/ppcstub.c for why a stub is required rather than a real PPC port.

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-$DIR/ppcstub.c}"
OUT="${2:-$DIR/aquatransport-ppc.dylib}"

GCC=""
for c in /usr/bin/gcc-4.2 /Developer/usr/bin/gcc-4.2 /usr/bin/gcc-4.0 /Developer/usr/bin/gcc-4.0; do
  [ -x "$c" ] && { GCC="$c"; break; }
done
[ -n "$GCC" ] || { echo "no gcc-4.x found -- install Xcode 3.2.6 (Xcode 4+ dropped ppc)"; exit 1; }
[ -f "$SRC" ] || { echo "missing source: $SRC"; exit 1; }

echo "==> $GCC -arch ppc"
: > /tmp/ppcstub-nothing.exp
"$GCC" -arch ppc -dynamiclib -O2 \
  -mmacosx-version-min=10.4 \
  -install_name /Library/AquaTransport/aquatransport.dylib \
  -Wl,-exported_symbols_list,/tmp/ppcstub-nothing.exp \
  -o "$OUT" "$SRC"

echo "==> verifying"
lipo -info "$OUT" | sed 's/^/    /'
lipo -info "$OUT" | grep -q ppc || { echo "FATAL: not a ppc binary"; exit 1; }
n=$(nm -g "$OUT" 2>/dev/null | grep -cE " (T|D|B|S) _" || true)
[ "$n" = "0" ] || { echo "FATAL: stub exports $n symbols (must export none)"; exit 1; }
u=$(nm -u "$OUT" 2>/dev/null | grep -v dyld_stub_binder | grep -c . || true)
echo "    exports: 0   undefined (excluding stub binder): $u"
ls -l "$OUT" | awk '{print "    size: "$5" bytes"}'
echo "built: $OUT"
