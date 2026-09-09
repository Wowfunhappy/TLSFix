#!/bin/bash
# Builds AquaTransport for Mac OS X 10.6 - 10.9.
#
# OpenSSL is vendored. The GSA module also needs a GC-capable compiler;
# see docs/ICLOUD.md. Once the toolchain is present, builds need no network access.
#
# Output: build/stage/usr/share/aquatransport/aquatransport.dylib (fat i386 + x86_64)
#
# install-macos.sh adds a load command naming that dylib to Security.framework, so it is loaded
# into every process that loads Security. Two requirements the build verifies before finishing:
#   * both architectures present -- so it loads in i386 and x86_64 processes alike
#   * no symbols exported -- OpenSSL defines the whole SSL_*/EVP_* namespace, which must
#     not be visible to any process it is loaded into

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.7}"
MIN="${AQUATRANSPORT_MIN_OS:-10.6}"
ARCHS=(x86_64 i386)

BUILD="$DIR/build"
mkdir -p "$BUILD"
GSA_CC="${AQUATRANSPORT_GSA_CC:-$BUILD/gsa-toolchain/bin/clang}"
[ -x "$GSA_CC" ] || GSA_CC="${AQUATRANSPORT_GSA_CC:-clang}"
# Clang 3.4 still emits GC write barriers; newer Apple clang cannot. See docs/ICLOUD.md.
if ! printf '@interface AQGC @end\n@implementation AQGC @end\n' | \
    "$GSA_CC" -x objective-c -fobjc-gc -c -o "$BUILD/gsa-gc-check.o" - 2>/dev/null; then
  echo "GSA needs a GC-capable compiler. Set AQUATRANSPORT_GSA_CC (see docs/ICLOUD.md)."
  exit 1
fi
rm -f "$BUILD/gsa-gc-check.o"
LS_SRC="$BUILD/src/openssl-$OPENSSL_VERSION"
LS_OUT="$BUILD/openssl"
TARBALL="$DIR/deps/openssl-$OPENSSL_VERSION.tar.gz"

[ -f "$TARBALL" ] || { echo "missing vendored dependency: $TARBALL"; exit 1; }

# ---- 1. OpenSSL (cached; delete build/openssl to force a rebuild) ----------
#
# 3.5 is the current LTS, supported to 2030-04. The engine needs a TLS library that still
# negotiates TLS 1.0, so that a legacy server stock Secure Transport can reach stays
# reachable through the engine; OpenSSL does at security level 0.
if [ ! -f "$LS_OUT/lib/libssl.a" ] || [ ! -f "$LS_OUT/lib/libcrypto.a" ]; then
  echo "==> building OpenSSL $OPENSSL_VERSION (min $MIN)"
  mkdir -p "$BUILD/src"
  [ -d "$LS_SRC" ] || tar xzf "$TARBALL" -C "$BUILD/src"
  for a in "${ARCHS[@]}"; do
    if [ ! -f "$BUILD/ossl-$a/libssl.a" ]; then
      echo "    configure $a"
      mkdir -p "$BUILD/ossl-$a"
      case "$a" in
        x86_64) target=darwin64-x86_64-cc; extra="" ;;
        # i386 has no inline 8-byte atomic, and this era's clang cannot emit the libatomic
        # call either ("cannot compile this atomic library call yet" in threads_pthread.c).
        # BROKEN_CLANG_ATOMICS is OpenSSL's own escape for exactly this; it selects the
        # mutex-backed paths instead.
        i386)   target=darwin-i386-cc;    extra="-DBROKEN_CLANG_ATOMICS" ;;
      esac
      # --with-rand-seed=devrandom keeps the seeding off getentropy(), which is 10.12+ and
      # would bind lazily then kill the process on first use (see the import check below).
      ( cd "$BUILD/ossl-$a" && perl "$LS_SRC/Configure" "$target" \
          no-shared no-tests no-docs no-apps no-legacy no-engine \
          --with-rand-seed=devrandom \
          -mmacosx-version-min="$MIN" -O2 -fPIC $extra > configure.log 2>&1 )
      echo "    compile $a"
      ( cd "$BUILD/ossl-$a" && make -j4 build_libs > build.log 2>&1 )
    fi
  done
  mkdir -p "$LS_OUT/lib" "$LS_OUT/include"
  crypto=(); ssl=()
  for a in "${ARCHS[@]}"; do crypto+=("$BUILD/ossl-$a/libcrypto.a"); ssl+=("$BUILD/ossl-$a/libssl.a"); done
  lipo -create "${crypto[@]}" -output "$LS_OUT/lib/libcrypto.a"
  lipo -create "${ssl[@]}"    -output "$LS_OUT/lib/libssl.a"
  # Headers: the shipped tree plus the per-arch generated ones (opensslconf.h and friends).
  # They agree across our two targets, so either arch's generated set will do.
  cp -R "$LS_SRC/include/"* "$LS_OUT/include/"
  cp -R "$BUILD/ossl-${ARCHS[0]}/include/"* "$LS_OUT/include/"
  echo "    OpenSSL ready"
else
  echo "==> OpenSSL $OPENSSL_VERSION already built (cached)"
fi

# ---- 2. the dylib ----------------------------------------------------------
echo "==> building aquatransport.dylib (min $MIN)"
SRCS=("$DIR/src/aquatransport_engine.c" "$DIR/src/mac/aquatransport_hooks_mac.c" "$DIR/src/mac/aquatransport_config.c"
      "$DIR/src/mac/aquatransport_rewrite.c" "$DIR/src/mac/aquatransport_trust_mac.c" "$DIR/deps/fishhook/fishhook.c")
OBJDIR="$BUILD/obj"; rm -rf "$OBJDIR"; mkdir -p "$OBJDIR"
: > "$BUILD/nothing.exp"

slices=()
loader_slices=()
gsa_slices=()
for a in "${ARCHS[@]}"; do
  objs=()
  for src in "${SRCS[@]}"; do
    o="$OBJDIR/$(basename "${src%.c}")-$a.o"
    clang -arch "$a" -mmacosx-version-min="$MIN" -O2 -fPIC -fvisibility=hidden \
      -Wall -Wno-deprecated-declarations -I"$LS_OUT/include" \
      -c "$src" -o "$o"
    objs+=("$o")
  done
  out="$OBJDIR/aquatransport_engine-$a.dylib"
  clang -arch "$a" -mmacosx-version-min="$MIN" -dynamiclib -o "$out" \
    -install_name /usr/share/aquatransport/aquatransport_engine.dylib \
    "${objs[@]}" "$LS_OUT/lib/libssl.a" "$LS_OUT/lib/libcrypto.a" \
    -Wl,-lazy_framework,Security -Wl,-lazy_framework,CoreFoundation \
    -Wl,-exported_symbols_list,"$BUILD/nothing.exp"
  slices+=("$out")

  # The loader is what Security.framework's load command names, so it is mapped into every
  # process on the system. It links nothing but libc: see the header of the source for why
  # the engine must not be reachable through a load command.
  lout="$OBJDIR/aquatransport-$a.dylib"
  clang -arch "$a" -mmacosx-version-min="$MIN" -O2 -fPIC -fvisibility=hidden \
    -Wall -Wno-deprecated-declarations -dynamiclib -o "$lout" \
    -install_name /usr/share/aquatransport/aquatransport.dylib \
    "$DIR/src/mac/aquatransport_loader.c" \
    -Wl,-exported_symbols_list,"$BUILD/nothing.exp"
  loader_slices+=("$lout")

  # iCloud begins at 10.7. This separate image supports GC for System Preferences;
  # the engine stays pure C and the loader never maps it during process startup.
  gobj="$OBJDIR/aquatransport_gsa-$a.o"
  "$GSA_CC" -arch "$a" -mmacosx-version-min=10.7 -O2 -fPIC -fvisibility=hidden \
    -fobjc-gc -Wall -Wno-deprecated-declarations -I"$LS_OUT/include" \
    -c "$DIR/src/mac/aquatransport_gsa.m" -o "$gobj"
  cobj="$OBJDIR/aquatransport_gsa_crypto-$a.o"
  clang -arch "$a" -mmacosx-version-min=10.7 -O2 -fPIC -fvisibility=hidden \
    -Wall -Wno-deprecated-declarations -I"$LS_OUT/include" \
    -c "$DIR/src/mac/aquatransport_gsa_crypto.c" -o "$cobj"
  gout="$OBJDIR/aquatransport_gsa-$a.dylib"
  clang -arch "$a" -mmacosx-version-min=10.7 -dynamiclib -o "$gout" \
    -install_name /usr/share/aquatransport/aquatransport_gsa.dylib \
    "$gobj" "$cobj" "$OBJDIR/aquatransport_config-$a.o" "$LS_OUT/lib/libcrypto.a" \
    -framework Foundation -framework IOKit -lz -Wl,-exported_symbols_list,"$BUILD/nothing.exp"
  gsa_slices+=("$gout")
  echo "    $a ok"
done

# The stage holds the build's output -- the loader and engine dylibs -- alongside the rule-file
# fixtures selftest.sh reads through AQUATRANSPORT_DIR. install-macos.sh copies the dylibs from
# here; the installer package is assembled separately under packaging/.
ST="$BUILD/stage/usr/share/aquatransport"

# Clear the regenerated files first, keeping only the rule files. Anything left at a path this
# build no longer writes would linger in the stage install-macos.sh copies from, so a binary
# from a retired layout could ship alongside the real one. Clearing everything the build
# regenerates -- rather than a list of names it knows about -- is what keeps that true through a
# rename: a name dropped from the list is exactly the file that would survive.
#
# The rule files are the exception: they are hand-maintained fixtures that selftest.sh reads
# through AQUATRANSPORT_DIR, and nothing regenerates them.
if [ -d "$BUILD/stage" ]; then
  find "$BUILD/stage" -type f ! -name '*.txt' -delete
fi

mkdir -p "$ST"

lipo -create "${slices[@]}" -output "$ST/aquatransport_engine.dylib"
lipo -create "${loader_slices[@]}" -output "$ST/aquatransport.dylib"
lipo -create "${gsa_slices[@]}" -output "$ST/aquatransport_gsa.dylib"

# The URL rewriter is pure C compiled into the dylib above (src/mac/aquatransport_rewrite.c),
# and has no Objective-C dependency. The GSA image is loaded at request time.

# ---- 3. verify the invariants ----------------------------------------------
# Per slice: the architecture is present; nothing is exported (OpenSSL's whole SSL_*/EVP_*
# namespace must not leak into host processes); and
# nothing is imported that postdates the deployment target. Post-10.6 imports bind lazily, so
# the dylib would load and then crash the process on first use -- checked per slice because
# i386 legitimately imports $UNIX2003 variants x86_64 never has.
#   Added in 10.7:  strndup strnlen getline getdelim memmem arc4random_buf
#   Added in 10.12: getentropy clock_gettime clock_gettime_nsec_np
echo "==> verifying"
for img in aquatransport.dylib aquatransport_engine.dylib aquatransport_gsa.dylib; do
have=$(lipo -info "$ST/$img" | sed 's/.*://')
echo "    $img architectures:$have"
POST106='^_(strndup|strnlen|getline|getdelim|memmem|getentropy|clock_gettime|clock_gettime_nsec_np|arc4random_buf|dispatch_activate|os_unfair_lock_lock)$'
for a in "${ARCHS[@]}"; do
  echo "$have" | grep -qw "$a" || { echo "FATAL: $img missing $a slice; $a processes would go unpatched"; exit 1; }
  n=$(nm -arch "$a" -g "$ST/$img" 2>/dev/null | grep -cE " (T|D|B|S) _" || true)
  [ "$n" = "0" ] || { echo "FATAL: $img $a exports $n symbols (OpenSSL namespace would leak)"; exit 1; }
  bad=$(nm -arch "$a" -u "$ST/$img" 2>/dev/null | tr -d ' ' | grep -E "$POST106" || true)
  [ -z "$bad" ] || { echo "FATAL: $img $a imports symbols absent on $MIN (would crash on first use):"
                     echo "$bad" | sed 's/^/      /'; exit 1; }
done
done
echo "    per slice: present, 0 exports, no post-$MIN imports"
# OS X's Objective-C collector is x86_64 only; i386 uses retain/release.
otool -arch x86_64 -ov "$ST/aquatransport_gsa.dylib" | grep -q 'OBJC_IMAGE_SUPPORTS_GC' ||
  { echo "FATAL: GSA x86_64 does not support Objective-C garbage collection"; exit 1; }
echo "    GSA: GC-compatible, deployment target 10.7"

ls -lh "$ST/aquatransport.dylib" "$ST/aquatransport_engine.dylib" | awk '{print "    "$9": "$5}'
# The loader must stay small: its whole purpose is to be harmless to map.
lsz=$(stat -f%z "$ST/aquatransport.dylib")
[ "$lsz" -lt 200000 ] || { echo "FATAL: loader is $lsz bytes; it is meant to be a stub"; exit 1; }
echo "built: loader + TLS engine + iCloud GSA module in $ST"
