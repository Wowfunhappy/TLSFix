#!/bin/bash
# Builds AquaTransport for Mac OS X 10.6 - 10.9.
#
# Everything is built from sources in this repo: deps/libressl-*.tar.gz is the only
# external dependency and it is vendored, so a build needs no network access.
#
# Output: .build/stage/Library/AquaTransport/aquatransport.dylib   (fat i386 + x86_64)
#
# The dylib is loaded into every process on the system via DYLD_INSERT_LIBRARIES,
# which imposes two hard requirements the build verifies before finishing:
#   * both architectures must be present -- dyld treats a missing slice in an
#     inserted library as fatal, so an x86_64-only build kills every 32-bit process
#   * no symbols may be exported -- LibreSSL defines arc4random, getentropy and the
#     whole SSL_*/EVP_* namespace, which must not be visible to other images

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
LIBRESSL_VERSION="${LIBRESSL_VERSION:-4.3.2}"
MIN="${AQUATRANSPORT_MIN_OS:-10.6}"
ARCHS=(x86_64 i386)

BUILD="$DIR/.build"
LS_SRC="$BUILD/src/libressl-$LIBRESSL_VERSION"
LS_OUT="$BUILD/libressl"
TARBALL="$DIR/deps/libressl-$LIBRESSL_VERSION.tar.gz"

[ -f "$TARBALL" ] || { echo "missing vendored dependency: $TARBALL"; exit 1; }

# ---- 1. LibreSSL (cached; delete .build/libressl to force a rebuild) --------
if [ ! -f "$LS_OUT/lib/libssl.a" ] || [ ! -f "$LS_OUT/lib/libcrypto.a" ]; then
  echo "==> building LibreSSL $LIBRESSL_VERSION (min $MIN)"
  mkdir -p "$BUILD/src"
  [ -d "$LS_SRC" ] || tar xzf "$TARBALL" -C "$BUILD/src"
  for a in "${ARCHS[@]}"; do
    if [ ! -f "$BUILD/$a/ssl/.libs/libssl.a" ]; then
      echo "    configure $a"
      mkdir -p "$BUILD/$a"
      # LibreSSL's configure probes the *SDK*, not the deployment target, so on a 10.9
      # host it finds strndup/strnlen/getline/getdelim and skips its own compat versions.
      # Those were added in 10.7, so the result links but dies on 10.6 the moment the
      # code path is reached -- a lazy binding failure, which is why the dylib loaded
      # fine and only crashed on first use. Force the compat implementations in.
      ( cd "$BUILD/$a" && CC="clang -arch $a -mmacosx-version-min=$MIN" CFLAGS="-O2 -fPIC" \
          ac_cv_func_strndup=no ac_cv_func_strnlen=no \
          ac_cv_func_getline=no ac_cv_func_getdelim=no \
          "$LS_SRC/configure" --disable-shared --enable-static --disable-tests \
          --host="$a-apple-darwin" > configure.log 2>&1 )
      echo "    compile $a"
      ( cd "$BUILD/$a" && make -C crypto -j4 > build.log 2>&1 && make -C ssl -j4 >> build.log 2>&1 )
    fi
  done
  mkdir -p "$LS_OUT/lib" "$LS_OUT/include"
  crypto=(); ssl=()
  for a in "${ARCHS[@]}"; do crypto+=("$BUILD/$a/crypto/.libs/libcrypto.a"); ssl+=("$BUILD/$a/ssl/.libs/libssl.a"); done
  lipo -create "${crypto[@]}" -output "$LS_OUT/lib/libcrypto.a"
  lipo -create "${ssl[@]}"    -output "$LS_OUT/lib/libssl.a"
  cp -R "$LS_SRC/include/"* "$LS_OUT/include/"
  echo "    LibreSSL ready"
else
  echo "==> LibreSSL $LIBRESSL_VERSION already built (cached)"
fi

# ---- 2. the dylib ----------------------------------------------------------
echo "==> building aquatransport.dylib (min $MIN)"
SRCS=("$DIR/src/aquatransport_engine.c" "$DIR/src/mac/aquatransport_hooks_mac.c" "$DIR/src/mac/aquatransport_config.c"
      "$DIR/src/mac/aquatransport_rewrite.c" "$DIR/deps/fishhook/fishhook.c")
OBJDIR="$BUILD/obj"; rm -rf "$OBJDIR"; mkdir -p "$OBJDIR"
: > "$BUILD/nothing.exp"

slices=()
for a in "${ARCHS[@]}"; do
  objs=()
  for src in "${SRCS[@]}"; do
    o="$OBJDIR/$(basename "${src%.c}")-$a.o"
    clang -arch "$a" -mmacosx-version-min="$MIN" -O2 -fPIC -fvisibility=hidden \
      -Wall -Wno-deprecated-declarations -I"$LS_OUT/include" \
      -c "$src" -o "$o"
    objs+=("$o")
  done
  out="$OBJDIR/aquatransport-$a.dylib"
  clang -arch "$a" -mmacosx-version-min="$MIN" -dynamiclib -o "$out" \
    -install_name /Library/AquaTransport/aquatransport.dylib \
    "${objs[@]}" "$LS_OUT/lib/libssl.a" "$LS_OUT/lib/libcrypto.a" \
    -framework Security -framework CoreFoundation \
    -Wl,-exported_symbols_list,"$BUILD/nothing.exp"
  slices+=("$out")
  echo "    $a ok"
done

ST="$BUILD/stage/Library/AquaTransport"
mkdir -p "$ST"

# The PowerPC no-op slice. Prebuilt and vendored because it needs gcc-4.2 from Xcode 3.2.6
# (clang has no ppc backend), and it never changes -- see src/mac/ppcstub.c.
#
# Without it, a system-wide install on 10.6 with Rosetta stops every PowerPC app from
# launching: measured exit 133, "dyld: could not load inserted library".
PPCSTUB="$DIR/deps/ppcstub/aquatransport-ppc.dylib"
if [ -f "$PPCSTUB" ]; then
  slices+=("$PPCSTUB")
  echo "    ppc (vendored no-op stub) ok"
else
  echo
  echo "    WARNING: $PPCSTUB is missing."
  echo "    The dylib will have no ppc slice. That is fine for 10.7+ and for 10.6 without"
  echo "    Rosetta, but a system-wide install on 10.6 WITH Rosetta will stop every"
  echo "    PowerPC application from launching. Rebuild it with tools/build-ppcstub.sh."
  echo
fi
lipo -create "${slices[@]}" -output "$ST/aquatransport.dylib"

# The URL rewriter used to be a separate Foundation bundle dlopen'd per process. It is now
# pure C compiled into the dylib above (src/mac/aquatransport_rewrite.c), so nothing extra is
# staged and no process ever has Objective-C injected into it.

# ---- 3. verify the two fatal-if-wrong invariants ---------------------------
echo "==> verifying"
have=$(lipo -info "$ST/aquatransport.dylib" | sed 's/.*://')
for a in "${ARCHS[@]}"; do
  echo "$have" | grep -qw "$a" || { echo "FATAL: missing $a slice; would kill every $a process"; exit 1; }
done
case "$have" in *ppc*) ;; *) echo "    note: no ppc slice (see warning above)";; esac
echo "    architectures:$have"

for a in "${ARCHS[@]}"; do
  n=$(nm -arch "$a" -g "$ST/aquatransport.dylib" 2>/dev/null | grep -cE " (T|D|B|S) _" || true)
  [ "$n" = "0" ] || { echo "FATAL: $a exports $n symbols (LibreSSL namespace would leak)"; exit 1; }
done
echo "    exported symbols: 0 (both slices)"

# Undefined references to libc functions that postdate the deployment target. These bind
# lazily, so the dylib loads successfully and then kills the process on first use -- the
# failure looks like a crash in unrelated code. Checked per slice, because i386 legitimately
# imports $UNIX2003 variants that x86_64 never has.
#
# Added in 10.7: strndup strnlen getline getdelim memmem
# Added in 10.12: getentropy clock_gettime clock_gettime_nsec_np
# Added in 10.7: arc4random_buf   (arc4random itself is older)
POST106='^_(strndup|strnlen|getline|getdelim|memmem|getentropy|clock_gettime|clock_gettime_nsec_np|arc4random_buf|dispatch_activate|os_unfair_lock_lock)$'
for a in "${ARCHS[@]}"; do
  bad=$(nm -arch "$a" -u "$ST/aquatransport.dylib" 2>/dev/null | tr -d ' ' | grep -E "$POST106" || true)
  [ -z "$bad" ] || {
    echo "FATAL: $a imports symbols that do not exist on $MIN:"; echo "$bad" | sed 's/^/      /'
    echo "      These bind lazily -- the dylib would load and then crash the process on first use."
    exit 1; }
done
echo "    no post-$MIN undefined symbols (checked per slice)"

ls -lh "$ST/aquatransport.dylib" | awk '{print "    size: "$5}'
echo "built: $ST/aquatransport.dylib"
