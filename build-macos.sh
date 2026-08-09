#!/bin/bash
# Builds AquaTransport for Mac OS X 10.6 - 10.9.
#
# Everything is built from sources in this repo: deps/openssl-*.tar.gz is the only
# external dependency and it is vendored, so a build needs no network access.
#
# Output: build/stage/usr/share/aquatransport/aquatransport.dylib (fat i386 + x86_64)
#         build/stage/Library/AquaTransport/{aqinject, aqwatch}
#
# aqinject/aqwatch load the dylib into other processes. Two requirements the build verifies
# before finishing:
#   * both architectures present -- so the library can load into i386 and x86_64 targets
#   * no symbols exported -- OpenSSL defines the whole SSL_*/EVP_* namespace, which must
#     not be visible to any host process it loads into

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.7}"
MIN="${AQUATRANSPORT_MIN_OS:-10.6}"
ARCHS=(x86_64 i386)

BUILD="$DIR/build"
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
    -install_name /usr/share/aquatransport/aquatransport.dylib \
    "${objs[@]}" "$LS_OUT/lib/libssl.a" "$LS_OUT/lib/libcrypto.a" \
    -Wl,-lazy_framework,Security -Wl,-lazy_framework,CoreFoundation \
    -Wl,-exported_symbols_list,"$BUILD/nothing.exp"
  slices+=("$out")
  echo "    $a ok"
done

# The stage mirrors the installed layout, so it doubles as a pkgbuild root.
#
#   usr/share/aquatransport/   the dylib and the rule files -- everything a target reads for
#                              itself. /usr/share is one of the few directories a sandboxed
#                              process may read; see src/mac/aquatransport_config.c.
#   Library/AquaTransport/     aqinject and aqwatch, which root runs from outside any sandbox.
ST="$BUILD/stage/usr/share/aquatransport"
STOOL="$BUILD/stage/Library/AquaTransport"

# Clear the build's own products from the whole stage tree first. Because the stage is a
# pkgbuild root, a binary sitting at a path this build no longer writes is still packaged and
# installed, so a copy at a retired path would ship alongside the real one. Matching by name
# across the tree keeps that true for any path the layout leaves behind.
#
# The rule files are deliberately not touched: they are hand-maintained fixtures that
# selftest.sh reads through AQUATRANSPORT_DIR, and nothing regenerates them.
if [ -d "$BUILD/stage" ]; then
  find "$BUILD/stage" -type f \
    \( -name aquatransport.dylib -o -name aqinject -o -name aqwatch \) -delete
fi

mkdir -p "$ST" "$STOOL"

lipo -create "${slices[@]}" -output "$ST/aquatransport.dylib"

# The URL rewriter is pure C compiled into the dylib above (src/mac/aquatransport_rewrite.c),
# so nothing extra is staged and no process has Objective-C loaded into it.

# ---- 3. verify the invariants ----------------------------------------------
# Per slice: the architecture is present; nothing is exported (OpenSSL's whole SSL_*/EVP_*
# namespace must not leak into host processes); and
# nothing is imported that postdates the deployment target. Post-10.6 imports bind lazily, so
# the dylib would load and then crash the process on first use -- checked per slice because
# i386 legitimately imports $UNIX2003 variants x86_64 never has.
#   Added in 10.7:  strndup strnlen getline getdelim memmem arc4random_buf
#   Added in 10.12: getentropy clock_gettime clock_gettime_nsec_np
echo "==> verifying"
have=$(lipo -info "$ST/aquatransport.dylib" | sed 's/.*://')
echo "    architectures:$have"
POST106='^_(strndup|strnlen|getline|getdelim|memmem|getentropy|clock_gettime|clock_gettime_nsec_np|arc4random_buf|dispatch_activate|os_unfair_lock_lock)$'
for a in "${ARCHS[@]}"; do
  echo "$have" | grep -qw "$a" || { echo "FATAL: missing $a slice; aqinject could not load into $a targets"; exit 1; }
  n=$(nm -arch "$a" -g "$ST/aquatransport.dylib" 2>/dev/null | grep -cE " (T|D|B|S) _" || true)
  [ "$n" = "0" ] || { echo "FATAL: $a exports $n symbols (OpenSSL namespace would leak)"; exit 1; }
  bad=$(nm -arch "$a" -u "$ST/aquatransport.dylib" 2>/dev/null | tr -d ' ' | grep -E "$POST106" || true)
  [ -z "$bad" ] || { echo "FATAL: $a imports symbols absent on $MIN (would crash on first use):"
                     echo "$bad" | sed 's/^/      /'; exit 1; }
done
echo "    per slice: present, 0 exports, no post-$MIN imports"

ls -lh "$ST/aquatransport.dylib" | awk '{print "    size: "$5}'
echo "built: $ST/aquatransport.dylib"

# ---- 4. the loader tools ---------------------------------------------------
# aqinject loads the dylib into a running process (task_for_pid + a hand-built mach_inject);
# aqwatch drives aqinject for each process as it launches, off the process list. Both are fat,
# so a slice loads same-arch targets and re-execs the matching slice for the other architecture.
iargs=(); for a in "${ARCHS[@]}"; do iargs+=(-arch "$a"); done
for t in aqinject aqwatch; do
  echo "==> building $t"
  clang "${iargs[@]}" -mmacosx-version-min="$MIN" -O2 -Wall -o "$STOOL/$t" "$DIR/tools/$t.c"
  echo "    architectures:$(lipo -info "$STOOL/$t" | sed 's/.*://')"
done
echo "built: $STOOL/aqinject, $STOOL/aqwatch"
