#!/bin/bash
# Builds TLSFix for Mac OS X 10.6 - 10.9.
#
# Everything is built from sources in this repo: deps/libressl-*.tar.gz is the only
# external dependency and it is vendored, so a build needs no network access.
#
# Output: .build/stage/Library/TLSFix/tlsfix.dylib   (fat i386 + x86_64)
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
MIN="${TLSFIX_MIN_OS:-10.6}"
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
      ( cd "$BUILD/$a" && CC="clang -arch $a -mmacosx-version-min=$MIN" CFLAGS="-O2 -fPIC" \
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
echo "==> building tlsfix.dylib (min $MIN)"
SRCS=("$DIR/src/tlsfix_engine.c" "$DIR/src/mac/tlsfix_hooks_mac.c" "$DIR/src/mac/tlsfix_config.c")
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
  out="$OBJDIR/tlsfix-$a.dylib"
  clang -arch "$a" -mmacosx-version-min="$MIN" -dynamiclib -o "$out" \
    -install_name /Library/TLSFix/tlsfix.dylib \
    "${objs[@]}" "$LS_OUT/lib/libssl.a" "$LS_OUT/lib/libcrypto.a" \
    -framework Security -framework CoreFoundation \
    -Wl,-exported_symbols_list,"$BUILD/nothing.exp"
  slices+=("$out")
  echo "    $a ok"
done

ST="$BUILD/stage/Library/TLSFix"
mkdir -p "$ST"
lipo -create "${slices[@]}" -output "$ST/tlsfix.dylib"

# ---- 2b. the rewrite bundle (Foundation; dlopen'd, never inserted) ---------
echo "==> building rewrite.bundle"
RB="$ST/rewrite.bundle/Contents/MacOS"
mkdir -p "$RB"
rslices=()
for a in "${ARCHS[@]}"; do
  out="$OBJDIR/rewrite-$a.dylib"
  clang -arch "$a" -mmacosx-version-min="$MIN" -O2 -bundle -fvisibility=hidden \
    -Wall -Wno-deprecated-declarations -fno-objc-arc \
    -o "$out" "$DIR/src/mac/TFRewrite.m" "$DIR/src/mac/tlsfix_config.c" \
    -framework Foundation -lobjc \
    -Wl,-exported_symbols_list,"$BUILD/nothing.exp"
  rslices+=("$out")
  echo "    $a ok"
done
lipo -create "${rslices[@]}" -output "$RB/rewrite"
cat > "$ST/rewrite.bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>English</string>
	<key>CFBundleExecutable</key><string>rewrite</string>
	<key>CFBundleIdentifier</key><string>com.tlsfix.rewrite</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundleName</key><string>TLSFix URL rewriter</string>
	<key>CFBundlePackageType</key><string>BNDL</string>
	<key>CFBundleVersion</key><string>1.0</string>
</dict>
</plist>
PLIST

# ---- 3. verify the two fatal-if-wrong invariants ---------------------------
echo "==> verifying"
have=$(lipo -info "$ST/tlsfix.dylib" | sed 's/.*://')
for a in "${ARCHS[@]}"; do
  echo "$have" | grep -qw "$a" || { echo "FATAL: missing $a slice; would kill every $a process"; exit 1; }
done
echo "    architectures:$have"

for a in "${ARCHS[@]}"; do
  n=$(nm -arch "$a" -g "$ST/tlsfix.dylib" 2>/dev/null | grep -cE " (T|D|B|S) _" || true)
  [ "$n" = "0" ] || { echo "FATAL: $a exports $n symbols (LibreSSL namespace would leak)"; exit 1; }
done
echo "    exported symbols: 0 (both slices)"

# Symbols that do not exist before 10.12 / 10.7. LibreSSL provides its own, so any
# *undefined* reference here means we would fail to launch on an older system.
for a in "${ARCHS[@]}"; do
  bad=$(nm -arch "$a" -u "$ST/tlsfix.dylib" 2>/dev/null | grep -E "getentropy|clock_gettime|arc4random" || true)
  [ -z "$bad" ] || { echo "FATAL: $a has undefined modern symbols:"; echo "$bad"; exit 1; }
done
echo "    no post-10.6 undefined symbols"

ls -lh "$ST/tlsfix.dylib" | awk '{print "    size: "$5}'
echo "built: $ST/tlsfix.dylib"
