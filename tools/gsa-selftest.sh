#!/bin/bash
# Offline. Synthetic credentials only; HTTP is intercepted by a catch-all
# NSURLProtocol. IPC tests use temporary Unix sockets (no IP networking).
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
GSA_CC="${AQUATRANSPORT_GSA_CC:-$DIR/build/gsa-toolchain/bin/clang}"
[ -x "$GSA_CC" ] || GSA_CC="${AQUATRANSPORT_GSA_CC:-clang}"
LIB="$DIR/build/stage/usr/share/aquatransport/aquatransport.dylib"
[ -f "$LIB" ] || { echo 'Run ./build-macos.sh first'; exit 1; }
CONF=$(mktemp -d /tmp/aquatransport-gsa-test.XXXXXX)
trap 'rm -rf "$CONF"' EXIT
: > "$CONF/flags.txt"
mkdir "$CONF/diagnostic"
# The diagnostic embeds production source. Prevent the installed loader from
# loading a second copy when the provisioning fixture creates Apple requests.
printf 'disable-icloud-gsa\n' > "$CONF/diagnostic/flags.txt"
# Obsolete configuration must never re-enable HTTP device authentication.
printf 'https://retired-provider.example.invalid/anisette\n' > "$CONF/gsa-anisette-url.txt"
# These would break the exchange if authentication were subject to generic rules.
printf '*\nhttps://gsa.apple.com/\nhttps://example.invalid/\n' > "$CONF/redirects.txt"
printf '*\nhttps://setup.icloud.com/\nAuthorization: must-not-replace-token\n\n*\nhttps://profile.ess.apple.com/\nAuthorization: must-not-replace-token\n' > "$CONF/headers.txt"
python tools/gsa-vectors.py > build/gsa-vectors.h
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -Wno-deprecated-declarations \
    -Ibuild -Ibuild/openssl/include tools/gsacrypto.c build/openssl/lib/libcrypto.a -o build/gsacrypto
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -Wno-deprecated-declarations \
    -Ibuild/openssl/include tools/gsaprobe.m build/openssl/lib/libcrypto.a -lz -framework Foundation -o build/gsaprobe
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -Wno-deprecated-declarations \
    -Ibuild/openssl/include tools/gsa-diagnose.m src/mac/aquatransport_gsa_crypto.c \
    src/mac/aquatransport_config.c build/openssl/lib/libcrypto.a \
    -framework Foundation -framework IOKit -lz -o build/gsa-diagnose
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -Wno-deprecated-declarations \
    -Ibuild/openssl/include tools/anisette-service-test.m build/openssl/lib/libcrypto.a \
    -framework Foundation -framework IOKit -o build/anisette-service-test
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -Wno-deprecated-declarations \
    -Ibuild/openssl/include tools/anisette-ipc-test.m src/mac/aquatransport_gsa_crypto.c \
    src/mac/aquatransport_config.c build/openssl/lib/libcrypto.a \
    -framework Foundation -framework IOKit -lz -o build/anisette-ipc-test
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 tools/davprobe.m -framework Foundation -o build/davprobe
clang -arch x86_64 -mmacosx-version-min=10.7 tools/mailprobe.m -framework Foundation -framework Security -o build/mailprobe
for mode in success success-opaque missing missing-opaque; do
    # Mavericks MailCore is x86_64 and cannot load into a GC process.
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/mailprobe "$mode"
done
"$GSA_CC" -arch x86_64 -mmacosx-version-min=10.7 -fobjc-gc tools/davprobe.m -framework Foundation -o build/davprobe-gc
for a in x86_64 i386; do
    for mode in success auth missing native-calendar native-contacts; do
        AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/davprobe "$mode"
    done
done
for mode in success auth missing native-calendar native-contacts; do
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/davprobe-gc "$mode"
done
for a in x86_64 i386; do
    arch -"$a" build/gsacrypto
    AQUATRANSPORT_DIR="$CONF/diagnostic" arch -"$a" build/gsa-diagnose --selftest
    AQUATRANSPORT_DIR="$CONF/diagnostic" arch -"$a" build/anisette-service-test
    AQUATRANSPORT_DIR="$CONF/diagnostic" arch -"$a" build/anisette-ipc-test
    for mode in success bad-proof short-proof malformed redirect missing-anisette 2fa aos aos-basic aos-mixed settings settings-opaque settings-missing settings-redirect aos-settings aos-settings-opaque ids-success ids-gzip ids-2fa ids-rejected ids-bad-gzip ids-gzip-limit ids-gzip-trailing ids-bad-proof ids-missing-anisette ids-redirect ids-bad-delegate ids-missing-token ids-missing-profile ids-bad-status-type; do
        AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/gsaprobe "$mode"
    done
done
"$GSA_CC" -arch x86_64 -mmacosx-version-min=10.7 -fobjc-gc -Wno-deprecated-declarations \
    -Ibuild/openssl/include tools/gsaprobe.m build/openssl/lib/libcrypto.a -lz -framework Foundation -o build/gsaprobe-gc
"$GSA_CC" -arch x86_64 -mmacosx-version-min=10.7 -fobjc-gc -Wno-deprecated-declarations \
    -Ibuild/openssl/include tools/anisette-ipc-test.m src/mac/aquatransport_gsa_crypto.c \
    src/mac/aquatransport_config.c build/openssl/lib/libcrypto.a \
    -framework Foundation -framework IOKit -lz -o build/anisette-ipc-test-gc
AQUATRANSPORT_DIR="$CONF/diagnostic" build/anisette-ipc-test-gc
for mode in success 2fa aos aos-basic aos-mixed settings settings-opaque aos-settings aos-settings-opaque ids-gzip ids-2fa ids-rejected ids-bad-gzip; do
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/gsaprobe-gc "$mode"
done
printf 'disable-icloud-gsa\n' > "$CONF/flags.txt"
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/mailprobe disabled
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/mailprobe disabled-opaque
# Remove intentionally conflicting rules to test the ordinary native request.
: > "$CONF/redirects.txt"
: > "$CONF/headers.txt"
for a in x86_64 i386; do
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/gsaprobe disabled
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/gsaprobe ids-disabled
done
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/gsaprobe-gc disabled
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/gsaprobe-gc ids-disabled
for a in x86_64 i386; do
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/davprobe disabled
done
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/davprobe-gc disabled
