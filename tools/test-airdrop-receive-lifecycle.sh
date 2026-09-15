#!/bin/bash
# Mavericks-only, localhost-only; needs the built/installed server TLS engine.
set -euo pipefail
umask 077
DIR="$(cd "$(dirname "$0")/.." && pwd)"
TEST=$(mktemp -d /tmp/aq-receive-lifecycle.XXXXXX)
trap 'rm -rf "$TEST"' EXIT
mkdir "$TEST/config" "$TEST/source" "$TEST/output"
export AQ_TEST_DIR="$TEST" AQ_TEST_IDENTITY="$TEST/identity.p12" AQ_TEST_DESTINATION="$TEST/output"
printf 'enable-server-tls\n' > "$TEST/config/flags.txt"
printf 'Native receiver completion fixture.\n' > "$TEST/source/fixture.txt"
dd if=/dev/zero of="$TEST/source/large.bin" bs=1048576 count=5 2>/dev/null
/usr/bin/ditto -c "$TEST/source" "$TEST/archive.cpio"
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TEST/key.pem" -out "$TEST/cert.pem" -days 1 -subj /CN=localhost > "$TEST/certificate.log" 2>&1
/usr/bin/openssl pkcs12 -export -inkey "$TEST/key.pem" -in "$TEST/cert.pem" -out "$TEST/identity.p12" -passout pass:test123
clang -fobjc-arc -fblocks -mmacosx-version-min=10.9 "$DIR/tools/airdrop-receive-lifecycle-test.m" -framework Foundation -framework CFNetwork -o "$TEST/scope"
"$TEST/scope"
clang -fblocks -Wno-deprecated-declarations -I"$DIR/build/openssl/include" "$DIR/tools/airdrop-receive-http-test.c" "$DIR/build/ossl-x86_64/libssl.a" "$DIR/build/ossl-x86_64/libcrypto.a" -framework CFNetwork -framework CoreFoundation -framework Security -o "$TEST/http"
export AQUATRANSPORT_DIR="$TEST/config"
export DYLD_INSERT_LIBRARIES="${AQ_TEST_LOADER:-/usr/share/aquatransport/aquatransport.dylib}"
export AQ_TEST_ARCHIVE="$TEST/archive.cpio" AQ_TEST_HOLD_OPEN=1 AQ_TEST_COALESCE=1 AQ_TEST_SLOW=1
if "$TEST/http" 0 0 tls; then
    echo 'FAIL: old producer join did not reproduce'; exit 1
else
    result=$?
    [ "$result" = 20 ] || { echo "FAIL: unexpected reproduction status $result"; exit 1; }
fi
export AQ_TEST_CLOSE_AFTER_COPY=1
"$TEST/http" 0 0 tls
cmp "$TEST/source/large.bin" "$TEST/output/large.bin"
cmp "$TEST/source/fixture.txt" "$TEST/output/fixture.txt"
unset AQ_TEST_HOLD_OPEN AQ_TEST_COALESCE
"$TEST/http" 0 4 tls
cmp "$TEST/source/large.bin" "$TEST/output/large.bin"
printf 'PASS: native BOM join regression, consumed-stream close, normal HTTP EOF, and exact extracted contents\n'
