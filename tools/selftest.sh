#!/bin/bash
# Per-process test suite for the macOS build. Touches no system state: everything runs
# with DYLD_INSERT_LIBRARIES on individual commands, so nothing here can affect other
# processes or require an install.
#
#   ./build-macos.sh && ./tools/selftest.sh
#
# Needs network access. Uses api.twitter.com as the TLS regression target because stock
# 10.9 Secure Transport fails it with -9824 (errSSLPeerHandshakeFail) while LibreSSL
# negotiates TLS 1.3 fine.

DIR="$(cd "$(dirname "$0")/.." && pwd)"
T="$DIR/.build/stage/Library/TLSFix"
D="$T/tlsfix.dylib"
PROBE="$DIR/.build/httpsprobe"
URLPROBE="$DIR/.build/urlprobe"
pass=0; fail=0

[ -f "$D" ] || { echo "no build -- run ./build-macos.sh"; exit 1; }
[ -x "$PROBE" ] || clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
    -framework CoreFoundation -framework CFNetwork -o "$PROBE" "$DIR/tools/httpsprobe.c"
[ -x "$URLPROBE" ] || clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 \
    -framework Foundation -o "$URLPROBE" "$DIR/tools/urlprobe.m"

# Rules used only by the rewrite tests. example.invalid deliberately does not resolve:
# if the redirect works, DNS is never consulted for it.
mkdir -p "$T"
cat > "$T/redirects.txt" <<'EOF'
https://example.invalid/gone
https://httpbin.org/get?rewritten=yes

http://neverssl.com/tlsfix
https://httpbin.org/get?upgraded=yes
EOF
cat > "$T/headers.txt" <<'EOF'
https://httpbin.org/headers
X-TLSFix-Test: hello
EOF
rm -f "$T/disabled" "$T/disabled-tls" "$T/disabled-rewrite"

run() { TLSFIX_DIR="$T" DYLD_INSERT_LIBRARIES="$D" "$@" 2>&1 | tail -1; }
check() { # check <name> <expected-substring> <actual>
  if echo "$3" | grep -q "$2"; then printf "  ok    %s\n" "$1"; pass=$((pass+1));
  else printf "  FAIL  %-42s got: %s\n" "$1" "$3"; fail=$((fail+1)); fi
}

echo "== TLS engine =="
for a in x86_64 i386; do
  check "$a: stock fails api.twitter.com" "9824" "$(arch -$a "$PROBE" https://api.twitter.com/ 2>&1|tail -1)"
  check "$a: TLSFix connects api.twitter.com" "^404" "$(run arch -$a "$PROBE" https://api.twitter.com/)"
  check "$a: no regression on cloudflare" "^200" "$(run arch -$a "$PROBE" https://www.cloudflare.com/)"
done

echo "== certificate validation (must still reject) =="
for h in expired self-signed wrong.host untrusted-root; do
  check "rejects $h.badssl.com" "FAIL" "$(run "$PROBE" "https://$h.badssl.com/")"
done
check "accepts valid badssl.com" "^200" "$(run "$PROBE" https://badssl.com/)"

echo "== URL rewriting =="
for a in x86_64 i386; do
  check "$a: cross-host redirect" "rewritten=yes" "$(run arch -$a "$URLPROBE" 'https://example.invalid/gone')"
  check "$a: http->https upgrade"  "upgraded=yes"  "$(run arch -$a "$URLPROBE" 'http://neverssl.com/tlsfix')"
  check "$a: header injection" "X-Tlsfix-Test" \
    "$(TLSFIX_DIR=$T DYLD_INSERT_LIBRARIES=$D arch -$a "$URLPROBE" https://httpbin.org/headers show 2>&1 | grep -i 'X-Tlsfix-Test' | head -1)"
done

echo "== kill switches =="
touch "$T/disabled-tls"
check "disabled-tls -> stock behaviour" "9824" "$(run "$PROBE" https://api.twitter.com/)"
rm -f "$T/disabled-tls"
touch "$T/disabled-rewrite"
check "disabled-rewrite -> no rewrite" "FAIL" "$(run "$URLPROBE" 'https://example.invalid/gone')"
rm -f "$T/disabled-rewrite"
touch "$T/disabled"
check "disabled -> everything off" "9824" "$(run "$PROBE" https://api.twitter.com/)"
rm -f "$T/disabled"
check "re-enabled" "^404" "$(run "$PROBE" https://api.twitter.com/)"

echo "== deny list =="
# The gate matches on process name, so a copy named ocspd must pass straight through.
cp "$PROBE" "$DIR/.build/ocspd"
check "process named ocspd is skipped" "9824" "$(run "$DIR/.build/ocspd" https://api.twitter.com/)"
rm -f "$DIR/.build/ocspd"

echo
echo "$pass passed, $fail failed"
[ "$fail" = "0" ]
