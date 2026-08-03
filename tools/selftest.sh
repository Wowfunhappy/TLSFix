#!/bin/bash
# Per-process test suite for the macOS build. Touches no system state: everything runs
# with DYLD_INSERT_LIBRARIES on individual commands, so nothing here can affect other
# processes or require an install.
#
#   ./build-macos.sh && ./tools/selftest.sh
#
# Needs network access. Uses api.twitter.com as the TLS regression target because stock
# Secure Transport fails it (-9824 on 10.9, -9836 on 10.6) while OpenSSL
# negotiates TLS 1.3 fine.

DIR="$(cd "$(dirname "$0")/.." && pwd)"
T="$DIR/build/stage/Library/AquaTransport"
D="$T/aquatransport.dylib"
PROBE="$DIR/build/httpsprobe"
URLPROBE="$DIR/build/urlprobe"
ASYNCPROBE="$DIR/build/asyncprobe"
SESSIONPROBE="$DIR/build/sessionprobe"
MULTIPROBE="$DIR/build/multiprobe"
LATECHECK="$DIR/build/latecheck"
POOLPROBE="$DIR/build/poolprobe"
pass=0; fail=0

[ -f "$D" ] || { echo "no build -- run ./build-macos.sh"; exit 1; }

# The "stock fails" cases launch a probe with no library inserted and require it to fail.
# An installed aqwatch patches every process as it launches, this one included, so those
# cases turn into passes-that-report-as-failures -- the suite ends up measuring the watcher
# rather than the build. Refuse to run rather than report a confusing result.
if ps ax -o command= 2>/dev/null | grep -q '[a]qwatch'; then
    echo "aqwatch is running: it would inject into the 'stock' probes and make them succeed."
    echo "stop it first, then re-run:"
    echo "    sudo launchctl unload /Library/LaunchDaemons/org.aquatransport.watch.plist"
    echo "    ./tools/selftest.sh"
    echo "    sudo launchctl load -w /Library/LaunchDaemons/org.aquatransport.watch.plist"
    exit 1
fi
[ -x "$PROBE" ] || clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
    -framework CoreFoundation -framework CFNetwork -o "$PROBE" "$DIR/tools/httpsprobe.c"
[ -x "$URLPROBE" ] || clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 \
    -framework Foundation -o "$URLPROBE" "$DIR/tools/urlprobe.m"
[ -x "$ASYNCPROBE" ] || clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 \
    -framework Foundation -o "$ASYNCPROBE" "$DIR/tools/asyncprobe.m"
[ -x "$LATECHECK" ] || clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 \
    -o "$LATECHECK" "$DIR/tools/latecheck.c"
[ -x "$POOLPROBE" ] || clang -arch x86_64 -mmacosx-version-min=10.6 \
    -framework Foundation -o "$POOLPROBE" "$DIR/tools/poolprobe.m"
[ -x "$MULTIPROBE" ] || clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
    -framework CoreFoundation -framework CFNetwork -o "$MULTIPROBE" "$DIR/tools/multiprobe.c"

# Rules used only by the rewrite tests. example.invalid deliberately does not resolve:
# if the redirect works, DNS is never consulted for it.
mkdir -p "$T"
# Blocks are: scope, from, to.  "*" applies to every process.
cat > "$T/redirects.txt" <<'EOF'
*
https://example.invalid/gone
https://httpbin.org/get?rewritten=yes

*
http://neverssl.com/aquatransport
https://httpbin.org/get?upgraded=yes

urlprobe
https://example.invalid/scoped-to-urlprobe
https://httpbin.org/get?scoped=urlprobe

asyncprobe
https://example.invalid/scoped-elsewhere
https://httpbin.org/get?scoped=wrongapp
EOF
cat > "$T/headers.txt" <<'EOF'
*
https://httpbin.org/headers
X-AquaTransport-Test: hello
EOF
: > "$T/flags.txt"

run() { AQUATRANSPORT_DIR="$T" DYLD_INSERT_LIBRARIES="$D" "$@" 2>&1 | tail -1; }
# Stock Secure Transport rejects api.twitter.com across the whole supported range, but the
# code it reports differs by version: 10.9 gives -9824 (errSSLPeerHandshakeFail), 10.6.8
# gives -9836. Match either, or every "must behave like stock" assertion fails on 10.6 for
# a reason that has nothing to do with what is being tested.
STOCKFAIL="9824|9836"

check() { # check <name> <expected-ERE> <actual>
  if echo "$3" | grep -qE "$2"; then printf "  ok    %s\n" "$1"; pass=$((pass+1));
  else printf "  FAIL  %-42s got: %s\n" "$1" "$3"; fail=$((fail+1)); fi
}

echo "== TLS engine =="
for a in x86_64 i386; do
  check "$a: stock fails api.twitter.com" "$STOCKFAIL" "$(arch -$a "$PROBE" https://api.twitter.com/ 2>&1|tail -1)"
  check "$a: AquaTransport connects api.twitter.com" "^404" "$(run arch -$a "$PROBE" https://api.twitter.com/)"
  check "$a: no regression on cloudflare" "^200" "$(run arch -$a "$PROBE" https://www.cloudflare.com/)"
done

echo "== certificate validation (must still reject) =="
for h in expired self-signed wrong.host untrusted-root; do
  check "rejects $h.badssl.com" "FAIL" "$(run "$PROBE" "https://$h.badssl.com/")"
done
check "accepts valid badssl.com" "^200" "$(run "$PROBE" https://badssl.com/)"

echo "== URL rewriting =="
# Sync and async requests funnel through different CFNetwork entry points
# (CFURLConnectionSendSynchronousRequest vs CFURLConnectionCreateWithProperties), so both
# are covered here. Real apps are async.
for a in x86_64 i386; do
  check "$a: cross-host redirect" "rewritten=yes" "$(run arch -$a "$URLPROBE" 'https://example.invalid/gone')"
  check "$a: cross-host redirect (async)" "rewritten=yes" "$(run arch -$a "$ASYNCPROBE" 'https://example.invalid/gone')"
  check "$a: http->https upgrade"  "upgraded=yes"  "$(run arch -$a "$URLPROBE" 'http://neverssl.com/aquatransport')"
  check "$a: http->https upgrade (async)" "upgraded=yes" "$(run arch -$a "$ASYNCPROBE" 'http://neverssl.com/aquatransport')"
  check "$a: header injection" "X-Aquatransport-Test" \
    "$(AQUATRANSPORT_DIR=$T DYLD_INSERT_LIBRARIES=$D arch -$a "$URLPROBE" https://httpbin.org/headers show 2>&1 | grep -i 'X-Aquatransport-Test' | head -1)"
done

# NSURLSession is 10.9+ and reaches the network without touching any CFURLConnection*
# entry point, so it is only covered by the CFURLRequestCreateMutableCopy hook. Skipped on
# older systems, where the API does not exist.
case "$(sw_vers -productVersion)" in
  10.9*|10.1[0-9]*|1[1-9].*)
    [ -x "$SESSIONPROBE" ] || clang -arch x86_64 -mmacosx-version-min=10.9 \
        -framework Foundation -o "$SESSIONPROBE" "$DIR/tools/sessionprobe.m"
    check "NSURLSession: cross-host redirect" "rewritten=yes" \
      "$(run "$SESSIONPROBE" 'https://example.invalid/gone')"
    ;;
  *) echo "  skip  NSURLSession (not present before 10.9)" ;;
esac

echo "== app scoping =="
# The rules file scopes one redirect to "urlprobe" and another to "asyncprobe". A rule must
# fire for the named process and must NOT fire for any other.
check "scoped rule fires for its own app" "scoped=urlprobe" \
  "$(run "$URLPROBE" 'https://example.invalid/scoped-to-urlprobe')"
check "scoped rule ignored by another app" "FAIL" \
  "$(run "$ASYNCPROBE" 'https://example.invalid/scoped-to-urlprobe')"
check "other app's rule not applied here" "FAIL" \
  "$(run "$URLPROBE" 'https://example.invalid/scoped-elsewhere')"
check "and it does fire for that other app" "scoped=wrongapp" \
  "$(run "$ASYNCPROBE" 'https://example.invalid/scoped-elsewhere')"

echo "== flags.txt =="
# A flag is on when its name is a line in flags.txt. Exercise it through "debug", which makes
# the engine log each handshake -- so a log line proves flags.txt is read and honoured.
LOG="/tmp/aquatransport-$(id -u).log"
rm -f "$LOG"
echo debug > "$T/flags.txt"
run "$PROBE" https://api.twitter.com/ >/dev/null
check "debug flag in flags.txt enables logging" "handshake" "$(grep 'httpsprobe\]' "$LOG" 2>/dev/null)"
: > "$T/flags.txt"; rm -f "$LOG"

echo "== loading with no gate =="
# The property the loader design rests on: loaded into a process with no CoreFoundation and no
# Security, the library must pull in neither, and must still work if Secure Transport turns up
# later. Without it, injection would have to wait for Security.framework before it was safe.
for a in x86_64 i386; do
  out=$(arch -$a "$LATECHECK" "$D" 2>&1)
  check "$a: loading pulls in no frameworks" "injected=|loaded\): CF=0 Security=0" "$(echo "$out" | sed -n 2p)"
  check "$a: works when Security arrives later" "HTTP 404" "$(echo "$out" | tail -1)"
done

echo "== session resumption =="
# Connection 1 is a full handshake; the rest should resume it. Asserted through the debug log
# rather than by timing, so the result does not depend on how fast the network happens to be.
rm -f "$LOG"
echo debug > "$T/flags.txt"
AQUATRANSPORT_DIR="$T" DYLD_INSERT_LIBRARIES="$D" "$MULTIPROBE" https://www.cloudflare.com/robots.txt 3 >/dev/null 2>&1
# Only this probe's lines: the log is shared per-uid with every other patched process.
check "first connection is a full handshake" "full"    "$(grep 'multiprobe\]' "$LOG" 2>/dev/null | grep handshake | head -1)"
check "later connections resume it"          "resumed" "$(grep 'multiprobe\]' "$LOG" 2>/dev/null | grep handshake | sed -n '2,3p')"
: > "$T/flags.txt"; rm -f "$LOG"

# The security property the cache must not break. Resumption skips the certificate message,
# so a resumed session must never become a way round a rejection: every connection to a host
# whose chain the system refuses has to fail, warm cache or not.
for h in wrong.host expired; do
  ok=$(AQUATRANSPORT_DIR="$T" DYLD_INSERT_LIBRARIES="$D" \
       "$MULTIPROBE" "https://$h.badssl.com/" 3 2>&1 | grep -c 'rc=200')
  check "$h.badssl.com rejected on every connection (warm cache)" "^0$" "$ok"
done

echo "== warm connections =="
# Pooled requests reuse one connection, so the peer chain -- and therefore the trust decision --
# cannot change between them. A SecTrustEvaluate costs ~335ms on 10.9 hardware, so it must
# happen once per connection, not once per request.
rm -f "$LOG"
echo debug > "$T/flags.txt"
AQUATRANSPORT_DIR="$T" DYLD_INSERT_LIBRARIES="$D" "$POOLPROBE" https://www.cloudflare.com/robots.txt 6 >/dev/null 2>&1
# Count only this probe's lines: the log is shared per-uid, so any other patched process on
# the machine writes into it too.
ntrust=$(grep 'poolprobe\]' "$LOG" 2>/dev/null | grep -c build_trust)
nconn=$(grep 'poolprobe\]' "$LOG" 2>/dev/null | grep -c 'handshake ok')
check "trust is evaluated per connection, not per request" "^[0-2] " "$ntrust ($nconn connections)"
: > "$T/flags.txt"; rm -f "$LOG"

echo "== deny list =="
# The gate matches on process name, so a copy named ocspd must pass straight through.
cp "$PROBE" "$DIR/build/ocspd"
check "process named ocspd is skipped" "$STOCKFAIL" "$(run "$DIR/build/ocspd" https://api.twitter.com/)"
rm -f "$DIR/build/ocspd"

echo
echo "$pass passed, $fail failed"
[ "$fail" = "0" ]
