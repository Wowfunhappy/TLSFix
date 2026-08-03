#!/bin/bash
# Compatibility probe for older systems (10.6 / 10.7 / 10.8). Verified against 10.6.8.
#
#   ./build-macos.sh                       # produces the payload and the helper binaries
#   tools/ship-probe.sh user@host          # copies everything over and runs this
#
# Or by hand:
#   scp -O tools/probe-10.6.sh build/symprobe build/urlprobe \
#          build/stage/Library/AquaTransport/aquatransport.dylib user@host:/tmp/probe/
#   ssh user@host 'cd /tmp/probe && ./probe-10.6.sh'
#
# Requires no compiler on the target and installs nothing. Two notes on why it works the
# way it does:
#
#   * Symbol checks go through ./symprobe (dlsym at runtime), NOT nm. A stock 10.6
#     install has lipo but no nm or otool, which silently turned every nm-based check
#     into a false "MISSING" and made it look like 10.6 had no Secure Transport at all.
#
#   * HTTPS checks go through ./urlprobe (NSURLConnection), NOT curl. Curl on 10.6 is
#     built against OpenSSL 0.9.8, so it never touches Secure Transport and cannot show
#     anything about our hooks.

DIR="$(cd "$(dirname "$0")" && pwd)"
DYLIB="$DIR/aquatransport.dylib"
SEC=/System/Library/Frameworks/Security.framework/Security
FOUND=/System/Library/Frameworks/Foundation.framework/Foundation
# CFNetwork is a CoreServices subframework before 10.7, and top-level from 10.7 on.
CFN=/System/Library/Frameworks/CFNetwork.framework/CFNetwork
[ -e "$CFN" ] || CFN=/System/Library/Frameworks/CoreServices.framework/Frameworks/CFNetwork.framework/CFNetwork

hdr() { printf "\n=== %s ===\n" "$1"; }
q()   { printf "  %-50s %s\n" "$1" "$2"; }
have_probe() { [ -x "$DIR/symprobe" ] && [ -x "$DIR/urlprobe" ]; }

echo "AquaTransport compatibility probe"
q "OS version"    "$(sw_vers -productVersion 2>/dev/null)"
q "build"         "$(sw_vers -buildVersion 2>/dev/null)"
q "kernel arch"   "$(uname -m)"
q "64-bit capable" "$(sysctl -n hw.cpu64bit_capable 2>/dev/null)"
have_probe || { echo; echo "MISSING helpers: copy build/symprobe and build/urlprobe here first."; exit 1; }
[ -f "$DYLIB" ] || { echo; echo "MISSING $DYLIB"; exit 1; }
q "payload slices" "$(lipo -info "$DYLIB" 2>/dev/null | sed 's/.*://')"

ARCHS_HERE=""
for a in x86_64 i386; do arch -$a /usr/bin/true >/dev/null 2>&1 && ARCHS_HERE="$ARCHS_HERE $a"; done
q "runnable native archs" "$ARCHS_HERE"

# ---------------------------------------------------------------------------
hdr "Q1  Secure Transport surface (runtime dlsym)"
for a in $ARCHS_HERE; do
  echo "  --- $a ---"
  arch -$a "$DIR/symprobe" SSLSetIOFuncs SSLSetConnection SSLSetPeerDomainName \
    SSLSetSessionOption SSLHandshake SSLRead SSLWrite SSLClose SSLGetSessionState \
    SSLGetNegotiatedProtocolVersion SSLGetNegotiatedCipher SSLGetBufferedReadSize \
    SSLCopyPeerTrust SSLCopyPeerCertificates SSLSetCertificate 2>/dev/null | tail -1
done

hdr "Q2  Security API the engine depends on"
for a in $ARCHS_HERE; do
  echo "  --- $a ---"
  arch -$a "$DIR/symprobe" SecKeyRawSign SecKeyDecrypt SecKeyGetBlockSize SecTrustEvaluate \
    SecPolicyCreateSSL SecTrustCreateWithCertificates SecIdentityCopyPrivateKey \
    SecIdentityCopyCertificate SecCertificateCreateWithData 2>/dev/null | grep -E "MISSING|missing"
  echo "      (SecKeyRawSign + SecKeyDecrypt are the mtls signing path -- PKCS#1 and PSS"
  echo "       respectively; if either is MISSING, mtls must clientBypass)"
done

# ---------------------------------------------------------------------------
hdr "Q3  Engine: does it fix TLS here, and is trust still enforced?"
echo "  NOTE: a stock old system has no modern roots. Hosts may fail trust evaluation"
echo "        even though the handshake succeeded. Install modern roots before concluding"
echo "        that the OS cannot validate modern chains."
export AQUATRANSPORT_DIR="$DIR"
echo debug > "$DIR/flags.txt"; rm -f /tmp/aquatransport-$(id -u).log
for a in $ARCHS_HERE; do
  echo "  --- $a ---"
  for h in https://github.com/ https://www.cloudflare.com/ https://letsencrypt.org/; do
    s=$(arch -$a "$DIR/urlprobe" "$h" 2>&1 | tail -1 | cut -c1-16)
    t=$(DYLD_INSERT_LIBRARIES="$DYLIB" arch -$a "$DIR/urlprobe" "$h" 2>&1 | tail -1 | cut -c1-34)
    printf "    %-28s stock=%-17s aquatransport=%s\n" "$h" "$s" "$t"
  done
done

hdr "Q3b  Bad certificates must still be REJECTED"
for h in expired self-signed wrong.host untrusted-root; do
  r=$(DYLD_INSERT_LIBRARIES="$DYLIB" "$DIR/urlprobe" "https://$h.badssl.com/" 2>&1 | tail -1)
  case "$r" in FAIL*) v="rejected (correct)";; *) v="*** ACCEPTED - BUG *** $r";; esac
  q "$h.badssl.com" "$v"
done

hdr "Q4  Rewriter, including the legacy ObjC runtime on i386"
cat > "$DIR/redirects.txt" <<'EOF'
https://example.invalid/probe
https://www.cloudflare.com/
EOF
for a in $ARCHS_HERE; do
  r=$(DYLD_INSERT_LIBRARIES="$DYLIB" arch -$a "$DIR/urlprobe" https://example.invalid/probe 2>&1 | tail -1)
  case "$r" in *cloudflare*) v="rewrite applied";; *) v="NOT applied: $r";; esac
  q "$a redirect" "$v"
done

hdr "Handshakes observed"
grep "handshake" /tmp/aquatransport-$(id -u).log 2>/dev/null | sed 's/.*handshake/  handshake/' | sort -u | head -12
[ -s /tmp/aquatransport-$(id -u).log ] || echo "  (none -- the engine never engaged; check Q4 and the log path)"
rm -f "$DIR/flags.txt" "$DIR/redirects.txt"
