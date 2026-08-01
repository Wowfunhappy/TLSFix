#!/bin/bash
# Compatibility probe for older systems (10.6 / 10.7 / 10.8). Verified against 10.6.8.
#
#   ./build-macos.sh                       # produces the payload and the helper binaries
#   tools/ship-probe.sh user@host          # copies everything over and runs this
#
# Or by hand:
#   scp -O tools/probe-10.6.sh .build/symprobe .build/urlprobe \
#          .build/stage/Library/AquaTransport/aquatransport.dylib user@host:/tmp/probe/
#   tar cf - -C .build/stage/Library/AquaTransport rewrite.bundle | ssh user@host 'cd /tmp/probe && tar xf -'
#   ssh user@host 'cd /tmp/probe && ./probe-10.6.sh'
#
# Requires no compiler on the target and installs nothing. Two hard-won notes on why it
# works the way it does:
#
#   * Symbol checks go through ./symprobe (dlsym at runtime), NOT nm. A stock 10.6
#     install has lipo but no nm or otool, which silently turned every nm-based check
#     into a false "MISSING" and made it look like 10.6 had no Secure Transport at all.
#
#   * HTTPS checks go through ./urlprobe (NSURLConnection), NOT curl. Curl on 10.6 is
#     built against OpenSSL 0.9.8, so it never touches Secure Transport and cannot show
#     anything about our hooks. Apple only switched curl to Secure Transport later.

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
have_probe || { echo; echo "MISSING helpers: copy .build/symprobe and .build/urlprobe here first."; exit 1; }
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
  arch -$a "$DIR/symprobe" SecKeyRawSign SecKeyGetBlockSize SecTrustEvaluate \
    SecPolicyCreateSSL SecTrustCreateWithCertificates SecIdentityCopyPrivateKey \
    SecIdentityCopyCertificate SecCertificateCreateWithData 2>/dev/null | grep -E "MISSING|missing"
  echo "      (SecKeyRawSign is the mtls signing path; if MISSING, mtls must clientBypass)"
done

# ---------------------------------------------------------------------------
hdr "Q3  PowerPC / Rosetta"
for f in "$SEC" "$FOUND" "$CFN"; do
  sl=$(lipo -info "$f" 2>/dev/null | sed 's/.*://')
  case "$sl" in *ppc*) v="yes ($sl)";; "") v="PATH NOT FOUND: $f";; *) v="no ($sl)";; esac
  q "$(basename "$f") ppc slice" "$v"
done
if arch -ppc /usr/bin/true >/dev/null 2>&1; then
  q "Rosetta usable" "YES"
  case "$(lipo -info "$DYLIB" 2>/dev/null)" in
    *ppc*) q "payload has ppc slice" "yes" ;;
    *)     q "payload has ppc slice" "NO -- expect PPC apps to die below" ;;
  esac
  base=$(arch -ppc /usr/bin/true >/dev/null 2>&1; echo $?)
  ins=$(DYLD_INSERT_LIBRARIES="$DYLIB" arch -ppc /usr/bin/true 2>&1 >/dev/null); rc=$?
  q "ppc baseline exit" "$base"
  q "ppc with insertion exit" "$rc"
  if [ "$rc" = "$base" ]; then echo "      VERDICT: PPC apps unaffected by the insertion."
  else echo "      VERDICT: INSERTION BREAKS PPC APPS -- ${ins:-no message}"
       echo "               A ppc stub slice is required (tools/build-ppcstub.sh)."; fi
else
  q "Rosetta usable" "no -- PPC apps cannot run here, so the risk does not apply"
fi

# ---------------------------------------------------------------------------
hdr "Q4  Is a failed insertion fatal on this dyld?"
DYLD_INSERT_LIBRARIES=/nonexistent/nope.dylib /usr/bin/true 2>/dev/null; rc=$?
q "missing dylib -> exit" "$rc  $([ $rc = 0 ] && echo '(non-fatal, only warns)' || echo '(FATAL)')"

# ---------------------------------------------------------------------------
hdr "Q5  Engine: does it fix TLS here, and is trust still enforced?"
echo "  NOTE: a stock old system has no modern roots. Hosts may fail trust evaluation"
echo "        even though the handshake succeeded. Install modern roots before concluding"
echo "        that the OS cannot validate modern chains."
export AQUATRANSPORT_DIR="$DIR"
: > "$DIR/debug"; rm -f /tmp/aquatransport-$(id -u).log "$DIR/disabled" "$DIR/disabled-tls" "$DIR/disabled-rewrite"
for a in $ARCHS_HERE; do
  echo "  --- $a ---"
  for h in https://github.com/ https://www.cloudflare.com/ https://letsencrypt.org/; do
    s=$(arch -$a "$DIR/urlprobe" "$h" 2>&1 | tail -1 | cut -c1-16)
    t=$(DYLD_INSERT_LIBRARIES="$DYLIB" arch -$a "$DIR/urlprobe" "$h" 2>&1 | tail -1 | cut -c1-34)
    printf "    %-28s stock=%-17s aquatransport=%s\n" "$h" "$s" "$t"
  done
done

hdr "Q5b  Bad certificates must still be REJECTED"
for h in expired self-signed wrong.host untrusted-root; do
  r=$(DYLD_INSERT_LIBRARIES="$DYLIB" "$DIR/urlprobe" "https://$h.badssl.com/" 2>&1 | tail -1)
  case "$r" in FAIL*) v="rejected (correct)";; *) v="*** ACCEPTED - BUG *** $r";; esac
  q "$h.badssl.com" "$v"
done

hdr "Q6  Rewriter, including the legacy ObjC runtime on i386"
cat > "$DIR/redirects.txt" <<'EOF'
https://example.invalid/probe
https://www.cloudflare.com/
EOF
for a in $ARCHS_HERE; do
  r=$(DYLD_INSERT_LIBRARIES="$DYLIB" arch -$a "$DIR/urlprobe" https://example.invalid/probe 2>&1 | tail -1)
  case "$r" in *cloudflare*) v="rewrite applied (bundle loaded)";; *) v="NOT applied: $r";; esac
  q "$a redirect" "$v"
done
grep "rewrite bundle load failed" /tmp/aquatransport-$(id -u).log 2>/dev/null | sed 's/^/      /'

hdr "Handshakes observed"
grep "handshake" /tmp/aquatransport-$(id -u).log 2>/dev/null | sed 's/.*handshake/  handshake/' | sort -u | head -12
[ -s /tmp/aquatransport-$(id -u).log ] || echo "  (none -- the engine never engaged; check Q4 and the log path)"
rm -f "$DIR/debug" "$DIR/redirects.txt"
