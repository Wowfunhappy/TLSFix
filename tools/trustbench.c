// What a SecTrustEvaluate costs, and what it costs to do it twice.
//
// Fetches a host's certificate chain through CFNetwork, then evaluates it several ways.
// The three questions it answers, all of which the engine's trust path depends on:
//
//   1. How expensive is one evaluation for THIS chain? Signature verification varies by
//      algorithm on 10.9-era hardware: an RSA-2048 chain lands around 10-30 ms, an ECDSA
//      chain 200-700 ms. Revocation checking adds to that on top -- see tools/revprobe.c,
//      which separates the two -- and is the larger term for a chain whose issuer CRL is
//      not cached yet.
//
//   2. Does Security cache the result? No -- "same object, again" costs the same as the
//      first evaluation, and so does a fresh object over identical certificates. There is
//      nothing to reuse and nothing to warm up, so any saving has to come from not asking.
//      ("Network fetch off" is no cheaper here, but only because these chains' CRLs are
//      already cached; revprobe against an uncached issuer shows what the fetch costs.)
//
//   3. Is an unevaluated SecTrustRef usable? Yes. SecTrustCopyExceptions and
//      SecTrustGetCertificateCount both succeed on a trust that has never been evaluated --
//      Security evaluates on demand underneath them. That is what lets sh_build_trust hand
//      CFNetwork an unevaluated object, so a chain is evaluated once per connection rather
//      than twice.
//
//   clang -arch x86_64 -mmacosx-version-min=10.9 -framework CoreFoundation \
//       -framework CFNetwork -framework Security -o trustbench tools/trustbench.c
//
//   ./trustbench en.wikipedia.org        # ECDSA chain: slow
//   ./trustbench www.gnu.org             # for contrast
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <Security/Security.h>
#include <stdio.h>
#include <sys/time.h>

// 10.9 exports this but declares it only in the iOS headers, same as SecKeyRawSign.
extern OSStatus SecTrustSetNetworkFetchAllowed(SecTrustRef trust, Boolean allow);

static double now_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

// The peer chain, taken from a real connection rather than a file, so the certificates are
// exactly what the server sends today.
static CFArrayRef fetch_chain(const char *host) {
    char u[512];
    snprintf(u, sizeof u, "https://%s/", host);
    CFStringRef us = CFStringCreateWithCString(NULL, u, kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateWithString(NULL, us, NULL);
    CFRelease(us);
    if (!url) return NULL;
    CFHTTPMessageRef req = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), url, kCFHTTPVersion1_1);
    CFReadStreamRef st = CFReadStreamCreateForHTTPRequest(NULL, req);
    CFArrayRef out = NULL;
    if (CFReadStreamOpen(st)) {
        UInt8 buf[8192];
        while (CFReadStreamRead(st, buf, sizeof buf) > 0) { }
        SecTrustRef t = (SecTrustRef)CFReadStreamCopyProperty(st, kCFStreamPropertySSLPeerTrust);
        if (t) {
            CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
            for (CFIndex i = 0, n = SecTrustGetCertificateCount(t); i < n; i++)
                CFArrayAppendValue(arr, SecTrustGetCertificateAtIndex(t, i));
            CFRelease(t);
            out = arr;
        }
    }
    CFReadStreamClose(st);
    CFRelease(st); CFRelease(req); CFRelease(url);
    return out;
}

static SecTrustRef mk(CFArrayRef chain, const char *host) {
    CFStringRef h = CFStringCreateWithCString(NULL, host, kCFStringEncodingUTF8);
    SecPolicyRef pol = SecPolicyCreateSSL(true, h);
    CFRelease(h);
    SecTrustRef t = NULL;
    SecTrustCreateWithCertificates(chain, pol, &t);
    CFRelease(pol);
    return t;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: trustbench <host>\n"); return 2; }
    const char *host = argv[1];

    CFArrayRef chain = fetch_chain(host);
    if (!chain) { fprintf(stderr, "could not fetch a chain for %s\n", host); return 1; }
    printf("%s: %ld certificates\n\n", host, (long)CFArrayGetCount(chain));

    SecTrustResultType r;
    double t0;

    // 1 + 2: cost, and whether anything is cached between calls.
    SecTrustRef t1 = mk(chain, host);
    t0 = now_ms(); SecTrustEvaluate(t1, &r);
    printf("  first evaluation          %7.0f ms   result=%d\n", now_ms() - t0, (int)r);
    t0 = now_ms(); SecTrustEvaluate(t1, &r);
    printf("  same object, again        %7.0f ms   result=%d\n", now_ms() - t0, (int)r);
    CFRelease(t1);

    SecTrustRef t2 = mk(chain, host);
    t0 = now_ms(); SecTrustEvaluate(t2, &r);
    printf("  fresh object, same certs  %7.0f ms   result=%d\n", now_ms() - t0, (int)r);
    CFRelease(t2);

    SecTrustRef t3 = mk(chain, host);
    SecTrustSetNetworkFetchAllowed(t3, false);
    t0 = now_ms(); SecTrustEvaluate(t3, &r);
    printf("  network fetch off         %7.0f ms   result=%d\n", now_ms() - t0, (int)r);
    CFRelease(t3);

    // 3: an object that has never been evaluated still answers.
    SecTrustRef t4 = mk(chain, host);
    CFDataRef exc = SecTrustCopyExceptions(t4);
    CFIndex n = SecTrustGetCertificateCount(t4);
    printf("\n  unevaluated trust: SecTrustCopyExceptions=%s SecTrustGetCertificateCount=%ld\n",
           exc ? "ok" : "NULL", (long)n);
    if (exc) CFRelease(exc);
    CFRelease(t4);

    CFRelease(chain);
    return 0;
}
