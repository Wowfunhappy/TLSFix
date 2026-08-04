// What revocation checking costs a trust evaluation, and what the policy list does about it.
//
// Trust evaluation on 10.9 checks revocation by "best attempt" whenever the policy list is
// just the SSL policy, and that runs through Security's legacy CSSM path. The engine leaves
// it there deliberately -- tools/crltest/ shows that naming an explicit revocation policy
// switches the check off -- so this tool measures what that costs.
//
// Fetches <host>'s chain, then evaluates fresh trust objects three ways, reporting the time
// and how many files the system CRL cache gains in each case:
//   default        -- policy list is just the SSL policy: what the engine builds
//   ocsp-only      -- [SSL, revocation(OCSP method)]
//   ocsp-nonet     -- [SSL, revocation(OCSP | no network)]
//
// Two costs separate out. The first is the legacy path itself, paid on every evaluation
// whether or not any revocation data exists -- github.com's issuer publishes no CRL
// distribution point at all, so no CRL work is possible there, and it still runs 540 ms
// against 320 ms under any explicit policy. Measured on 10.9.5:
//
//                     default   ocsp-only   ocsp-nonet
//   github.com         495 ms     296 ms      296 ms
//   en.wikipedia.org   469 ms     198 ms      201 ms
//   stackoverflow.com  468 ms     201 ms      201 ms
//
// The second is the CRL download, which shows up as cache growth rather than in the table
// above: run this against a host whose issuer is not in /var/db/crls yet. A DigiCert chain
// costs 911 ms against 32 ms there, the whole difference being one fetch, and reports
// crl-cache +1. A CRL already cached is cheap to consult -- Amazon and GoDaddy chains
// evaluate in 7-8 ms under the default -- so the download is a per-issuer cost, not a
// per-evaluation one.
//
//   clang -arch x86_64 -mmacosx-version-min=10.9 -framework CoreFoundation \
//       -framework CFNetwork -framework Security -o revprobe revprobe.c
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <Security/Security.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/time.h>

static double now_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static int crl_count(void) {
    DIR *d = opendir("/var/db/crls");
    if (!d) return -1;
    int n = 0; struct dirent *e;
    while ((e = readdir(d))) if (strstr(e->d_name, ".crl")) n++;
    closedir(d);
    return n;
}

static CFArrayRef fetch_chain(const char *host) {
    char u[512]; snprintf(u, sizeof u, "https://%s/", host);
    CFStringRef us = CFStringCreateWithCString(NULL, u, kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateWithString(NULL, us, NULL); CFRelease(us);
    if (!url) return NULL;
    CFHTTPMessageRef req = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), url, kCFHTTPVersion1_1);
    CFReadStreamRef st = CFReadStreamCreateForHTTPRequest(NULL, req);
    CFArrayRef out = NULL;
    if (CFReadStreamOpen(st)) {
        UInt8 b[8192]; while (CFReadStreamRead(st, b, sizeof b) > 0) {}
        SecTrustRef t = (SecTrustRef)CFReadStreamCopyProperty(st, kCFStreamPropertySSLPeerTrust);
        if (t) {
            CFMutableArrayRef a = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
            for (CFIndex i = 0, n = SecTrustGetCertificateCount(t); i < n; i++)
                CFArrayAppendValue(a, SecTrustGetCertificateAtIndex(t, i));
            CFRelease(t); out = a;
        }
    }
    CFReadStreamClose(st); CFRelease(st); CFRelease(req); CFRelease(url);
    return out;
}

static void run(const char *label, CFArrayRef chain, const char *host, CFOptionFlags rev, int useRev) {
    CFStringRef h = CFStringCreateWithCString(NULL, host, kCFStringEncodingUTF8);
    SecPolicyRef ssl = SecPolicyCreateSSL(true, h); CFRelease(h);
    SecTrustRef t = NULL;
    SecTrustCreateWithCertificates(chain, ssl, &t);
    if (useRev) {
        SecPolicyRef rp = SecPolicyCreateRevocation(rev);
        if (rp) {
            const void *pols[2] = { ssl, rp };
            CFArrayRef arr = CFArrayCreate(NULL, pols, 2, &kCFTypeArrayCallBacks);
            SecTrustSetPolicies(t, arr);
            CFRelease(arr); CFRelease(rp);
        } else { printf("  %-12s SecPolicyCreateRevocation unavailable\n", label); }
    }
    int before = crl_count();
    SecTrustResultType r = kSecTrustResultInvalid;
    double t0 = now_ms();
    OSStatus st = SecTrustEvaluate(t, &r);
    double ms = now_ms() - t0;
    int after = crl_count();
    printf("  %-12s %8.0f ms  result=%d status=%d  crl-cache %+d\n",
           label, ms, (int)r, (int)st, after - before);
    CFRelease(ssl); CFRelease(t);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: revprobe <host>...\n"); return 2; }
    for (int i = 1; i < argc; i++) {
        CFArrayRef chain = fetch_chain(argv[i]);
        if (!chain) { printf("%s: no chain\n", argv[i]); continue; }
        printf("%s (%ld certs)\n", argv[i], (long)CFArrayGetCount(chain));
        run("default",    chain, argv[i], 0, 0);
        run("ocsp-only",  chain, argv[i], kSecRevocationOCSPMethod, 1);
        run("ocsp-nonet", chain, argv[i], kSecRevocationOCSPMethod | kSecRevocationNetworkAccessDisabled, 1);
        CFRelease(chain);
    }
    return 0;
}
