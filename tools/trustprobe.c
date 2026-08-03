// Times the OS trust evaluation on its own, with no TLS in the picture.
//
// Separates "what does our stack cost" from "what does Security cost". capture connects and
// writes the peer chain to DER files; eval reads those files back, builds the same SecTrust a
// TLS client would, and times SecTrustEvaluate. eval runs without the dylib loaded, so its
// number is the platform's own cost for that chain.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -framework CoreFoundation \
//       -framework CFNetwork -framework Security -o trustprobe tools/trustprobe.c
//
//   trustprobe capture <https-url> <dir>
//   trustprobe eval    <host> <dir>

#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

static double now_ms(void) {
    struct timeval t; gettimeofday(&t, NULL);
    return t.tv_sec * 1000.0 + t.tv_usec / 1000.0;
}

static int capture(const char *url_s, const char *dir) {
    CFStringRef us = CFStringCreateWithCString(NULL, url_s, kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateWithString(NULL, us, NULL);
    if (!url) { printf("FAIL bad-url\n"); return 1; }
    CFHTTPMessageRef req = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), url, kCFHTTPVersion1_1);
    CFReadStreamRef st = CFReadStreamCreateForHTTPRequest(NULL, req);
    CFMutableDictionaryRef noproxy = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFReadStreamSetProperty(st, CFSTR("kCFStreamPropertyHTTPProxy"), noproxy);
    if (!CFReadStreamOpen(st)) { printf("FAIL open\n"); return 1; }

    UInt8 buf[2048];
    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + 25.0;
    while (CFReadStreamRead(st, buf, sizeof buf) > 0 && CFAbsoluteTimeGetCurrent() < deadline) break;

    SecTrustRef t = (SecTrustRef)CFReadStreamCopyProperty(st, kCFStreamPropertySSLPeerTrust);
    if (!t) { printf("FAIL no-trust\n"); return 1; }
    CFIndex n = SecTrustGetCertificateCount(t);
    for (CFIndex i = 0; i < n; i++) {
        SecCertificateRef c = SecTrustGetCertificateAtIndex(t, i);
        CFDataRef d = c ? SecCertificateCopyData(c) : NULL;
        if (!d) continue;
        char path[1024];
        snprintf(path, sizeof path, "%s/cert%ld.der", dir, (long)i);
        FILE *f = fopen(path, "wb");
        if (f) { fwrite(CFDataGetBytePtr(d), 1, (size_t)CFDataGetLength(d), f); fclose(f); }
        CFRelease(d);
    }
    printf("captured %ld certs\n", (long)n);
    CFReadStreamClose(st);
    return 0;
}

static CFArrayRef load_certs(const char *dir) {
    CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = 0; i < 16; i++) {
        char path[1024];
        snprintf(path, sizeof path, "%s/cert%d.der", dir, i);
        FILE *f = fopen(path, "rb");
        if (!f) break;
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        unsigned char *b = (unsigned char *)malloc((size_t)sz);
        if (b && fread(b, 1, (size_t)sz, f) == (size_t)sz) {
            CFDataRef d = CFDataCreate(NULL, b, sz);
            SecCertificateRef c = d ? SecCertificateCreateWithData(NULL, d) : NULL;
            if (c) { CFArrayAppendValue(arr, c); CFRelease(c); }
            if (d) CFRelease(d);
        }
        free(b); fclose(f);
    }
    return arr;
}

static int eval(const char *host, const char *dir) {
    CFArrayRef arr = load_certs(dir);
    if (!arr || CFArrayGetCount(arr) == 0) { printf("FAIL no-certs\n"); return 1; }

    CFStringRef h = CFStringCreateWithCString(NULL, host, kCFStringEncodingUTF8);
    SecPolicyRef pol = SecPolicyCreateSSL(true, h);
    SecTrustRef t = NULL;
    if (SecTrustCreateWithCertificates(arr, pol, &t) != errSecSuccess) { printf("FAIL create\n"); return 1; }

    SecTrustResultType rr = kSecTrustResultInvalid;
    double t0 = now_ms();
    OSStatus s = SecTrustEvaluate(t, &rr);
    double ms = now_ms() - t0;
    printf("certs=%ld evaluate=%.0f ms status=%d result=%d\n",
           (long)CFArrayGetCount(arr), ms, (int)s, (int)rr);
    return 0;
}

// Evaluates the same chain repeatedly, first with a fresh set of SecCertificateRef objects
// each time and then reusing one set, to show whether Security's internal caching keys on the
// certificate objects it is handed.
static int bench(const char *host, const char *dir, int iters) {
    CFStringRef h = CFStringCreateWithCString(NULL, host, kCFStringEncodingUTF8);
    for (int mode = 0; mode < 2; mode++) {
        CFMutableArrayRef shared = NULL;
        if (mode == 1) shared = (CFMutableArrayRef)load_certs(dir);
        double t0 = now_ms();
        for (int i = 0; i < iters; i++) {
            CFArrayRef arr = (mode == 0) ? load_certs(dir) : (CFArrayRef)CFRetain(shared);
            SecPolicyRef pol = SecPolicyCreateSSL(true, h);
            SecTrustRef t = NULL;
            if (SecTrustCreateWithCertificates(arr, pol, &t) == errSecSuccess && t) {
                SecTrustResultType rr = kSecTrustResultInvalid;
                SecTrustEvaluate(t, &rr);
                CFRelease(t);
            }
            CFRelease(pol); CFRelease(arr);
        }
        printf("  %-14s %d evaluations in %.0f ms  (%.0f ms each)\n",
               mode == 0 ? "fresh certs:" : "reused certs:", iters,
               now_ms() - t0, (now_ms() - t0) / iters);
        if (shared) CFRelease(shared);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: trustprobe capture|eval <url-or-host> <dir>\n"); return 2; }
    if (!strcmp(argv[1], "capture")) return capture(argv[2], argv[3]);
    if (!strcmp(argv[1], "eval"))    return eval(argv[2], argv[3]);
    if (!strcmp(argv[1], "bench"))   return bench(argv[2], argv[3], argc > 4 ? atoi(argv[4]) : 5);
    fprintf(stderr, "unknown mode\n");
    return 2;
}
