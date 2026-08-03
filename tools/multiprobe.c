// N sequential HTTPS requests in ONE process, each forced onto a fresh connection.
//
// The other probes make a single request per process, so they can say nothing about state the
// engine keeps across connections. This one exists for the client session cache: connection 1
// is a full handshake, and connections 2..N should resume it. That makes it the harness for
// two properties the single-shot probes cannot reach:
//
//   - resumption happens at all, and is faster (compare request 1 against the rest);
//   - a host whose certificate must be rejected is still rejected on every connection, with a
//     warm cache -- a resumed session must never become a way to skip that check.
//
// "Connection: close" is what forces a new connection, and therefore a new SSLContextRef, per
// request; without it CFNetwork keeps the socket alive and there is no second handshake to
// resume. Prints one line per request with the wall time and the HTTP status, or the negated
// CFError code when the request failed (so -9806 prints as rc=9806).
//
//   clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 \
//       -framework CoreFoundation -framework CFNetwork -o multiprobe tools/multiprobe.c

#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

static double now_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static int one(const char *urlstr, double *ms) {
    double t0 = now_ms();
    CFStringRef us = CFStringCreateWithCString(NULL, urlstr, kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateWithString(NULL, us, NULL);
    CFRelease(us);
    if (!url) return -1;
    CFHTTPMessageRef req = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), url, kCFHTTPVersion1_1);
    CFHTTPMessageSetHeaderFieldValue(req, CFSTR("Connection"), CFSTR("close"));
    CFReadStreamRef st = CFReadStreamCreateForHTTPRequest(NULL, req);

    // Bypass any system proxy, so this exercises our own TLS path rather than a proxy's.
    CFMutableDictionaryRef noproxy = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFReadStreamSetProperty(st, CFSTR("kCFStreamPropertyHTTPProxy"), noproxy);
    CFRelease(noproxy);

    int rc = -1;
    if (CFReadStreamOpen(st)) {
        UInt8 buf[8192];
        CFIndex n; long total = 0;
        while ((n = CFReadStreamRead(st, buf, sizeof buf)) > 0) total += n;
        CFHTTPMessageRef resp = (CFHTTPMessageRef)CFReadStreamCopyProperty(st,
            kCFStreamPropertyHTTPResponseHeader);
        if (resp) { rc = (int)CFHTTPMessageGetResponseStatusCode(resp); CFRelease(resp); }
        else if (n < 0) {
            CFErrorRef e = CFReadStreamCopyError(st);
            if (e) { rc = -(int)CFErrorGetCode(e); CFRelease(e); }
        }
    }
    CFReadStreamClose(st);
    CFRelease(st); CFRelease(req); CFRelease(url);
    *ms = now_ms() - t0;
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: multiprobe <url> <n>\n"); return 2; }
    int n = atoi(argv[2]);
    if (n < 1) return 2;
    double sum = 0;
    int fails = 0;
    for (int i = 1; i <= n; i++) {
        double ms = 0;
        int rc = one(argv[1], &ms);
        sum += ms;
        if (rc < 0) fails++;
        printf("%4d  %7.0f ms  rc=%d\n", i, ms, rc);
        fflush(stdout);
    }
    printf("---- %d requests, mean %.0f ms, %d failures\n", n, sum / n, fails);
    return 0;
}
