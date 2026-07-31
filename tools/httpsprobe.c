// Minimal CFNetwork HTTPS client used as a test harness.
//
// Goes through CFNetwork -> Secure Transport, which is the same path real apps take,
// and builds for both i386 and x86_64 so the 32-bit slice can be exercised (curl on
// 10.9 is x86_64-only). Prints "<status> <negotiated-protocol>" or "FAIL <reason>".
//
//   clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 \
//       -framework CoreFoundation -framework CFNetwork -o httpsprobe tools/httpsprobe.c

#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: httpsprobe <url>\n"); return 2; }
    CFStringRef us = CFStringCreateWithCString(NULL, argv[1], kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateWithString(NULL, us, NULL);
    if (!url) { printf("FAIL bad-url\n"); return 1; }

    CFHTTPMessageRef req = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), url, kCFHTTPVersion1_1);
    CFReadStreamRef st = CFReadStreamCreateForHTTPRequest(NULL, req);

    // Bypass any system proxy so we exercise our own TLS path rather than a proxy's.
    CFMutableDictionaryRef noproxy = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFReadStreamSetProperty(st, CFSTR("kCFStreamPropertyHTTPProxy"), noproxy);

    if (!CFReadStreamOpen(st)) { printf("FAIL open\n"); return 1; }

    UInt8 buf[4096];
    CFIndex n;
    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + 25.0;
    long total = 0;
    while ((n = CFReadStreamRead(st, buf, sizeof buf)) > 0) {
        total += n;
        if (CFAbsoluteTimeGetCurrent() > deadline) break;
    }

    if (n < 0) {
        CFErrorRef err = CFReadStreamCopyError(st);
        CFIndex code = err ? CFErrorGetCode(err) : 0;
        printf("FAIL err=%ld\n", (long)code);
        if (err) CFRelease(err);
        return 1;
    }

    CFHTTPMessageRef resp = (CFHTTPMessageRef)CFReadStreamCopyProperty(st,
        kCFStreamPropertyHTTPResponseHeader);
    if (resp) {
        printf("%ld bytes=%ld\n", (long)CFHTTPMessageGetResponseStatusCode(resp), total);
        CFRelease(resp);
    } else {
        printf("FAIL no-response\n");
    }
    CFReadStreamClose(st);
    return 0;
}
