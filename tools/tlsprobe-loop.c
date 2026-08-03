// tlsprobe-loop -- a long-lived, cooperating test harness for exercising aqinject on a
// machine you own (e.g. the disposable Snow Leopard test VM).
//
// PURPOSE. It repeatedly makes a real CFNetwork HTTPS request to a host that stock Secure
// Transport on 10.6-10.9 fails to negotiate (api.twitter.com: -9836 on 10.6, -9824 on
// 10.9) and that AquaTransport fixes (HTTP 404 to a bare GET). Run it, watch it fail, then
// load AquaTransport into it with aqinject and watch the SAME process start succeeding --
// no restart. That is the end-to-end demonstration that late loading repairs TLS in an
// already-running process.
//
// This is a test harness, not part of the shipped product: it exists so the injection path
// can be verified against a live process without disturbing a real application.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -framework CoreFoundation -framework CFNetwork \
//       -o tlsprobe-loop tools/tlsprobe-loop.c

#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <stdio.h>
#include <unistd.h>

static void attempt(int n) {
    CFURLRef url = CFURLCreateWithString(NULL, CFSTR("https://api.twitter.com/"), NULL);
    CFHTTPMessageRef req = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), url, kCFHTTPVersion1_1);
    CFReadStreamRef st = CFReadStreamCreateForHTTPRequest(NULL, req);
    CFMutableDictionaryRef noproxy = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFReadStreamSetProperty(st, CFSTR("kCFStreamPropertyHTTPProxy"), noproxy);

    char line[128];
    if (!CFReadStreamOpen(st)) { snprintf(line, sizeof line, "FAIL open"); goto out; }

    UInt8 buf[4096]; CFIndex nread; long total = 0;
    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + 15.0;
    while ((nread = CFReadStreamRead(st, buf, sizeof buf)) > 0) {
        total += nread;
        if (CFAbsoluteTimeGetCurrent() > deadline) break;
    }
    if (nread < 0) {
        CFErrorRef err = CFReadStreamCopyError(st);
        snprintf(line, sizeof line, "FAIL err=%ld", err ? (long)CFErrorGetCode(err) : 0L);
        if (err) CFRelease(err);
    } else {
        CFHTTPMessageRef resp = (CFHTTPMessageRef)CFReadStreamCopyProperty(st,
            kCFStreamPropertyHTTPResponseHeader);
        snprintf(line, sizeof line, "HTTP %ld (%ld bytes)",
                 resp ? (long)CFHTTPMessageGetResponseStatusCode(resp) : 0L, total);
        if (resp) CFRelease(resp);
    }
    CFReadStreamClose(st);
out:
    printf("[%03d] %s\n", n, line);
    fflush(stdout);
    if (url) CFRelease(url);
    if (req) CFRelease(req);
    if (st)  CFRelease(st);
    if (noproxy) CFRelease(noproxy);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("tlsprobe-loop pid=%d -- requesting api.twitter.com every 2s\n", getpid());
    fflush(stdout);
    for (int n = 1; ; n++) {
        attempt(n);
        sleep(2);
    }
    return 0;
}
