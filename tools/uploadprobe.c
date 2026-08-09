// A LARGE HTTPS POST through CFNetwork -- the write path every other probe here leaves
// untested. The existing probes issue GETs, so the only thing they ever hand SSLWrite is a
// request header that fits in one record and one socket write. An upload is the opposite: a
// multi-megabyte body pushed through SSLWrite in chunks, with the socket send buffer filling
// up partway, so the write returns short and has to be retried. That retry is the part of the
// Secure Transport contract nothing else here exercises.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
//       -framework CoreFoundation -framework CFNetwork -o uploadprobe tools/uploadprobe.c
//
//   uploadprobe <url> <megabytes> [async] [stream]
//
// Both stream modes matter and they are not the same test. Without "async" the stream is
// driven by blocking CFReadStreamRead calls; with it the stream is scheduled on a run loop and
// driven by events, which is the mode a browser uses. CFNetwork's tolerance for a would-block
// out of SSLWrite differs between the two, so an engine that satisfies one can still fail the
// other.
//
// "stream" hands CFNetwork a body stream over a file instead of an in-memory body, which is
// the shape a browser file upload takes. CFNetwork pumps the body itself there, so the sizes
// it presents to SSLWrite are its own; peak RSS is reported so a write path that grew with the
// body would show up as well.
//
// Prints the HTTP status, or the negated CFError code when the request failed (so a -9806
// abort prints as rc=-9806).

#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

static double now_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

// A multipart/form-data body of roughly n bytes, the shape a browser sends for a file input.
static CFDataRef make_body(size_t n, const char *boundary) {
    char head[512];
    int hl = snprintf(head, sizeof head,
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"probe.bin\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n", boundary);
    char tail[128];
    int tl = snprintf(tail, sizeof tail, "\r\n--%s--\r\n", boundary);

    size_t payload = n > (size_t)(hl + tl) ? n - (size_t)(hl + tl) : 1;
    CFMutableDataRef d = CFDataCreateMutable(NULL, 0);
    CFDataAppendBytes(d, (const UInt8 *)head, hl);
    UInt8 chunk[4096];
    for (size_t i = 0; i < sizeof chunk; i++) chunk[i] = (UInt8)('A' + (i % 26));
    for (size_t done = 0; done < payload; ) {
        size_t take = payload - done < sizeof chunk ? payload - done : sizeof chunk;
        CFDataAppendBytes(d, chunk, (CFIndex)take);
        done += take;
    }
    CFDataAppendBytes(d, (const UInt8 *)tail, tl);
    return d;
}

// ---- run-loop mode ---------------------------------------------------------
// The browser's shape: the stream is scheduled on a run loop and read from the event
// callback, so CFNetwork drives the socket from its own loop rather than from inside a
// blocking read.
typedef struct { long total; int rc; int done; } AsyncCtx;

static void finish(CFReadStreamRef st, AsyncCtx *a) {
    CFHTTPMessageRef resp = (CFHTTPMessageRef)CFReadStreamCopyProperty(st,
        kCFStreamPropertyHTTPResponseHeader);
    if (resp) { a->rc = (int)CFHTTPMessageGetResponseStatusCode(resp); CFRelease(resp); }
    else {
        CFErrorRef e = CFReadStreamCopyError(st);
        if (e) { a->rc = -(int)CFErrorGetCode(e); CFRelease(e); }
    }
    a->done = 1;
    CFRunLoopStop(CFRunLoopGetCurrent());
}

static void ev(CFReadStreamRef st, CFStreamEventType type, void *info) {
    AsyncCtx *a = (AsyncCtx *)info;
    if (type == kCFStreamEventHasBytesAvailable) {
        UInt8 buf[8192];
        CFIndex n = CFReadStreamRead(st, buf, sizeof buf);
        if (n > 0) { a->total += n; return; }
        finish(st, a);
    } else {
        finish(st, a);                      // error or end of stream
    }
}

// Writes the body to a file and hands CFNetwork a stream over it, which is what a browser
// does with a file input: the body is never held in memory as one object, and CFNetwork pumps
// it from the stream in its own chunks. Returns a body stream, or NULL on failure.
static CFReadStreamRef body_file_stream(CFDataRef body, char *path, size_t pathsz) {
    snprintf(path, pathsz, "/tmp/uploadprobe-%d.body", (int)getpid());
    FILE *f = fopen(path, "wb");
    if (!f) return NULL;
    size_t want = (size_t)CFDataGetLength(body);
    size_t got = fwrite(CFDataGetBytePtr(body), 1, want, f);
    fclose(f);
    if (got != want) { unlink(path); return NULL; }

    CFStringRef ps = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    CFURLRef fu = ps ? CFURLCreateWithFileSystemPath(NULL, ps, kCFURLPOSIXPathStyle, false) : NULL;
    if (ps) CFRelease(ps);
    if (!fu) { unlink(path); return NULL; }
    CFReadStreamRef bs = CFReadStreamCreateWithFile(NULL, fu);
    CFRelease(fu);
    if (!bs) unlink(path);
    return bs;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: uploadprobe <url> <megabytes> [async] [stream]\n"); return 2; }
    int async = 0, streamed = 0;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "async"))  async = 1;
        if (!strcmp(argv[i], "stream")) streamed = 1;
    }
    double mb = atof(argv[2]);
    size_t nbytes = (size_t)(mb * 1024 * 1024);
    const char *boundary = "----AquaTransportProbeBoundary9x7";

    CFStringRef us = CFStringCreateWithCString(NULL, argv[1], kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateWithString(NULL, us, NULL);
    CFRelease(us);
    if (!url) { fprintf(stderr, "bad url\n"); return 2; }

    CFHTTPMessageRef req = CFHTTPMessageCreateRequest(NULL, CFSTR("POST"), url, kCFHTTPVersion1_1);
    CFDataRef body = make_body(nbytes, boundary);

    char ct[128];
    snprintf(ct, sizeof ct, "multipart/form-data; boundary=%s", boundary);
    CFStringRef cts = CFStringCreateWithCString(NULL, ct, kCFStringEncodingUTF8);
    CFHTTPMessageSetHeaderFieldValue(req, CFSTR("Content-Type"), cts);
    CFRelease(cts);

    CFStringRef cl = CFStringCreateWithFormat(NULL, NULL, CFSTR("%ld"), (long)CFDataGetLength(body));
    CFHTTPMessageSetHeaderFieldValue(req, CFSTR("Content-Length"), cl);
    CFRelease(cl);
    CFHTTPMessageSetHeaderFieldValue(req, CFSTR("Connection"), CFSTR("close"));

    char bodyPath[256] = "";
    CFReadStreamRef st;
    if (streamed) {
        CFReadStreamRef bs = body_file_stream(body, bodyPath, sizeof bodyPath);
        if (!bs) { fprintf(stderr, "could not stage the body file\n"); return 2; }
        st = CFReadStreamCreateForStreamedHTTPRequest(NULL, req, bs);
        CFRelease(bs);
    } else {
        CFHTTPMessageSetBody(req, body);
        st = CFReadStreamCreateForHTTPRequest(NULL, req);
    }

    // Bypass any system proxy, so this measures our own TLS path rather than a proxy's.
    CFMutableDictionaryRef noproxy = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFReadStreamSetProperty(st, CFSTR("kCFStreamPropertyHTTPProxy"), noproxy);
    CFRelease(noproxy);

    double t0 = now_ms();
    int rc = -1; long total = 0;
    if (async) {
        AsyncCtx a = { 0, -1, 0 };
        CFStreamClientContext cc = { 0, &a, NULL, NULL, NULL };
        CFReadStreamSetClient(st,
            kCFStreamEventHasBytesAvailable | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered,
            ev, &cc);
        CFReadStreamScheduleWithRunLoop(st, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        if (CFReadStreamOpen(st)) {
            // Bounded, so a stall shows up as a timeout rather than hanging the probe.
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 120.0, false);
            if (!a.done) a.rc = -1;
        } else {
            CFErrorRef e = CFReadStreamCopyError(st);
            if (e) { a.rc = -(int)CFErrorGetCode(e); CFRelease(e); }
        }
        CFReadStreamUnscheduleFromRunLoop(st, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        rc = a.rc; total = a.total;
    } else if (CFReadStreamOpen(st)) {
        UInt8 buf[8192];
        CFIndex n;
        while ((n = CFReadStreamRead(st, buf, sizeof buf)) > 0) total += n;
        CFHTTPMessageRef resp = (CFHTTPMessageRef)CFReadStreamCopyProperty(st,
            kCFStreamPropertyHTTPResponseHeader);
        if (resp) { rc = (int)CFHTTPMessageGetResponseStatusCode(resp); CFRelease(resp); }
        else {
            CFErrorRef e = CFReadStreamCopyError(st);
            if (e) { rc = -(int)CFErrorGetCode(e); CFRelease(e); }
        }
    } else {
        CFErrorRef e = CFReadStreamCopyError(st);
        if (e) { rc = -(int)CFErrorGetCode(e); CFRelease(e); }
    }
    double ms = now_ms() - t0;
    CFReadStreamClose(st);
    if (bodyPath[0]) unlink(bodyPath);

    // Peak resident size answers the question the body size raises: whether anything on the
    // write path grows with the size of the upload. Under a streamed body nothing here holds
    // the body either, so what this measures is the engine.
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("POST %.2f MB %s %-6s -> rc=%d  %.0f ms  resp=%ld bytes  peakRSS=%.1f MB\n",
           mb, async ? "async" : "sync ", streamed ? "stream" : "memory",
           rc, ms, total, ru.ru_maxrss / (1024.0 * 1024.0));
    CFRelease(st); CFRelease(req); CFRelease(body); CFRelease(url);
    return rc >= 200 && rc < 400 ? 0 : 1;
}
