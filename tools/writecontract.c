// What SSLWrite reports when the transport will not take everything, and what it expects on
// the retry. The engine has to answer a blocked write the way Secure Transport answers it, and
// this is what says how that is.
//
// The write callback here is a throttle: it accepts up to a budget and then reports
// errSSLWouldBlock with a short count, which is what a non-blocking socket does. Run it
// against the stock stack for the reference answer, then against the engine -- the two must
// agree line for line.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
//       -framework CoreFoundation -framework Security -o writecontract tools/writecontract.c
//
//   writecontract [host]
//
// Reports, for each case: the OSStatus, *processed, how many times the callback was called,
// and how many bytes it took. What matters is whether errSSLWouldBlock ever comes back with
// *processed of 0, since that is the answer a caller has to be able to act on.

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define UNLIMITED ((size_t)-1)

static size_t g_budget = UNLIMITED;   // what the transport will still accept
static int    g_calls;                // callback invocations since the last reset
static size_t g_taken;                // bytes it accepted since the last reset

static void reset(size_t budget) { g_budget = budget; g_calls = 0; g_taken = 0; }

static OSStatus sock_read(SSLConnectionRef c, void *data, size_t *len) {
    int fd = *(const int *)c;
    size_t want = *len, got = 0;
    while (got < want) {
        ssize_t n = read(fd, (char *)data + got, want - got);
        if (n > 0) { got += (size_t)n; continue; }
        *len = got;
        return n == 0 ? errSSLClosedGraceful : errSSLWouldBlock;
    }
    *len = got;
    return noErr;
}

// Accepts at most the remaining budget, and reports a short write the way a non-blocking
// socket does: the count it took, and errSSLWouldBlock.
static OSStatus sock_write(SSLConnectionRef c, const void *data, size_t *len) {
    int fd = *(const int *)c;
    size_t want = *len;
    size_t take = (g_budget == UNLIMITED || want < g_budget) ? want : g_budget;
    size_t put = 0;
    g_calls++;
    while (put < take) {
        ssize_t n = write(fd, (const char *)data + put, take - put);
        if (n <= 0) break;
        put += (size_t)n;
    }
    if (g_budget != UNLIMITED) g_budget -= put;
    g_taken += put;
    *len = put;
    return put == want ? noErr : errSSLWouldBlock;
}

static const char *stname(OSStatus s) {
    switch (s) {
        case noErr:                 return "noErr";
        case errSSLWouldBlock:      return "errSSLWouldBlock";
        case errSSLClosedAbort:     return "errSSLClosedAbort";
        case errSSLClosedGraceful:  return "errSSLClosedGraceful";
        default:                    return "other";
    }
}

static void report(const char *what, OSStatus st, size_t processed, size_t asked) {
    printf("  %-34s st=%-18s processed=%-7lu of %-7lu  cb_calls=%d cb_took=%lu\n",
           what, stname(st), (unsigned long)processed, (unsigned long)asked, g_calls,
           (unsigned long)g_taken);
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "postman-echo.com";

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) || !res) { printf("FAIL: resolve\n"); return 1; }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen)) { printf("FAIL: connect\n"); return 1; }
    freeaddrinfo(res);

    SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    SSLSetIOFuncs(ctx, sock_read, sock_write);
    SSLSetConnection(ctx, &fd);
    SSLSetPeerDomainName(ctx, host, strlen(host));
    OSStatus st;
    while ((st = SSLHandshake(ctx)) == errSSLWouldBlock) ;
    if (st != noErr) { printf("FAIL: handshake %d\n", (int)st); return 1; }

    // A request whose declared length is far more than will ever be sent, so the server waits
    // for a body instead of answering and closing while the cases below run.
    size_t chunk = 100000;
    char *buf = (char *)malloc(chunk);
    memset(buf, 'A', chunk);
    char head[512];
    int hl = snprintf(head, sizeof head,
        "POST /post HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000000000\r\n\r\n", host);
    size_t n = 0;
    reset(UNLIMITED);
    SSLWrite(ctx, head, (size_t)hl, &n);

    printf("case 1: transport takes 5000 bytes, then blocks; one 100000-byte SSLWrite\n");
    reset(5000);
    n = 0;
    st = SSLWrite(ctx, buf, chunk, &n);
    report("first write, transport starved", st, n, chunk);
    size_t firstProcessed = n;
    OSStatus firstStatus = st;

    printf("case 2: transport unblocks; SSLWrite retried with the REMAINDER\n");
    reset(UNLIMITED);
    n = 0;
    st = SSLWrite(ctx, buf + firstProcessed, chunk - firstProcessed, &n);
    report("retry with remainder", st, n, chunk - firstProcessed);
    int retryOK = (st == noErr);

    printf("case 3: starve again, then retry with the SAME buffer and length\n");
    reset(3000);
    n = 0;
    st = SSLWrite(ctx, buf, chunk, &n);
    report("second write, starved", st, n, chunk);
    size_t p2 = n;
    reset(UNLIMITED);
    n = 0;
    st = SSLWrite(ctx, buf + p2, chunk - p2, &n);
    report("retry with remainder", st, n, chunk - p2);

    // The retry a caller makes after a fully-consumed blocked write is zero-length, since
    // *processed came back equal to dataLength. It has to mean "flush what you are holding".
    printf("case 4: zero-length SSLWrite while the transport is blocked, then unblocked\n");
    reset(0);
    n = 0;
    st = SSLWrite(ctx, buf, chunk, &n);
    report("starve, fill the queue", st, n, chunk);
    reset(0);
    n = 0;
    st = SSLWrite(ctx, buf, 0, &n);
    report("zero-length, still blocked", st, n, 0);
    reset(UNLIMITED);
    n = 0;
    st = SSLWrite(ctx, buf, 0, &n);
    report("zero-length, unblocked", st, n, 0);

    printf("case 5: NEW data offered while the queue is still full\n");
    reset(0);
    n = 0;
    st = SSLWrite(ctx, buf, chunk, &n);
    report("starve, fill the queue", st, n, chunk);
    reset(0);
    n = 0;
    st = SSLWrite(ctx, buf, chunk, &n);
    report("new data, still blocked", st, n, chunk);
    reset(UNLIMITED);
    n = 0;
    st = SSLWrite(ctx, buf, 0, &n);
    report("flush", st, n, 0);

    printf("\nsummary: blocked SSLWrite -> %s with processed=%lu (%s); retry accepted=%s\n",
           stname(firstStatus), (unsigned long)firstProcessed,
           firstProcessed == 0 ? "NO forward progress" : "forward progress",
           retryOK ? "yes" : "no");

    SSLClose(ctx);
    CFRelease(ctx);
    close(fd);
    free(buf);
    return 0;
}
