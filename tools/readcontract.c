// What SSLRead reports when the caller asks for more than has arrived, and what it leaves
// buffered. The companion to tools/writecontract.c, and read the same way: run it against the
// stock stack for the reference answer, then against the engine, and require the two to agree.
//
// The read callback here is a throttle. It hands over at most a budget and then reports
// errSSLWouldBlock with a short count, which is what a non-blocking socket does, so each case
// below can put the transport in a chosen state before calling in.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
//       -framework CoreFoundation -framework Security -o readcontract tools/readcontract.c
//
//   readcontract [host]
//
// Reports, per case: the OSStatus, *processed, how many times the callback was asked, and what
// SSLGetBufferedReadSize says afterwards -- which is how a caller learns that bytes are held
// here rather than on the socket, and therefore whether a short read may be reported as noErr.

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define UNLIMITED ((size_t)-1)

static size_t g_budget = UNLIMITED;
static int    g_calls;
static size_t g_gave;

static void reset(size_t budget) { g_budget = budget; g_calls = 0; g_gave = 0; }

// Hands over at most the remaining budget. Never asks the socket for more than the budget, so
// a budget of 0 is a transport with nothing available rather than one that blocks forever.
static OSStatus sock_read(SSLConnectionRef c, void *data, size_t *len) {
    int fd = *(const int *)c;
    size_t want = *len;
    size_t take = (g_budget == UNLIMITED || want < g_budget) ? want : g_budget;
    size_t got = 0;
    g_calls++;
    while (got < take) {
        ssize_t n = read(fd, (char *)data + got, take - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    if (g_budget != UNLIMITED) g_budget -= got;
    g_gave += got;
    *len = got;
    return got == want ? noErr : errSSLWouldBlock;
}

static OSStatus sock_write(SSLConnectionRef c, const void *data, size_t *len) {
    int fd = *(const int *)c;
    size_t want = *len, put = 0;
    while (put < want) {
        ssize_t n = write(fd, (const char *)data + put, want - put);
        if (n <= 0) break;
        put += (size_t)n;
    }
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

static SSLContextRef g_ctx;

// How much of the ask was satisfied, as the contract sees it. Whether a read came back short,
// full, or empty is the answer being measured; the exact byte count of a short one is however
// much of the response had arrived from the network at that instant, and case 1 below reads a
// live one, so that number differs from run to run on the same stack. selftest.sh compares
// this word and drops the count.
static const char *fill(size_t processed, size_t asked) {
    if (processed == 0)     return "none";
    if (processed >= asked) return "full";
    return "short";
}

static void report(const char *what, OSStatus st, size_t processed, size_t asked) {
    size_t buffered = 0;
    SSLGetBufferedReadSize(g_ctx, &buffered);
    printf("  %-32s st=%-20s processed=%-6lu of %-6lu %-5s cb_calls=%d buffered=%s\n",
           what, stname(st), (unsigned long)processed, (unsigned long)asked,
           fill(processed, asked), g_calls, buffered ? "yes" : "no");
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
    // A read that never returns would hang the probe rather than report anything, so the
    // socket gives up after a while and the callback reports the short count as a would-block.
    struct timeval rcvto = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof rcvto);

    SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    g_ctx = ctx;
    SSLSetIOFuncs(ctx, sock_read, sock_write);
    SSLSetConnection(ctx, &fd);
    SSLSetPeerDomainName(ctx, host, strlen(host));
    OSStatus st;
    reset(UNLIMITED);
    while ((st = SSLHandshake(ctx)) == errSSLWouldBlock) ;
    if (st != noErr) { printf("FAIL: handshake %d\n", (int)st); return 1; }

    // A POST whose echoed response is far larger than one TLS record, so there is always more
    // to come and the cases below are about what SSLRead chooses to report, not about the
    // response running out.
    size_t bodyLen = 64 * 1024;
    char *body = (char *)malloc(bodyLen + 1024);
    int hl = snprintf(body, 1024,
        "POST /post HTTP/1.1\r\nHost: %s\r\nContent-Type: application/octet-stream\r\n"
        "Content-Length: %lu\r\n\r\n", host, (unsigned long)bodyLen);
    memset(body + hl, 'A', bodyLen);
    // A blocked write reports the whole buffer as taken and holds the remainder, so advancing
    // by *processed can leave data still queued inside. Zero-length writes flush it; without
    // them the request is short and the response never comes.
    size_t n = 0;
    for (size_t off = 0; off < (size_t)hl + bodyLen; ) {
        st = SSLWrite(ctx, body + off, (size_t)hl + bodyLen - off, &n);
        off += n;
        if (st != noErr && st != errSSLWouldBlock) break;
    }
    while ((st = SSLWrite(ctx, body, 0, &n)) == errSSLWouldBlock) ;
    free(body);

    char *buf = (char *)malloc(1 << 20);

    printf("case 1: ask for far more than one record, transport free\n");
    reset(UNLIMITED);
    n = 0;
    st = SSLRead(ctx, buf, 1 << 20, &n);
    report("big ask, data available", st, n, 1 << 20);

    printf("case 2: ask for less than is buffered, then again from the buffer\n");
    reset(UNLIMITED);
    n = 0;
    st = SSLRead(ctx, buf, 100, &n);
    report("small ask", st, n, 100);
    reset(0);                                  // transport now offers nothing
    n = 0;
    st = SSLRead(ctx, buf, 100, &n);
    report("again, transport starved", st, n, 100);

    printf("case 3: transport has nothing at all\n");
    // Drain whatever is already buffered first, so this is really about an empty transport.
    reset(0);
    do { n = 0; st = SSLRead(ctx, buf, 1 << 20, &n); } while (n > 0);
    reset(0);
    n = 0;
    st = SSLRead(ctx, buf, 1000, &n);
    report("nothing available", st, n, 1000);

    printf("case 4: zero-length read\n");
    reset(0);
    n = 0;
    st = SSLRead(ctx, buf, 0, &n);
    report("zero length", st, n, 0);

    SSLClose(ctx);
    CFRelease(ctx);
    close(fd);
    free(buf);
    return 0;
}
