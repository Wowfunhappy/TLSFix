// The sizes a direct Secure Transport caller is entitled to pass: one SSLWrite far larger
// than a single TLS record, and one SSLRead into a buffer whose length does not fit in an int.
//
// SSLWrite and SSLRead take a size_t dataLength and Secure Transport documents no limit on it,
// fragmenting into records internally, so an application may hand either one a buffer of any
// size. CFNetwork never does -- it chunks at 32 KB -- so nothing reaching Secure Transport
// through it exercises this, and only a direct caller can. Mail's and other clients' socket
// code is a direct caller.
//
// Talks to an ordinary HTTPS server over a plain socket, doing the TLS through Secure
// Transport itself. Run it with and without the library inserted: both must agree.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
//       -framework CoreFoundation -framework Security -o bigbufprobe tools/bigbufprobe.c
//
//   bigbufprobe <host> [gigabytes]
//
// The buffer is allocated but only its first bytes are ever filled, so the pages behind the
// rest are never touched and the resident cost stays small.

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

static OSStatus sock_write(SSLConnectionRef c, const void *data, size_t *len) {
    int fd = *(const int *)c;
    size_t want = *len, put = 0;
    while (put < want) {
        ssize_t n = write(fd, (const char *)data + put, want - put);
        if (n > 0) { put += (size_t)n; continue; }
        *len = put;
        return errSSLWouldBlock;
    }
    *len = put;
    return noErr;
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "postman-echo.com";
    double gb = argc > 2 ? atof(argv[2]) : 3.0;
    size_t huge = (size_t)(gb * 1024.0 * 1024.0 * 1024.0);
    if (sizeof(size_t) < 8) { printf("SKIP: needs a 64-bit slice\n"); return 0; }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) || !res) { printf("FAIL: resolve\n"); return 1; }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen)) { printf("FAIL: connect\n"); return 1; }
    freeaddrinfo(res);

    SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if (!ctx) { printf("FAIL: no context\n"); return 1; }
    SSLSetIOFuncs(ctx, sock_read, sock_write);
    SSLSetConnection(ctx, &fd);
    SSLSetPeerDomainName(ctx, host, strlen(host));
    OSStatus st;
    while ((st = SSLHandshake(ctx)) == errSSLWouldBlock) ;
    if (st != noErr) { printf("FAIL: handshake %d\n", (int)st); return 1; }

    // One SSLWrite far larger than a single record, and larger than any run the engine hands
    // to its TLS library at a time, so the whole request goes out under one call from the
    // caller's point of view however many records and runs it becomes underneath.
    size_t bodyLen = 1024 * 1024;
    char *req = (char *)malloc(bodyLen + 4096);
    if (!req) { printf("SKIP: out of memory\n"); return 0; }
    int head = snprintf(req, 4096,
        "POST /post HTTP/1.1\r\nHost: %s\r\nContent-Type: application/octet-stream\r\n"
        "Content-Length: %lu\r\nConnection: close\r\n\r\n", host, (unsigned long)bodyLen);
    memset(req + head, 'A', bodyLen);
    size_t sent = 0;
    st = SSLWrite(ctx, req, (size_t)head + bodyLen, &sent);
    int wok = (st == noErr) && sent == (size_t)head + bodyLen;
    printf("SSLWrite of %lu bytes in one call: st=%d sent=%lu\n",
           (unsigned long)(head + bodyLen), (int)st, (unsigned long)sent);
    free(req);

    // A read buffer whose length does not fit in an int -- the size a caller is entitled to
    // pass, and the one a length truncated to an int would turn negative. Allocated but never
    // filled past what arrives, so the pages behind the rest are never touched.
    char *buf = (char *)malloc(huge);
    if (!buf) { printf("SKIP: could not allocate %.1f GB\n", gb); return 0; }
    size_t got = 0;
    st = SSLRead(ctx, buf, huge, &got);
    int rok = (st == noErr || st == errSSLWouldBlock || st == errSSLClosedGraceful) && got > 0;
    printf("SSLRead into a %.1f GB buffer: st=%d got=%lu  %.*s\n",
           gb, (int)st, (unsigned long)got, got > 12 ? 12 : (int)got, buf);
    int ok = wok && rok;

    SSLClose(ctx);
    CFRelease(ctx);
    close(fd);
    free(buf);
    printf(ok ? "PASS\n" : "FAIL\n");
    return ok ? 0 : 1;
}
