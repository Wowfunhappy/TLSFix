// adoptprobe -- the refusal half of context adoption.
//
// Under the connection gate a process is patched at its first connect(), which is after
// CFNetwork has already created and configured its SSLContext. Our setters never ran, so the
// engine takes the context over at the handshake (sh_adopt_into in aquatransport_hooks_mac.c).
// tools/gatetest.sh covers that working: a first HTTPS request is carried by the engine, and an
// adopted context still rejects the badssl hosts.
//
// This covers the case that must NOT work. Adoption reads the peer name out of the system
// context because that is what SNI is sent from and what the certificate is verified against,
// and a context whose name cannot be read is refused rather than taken over -- verifying
// nothing is worse than declining. That refusal is a security property with no visible
// symptom: a context adopted without a peer name would complete a handshake and look fine.
//
// Both cases configure a context, load the library afterwards, and then handshake, each in a
// fresh child so the library is absent while the setters run:
//
//   named    peer name set    -> adopted, and the engine's ClientHello goes out
//   unnamed  peer name unset  -> refused, and the system's ClientHello goes out
//
// The two are told apart from the ClientHello itself, read off a plain TCP listener: OpenSSL
// offers the supported_versions extension (0x002b), and Secure Transport on 10.6-10.9 has no
// TLS 1.3 to advertise and never sends it. No network, no log parsing, no timing.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
//       -framework Security -framework CoreFoundation -o build/adoptprobe tools/adoptprobe.c
//   ./build/adoptprobe /usr/share/aquatransport/aquatransport.dylib

#include <Security/SecureTransport.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXT_SUPPORTED_VERSIONS 0x002b
#define EXT_SERVER_NAME        0x0000

// Does this ClientHello carry `want`? Parsed rather than scanned for the byte pair, which
// occurs often enough inside 32 bytes of client random to make a search meaningless.
static int hello_has_ext(const unsigned char *b, size_t n, unsigned want) {
    size_t p = 0;
    if (n < 45 || b[0] != 0x16 || b[5] != 0x01) return 0;   // handshake record, ClientHello
    p = 9 + 2 + 32;                                          // versions + client random
    if (p >= n) return 0;
    p += 1 + b[p];                                           // session id
    if (p + 2 > n) return 0;
    p += 2 + ((b[p] << 8) | b[p + 1]);                       // cipher suites
    if (p + 1 > n) return 0;
    p += 1 + b[p];                                           // compression methods
    if (p + 2 > n) return 0;
    size_t elen = (b[p] << 8) | b[p + 1];
    p += 2;
    size_t end = p + elen < n ? p + elen : n;
    while (p + 4 <= end) {
        unsigned type = (b[p] << 8) | b[p + 1];
        size_t len = (b[p + 2] << 8) | b[p + 3];
        if (type == want) return 1;
        p += 4 + len;
    }
    return 0;
}

static OSStatus rd(SSLConnectionRef c, void *data, size_t *len) {
    int fd = (int)(long)c; size_t want = *len; size_t got = 0;
    while (got < want) {
        ssize_t r = read(fd, (char *)data + got, want - got);
        if (r <= 0) { *len = got; return r == 0 ? errSSLClosedGraceful : errSSLWouldBlock; }
        got += (size_t)r;
    }
    *len = got; return noErr;
}
static OSStatus wr(SSLConnectionRef c, const void *data, size_t *len) {
    int fd = (int)(long)c; size_t want = *len; size_t put = 0;
    while (put < want) {
        ssize_t r = write(fd, (const char *)data + put, want - put);
        if (r <= 0) { *len = put; return errSSLWouldBlock; }
        put += (size_t)r;
    }
    *len = put; return noErr;
}

// One case, in a child: configure a context, load the library, handshake. Returns a bitmask
// describing the ClientHello that reached the listener -- bit 0 the engine's supported_versions,
// bit 1 SNI -- or -1 if the case could not be run at all.
static int run_case(const char *dylib, int set_host, int lfd, unsigned short port) {
    pid_t kid = fork();
    if (kid != 0) {
        int st = 0;
        // The listener is the parent's: read the ClientHello here, whichever stack sent it.
        struct timeval tv = { 10, 0 };
        setsockopt(lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        int c = accept(lfd, NULL, NULL);
        if (c >= 0) setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        unsigned char buf[4096]; ssize_t n = 0;
        if (c >= 0) { n = read(c, buf, sizeof buf); close(c); }
        waitpid(kid, &st, 0);
        if (n <= 0) { fprintf(stderr, "  (set_host=%d accept=%d read=%zd errno=%d child=%d)\n", set_host, c, n, errno, st); return -1; }
        // bit 0: OpenSSL sent it (supported_versions).  bit 1: it carried SNI.
        return (hello_has_ext(buf, (size_t)n, EXT_SUPPORTED_VERSIONS) ? 1 : 0)
             | (hello_has_ext(buf, (size_t)n, EXT_SERVER_NAME) ? 2 : 0);
    }

    // Nothing here may hang a suite: the listener never answers, so a stack that waits for a
    // ServerHello would wait forever.
    alarm(10);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_len = sizeof a; a.sin_family = AF_INET; a.sin_port = htons(port);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) _exit(2);

    SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if (!ctx) _exit(2);

    // Everything below happens with the library absent, which is what the gate guarantees:
    // the process is frozen at connect(), so by the time it is patched these have all run.
    if (SSLSetIOFuncs(ctx, rd, wr) != noErr) _exit(2);
    if (SSLSetConnection(ctx, (SSLConnectionRef)(long)fd) != noErr) _exit(2);
    if (set_host && SSLSetPeerDomainName(ctx, "example.com", 11) != noErr) _exit(2);

    // The injection the gate performs, after the context is already built.
    if (!dlopen(dylib, RTLD_NOW | RTLD_GLOBAL)) _exit(2);

    SSLHandshake(ctx);          // fails either way against a plain listener; the bytes are the point
    _exit(0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: %s <aquatransport.dylib>\n", argv[0]); return 2; }
    const char *dylib = argv[1];

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_len = sizeof a; a.sin_family = AF_INET; a.sin_port = 0;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(lfd, (struct sockaddr *)&a, sizeof a) || listen(lfd, 4)) { perror("listen"); return 2; }
    socklen_t sl = sizeof a; getsockname(lfd, (struct sockaddr *)&a, &sl);
    unsigned short port = ntohs(a.sin_port);

    int fails = 0;

    int named = run_case(dylib, 1, lfd, port);
    if (named < 0) { printf("FAIL - the named case could not be run\n"); fails++; }
    else if (named & 1) printf("ok   - a context configured before the library loaded is adopted (SNI %s)\n",
                               (named & 2) ? "sent" : "MISSING");
    else { printf("FAIL - a named context was NOT adopted; the engine conceded a request it should carry\n"); fails++; }

    int unnamed = run_case(dylib, 0, lfd, port);
    if (unnamed < 0) { printf("FAIL - the unnamed case could not be run\n"); fails++; }
    else if (!(unnamed & 1)) printf("ok   - a context with no peer name is refused and handed to the system stack\n");
    else {
        printf("FAIL - a context with NO PEER NAME was adopted and handshaked by the engine.\n");
        printf("       ClientHello: supported_versions=yes  server_name=%s\n", (unnamed & 2) ? "yes" : "NO");
        printf("       sh_adopt_into commits s->rf/s->wf/s->conn before the peer-name check,\n");
        printf("       so returning 0 there leaves the caller's guard satisfied and the\n");
        printf("       handshake proceeds with nothing to verify the certificate against.\n");
        fails++;
    }

    close(lfd);
    printf("%s\n", fails ? "adoptprobe: FAILED" : "adoptprobe: ok");
    return fails ? 1 : 0;
}
