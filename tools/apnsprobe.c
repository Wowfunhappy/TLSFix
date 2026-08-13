// Reproduces the trust evaluation apsd does on its courier connection: handshake with
// kSSLSessionOptionBreakOnServerAuth, then evaluate the peer trust the way a pinning client
// does -- against a fixed anchor set, anchors-only.
//
// Built twice under different names. The engine's deny list keys off getprogname(), so a copy
// named "trustd" runs unhooked and is the control the hooked copy is diffed against.
//
//   apnsprobe <host> <port> [anchors.pem]
//
// cc -o apnsprobe apnsprobe.c -framework Security -framework CoreFoundation

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static OSStatus sockRead(SSLConnectionRef c, void *data, size_t *len) {
    int fd = (int)(long)c; size_t want = *len, got = 0;
    while (got < want) {
        ssize_t n = read(fd, (char *)data + got, want - got);
        if (n > 0) { got += (size_t)n; continue; }
        *len = got;
        return n == 0 ? errSSLClosedGraceful : errSSLClosedAbort;
    }
    *len = got;
    return noErr;
}

static OSStatus sockWrite(SSLConnectionRef c, const void *data, size_t *len) {
    int fd = (int)(long)c; size_t want = *len, put = 0;
    while (put < want) {
        ssize_t n = write(fd, (const char *)data + put, want - put);
        if (n > 0) { put += (size_t)n; continue; }
        *len = put;
        return errSSLClosedAbort;
    }
    *len = put;
    return noErr;
}

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) || !res) return -1;
    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        if (!connect(fd, a->ai_addr, a->ai_addrlen)) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void print_cert(int i, SecCertificateRef c) {
    CFDataRef d = SecCertificateCopyData(c);
    unsigned char dg[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(CFDataGetBytePtr(d), (CC_LONG)CFDataGetLength(d), dg);
    char hex[2 * CC_SHA256_DIGEST_LENGTH + 1];
    for (int k = 0; k < CC_SHA256_DIGEST_LENGTH; k++) sprintf(hex + 2 * k, "%02x", dg[k]);
    CFStringRef sum = SecCertificateCopySubjectSummary(c);
    char name[256] = "?";
    if (sum) { CFStringGetCString(sum, name, sizeof name, kCFStringEncodingUTF8); CFRelease(sum); }
    printf("  cert[%d] len=%5ld sha256=%.16s... subject=%s\n", i, (long)CFDataGetLength(d), hex, name);
    CFRelease(d);
}

// Certificates from a PEM bundle, used as the pinned anchor set.
static CFArrayRef load_anchors(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    CFMutableArrayRef out = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    char line[512];
    char b64[65536]; size_t b64n = 0; int in = 0;
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, "BEGIN CERTIFICATE")) { in = 1; b64n = 0; continue; }
        if (strstr(line, "END CERTIFICATE")) {
            in = 0;
            CFDataRef raw = CFDataCreate(NULL, (const UInt8 *)b64, (CFIndex)b64n);
            CFErrorRef err = NULL;
            CFDataRef der = NULL;
            SecTransformRef t = SecDecodeTransformCreate(kSecBase64Encoding, &err);
            if (t) {
                SecTransformSetAttribute(t, kSecTransformInputAttributeName, raw, &err);
                der = (CFDataRef)SecTransformExecute(t, &err);
                CFRelease(t);
            }
            if (der) {
                SecCertificateRef c = SecCertificateCreateWithData(NULL, der);
                if (c) { CFArrayAppendValue(out, c); CFRelease(c); }
                CFRelease(der);
            }
            CFRelease(raw);
            continue;
        }
        if (in) {
            size_t l = strlen(line);
            while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) l--;
            if (b64n + l < sizeof b64) { memcpy(b64 + b64n, line, l); b64n += l; }
        }
    }
    fclose(f);
    return out;
}

static void evaluate(const char *label, SecTrustRef trust, CFArrayRef anchors) {
    if (anchors) {
        SecTrustSetAnchorCertificates(trust, anchors);
        SecTrustSetAnchorCertificatesOnly(trust, true);
    }
    SecTrustResultType r = kSecTrustResultInvalid;
    OSStatus st = SecTrustEvaluate(trust, &r);
    printf("  evaluate[%s]: status=%d result=%d\n", label, (int)st, (int)r);
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "courier.push.apple.com";
    const char *port = argc > 2 ? argv[2] : "5223";
    const char *anchorPath = argc > 3 ? argv[3] : NULL;

    printf("progname=%s host=%s port=%s\n", getprogname(), host, port);

    int fd = tcp_connect(host, port);
    if (fd < 0) { printf("connect failed\n"); return 1; }

    SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    SSLSetIOFuncs(ctx, sockRead, sockWrite);
    SSLSetConnection(ctx, (SSLConnectionRef)(long)fd);
    SSLSetPeerDomainName(ctx, host, strlen(host));
    SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);

    OSStatus h;
    do { h = SSLHandshake(ctx); } while (h == errSSLWouldBlock);
    printf("handshake -> %d %s\n", (int)h, h == errSSLPeerAuthCompleted ? "(peer auth break)" : "");

    if (h != errSSLPeerAuthCompleted && h != noErr) { close(fd); return 2; }

    SSLProtocol proto = 0; SSLCipherSuite suite = 0;
    SSLGetNegotiatedProtocolVersion(ctx, &proto);
    SSLGetNegotiatedCipher(ctx, &suite);
    printf("negotiated protocol=%d cipher=0x%04x\n", (int)proto, (unsigned)suite);

    // The wire chain, before any evaluation has had a chance to complete it from the trust
    // store. This is what a caller inspecting the peer's certificates sees.
    CFArrayRef peer = NULL;
    if (SSLCopyPeerCertificates(ctx, &peer) == errSecSuccess && peer) {
        printf("SSLCopyPeerCertificates count=%ld\n", (long)CFArrayGetCount(peer));
        for (CFIndex i = 0; i < CFArrayGetCount(peer); i++)
            print_cert((int)i, (SecCertificateRef)CFArrayGetValueAtIndex(peer, i));
        CFRelease(peer);
    }

    SecTrustRef trust = NULL;
    OSStatus ct = SSLCopyPeerTrust(ctx, &trust);
    printf("SSLCopyPeerTrust -> %d\n", (int)ct);
    if (trust) {
        CFIndex n = SecTrustGetCertificateCount(trust);
        printf("chain count=%ld\n", (long)n);
        for (CFIndex i = 0; i < n; i++) print_cert((int)i, SecTrustGetCertificateAtIndex(trust, i));
        evaluate("system-roots", trust, NULL);
        CFRelease(trust);
    }

    if (anchorPath) {
        // A second, independent trust object: an evaluated SecTrustRef caches nothing, but
        // reusing one that already ran keeps its earlier anchor state out of the comparison.
        SecTrustRef t2 = NULL;
        if (SSLCopyPeerTrust(ctx, &t2) == errSecSuccess && t2) {
            CFArrayRef anchors = load_anchors(anchorPath);
            printf("anchors loaded=%ld from %s\n", anchors ? (long)CFArrayGetCount(anchors) : -1L, anchorPath);
            evaluate("pinned-anchors-only", t2, anchors);
            if (anchors) CFRelease(anchors);
            CFRelease(t2);
        }
    }

    CFRelease(ctx);
    close(fd);
    return 0;
}
