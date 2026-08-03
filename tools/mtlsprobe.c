// mtlsprobe -- a Secure Transport client that presents a client certificate.
//
// This is the shape of a real mTLS app: import a .p12, hand the identity to
// SSLSetCertificate, handshake. Run it once bare and once under
// DYLD_INSERT_LIBRARIES=aquatransport.dylib to compare the stock stack against the engine.
//
// kSSLSessionOptionBreakOnServerAuth is set because that is what CFNetwork does on nearly
// every connection, and because the test CA is not in the system trust store. It also puts
// the interesting path under test: with the break set, the engine must suspend before
// sending the client certificate, hand the server chain to us, and only then continue.
// errSSLPeerAuthCompleted (-9841) is that pause; calling SSLHandshake again resumes.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
//       -o mtlsprobe tools/mtlsprobe.c -framework Security -framework CoreFoundation
//
//   ./mtlsprobe 127.0.0.1 4443 client.p12 test123

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static OSStatus sock_read(SSLConnectionRef c, void *data, size_t *len) {
    int fd = (int)(long)c; size_t want = *len, got = 0;
    while (got < want) {
        ssize_t n = read(fd, (char *)data + got, want - got);
        if (n > 0) { got += n; continue; }
        *len = got;
        return n == 0 ? errSSLClosedGraceful : errSSLWouldBlock;
    }
    *len = got;
    return noErr;
}
static OSStatus sock_write(SSLConnectionRef c, const void *data, size_t *len) {
    int fd = (int)(long)c; size_t want = *len, put = 0;
    while (put < want) {
        ssize_t n = write(fd, (const char *)data + put, want - put);
        if (n > 0) { put += n; continue; }
        *len = put;
        return errSSLWouldBlock;
    }
    *len = put;
    return noErr;
}

// Import into a scratch keychain so the user's own keychain is never touched.
static SecIdentityRef load_identity(const char *p12path, const char *pass, SecKeychainRef *out_kc) {
    char kcpath[1024];
    snprintf(kcpath, sizeof(kcpath), "/tmp/aqmtls-%d.keychain", (int)getpid());
    unlink(kcpath);
    SecKeychainRef kc = NULL;
    if (SecKeychainCreate(kcpath, (UInt32)strlen("test"), "test", false, NULL, &kc) != errSecSuccess) {
        fprintf(stderr, "could not create scratch keychain\n");
        return NULL;
    }
    *out_kc = kc;

    CFDataRef blob = NULL;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)p12path,
                                                          (CFIndex)strlen(p12path), false);
    SInt32 err = 0;
    CFURLCreateDataAndPropertiesFromResource(NULL, url, &blob, NULL, NULL, &err);
    CFRelease(url);
    if (!blob) { fprintf(stderr, "could not read %s\n", p12path); return NULL; }

    CFStringRef pw = CFStringCreateWithCString(NULL, pass, kCFStringEncodingUTF8);
    const void *k[] = { kSecImportExportPassphrase, kSecImportExportKeychain };
    const void *v[] = { pw, kc };
    CFDictionaryRef opts = CFDictionaryCreate(NULL, k, v, 2, &kCFTypeDictionaryKeyCallBacks,
                                              &kCFTypeDictionaryValueCallBacks);
    CFArrayRef items = NULL;
    OSStatus st = SecPKCS12Import(blob, opts, &items);
    CFRelease(opts); CFRelease(pw); CFRelease(blob);
    if (st != errSecSuccess || !items || CFArrayGetCount(items) < 1) {
        fprintf(stderr, "SecPKCS12Import failed: %d\n", (int)st);
        return NULL;
    }
    CFDictionaryRef item = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef ident = (SecIdentityRef)CFDictionaryGetValue(item, kSecImportItemIdentity);
    if (ident) CFRetain(ident);
    CFRelease(items);
    return ident;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: mtlsprobe <host> <port> <p12> <password>\n"); return 2; }
    const char *host = argv[1];
    int port = atoi(argv[2]);

    // "none" as the p12 path skips SSLSetCertificate entirely, which is the control case:
    // same probe, same server, no client identity in play.
    int use_cert = strcmp(argv[3], "none") != 0;
    SecKeychainSetUserInteractionAllowed(false);   // never prompt; fail instead
    SecKeychainRef kc = NULL;
    SecIdentityRef ident = NULL;
    if (use_cert) {
        ident = load_identity(argv[3], argv[4], &kc);
        if (!ident) return 2;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    sa.sin_addr.s_addr = inet_addr(host);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { perror("connect"); return 2; }
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    SSLContextRef ctx = NULL;
    SSLNewContext(false, &ctx);
    SSLSetIOFuncs(ctx, sock_read, sock_write);
    SSLSetConnection(ctx, (SSLConnectionRef)(long)fd);
    SSLSetPeerDomainName(ctx, "localhost", strlen("localhost"));
    SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);

    OSStatus st = noErr;
    if (use_cert) {
        CFArrayRef certs = CFArrayCreate(NULL, (const void **)&ident, 1, &kCFTypeArrayCallBacks);
        st = SSLSetCertificate(ctx, certs);
        if (st != errSecSuccess) fprintf(stderr, "SSLSetCertificate: %d\n", (int)st);
    }

    int breaks = 0;
    do {
        st = SSLHandshake(ctx);
        if (st == errSSLPeerAuthCompleted) {   // -9841: server cert is ours to judge
            breaks++;
            SSLProtocol p = 0; SSLGetNegotiatedProtocolVersion(ctx, &p);
            printf("  server auth break (app would verify the chain here)\n");
        }
    } while ((st == errSSLPeerAuthCompleted || st == errSSLWouldBlock) && breaks < 8);

    if (st != noErr) {
        printf("HANDSHAKE FAILED: OSStatus %d\n", (int)st);
        goto out;
    }
    SSLProtocol proto = 0;
    SSLCipherSuite cs = 0;
    SSLGetNegotiatedProtocolVersion(ctx, &proto);
    SSLGetNegotiatedCipher(ctx, &cs);
    printf("HANDSHAKE OK (protocol=0x%x cipher=0x%04x)\n", (unsigned)proto, (unsigned)cs);

    const char *req = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    size_t n = 0;
    SSLWrite(ctx, req, strlen(req), &n);
    char buf[512];
    size_t got = 0;
    if (SSLRead(ctx, buf, sizeof(buf) - 1, &got) == noErr && got > 0) {
        buf[got] = 0;
        char *nl = strchr(buf, '\n');
        if (nl) *nl = 0;
        printf("server said: %s\n", buf);
    }
out:
    SSLClose(ctx);
    SSLDisposeContext(ctx);
    close(fd);
    if (kc) { SecKeychainDelete(kc); CFRelease(kc); }
    return st == noErr ? 0 : 1;
}
