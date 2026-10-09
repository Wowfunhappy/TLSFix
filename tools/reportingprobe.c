// Exercise real Secure Transport callers against a TLS-1.3-only OpenSSL peer.
// socketpair keeps the regression independent of DNS, public servers and roots.
// See test-reporting.sh. The executable must not export its own OpenSSL symbols.
#include <Security/SecureTransport.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static OSStatus (*setmin)(SSLContextRef, SSLProtocol);
static OSStatus (*setmax)(SSLContextRef, SSLProtocol);
static OSStatus (*getmax)(SSLContextRef, SSLProtocol *);

static OSStatus rd(SSLConnectionRef c, void *buf, size_t *len) {
    size_t want = *len, got = 0;
    while (got < want) {
        ssize_t n = read(*(const int *)c, (char *)buf + got, want - got);
        if (n <= 0) { *len = got; return errSSLClosedGraceful; }
        got += (size_t)n;
    }
    return noErr;
}
static OSStatus wr(SSLConnectionRef c, const void *buf, size_t *len) {
    size_t want = *len, got = 0;
    while (got < want) {
        ssize_t n = write(*(const int *)c, (const char *)buf + got, want - got);
        if (n <= 0) { *len = got; return errSSLClosedAbort; }
        got += (size_t)n;
    }
    return noErr;
}

static void run_case(SSL_CTX *server, const char *name, int mode, int use_create) {
    SSLContextRef c = NULL;
    if (use_create) {
        SSLContextRef (*create)(CFAllocatorRef, SSLProtocolSide, SSLConnectionType) =
            dlsym(RTLD_DEFAULT, "SSLCreateContext");
        // dlsym bypasses fishhook, but the IO setters below create the shadow.
        CHECK(create != NULL);
        c = create(NULL, kSSLClientSide, kSSLStreamType);
    } else CHECK(SSLNewContext(false, &c) == noErr);
    CHECK(c != NULL);
    SSLProtocol expected = kTLSProtocol1;
    if (getmax) CHECK(getmax(c, &expected) == noErr);
    SSLCipherSuite cipher = 0x002f;
    if (mode == 1 || mode == 4) {
        CHECK(SSLSetProtocolVersion(c, kTLSProtocol1Only) == noErr);
        expected = kTLSProtocol1;
    } else if (mode == 2) {
        CHECK(SSLSetProtocolVersionEnabled(c, kSSLProtocolAll, false) == noErr);
        CHECK(SSLSetProtocolVersionEnabled(c, kTLSProtocol1, true) == noErr);
        expected = kTLSProtocol1;
    } else if (mode == 3) {
        CHECK(setmin(c, (SSLProtocol)8) == noErr);
        expected = (SSLProtocol)8;
        cipher = 0xc027;
    } else if (mode == 5) {
        CHECK(setmin(c, (SSLProtocol)7) == noErr);
        CHECK(setmax(c, (SSLProtocol)7) == noErr);
        expected = (SSLProtocol)7;
    } else if (mode == 6) {
        CHECK(SSLSetProtocolVersion(c, kSSLProtocol3Only) == noErr);
        expected = kSSLProtocol3;
        cipher = 0x000a;
    }
    // Invalid setters must leave the previous effective configuration intact.
    CHECK(SSLSetProtocolVersion(c, (SSLProtocol)999) != noErr);
    if (mode == 4) {
        const SSLCipherSuite candidates[] = { 0xc027, 0x002f };
        CHECK(SSLSetEnabledCiphers(c, candidates, 2) == noErr);
    } else CHECK(SSLSetEnabledCiphers(c, &cipher, 1) == noErr);
    CHECK(SSLSetSessionOption(c, kSSLSessionOptionBreakOnServerAuth, true) == noErr);

    int pair[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        close(pair[0]); alarm(15);
        SSL *ssl = SSL_new(server);
        CHECK(ssl && SSL_set_fd(ssl, pair[1]) == 1);
        CHECK(SSL_accept(ssl) == 1);
        CHECK(SSL_version(ssl) == TLS1_3_VERSION);
        CHECK(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(ssl)) == 0x1301);
        char ch = 0;
        CHECK(SSL_read(ssl, &ch, 1) == 1 && ch == 'Q');
        CHECK(SSL_write(ssl, "A", 1) == 1);
        SSL_free(ssl); close(pair[1]); _exit(0);
    }
    close(pair[1]); alarm(15);
    CHECK(SSLSetIOFuncs(c, rd, wr) == noErr);
    CHECK(SSLSetConnection(c, &pair[0]) == noErr);
    int paused = 0;
    OSStatus status;
    do {
        status = SSLHandshake(c);
        if (status == -9841 || status == noErr) {
            SSLProtocol reported = 0; SSLCipherSuite reported_cipher = 0;
            CHECK(SSLGetNegotiatedProtocolVersion(c, &reported) == noErr);
            CHECK(reported == expected);
            CHECK(SSLGetNegotiatedCipher(c, &reported_cipher) == noErr);
            CHECK(reported_cipher == cipher);
            if (status == -9841) {
                ++paused;
                // Native context remains idle; ensure late changes cannot change
                // the pair already presented at the authentication pause.
                CHECK(SSLSetProtocolVersion(c, kSSLProtocol3Only) == noErr);
                SSLCipherSuite late = 0x0005;
                CHECK(SSLSetEnabledCiphers(c, &late, 1) == noErr);
            }
        }
    } while (status == -9841 || status == errSSLWouldBlock);
    CHECK(status == noErr && paused == 1);
    size_t n = 0; char answer = 0;
    CHECK(SSLWrite(c, "Q", 1, &n) == noErr && n == 1);
    CHECK(SSLRead(c, &answer, 1, &n) == noErr && n == 1 && answer == 'A');
    SSLClose(c); SSLDisposeContext(c); close(pair[0]);
    int result = 0; CHECK(waitpid(child, &result, 0) == child);
    CHECK(WIFEXITED(result) && WEXITSTATUS(result) == 0);
    alarm(0);
    printf("PASS %-24s reported=%d/0x%04x wire=TLS1.3/0x1301\n", name, expected, cipher);
}

int main(int argc, char **argv) {
    CHECK(argc == 3);
    signal(SIGPIPE, SIG_IGN);
    // Startup config excludes this probe from the installed loader. Switch to
    // isolated rules before loading the exact engine under test.
    CHECK(setenv("AQUATRANSPORT_DIR", argv[2], 1) == 0);
    CHECK(dlopen(argv[1], RTLD_NOW | RTLD_LOCAL) != NULL);
    setmin = dlsym(RTLD_DEFAULT, "SSLSetProtocolVersionMin");
    setmax = dlsym(RTLD_DEFAULT, "SSLSetProtocolVersionMax");
    getmax = dlsym(RTLD_DEFAULT, "SSLGetProtocolVersionMax");

    SSL_CTX *server = SSL_CTX_new(TLS_server_method()); CHECK(server);
    CHECK(SSL_CTX_set_min_proto_version(server, TLS1_3_VERSION) == 1);
    CHECK(SSL_CTX_set_max_proto_version(server, TLS1_3_VERSION) == 1);
    CHECK(SSL_CTX_set_ciphersuites(server, "TLS_AES_128_GCM_SHA256") == 1);
    EVP_PKEY_CTX *kg = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); CHECK(kg);
    EVP_PKEY *key = NULL;
    CHECK(EVP_PKEY_keygen_init(kg) == 1);
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(kg, 2048) == 1);
    CHECK(EVP_PKEY_keygen(kg, &key) == 1); EVP_PKEY_CTX_free(kg);
    X509 *cert = X509_new(); CHECK(cert);
    CHECK(X509_set_version(cert, 2) == 1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(cert), -60));
    CHECK(X509_gmtime_adj(X509_getm_notAfter(cert), 3600));
    CHECK(X509_set_pubkey(cert, key) == 1);
    X509_NAME *subject = X509_get_subject_name(cert);
    CHECK(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                   (unsigned char *)"reporting test", -1, -1, 0) == 1);
    CHECK(X509_set_issuer_name(cert, subject) == 1);
    CHECK(X509_sign(cert, key, EVP_sha256()) > 0);
    CHECK(SSL_CTX_use_certificate(server, cert) == 1);
    CHECK(SSL_CTX_use_PrivateKey(server, key) == 1);
    X509_free(cert); EVP_PKEY_free(key);

    run_case(server, "native default", 0, 0);
    run_case(server, "legacy TLS1 only", 1, 0);
    run_case(server, "legacy enabled set", 2, 0);
    run_case(server, "legacy SSL3 only", 6, 0);
    if (setmin && setmax) {
        run_case(server, "Qt TLS1.2 minimum", 3, 1);
        run_case(server, "TLS1.1 exact", 5, 1);
        run_case(server, "skip TLS1.2-only cipher", 4, 1);
    }
    SSL_CTX_free(server);
    return 0;
}
