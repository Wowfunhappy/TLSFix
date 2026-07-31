// macOS hook layer for TLSFix (10.6 - 10.9).
//
// Injection is via DYLD_INSERT_LIBRARIES, so hooks are installed with dyld
// interposing rather than MSHookFunction. Two consequences differ from the iOS build:
//
//   1. Interposing rebinds call sites instead of patching function bodies, so the
//      "function too small, clobbers adjacent memory" problem does not exist and
//      SSLClose/SSLDisposeContext are safe to hook.
//   2. Interposing is applied by dyld at load time and cannot be declined, so the
//      kill switch and deny list are a runtime gate (tf_on) checked by every hook,
//      which falls through to the original when off.
//
// Inside an interposing image, calling the original *by name* reaches the real
// function -- dyld does not interpose calls made from the interposing image itself.
// Do NOT use dlsym(RTLD_NEXT, ...) here: it resolves back to the replacement and
// recurses until the process dies.

#include "../tlsfix.h"
#include "tlsfix_config.h"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

#define DYLD_INTERPOSE(_repl, _orig)                                              \
    __attribute__((used)) static struct { const void *repl; const void *orig; }   \
    _interpose_##_orig __attribute__((section("__DATA,__interpose"))) = {         \
        (const void *)(unsigned long)&_repl, (const void *)(unsigned long)&_orig  \
    };

// Processes where injecting would recurse or destabilise the system.
// ocspd performs the revocation fetches that SecTrustEvaluate triggers, and
// securityd backs the keychain that SecTrustEvaluate queries, so both would
// re-enter our verify path. ReportCrash is excluded so a fault here cannot
// amplify into a crash-reporting loop.
static const char *kDeny[] = {
    "ocspd", "securityd", "securityd_service", "trustd", "launchd",
    "ReportCrash", "kextd", "notifyd", "configd", "opendirectoryd",
    "DirectoryService", "syslogd", "distnoted", "mds", "mdworker", 0
};

static int g_on = 0;
static pthread_once_t g_gate = PTHREAD_ONCE_INIT;

static void gate_init(void) {
    const char *pn = getprogname();
    if (pn) for (int i = 0; kDeny[i]; i++) if (!strcmp(pn, kDeny[i])) { g_on = 0; return; }
    if (tf_flag("disabled") || tf_flag("disabled-tls")) { g_on = 0; return; }
    g_on = 1;
}

// Runtime gate. Lazily evaluated rather than set from the constructor because another
// inserted library's initialiser could reach a hook before ours has run.
static inline int tf_on(void) { pthread_once(&g_gate, gate_init); return g_on; }

// The URL rewriter lives in a separate Foundation-linked bundle. It is loaded only where
// Foundation is already present, so daemons and command-line tools never pull Foundation
// in on our account. dlopen failure is ignored on purpose: the TLS engine has to keep
// working even when rewriting cannot load, and unlike a failed dyld insertion (fatal to
// every process launch) a failed dlopen costs nothing.
//
// This registers as early as possible so no request escapes unrewritten. Deferring to the
// main queue would be gentler on initialiser ordering but risks missing the first request
// in tools that never spin a run loop.
__attribute__((constructor))
static void tlsfix_init(void) {
    if (!tf_on()) return;
    if (tf_flag("disabled-rewrite")) return;

    // Probe for Foundation with a plain C symbol. Objective-C class symbols are not
    // usable here: x86_64 uses the modern ABI (_OBJC_CLASS_$_NSURLProtocol) while i386
    // uses the legacy runtime (.objc_class_name_NSURLProtocol), so a class-symbol probe
    // silently fails on every 32-bit process. NSLog is spelled the same in both.
    if (!dlsym(RTLD_DEFAULT, "NSLog")) return;

    char p[1024];
    snprintf(p, sizeof p, "%s/rewrite.bundle/Contents/MacOS/rewrite", tf_dir());
    if (!dlopen(p, RTLD_LAZY | RTLD_LOCAL) && tf_flag("debug")) {
        const char *e = dlerror();
        FILE *f = fopen("/tmp/tlsfix.log", "a");
        if (f) { fprintf(f, "[%s] rewrite bundle load failed: %s\n", getprogname(), e ? e : "?"); fclose(f); }
    }
}

static OSStatus my_SSLSetIOFuncs(SSLContextRef c, SSLReadFunc rf, SSLWriteFunc wf) {
    if (!tf_on() || ensure_ready() != 1) return SSLSetIOFuncs(c, rf, wf);
    OSStatus r = SSLSetIOFuncs(c, rf, wf);
    Shadow *s = sh_create(c);
    if (s) { s->rf = rf; s->wf = wf; sh_release(s); }
    return r;
}
DYLD_INTERPOSE(my_SSLSetIOFuncs, SSLSetIOFuncs)

static OSStatus my_SSLSetConnection(SSLContextRef c, SSLConnectionRef conn) {
    if (!tf_on() || ensure_ready() != 1) return SSLSetConnection(c, conn);
    OSStatus r = SSLSetConnection(c, conn);
    Shadow *s = sh_create(c);
    if (s) { s->conn = conn; sh_release(s); }
    return r;
}
DYLD_INTERPOSE(my_SSLSetConnection, SSLSetConnection)

static OSStatus my_SSLSetPeerDomainName(SSLContextRef c, const char *name, size_t len) {
    if (!tf_on() || ensure_ready() != 1) return SSLSetPeerDomainName(c, name, len);
    OSStatus r = SSLSetPeerDomainName(c, name, len);
    Shadow *s = sh_create(c);
    if (s) {
        if (name && len) {
            size_t n = len < 255 ? len : 255; memcpy(s->host, name, n); s->host[n] = 0;
            if (s->inited && s->state != -1) { SSL_free(s->ssl); s->ssl = NULL; s->inited = 0; s->state = 0; } // late SNI -> re-init
        }
        sh_release(s);
    }
    return r;
}
DYLD_INTERPOSE(my_SSLSetPeerDomainName, SSLSetPeerDomainName)

static OSStatus my_SSLSetSessionOption(SSLContextRef c, SSLSessionOption opt, Boolean val) {
    if (tf_on() && ensure_ready() == 1 && opt == kSSLSessionOptionBreakOnServerAuth) {
        Shadow *s = sh_create(c);
        if (s) { s->breakAuth = val ? 1 : 0; sh_release(s); }
    }
    return SSLSetSessionOption(c, opt, val);
}
DYLD_INTERPOSE(my_SSLSetSessionOption, SSLSetSessionOption)

static OSStatus my_SSLHandshake(SSLContextRef c) {
    if (!tf_on()) return SSLHandshake(c);
    Shadow *s = sh_get(c);
    if (!s) return SSLHandshake(c);
    OSStatus rv;
    if (!s->rf || !s->wf || !s->conn || s->clientBypass || s->state == -1) { rv = SSLHandshake(c); goto done; }
    if (!s->inited) { if (ossl_init(s)) { s->state = -1; rv = SSLHandshake(c); goto done; } s->state = 1; }
    if (s->state == 3) s->approved = 1;   // app approved the server after the auth break, let it proceed
    int ret = SSL_do_handshake(s->ssl);
    if (ret == 1) {
        if (tf_debug())
            tf_log("handshake ok  host=%s proto=%s cipher=%s%s",
                   s->host[0] ? s->host : "(none)",
                   SSL_get_version(s->ssl), SSL_get_cipher(s->ssl),
                   s->breakAuth ? " [app-verified]" : "");
        // server-auth-only pinning has no client-cert pause point, so ask the app here (once) before connecting
        if (s->breakAuth && !s->approved) { s->state = 3; rv = ST_PeerAuth; goto done; }
        s->state = 2; rv = noErr; goto done;
    }
    int e = SSL_get_error(s->ssl, ret);
    // mutual TLS + pinning: cert_cb suspended us before sending our cert -> hand the server cert to the app
    if (e == SSL_ERROR_WANT_X509_LOOKUP) { s->state = 3; rv = ST_PeerAuth; goto done; }
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) rv = errSSLWouldBlock;
    else {
        tf_log("handshake FAILED host=%s ssl_err=%d", s->host[0] ? s->host : "(none)", e);
        s->state = -1; rv = ST_ClosedAbort;
    }
done:
    sh_release(s);
    return rv;
}
DYLD_INTERPOSE(my_SSLHandshake, SSLHandshake)

static OSStatus my_SSLRead(SSLContextRef c, void *data, size_t len, size_t *processed) {
    if (!tf_on()) return SSLRead(c, data, len, processed);
    Shadow *s = sh_get(c);
    if (!s || s->state != 2) { OSStatus r = SSLRead(c, data, len, processed); sh_release(s); return r; }
    *processed = 0;
    int n = SSL_read(s->ssl, data, (int)len);
    OSStatus rv;
    if (n > 0) { *processed = (size_t)n; rv = noErr; }
    else {
        int e = SSL_get_error(s->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) rv = errSSLWouldBlock;
        else if (e == SSL_ERROR_ZERO_RETURN) rv = ST_ClosedGraceful;
        else rv = ST_ClosedAbort;
    }
    sh_release(s);
    return rv;
}
DYLD_INTERPOSE(my_SSLRead, SSLRead)

static OSStatus my_SSLWrite(SSLContextRef c, const void *data, size_t len, size_t *processed) {
    if (!tf_on()) return SSLWrite(c, data, len, processed);
    Shadow *s = sh_get(c);
    if (!s || s->state != 2) { OSStatus r = SSLWrite(c, data, len, processed); sh_release(s); return r; }
    *processed = 0;
    int n = SSL_write(s->ssl, data, (int)len);
    OSStatus rv;
    if (n > 0) { *processed = (size_t)n; rv = noErr; }
    else {
        int e = SSL_get_error(s->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) rv = errSSLWouldBlock;
        else rv = ST_ClosedAbort;
    }
    sh_release(s);
    return rv;
}
DYLD_INTERPOSE(my_SSLWrite, SSLWrite)

static OSStatus my_SSLClose(SSLContextRef c) {
    if (!tf_on()) return SSLClose(c);
    Shadow *s = sh_get(c);
    if (s && s->state == 2 && s->ssl) SSL_shutdown(s->ssl);
    sh_release(s);
    OSStatus r = SSLClose(c);
    sh_free(c);
    return r;
}
DYLD_INTERPOSE(my_SSLClose, SSLClose)

static OSStatus my_SSLGetSessionState(SSLContextRef c, SSLSessionState *st) {
    if (!tf_on()) return SSLGetSessionState(c, st);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (s && s->state == 2) { if (st) *st = ST_Connected; rv = noErr; }
    else rv = SSLGetSessionState(c, st);
    sh_release(s);
    return rv;
}
DYLD_INTERPOSE(my_SSLGetSessionState, SSLGetSessionState)

// Report a protocol/cipher from the era the caller understands. On 10.6/10.7 the
// kTLSProtocol11/12 enum values do not exist at all, so kTLSProtocol1 (4) and
// 0x002F are the only pair safe across the whole 10.6-10.9 range. The connection
// underneath is whatever LibreSSL actually negotiated.
static OSStatus my_SSLGetNegotiatedProtocolVersion(SSLContextRef c, SSLProtocol *p) {
    if (!tf_on()) return SSLGetNegotiatedProtocolVersion(c, p);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (s && (s->state == 2 || s->state == 3)) { if (p) *p = kTLSProtocol1; rv = noErr; }
    else rv = SSLGetNegotiatedProtocolVersion(c, p);
    sh_release(s);
    return rv;
}
DYLD_INTERPOSE(my_SSLGetNegotiatedProtocolVersion, SSLGetNegotiatedProtocolVersion)

static OSStatus my_SSLGetNegotiatedCipher(SSLContextRef c, SSLCipherSuite *cipher) {
    if (!tf_on()) return SSLGetNegotiatedCipher(c, cipher);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (s && (s->state == 2 || s->state == 3)) {
        if (cipher) *cipher = 0x002F; // TLS_RSA_WITH_AES_128_CBC_SHA
        rv = noErr;
    }
    else rv = SSLGetNegotiatedCipher(c, cipher);
    sh_release(s);
    return rv;
}
DYLD_INTERPOSE(my_SSLGetNegotiatedCipher, SSLGetNegotiatedCipher)

static OSStatus my_SSLGetBufferedReadSize(SSLContextRef c, size_t *sz) {
    if (!tf_on()) return SSLGetBufferedReadSize(c, sz);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (s && s->state == 2) { if (sz) *sz = (size_t)SSL_pending(s->ssl); rv = noErr; }
    else rv = SSLGetBufferedReadSize(c, sz);
    sh_release(s);
    return rv;
}
DYLD_INTERPOSE(my_SSLGetBufferedReadSize, SSLGetBufferedReadSize)

static OSStatus my_SSLCopyPeerTrust(SSLContextRef c, SecTrustRef *trust) {
    if (!tf_on()) return SSLCopyPeerTrust(c, trust);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (!s || (s->state != 2 && s->state != 3) || !trust) rv = SSLCopyPeerTrust(c, trust);
    else if (sh_build_trust(s, trust)) rv = noErr;
    else rv = SSLCopyPeerTrust(c, trust);
    sh_release(s);
    return rv;
}
DYLD_INTERPOSE(my_SSLCopyPeerTrust, SSLCopyPeerTrust)

static OSStatus my_SSLCopyPeerCertificates(SSLContextRef c, CFArrayRef *certs) {
    if (!tf_on()) return SSLCopyPeerCertificates(c, certs);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (!s || (s->state != 2 && s->state != 3) || !certs) rv = SSLCopyPeerCertificates(c, certs);
    else { CFArrayRef arr = sh_cert_array(s); if (!arr) rv = SSLCopyPeerCertificates(c, certs); else { *certs = arr; rv = noErr; } }
    sh_release(s);
    return rv;
}
DYLD_INTERPOSE(my_SSLCopyPeerCertificates, SSLCopyPeerCertificates)

static OSStatus my_SSLSetCertificate(SSLContextRef c, CFArrayRef certRefs) {
    if (!tf_on() || ensure_ready() != 1) return SSLSetCertificate(c, certRefs);
    Shadow *s = sh_create(c);
    if (s) {
        // disabled-mtls hands client-certificate connections back to the system stack.
        // Escape hatch for servers that demand RSA-PSS, which the SecKeyRawSign path
        // cannot produce and LibreSSL gives us no way to avoid advertising.
        if (tf_flag("disabled-mtls")) s->clientBypass = 1;
        else capture_identity(s, certRefs);
        if (s->inited && s->state != -1) { SSL_free(s->ssl); s->ssl = NULL; s->inited = 0; s->state = 0; }
        sh_release(s);
    }
    return SSLSetCertificate(c, certRefs);
}
DYLD_INTERPOSE(my_SSLSetCertificate, SSLSetCertificate)
