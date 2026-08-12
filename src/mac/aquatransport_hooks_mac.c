// macOS hook layer for AquaTransport (10.6 - 10.9).
//
// Hooks are installed with fishhook, which rebinds symbol pointers by name. Properties this
// relies on:
//
//   1. Rebinding rewrites call sites instead of patching function bodies, so the
//      "function too small, clobbers adjacent memory" problem does not arise and
//      SSLClose/SSLDisposeContext are safe to hook.
//   2. Rebinding does not require the library to be present at process launch. This library
//      arrives with Security.framework, which names it in a load command, and plenty of
//      processes reach Security through a dlopen long after CFNetwork has bound and used its
//      Secure Transport imports. Measured on 10.6.8 and 10.9.5, i386 and x86_64: an image
//      loaded at that point still rebinds CFNetwork's calls into Secure Transport, after
//      those symbols have already been bound and used.
//   3. install_ssl_hooks() decides per process whether to install anything, so a process on
//      the trust-daemon deny list carries no hooks at all. The per-hook tf_on() gate still
//      runs on every call, because tf_reentrant() is dynamic and cannot be decided at install
//      time.
//
// CALLING THE ORIGINAL -- READ THIS BEFORE EDITING
//
// Never call a hooked function by name from this file. fishhook rebinds the symbol in
// EVERY loaded image, including this one, so `SSLHandshake(c)` here would land back in
// my_SSLHandshake and recurse until the process dies. Always call through o_SSLHandshake.
// For the same reason, never use dlsym(RTLD_NEXT, ...) to reach an original: it resolves
// back to the replacement.
//
// The o_* pointers come from dlsym(RTLD_DEFAULT), not from fishhook's `replaced` output.
// That is deliberate. fishhook reports whatever value was sitting in the symbol slot, and
// for a lazy symbol that has not been called yet that value is dyld's stub binder helper,
// not the function. dlsym resolves through the symbol table and always yields the real
// implementation, whether or not the symbol has ever been bound.

#include "../aquatransport.h"
#include "aquatransport_config.h"
#include "../../deps/fishhook/fishhook.h"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
// The trust infrastructure itself. This is not a list of things that happen to break --
// it is a circular dependency: our verify path calls SecTrustEvaluate, which these
// processes implement. Routing their own traffic through that check would make trust
// evaluation depend on trust evaluation. tf_reentrant() in the engine guards the
// same-thread case; these are the processes where the cycle spans a process boundary.
//
// Nothing else is listed. If any other process misbehaves with the library loaded, that is a
// bug in the engine to fix, not a name to add here.
static const char *kDeny[] = {
    "ocspd", "securityd", "securityd_service", "trustd", 0
};

// Whether this process may be touched at all: every process except the trust daemons on the
// deny list, whose own traffic routing through our verify path would be a cycle.
static int process_eligible(void) {
    const char *pn = getprogname();
    if (pn) for (int i = 0; kDeny[i]; i++) if (!strcmp(pn, kDeny[i])) return 0;
    return 1;
}

static int g_on = 0;
static pthread_once_t g_gate = PTHREAD_ONCE_INIT;

static int origs_ready(void);

static void gate_init(void) { g_on = process_eligible(); }

// Runtime gate. Lazily evaluated rather than set from the constructor because another
// inserted library's initialiser could reach a hook before ours has run. Also off while
// we are inside our own Security calls, so a revocation fetch triggered by our trust
// evaluation goes out over the system stack instead of recursing into us.
// Also the point at which the original entry points are resolved, which is why every hook
// calls it before touching an o_* pointer: the hooks are installed unconditionally, possibly
// long before Security.framework is loaded, so resolution cannot happen at install time.
static inline int tf_on(void) {
    pthread_once(&g_gate, gate_init);
    if (!origs_ready()) return 0;      // fall through to the stub, which reports an error
    return g_on && !tf_reentrant();
}

// The real Secure Transport entry points. Resolved before any rebinding; see the header
// comment for why these exist and why they are not fishhook's `replaced` output.
static OSStatus (*o_SSLSetIOFuncs)(SSLContextRef, SSLReadFunc, SSLWriteFunc);
static OSStatus (*o_SSLSetConnection)(SSLContextRef, SSLConnectionRef);
static OSStatus (*o_SSLSetPeerDomainName)(SSLContextRef, const char *, size_t);
static OSStatus (*o_SSLSetPeerID)(SSLContextRef, const void *, size_t);
static OSStatus (*o_SSLSetSessionOption)(SSLContextRef, SSLSessionOption, Boolean);
static OSStatus (*o_SSLHandshake)(SSLContextRef);
static OSStatus (*o_SSLRead)(SSLContextRef, void *, size_t, size_t *);
static OSStatus (*o_SSLWrite)(SSLContextRef, const void *, size_t, size_t *);
static OSStatus (*o_SSLClose)(SSLContextRef);
static OSStatus (*o_SSLDisposeContext)(SSLContextRef);
static OSStatus (*o_SSLGetSessionState)(SSLContextRef, SSLSessionState *);
static OSStatus (*o_SSLGetNegotiatedProtocolVersion)(SSLContextRef, SSLProtocol *);
static OSStatus (*o_SSLGetNegotiatedCipher)(SSLContextRef, SSLCipherSuite *);
static OSStatus (*o_SSLGetBufferedReadSize)(SSLContextRef, size_t *);
static OSStatus (*o_SSLCopyPeerTrust)(SSLContextRef, SecTrustRef *);
static OSStatus (*o_SSLCopyPeerCertificates)(SSLContextRef, CFArrayRef *);
static OSStatus (*o_SSLSetCertificate)(SSLContextRef, CFArrayRef);

// Installs the URL rewriter's CFNetwork hooks. Pure C -- see src/mac/aquatransport_rewrite.c for
// why it rebinds CFNetwork's C API by name. Safe in every process and installed unconditionally:
// nothing is loaded, no framework is pulled in, and processes that never touch CFNetwork simply
// have nothing to rebind.
extern void tf_rewrite_install(void);

// Installs the certificate-trust hook. See src/mac/aquatransport_trust_mac.c. Installed under
// the same eligibility gate as the rest, so denied processes never carry it.
extern void tf_trust_install(void);

static OSStatus my_SSLSetIOFuncs(SSLContextRef c, SSLReadFunc rf, SSLWriteFunc wf) {
    if (!tf_on() || ensure_ready() != 1) return o_SSLSetIOFuncs(c, rf, wf);
    OSStatus r = o_SSLSetIOFuncs(c, rf, wf);
    Shadow *s = sh_create(c);
    if (s) { s->rf = rf; s->wf = wf; sh_release(s); }
    return r;
}

static OSStatus my_SSLSetConnection(SSLContextRef c, SSLConnectionRef conn) {
    if (!tf_on() || ensure_ready() != 1) return o_SSLSetConnection(c, conn);
    OSStatus r = o_SSLSetConnection(c, conn);
    Shadow *s = sh_create(c);
    if (s) { s->conn = conn; sh_release(s); }
    return r;
}

static OSStatus my_SSLSetPeerDomainName(SSLContextRef c, const char *name, size_t len) {
    if (!tf_on() || ensure_ready() != 1) return o_SSLSetPeerDomainName(c, name, len);
    OSStatus r = o_SSLSetPeerDomainName(c, name, len);
    Shadow *s = sh_create(c);
    if (s) {
        if (name && len) {
            size_t n = len < 255 ? len : 255; memcpy(s->host, name, n); s->host[n] = 0;
            // late SNI -> re-init; the cached trust goes too, since a new handshake means a
            // new peer chain, and so does everything the write side was holding for the old one.
            if (s->inited && s->state != -1) { SSL_free(s->ssl); s->ssl = NULL; s->inited = 0; s->state = 0;
                 sh_reset_write(s);
                 if (s->trust) { CFRelease(s->trust); s->trust = NULL; } }
        }
        sh_release(s);
    }
    return r;
}

// The caller's identifier for the endpoint, and the session cache's key -- see the cache
// comment in aquatransport_engine.c. Recorded rather than interpreted: the bytes are opaque
// by contract, so all this side does is hold on to them.
static OSStatus my_SSLSetPeerID(SSLContextRef c, const void *peerID, size_t len) {
    if (!tf_on() || ensure_ready() != 1) return o_SSLSetPeerID(c, peerID, len);
    OSStatus r = o_SSLSetPeerID(c, peerID, len);
    Shadow *s = sh_create(c);
    if (s) {
        // A replacement id names a different endpoint, so an id that does not fit leaves none
        // behind rather than the previous one.
        s->peerIDLen = 0;
        if (peerID && len && len <= sizeof s->peerID) { memcpy(s->peerID, peerID, len); s->peerIDLen = len; }
        sh_release(s);
    }
    return r;
}

static OSStatus my_SSLSetSessionOption(SSLContextRef c, SSLSessionOption opt, Boolean val) {
    if (tf_on() && ensure_ready() == 1 && opt == kSSLSessionOptionBreakOnServerAuth) {
        Shadow *s = sh_create(c);
        if (s) { s->breakAuth = val ? 1 : 0; sh_release(s); }
    }
    return o_SSLSetSessionOption(c, opt, val);
}

static OSStatus my_SSLHandshake(SSLContextRef c) {
    if (!tf_on()) return o_SSLHandshake(c);
    Shadow *s = sh_get(c);
    if (!s) return o_SSLHandshake(c);
    OSStatus rv;
    if (!s->rf || !s->wf || !s->conn || s->clientBypass || s->state == -1) { rv = o_SSLHandshake(c); goto done; }
    sh_unblock_write(s);   // an entry like any other; see bio_bwrite
    if (!s->inited) { if (ossl_init(s)) { s->state = -1; rv = o_SSLHandshake(c); goto done; } s->state = 1; }
    if (s->state == 3) s->approved = 1;   // app approved the server after the auth break, let it proceed
    int ret = SSL_do_handshake(s->ssl);
    if (ret == 1) {
        if (tf_debug())
            { STACK_OF(X509) *pc = SSL_get_peer_cert_chain(s->ssl);
              tf_log("handshake ok  host=%s proto=%s cipher=%s %s%s chain=%d",
                   s->host[0] ? s->host : "(none)",
                   SSL_get_version(s->ssl), SSL_get_cipher(s->ssl),
                   SSL_session_reused(s->ssl) ? "resumed" : "full",
                   s->breakAuth ? " [app-verified]" : "",
                   pc ? sk_X509_num(pc) : -1); }
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

// Secure Transport's read contract, measured on the stock stack by tools/readcontract.c with
// a read callback it can starve:
//
//   anything transferred          noErr, *processed = what was transferred, short or not
//   nothing available             errSSLWouldBlock, *processed = 0
//   zero length asked             noErr, *processed = 0, transport not touched
//
// So the status says whether the call made progress, not whether it filled the buffer. A short
// read is noErr, and bytes left over are not lost to the caller: they are held here and
// SSLGetBufferedReadSize reports them, which is how the caller knows to come back rather than
// wait on a socket that has already been drained. That hook answering correctly is what makes
// a short noErr safe -- both halves are the same mechanism.
//
// One record per call, which is what the stock stack returns and what `SSL_read` yields anyway.
// Filling the caller's buffer from further records would be legal -- the status says progress,
// not fullness -- but it is not what a caller measuring this stack would see, and it buys
// nothing: the bytes it would deliver early are reported by SSLGetBufferedReadSize and fetched
// by the next call, which the caller makes either way.
static OSStatus my_SSLRead(SSLContextRef c, void *data, size_t len, size_t *processed) {
    if (!tf_on()) return o_SSLRead(c, data, len, processed);
    Shadow *s = sh_get(c);
    if (!s || s->state != 2) { OSStatus r = o_SSLRead(c, data, len, processed); sh_release(s); return r; }
    // A read is another entry, so it is another chance for the queue to go out. One attempt,
    // never a wait: the caller's own flush is what this connection depends on, and a read must
    // not hold the thread waiting on a socket in the other direction.
    sh_unblock_write(s);
    if (sh_flush_write(s) < 0) { *processed = 0; sh_release(s); return ST_ClosedAbort; }
    size_t total = 0;
    OSStatus rv = noErr;
    if (len) {
        size_t want = len > IO_RUN_MAX ? IO_RUN_MAX : len;
        int n = SSL_read(s->ssl, (unsigned char *)data, (int)want);
        if (n > 0) total = (size_t)n;
        else {
            int e = SSL_get_error(s->ssl, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) rv = errSSLWouldBlock;
            else if (e == SSL_ERROR_ZERO_RETURN) rv = ST_ClosedGraceful;
            else rv = ST_ClosedAbort;
        }
    }
    *processed = total;
    sh_release(s);
    return rv;
}

// Never answers errSSLWouldBlock while it can avoid it: CFNetwork treats one as fatal to the
// whole stream. What the socket will not take is queued in the shadow and reported as
// written, as Secure Transport's own write queue does, and the next entry flushes it first.
// See sh_flush_write in the engine for the measurements behind that, and bio_bwrite for the
// other half -- why the caller's write callback is asked only once per entry.
// Secure Transport's write contract, which tools/writecontract.c measures on the stock stack
// by starving a write callback of its own. Four answers, and this reproduces each:
//
//   data offered, transport blocks    errSSLWouldBlock, *processed = dataLength
//   zero length, still blocked        errSSLWouldBlock, *processed = 0
//   zero length, transport free       noErr,            *processed = 0, queue drained
//   data offered, queue still full    errSSLWouldBlock, *processed = 0, data refused
//
// The first is what makes the rest work. A blocked write takes the caller's whole buffer into
// the context's own queue and says so, and errSSLWouldBlock then means "I am holding it, come
// back" rather than "I did nothing". The caller advances by *processed, which leaves nothing
// to re-present, so its retry is a zero-length call -- a pure flush. That is why a zero length
// must never reach SSL_write, which reads a zero-length write as an error.
//
// Refusing new data while the queue is still full is the backpressure. It bounds the queue at
// one call's worth, since nothing more is accepted until it has drained.
//
// dataLength is a size_t and Secure Transport documents no limit on it, so the buffer is
// consumed in runs -- SSL_write's length is an int.
static OSStatus my_SSLWrite(SSLContextRef c, const void *data, size_t len, size_t *processed) {
    if (!tf_on()) return o_SSLWrite(c, data, len, processed);
    Shadow *s = sh_get(c);
    if (!s || s->state != 2) { OSStatus r = o_SSLWrite(c, data, len, processed); sh_release(s); return r; }
    *processed = 0;
    sh_unblock_write(s);

    OSStatus rv;
    int f = sh_flush_write(s);
    if (f < 0)  { rv = ST_ClosedAbort;    goto done; }
    if (f == 0) { rv = errSSLWouldBlock;  goto done; }   // still holding: take nothing new
    if (len == 0) { rv = noErr;           goto done; }   // pure flush, and it succeeded

    for (size_t off = 0; off < len; ) {
        size_t take = len - off;
        if (take > IO_RUN_MAX) take = IO_RUN_MAX;
        int n = SSL_write(s->ssl, (const unsigned char *)data + off, (int)take);
        if (n > 0) { off += (size_t)n; continue; }
        int e = SSL_get_error(s->ssl, n);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) { rv = ST_ClosedAbort; goto done; }
        // Blocked part-way: keep the rest, report the whole buffer as taken, and say we are
        // holding it. Nothing more is accepted until the next entry drains this.
        if (!sh_hold_write(s, (const unsigned char *)data + off, len - off)) {
            *processed = off;                            // could not take a copy; the rest is the caller's
            rv = errSSLWouldBlock;
            goto done;
        }
        *processed = len;
        rv = errSSLWouldBlock;
        goto done;
    }
    *processed = len;
    rv = noErr;
done:
    sh_release(s);
    return rv;
}

static OSStatus my_SSLClose(SSLContextRef c) {
    if (!tf_on()) return o_SSLClose(c);
    Shadow *s = sh_get(c);
    if (s && s->state == 2 && s->ssl) { sh_unblock_write(s); sh_flush_write(s); SSL_shutdown(s->ssl); }
    sh_release(s);
    OSStatus r = o_SSLClose(c);
    sh_free(c);
    return r;
}

// A context can reach its end without SSLClose -- a connection abandoned before the
// handshake finishes is disposed, not closed -- and the shadow entry then lives until LRU
// eviction. In a long-lived, high-churn process (the shared WebKit networking service is
// the case that matters) those entries accumulate, lengthening every table scan and
// eventually evicting slots still in use. Freeing here costs nothing when SSLClose already
// ran: sh_free on a context with no entry is a no-op.
static OSStatus my_SSLDisposeContext(SSLContextRef c) {
    if (!tf_on()) return o_SSLDisposeContext(c);
    sh_free(c);
    return o_SSLDisposeContext(c);
}

static OSStatus my_SSLGetSessionState(SSLContextRef c, SSLSessionState *st) {
    if (!tf_on()) return o_SSLGetSessionState(c, st);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (s && s->state == 2) { if (st) *st = ST_Connected; rv = noErr; }
    else rv = o_SSLGetSessionState(c, st);
    sh_release(s);
    return rv;
}

// Report a protocol/cipher from the era the caller understands. On 10.6/10.7 the
// kTLSProtocol11/12 enum values do not exist at all, so kTLSProtocol1 (4) and
// 0x002F are the only pair safe across the whole 10.6-10.9 range. The connection
// underneath is whatever OpenSSL actually negotiated.
static OSStatus my_SSLGetNegotiatedProtocolVersion(SSLContextRef c, SSLProtocol *p) {
    if (!tf_on()) return o_SSLGetNegotiatedProtocolVersion(c, p);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (s && (s->state == 2 || s->state == 3)) { if (p) *p = kTLSProtocol1; rv = noErr; }
    else rv = o_SSLGetNegotiatedProtocolVersion(c, p);
    sh_release(s);
    return rv;
}

static OSStatus my_SSLGetNegotiatedCipher(SSLContextRef c, SSLCipherSuite *cipher) {
    if (!tf_on()) return o_SSLGetNegotiatedCipher(c, cipher);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (s && (s->state == 2 || s->state == 3)) {
        if (cipher) *cipher = 0x002F; // TLS_RSA_WITH_AES_128_CBC_SHA
        rv = noErr;
    }
    else rv = o_SSLGetNegotiatedCipher(c, cipher);
    sh_release(s);
    return rv;
}

// How much data can be had without waiting on the socket. CFNetwork drives its event loop off
// this: a zero answer means "nothing here, wait for the socket to become readable".
//
// SSL_pending() alone is the wrong answer, because it counts only decrypted application data.
// Bytes already pulled off the socket into OpenSSL's record buffer -- a partial record, or a
// record not yet processed -- are invisible to it. Reporting zero for those parks CFNetwork on
// a socket that has already been drained, so no readability event can ever arrive and the
// connection sits idle until CFNetwork times it out and reconnects. SSL_has_pending() reports
// buffered bytes of either kind, which is what this question is actually asking.
static OSStatus my_SSLGetBufferedReadSize(SSLContextRef c, size_t *sz) {
    if (!tf_on()) return o_SSLGetBufferedReadSize(c, sz);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (s && s->state == 2) {
        size_t n = (size_t)SSL_pending(s->ssl);
        if (n == 0 && SSL_has_pending(s->ssl)) n = 1;   // buffered, just not decrypted yet
        if (sz) *sz = n;
        rv = noErr;
    }
    else rv = o_SSLGetBufferedReadSize(c, sz);
    sh_release(s);
    return rv;
}

static OSStatus my_SSLCopyPeerTrust(SSLContextRef c, SecTrustRef *trust) {
    if (!tf_on()) return o_SSLCopyPeerTrust(c, trust);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (!s || (s->state != 2 && s->state != 3) || !trust) rv = o_SSLCopyPeerTrust(c, trust);
    else if (sh_build_trust(s, trust)) rv = noErr;
    else rv = o_SSLCopyPeerTrust(c, trust);
    sh_release(s);
    return rv;
}

static OSStatus my_SSLCopyPeerCertificates(SSLContextRef c, CFArrayRef *certs) {
    if (!tf_on()) return o_SSLCopyPeerCertificates(c, certs);
    Shadow *s = sh_get(c);
    OSStatus rv;
    if (!s || (s->state != 2 && s->state != 3) || !certs) rv = o_SSLCopyPeerCertificates(c, certs);
    else { CFArrayRef arr = sh_cert_array(s); if (!arr) rv = o_SSLCopyPeerCertificates(c, certs); else { *certs = arr; rv = noErr; } }
    sh_release(s);
    return rv;
}

static OSStatus my_SSLSetCertificate(SSLContextRef c, CFArrayRef certRefs) {
    if (!tf_on() || ensure_ready() != 1) return o_SSLSetCertificate(c, certRefs);
    Shadow *s = sh_create(c);
    if (s) {
        // disabled-mtls hands client-certificate connections back to the system stack:
        // SSLSetCertificate is forwarded below either way, so the system stack still holds
        // the identity and my_SSLHandshake defers the whole handshake to it. General escape
        // hatch for a client-certificate service this engine cannot carry -- one needing
        // TLS 1.3, or a key the Keychain will not sign for.
        if (tf_flag("disabled-mtls")) s->clientBypass = 1;
        else capture_identity(s, certRefs);
        if (s->inited && s->state != -1) { SSL_free(s->ssl); s->ssl = NULL; s->inited = 0; s->state = 0;
             sh_reset_write(s);
             if (s->trust) { CFRelease(s->trust); s->trust = NULL; } }   // new handshake -> new chain
        sh_release(s);
    }
    return o_SSLSetCertificate(c, certRefs);
}

// One row per hooked entry point. The original slot is filled from dlsym before anything
// is rebound, so an installed hook always has a working original to call through.
static const struct {
    const char *name;
    void       *repl;
    void      **orig;
} kHooks[] = {
    { "SSLSetIOFuncs",                   (void *)my_SSLSetIOFuncs,                   (void **)&o_SSLSetIOFuncs },
    { "SSLSetConnection",                (void *)my_SSLSetConnection,                (void **)&o_SSLSetConnection },
    { "SSLSetPeerDomainName",            (void *)my_SSLSetPeerDomainName,            (void **)&o_SSLSetPeerDomainName },
    { "SSLSetPeerID",                    (void *)my_SSLSetPeerID,                    (void **)&o_SSLSetPeerID },
    { "SSLSetSessionOption",             (void *)my_SSLSetSessionOption,             (void **)&o_SSLSetSessionOption },
    { "SSLHandshake",                    (void *)my_SSLHandshake,                    (void **)&o_SSLHandshake },
    { "SSLRead",                         (void *)my_SSLRead,                         (void **)&o_SSLRead },
    { "SSLWrite",                        (void *)my_SSLWrite,                        (void **)&o_SSLWrite },
    { "SSLClose",                        (void *)my_SSLClose,                        (void **)&o_SSLClose },
    { "SSLDisposeContext",               (void *)my_SSLDisposeContext,               (void **)&o_SSLDisposeContext },
    { "SSLGetSessionState",              (void *)my_SSLGetSessionState,              (void **)&o_SSLGetSessionState },
    { "SSLGetNegotiatedProtocolVersion", (void *)my_SSLGetNegotiatedProtocolVersion, (void **)&o_SSLGetNegotiatedProtocolVersion },
    { "SSLGetNegotiatedCipher",          (void *)my_SSLGetNegotiatedCipher,          (void **)&o_SSLGetNegotiatedCipher },
    { "SSLGetBufferedReadSize",          (void *)my_SSLGetBufferedReadSize,          (void **)&o_SSLGetBufferedReadSize },
    { "SSLCopyPeerTrust",                (void *)my_SSLCopyPeerTrust,                (void **)&o_SSLCopyPeerTrust },
    { "SSLCopyPeerCertificates",         (void *)my_SSLCopyPeerCertificates,         (void **)&o_SSLCopyPeerCertificates },
    { "SSLSetCertificate",               (void *)my_SSLSetCertificate,               (void **)&o_SSLSetCertificate },
};
#define NHOOKS (sizeof kHooks / sizeof kHooks[0])

// Resolving the originals is deferred to the first hook call rather than done here, because
// Secure Transport need not be loaded yet when this runs -- see the note on gating in the
// header. By the time any of these hooks is entered, the process is calling Secure Transport,
// so the whole framework is loaded and every one of these resolves.
//
// RTLD_DEFAULT rather than a handle, and safe at any point: this dylib exports no symbols at
// all (-exported_symbols_list of an empty file), so dlsym can never hand back one of our own
// replacements. That is also why RTLD_NEXT must never be used -- it would.
static pthread_once_t g_origs_once = PTHREAD_ONCE_INIT;
static int g_origs_ok = 0;

// Stands in for an entry point that could not be resolved, so an original slot is never
// NULL and no hook can dereference one. Declared without parameters and called through a
// pointer that has them, which is safe in the same way -- and for the same reason -- as the
// six-parameter pass-throughs in aquatransport_rewrite.c: the callee simply does not read
// what it was passed. Unreachable in practice, since a hook only runs when Secure Transport
// is loaded and every one of these then resolves.
static OSStatus st_unavailable(void) { return ST_Internal; }

static void resolve_origs(void) {
    int ok = 1;
    for (size_t i = 0; i < NHOOKS; i++) {
        void *real = dlsym(RTLD_DEFAULT, kHooks[i].name);
        if (!real) {
            tf_log("could not resolve %s", kHooks[i].name);
            *(kHooks[i].orig) = (void *)st_unavailable;
            ok = 0;
            continue;
        }
        *(kHooks[i].orig) = real;
    }
    g_origs_ok = ok;
}

// True once the original entry points are available. A hook may run its own logic only when
// this succeeds; otherwise it has no way to call through.
static int origs_ready(void) {
    pthread_once(&g_origs_once, resolve_origs);
    return g_origs_ok;
}

static void install_ssl_hooks(void) {
    struct rebinding r[NHOOKS];

    for (size_t i = 0; i < NHOOKS; i++) {
        r[i].name        = kHooks[i].name;
        r[i].replacement = kHooks[i].repl;
        r[i].replaced    = NULL;   // see header comment: fishhook's value is not the function
    }

    // Rebinding by name needs nothing to be loaded: a process with no Secure Transport simply
    // has no call sites to rewrite. fishhook also arms a dyld add-image callback, so a
    // framework that arrives later -- including Security.framework itself -- gets rebound the
    // moment it is loaded. That is what makes installing unconditionally here correct, and it
    // is an event, not a wait: nothing anywhere has to predict when Security will show up.
    rebind_symbols(r, NHOOKS);
}

__attribute__((constructor))
static void aquatransport_init(void) {
    // Denied processes get nothing installed, not even a gate.
    if (!process_eligible()) return;
    // Unconditionally, and deliberately not behind tf_on(): tf_on() reports false until Secure
    // Transport is loaded, so gating installation on it would mean never installing in a
    // process that loads Security later. Rebinding a symbol no loaded image imports is a
    // no-op, and fishhook rebinds the call sites when the framework does arrive.
    install_ssl_hooks();
    tf_rewrite_install();
    tf_trust_install();
}
