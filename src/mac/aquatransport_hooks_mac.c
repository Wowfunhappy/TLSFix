// macOS hook layer for AquaTransport (10.6 - 10.9).
//
// Hooks are installed with fishhook, which rebinds symbol pointers by name. Properties this
// relies on:
//
//   1. Rebinding rewrites call sites instead of patching function bodies, so the
//      "function too small, clobbers adjacent memory" problem does not arise and
//      SSLClose/SSLDisposeContext are safe to hook.
//   2. Rebinding does not require the library to be present at process launch. A library
//      loaded late -- via dlopen, or loaded into an already-running process -- installs
//      these hooks just as well. Measured on 10.6.8 and 10.9.5, i386 and x86_64: a dlopen'd
//      image rebinds CFNetwork's calls into Secure Transport even after those symbols have
//      already been bound and used. This is what lets aqinject/aqwatch load the library into
//      a process after it has started.
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
#include <malloc/malloc.h>
#include <openssl/err.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
// The one list the whole package shares. tf_reentrant() in the engine guards the same-thread
// case; the trust daemons on this list are where the cycle spans a process boundary.
#include "../aquatransport_deny.h"

// Whether this process may be touched at all. This gate runs inside the target, so it is the
// one that holds however the library arrived -- the injection-side list in aqwatch is defence
// in depth, not the sole protection, and this is what covers a library that got in some other
// way entirely.
static int process_eligible(void) {
    const char *pn = getprogname();
    if (pn) for (int i = 0; kAquaNeverTouch[i]; i++) if (!strcmp(pn, kAquaNeverTouch[i])) return 0;
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

// ---- adopting a context configured before this library arrived ----------------------------
//
// WHY THIS EXISTS. The connection gate holds a process at its first network syscall and loads
// this library before letting it go, which is in time for the handshake but NOT in time for the
// setup: measured on 10.9.5, CFNetwork builds and configures its SSLContext about 5 ms BEFORE it
// opens any socket, and roughly 80 ms before it calls SSLHandshake. So on the first TLS
// connection of a CFNetwork process the hooks are installed between SSLSetIOFuncs and
// SSLHandshake -- the context is fully configured, our hook for it never ran, and without this
// the connection would fall through to the system's own Secure Transport. That is exactly the
// old-TLS exposure this package exists to remove, and for a short-lived process it would be
// every request it ever makes.
//
// WHAT HAS TO BE RECOVERED. Everything the hooks would have recorded on the way in. All of it
// has a public getter except the two I/O callbacks:
//
//   connection      SSLGetConnection
//   peer name       SSLGetPeerDomainNameLength + SSLGetPeerDomainName   (SNI and verification)
//   peer id         SSLGetPeerID                                        (session cache key)
//   break-on-auth   SSLGetSessionOption
//   read/write      no getter -- see below
//
// The peer name is the one that would be a security regression if it were skipped rather than
// recovered: without it there is no SNI and no name to verify the certificate against.
//
// HOW THE CALLBACKS ARE FOUND. There is no SSLGetIOFuncs, so the offsets are DISCOVERED at
// runtime rather than written down: make a throwaway context, set sentinel callbacks through the
// real SSLSetIOFuncs, and find where they landed, with malloc_size bounding the search to the
// context's own allocation. Measured here: x86_64 {16, 24, 32}, i386 {8, 12, 16} -- but nothing
// depends on those numbers being right, because they are re-derived in each process.
//
// THREE THINGS KEEP A WRONG LAYOUT FROM BEING A CRASH:
//
//   1. The calibration has to succeed twice, on two independently created contexts, or no
//      adoption is attempted at all.
//   2. Every context is checked individually before it is trusted: the connection read through
//      the public SSLGetConnection must equal the word sitting at the calibrated offset. A
//      layout that does not apply to this context is caught here, before anything is called.
//   3. The recovered pointers must be non-null and resolve through dladdr to a loaded image.
//
// Any of those failing means the connection is handled by the system stack, which is what would
// have happened anyway.
//
// THE ONE PIECE THAT CANNOT BE READ is a client certificate: SSLSetCertificate refuses a
// sentinel array (-50), so its slot cannot be calibrated the way the callbacks are, and there is
// no getter. A context that had an identity set before this library arrived is therefore adopted
// without it, and if the server demands a client certificate that first connection fails. It is
// confined to a process's very first TLS connection presenting a client certificate -- and
// CFNetwork normally sets an identity only in response to a server's request, which is a later
// connection, by which time the hooks are installed and the identity is captured properly.

static long g_off_rf = -1, g_off_wf = -1, g_off_conn = -1;
static int  g_layout_ok = 0;
static pthread_once_t g_layout_once = PTHREAD_ONCE_INIT;
static int  g_sentinel_conn;

// Distinct bodies on purpose: identical ones can be folded to a single address by the linker,
// and then the two offsets could not be told apart.
static OSStatus probe_read(SSLConnectionRef c, void *d, size_t *l)        { (void)c; (void)d; (void)l; return errSSLWouldBlock; }
static OSStatus probe_write(SSLConnectionRef c, const void *d, size_t *l) { (void)c; (void)d; (void)l; return errSSLClosedAbort; }

// SSLCreateContext is 10.8+, SSLNewContext is what 10.6 and 10.7 have. Both are resolved rather
// than linked, so neither a missing symbol nor a weak import decides anything at build time.
static SSLContextRef probe_ctx_new(int *cf_owned) {
    SSLContextRef (*create)(CFAllocatorRef, SSLProtocolSide, SSLConnectionType) =
        (SSLContextRef (*)(CFAllocatorRef, SSLProtocolSide, SSLConnectionType))
        dlsym(RTLD_DEFAULT, "SSLCreateContext");
    if (create) { *cf_owned = 1; return create(NULL, kSSLClientSide, kSSLStreamType); }
    OSStatus (*newctx)(Boolean, SSLContextRef *) =
        (OSStatus (*)(Boolean, SSLContextRef *))dlsym(RTLD_DEFAULT, "SSLNewContext");
    if (newctx) { SSLContextRef c = NULL; if (newctx(false, &c) == noErr && c) { *cf_owned = 0; return c; } }
    return NULL;
}

static void probe_ctx_free(SSLContextRef c, int cf_owned) {
    if (!c) return;
    if (cf_owned) { CFRelease(c); return; }
    OSStatus (*dispose)(SSLContextRef) = (OSStatus (*)(SSLContextRef))dlsym(RTLD_DEFAULT, "SSLDisposeContext");
    if (dispose) dispose(c);
}

// Where do the callbacks land in a context of this OS version's layout? Returns 0 unless a
// context can be built, the sentinels planted, and all three found at distinct offsets.
static int probe_offsets(long *rf, long *wf, long *cn) {
    int cf_owned = 0;
    SSLContextRef p = probe_ctx_new(&cf_owned);
    if (!p) return 0;
    int ok = 0;
    size_t n = malloc_size((void *)p);
    SSLConnectionRef sconn = (SSLConnectionRef)&g_sentinel_conn;
    // A context is a few hundred bytes; anything outside this is not a layout to go scanning.
    if (n >= 64 && n <= 65536 &&
        o_SSLSetIOFuncs(p, probe_read, probe_write) == noErr &&
        o_SSLSetConnection(p, sconn) == noErr) {
        void **w = (void **)p;
        *rf = *wf = *cn = -1;
        for (size_t i = 0; i < n / sizeof(void *); i++) {
            if (w[i] == (void *)probe_read  && *rf < 0) *rf = (long)(i * sizeof(void *));
            if (w[i] == (void *)probe_write && *wf < 0) *wf = (long)(i * sizeof(void *));
            if (w[i] == (void *)sconn       && *cn < 0) *cn = (long)(i * sizeof(void *));
        }
        ok = (*rf >= 0 && *wf >= 0 && *cn >= 0 && *rf != *wf && *rf != *cn && *wf != *cn);
    }
    probe_ctx_free(p, cf_owned);
    return ok;
}

static void layout_init(void) {
    long rf1, wf1, cn1, rf2, wf2, cn2;
    // Twice, on two independently built contexts. One agreeing run could be a coincidence of
    // whatever happened to be in uninitialised memory; two cannot.
    if (!probe_offsets(&rf1, &wf1, &cn1)) return;
    if (!probe_offsets(&rf2, &wf2, &cn2)) return;
    if (rf1 != rf2 || wf1 != wf2 || cn1 != cn2) return;
    g_off_rf = rf1; g_off_wf = wf1; g_off_conn = cn1;
    g_layout_ok = 1;
    tf_log("adopt: context layout rf=%ld wf=%ld conn=%ld", rf1, wf1, cn1);
}

// Fill in what the setters that ran before we arrived would have recorded. Returns 1 when the
// shadow ends up complete enough to drive the handshake.
//
// A shadow may well already EXIST at this point without being usable, which is the case that
// matters: CFNetwork sets the I/O funcs and the connection up front, but sets the peer name and
// peer id later -- after the gate has released the process and our hooks are installed. Those
// later setters create a shadow with no callbacks in it, so "no shadow" is the wrong thing to
// test for. What matters is whether the callbacks are there.
static int sh_adopt_into(Shadow *s, SSLContextRef c) {
    if (ensure_ready() != 1) return 0;
    pthread_once(&g_layout_once, layout_init);
    if (!g_layout_ok) return 0;

    // NOTHING IS WRITTEN TO THE SHADOW UNTIL EVERY PIECE IS IN HAND. Committing as it goes and
    // returning 0 on a later failure looks like a refusal and is not one: the caller's guard
    // asks whether the callbacks are present, so a half-filled shadow satisfies it and the
    // handshake proceeds -- with no peer name, which means no SNI and nothing to verify the
    // certificate against. A takeover that verifies nothing is far worse than declining, so a
    // partial takeover must not be reachable at all. tools/adoptprobe.c asserts this directly
    // by reading the ClientHello off a plain listener.
    SSLReadFunc      rf = s->rf;
    SSLWriteFunc     wf = s->wf;
    SSLConnectionRef cn = s->conn;
    char             host[sizeof s->host];
    unsigned char    pid_blob[sizeof s->peerID];
    size_t           pid_len = 0;
    int              breakAuth = s->breakAuth;

    memcpy(host, s->host, sizeof host);

    // The per-context proof, before anything else is believed. SSLGetConnection is public and is
    // not one of ours, so what it returns is independent of anything calibrated -- and if the
    // word at the calibrated offset is not that value, this context is not laid out the way the
    // probe context was, and nothing else read from it may be trusted either.
    SSLConnectionRef conn = NULL;
    if (SSLGetConnection(c, &conn) != noErr || !conn) return 0;
    if (*(SSLConnectionRef *)((char *)c + g_off_conn) != conn) return 0;
    if (!cn) cn = conn;

    if (!rf || !wf) {
        SSLReadFunc  grf = *(SSLReadFunc  *)((char *)c + g_off_rf);
        SSLWriteFunc gwf = *(SSLWriteFunc *)((char *)c + g_off_wf);
        if (!grf || !gwf) return 0;
        Dl_info di;
        if (!dladdr((const void *)grf, &di) || !dladdr((const void *)gwf, &di)) return 0;
        rf = grf; wf = gwf;
    }

    // The peer name carries SNI and is what the certificate is verified against, so a context
    // whose name cannot be read is not one to take over. Security's own copy is authoritative
    // whether or not our setter ran.
    if (!host[0]) {
        size_t need = 0;
        if (SSLGetPeerDomainNameLength(c, &need) != noErr || need == 0 || need >= sizeof host) return 0;
        size_t hn = sizeof host;
        if (SSLGetPeerDomainName(c, host, &hn) != noErr) return 0;
        if (hn >= sizeof host) hn = sizeof host - 1;
        host[hn] = 0;                      // the getter does not promise a terminator
        if (!host[0]) return 0;
    }

    if (!s->peerIDLen) {
        const void *pv = NULL; size_t pl = 0;
        if (SSLGetPeerID(c, &pv, &pl) == noErr && pv && pl && pl <= sizeof pid_blob) {
            memcpy(pid_blob, pv, pl);
            pid_len = pl;
        }
    }
    {   // Read rather than assumed: Security holds the value whether or not our setter ran, and
        // "off" and "never set" are the same thing to every caller.
        Boolean ba = false;
        if (SSLGetSessionOption(c, kSSLSessionOptionBreakOnServerAuth, &ba) == noErr) breakAuth = ba ? 1 : 0;
    }

    // Everything needed is in hand: commit.
    s->rf = rf; s->wf = wf; s->conn = cn;
    memcpy(s->host, host, sizeof s->host);
    if (pid_len) { memcpy(s->peerID, pid_blob, pid_len); s->peerIDLen = pid_len; }
    s->breakAuth = breakAuth;

    tf_log("adopt %s: context configured before we loaded, taken over at handshake", s->host);
    return 1;
}

// Every connection this engine does NOT carry goes to the system's own Secure Transport, which
// is the stack this package exists to replace -- so a decision to decline one is exactly as
// interesting as a handshake, and until it is logged it is invisible. A connection that quietly
// falls through leaves no trace at all, which makes "the engine reported no failures" mean far
// less than it looks like it means.
//
// tf_reentrant is the one expected case: our own trust evaluation can open a connection of its
// own -- a revocation fetch -- and that one is deliberately handed to the system stack so it
// cannot recurse into us. It is named rather than hidden, so the log distinguishes "by design"
// from "could not".
static void declined(SSLContextRef c, const Shadow *s, const char *why) {
    if (!tf_debug()) return;
    (void)c;
    tf_log("DECLINED host=%s -- %s; this connection uses the system's Secure Transport",
           (s && s->host[0]) ? s->host : "(unknown)", why);
}

static OSStatus my_SSLHandshake(SSLContextRef c) {
    if (!tf_on()) {
        declined(c, NULL, tf_reentrant() ? "our own nested request, by design" : "hooks not ready");
        return o_SSLHandshake(c);
    }
    Shadow *s = sh_get(c);
    if (!s) s = sh_create(c);
    if (!s) { declined(c, NULL, "no shadow could be allocated"); return o_SSLHandshake(c); }
    // Missing callbacks mean SSLSetIOFuncs ran before this library was in the process. The gate
    // makes that the normal case for the first TLS connection of a process rather than a rare
    // one, so it is worth taking the context over instead of conceding it to the system stack.
    // A failure here leaves the shadow incomplete, and the guard below hands it to stock.
    if ((!s->rf || !s->wf || !s->conn) && !sh_adopt_into(s, c))
        declined(c, s, "the context could not be taken over");
    OSStatus rv;
    // A refusal is final. CFNetwork retries a failed handshake, and answering that retry with
    // the system stack would let a server this engine just rejected be accepted a moment later
    // -- so the weakest stack on the machine would get the last word on every security
    // decision. Fail closed instead: the caller sees the same error it saw the first time.
    if (s->refused) { rv = ST_ClosedAbort; goto done; }
    if (!s->rf || !s->wf || !s->conn || s->clientBypass || s->state == -1) {
        declined(c, s,
                 s->clientBypass  ? "client certificate, disabled-mtls" :
                 s->state == -1   ? "the OpenSSL side failed to initialise earlier" :
                 (!s->rf || !s->wf) ? "no I/O callbacks, and the context could not be taken over"
                                    : "no connection recorded, and the context could not be taken over");
        rv = o_SSLHandshake(c); goto done;
    }
    sh_unblock_write(s);   // an entry like any other; see bio_bwrite
    if (!s->inited) { if (ossl_init(s)) { s->state = -1; declined(c, s, "the OpenSSL side would not initialise"); rv = o_SSLHandshake(c); goto done; } s->state = 1; }
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
        // "ssl_err=1" says only that OpenSSL objected, which is not enough to tell a server
        // this engine SHOULD reject from one it merely cannot talk to -- and that difference
        // decides whether a refusal is correct or a compatibility bug. So the reason goes in,
        // along with the peer id, which is the only thing to hand that carries the PORT: a
        // probe suite like SSL Labs' reaches one hostname on many ports, and without the port
        // the log cannot say which probe was refused.
        if (tf_debug()) {
            char ebuf[256]; ebuf[0] = 0;
            unsigned long oe = ERR_peek_last_error();
            if (oe) ERR_error_string_n(oe, ebuf, sizeof ebuf);
            char peer[96]; size_t pn = s->peerIDLen < sizeof peer - 1 ? s->peerIDLen : sizeof peer - 1;
            memcpy(peer, s->peerID, pn); peer[pn] = 0;
            for (size_t i = 0; i < pn; i++) if (peer[i] < 32 || peer[i] > 126) peer[i] = '.';
            tf_log("handshake FAILED host=%s ssl_err=%d verify=%ld openssl=[%s] peer=[%s] (%s)",
                   s->host[0] ? s->host : "(none)", e,
                   (long)SSL_get_verify_result(s->ssl), ebuf[0] ? ebuf : "-", peer,
                   tf_flag("allow-legacy-tls")
                       ? "allow-legacy-tls: a retry on this context WILL be handed to the system stack"
                       : "refused; a retry on this context stays refused");
        }
        s->state = -1; rv = ST_ClosedAbort;
        // A refusal is final. CFNetwork retries a failed handshake, and answering that retry
        // with the system stack would let a server this engine just rejected be accepted a
        // moment later -- so the weakest stack on the machine would get the last word on every
        // security decision this one makes.
        //
        // allow-legacy-tls turns that off along with everything else it turns off, because it
        // is the same question asked twice. Refusing to negotiate an obsolete protocol and
        // refusing to let the system stack negotiate it instead are one decision: permitting
        // the first while forbidding the second reaches the server anyway, on worse terms and
        // without saying so. One flag, one meaning -- reach the server, or do not.
        if (!tf_flag("allow-legacy-tls")) s->refused = 1;
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
    if (s && s->refused) { sh_release(s); return ST_ClosedAbort; }
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
    if (s && s->refused) { sh_release(s); return ST_ClosedAbort; }
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
}
