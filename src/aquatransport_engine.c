#include "aquatransport.h"
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <time.h>

extern void tf_log(const char *fmt, ...);
extern int  tf_debug(void);

// CoreFoundation and Security are linked lazily, so this library can be loaded into a process
// that has not initialised them -- which is what lets it be loaded into any process at any
// time, with no gate (see build-macos.sh and the header of aquatransport_hooks_mac.c). A
// *data* reference would defeat that: the linker refuses outright with "illegal data
// reference to _kCFTypeArrayCallBacks in lazy loaded dylib". So the one callbacks struct we
// need is looked up by name instead of referenced directly.
//
// Only ever reached from inside a hook, which means from a process that is already using
// CoreFoundation, so the lookup always succeeds there. The racing initialisation is benign:
// both threads resolve the same address.
static double tf_now_ms(void);

static const CFArrayCallBacks *cf_type_array_cb(void) {
    static const CFArrayCallBacks *cb = NULL;
    if (!cb) cb = (const CFArrayCallBacks *)dlsym(RTLD_DEFAULT, "kCFTypeArrayCallBacks");
    return cb;
}

#define MAXSH 256
static Shadow *gTab[MAXSH];
static unsigned gClock = 0;
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

static SSL_CTX *gCtx = NULL;          // shared client context
static BIO_METHOD *gBioMeth = NULL;   // custom BIO bridged to CFNetwork's IO funcs
static RSA_METHOD *gRsaMeth = NULL;   // custom RSA method: private op to SecKeyRawSign (mtls)
static int gRsaExIdx = -1;
static int gSslExIdx = -1;

static pthread_key_t gGuardKey;
static pthread_once_t gGuardOnce = PTHREAD_ONCE_INIT;
static void guard_init(void) { pthread_key_create(&gGuardKey, NULL); }

void tf_guard_enter(void) {
    pthread_once(&gGuardOnce, guard_init);
    pthread_setspecific(gGuardKey, (void *)1);
}
void tf_guard_leave(void) {
    pthread_once(&gGuardOnce, guard_init);
    pthread_setspecific(gGuardKey, (void *)0);
}
int tf_reentrant(void) {
    pthread_once(&gGuardOnce, guard_init);
    return pthread_getspecific(gGuardKey) != NULL;
}

// ---- client session cache --------------------------------------------------
//
// Secure Transport keeps a session cache, so the engine keeps one too: without it every
// connection pays a full handshake where the stock stack resumes, costing an extra round trip
// against a TLS 1.2 server plus the certificate chain and its signature checks. A browser
// opens a lot of connections to the same host, so this is the difference that matters most.
//
// Keyed on the peer name, which is the name the handshake is bound to (SSL_set1_host) and
// therefore the only thing a session may be reused for.
//
// Connections carrying a client certificate are deliberately never cached or resumed: the
// cache key does not include the identity, so a resumed session could otherwise carry an
// identity the caller did not choose for this connection. mTLS connections are rare and a
// full handshake for them costs nothing anyone will notice.
//
// Resumption skips the certificate message, so verify_chain does not run on a resumed
// connection. That is correct and is what every TLS client does -- a session only enters this
// cache after a handshake that already verified -- and it does not weaken the app-verified
// path either: the chain lives on in the SSL_SESSION, so SSLCopyPeerTrust still hands
// CFNetwork the same certificates to evaluate, on a resumed connection as on a fresh one.
#define MAXSESS 32
typedef struct { char host[256]; SSL_SESSION *sess; unsigned lastUse; } SessEnt;
static SessEnt gSess[MAXSESS];
static unsigned gSessClock = 0;
static pthread_mutex_t gSessLock = PTHREAD_MUTEX_INITIALIZER;

static SSL_SESSION *sess_get(const char *host) {
    if (!host || !host[0]) return NULL;
    SSL_SESSION *r = NULL;
    pthread_mutex_lock(&gSessLock);
    for (int i = 0; i < MAXSESS; i++) {
        if (gSess[i].sess && !strcmp(gSess[i].host, host)) {
            gSess[i].lastUse = ++gSessClock;
            r = gSess[i].sess;
            SSL_SESSION_up_ref(r);
            break;
        }
    }
    pthread_mutex_unlock(&gSessLock);
    return r;
}

// Takes ownership of sess (the new_session_cb reference).
static void sess_put(const char *host, SSL_SESSION *sess) {
    if (!host || !host[0] || !sess) { if (sess) SSL_SESSION_free(sess); return; }
    SSL_SESSION *drop = NULL;
    pthread_mutex_lock(&gSessLock);
    int slot = -1;
    for (int i = 0; i < MAXSESS; i++) {
        if (gSess[i].sess && !strcmp(gSess[i].host, host)) { slot = i; break; }
        if (!gSess[i].sess && slot < 0) slot = i;
    }
    if (slot < 0) {                                  // full: evict least recently used
        slot = 0;
        for (int i = 1; i < MAXSESS; i++) if (gSess[i].lastUse < gSess[slot].lastUse) slot = i;
    }
    drop = gSess[slot].sess;                         // replaced or evicted, freed below
    snprintf(gSess[slot].host, sizeof gSess[slot].host, "%s", host);
    gSess[slot].sess = sess;
    gSess[slot].lastUse = ++gSessClock;
    pthread_mutex_unlock(&gSessLock);
    if (drop) SSL_SESSION_free(drop);
}

// Returning 1 keeps the reference OpenSSL handed us; returning 0 lets it free the session.
// For TLS 1.3 this fires when the server's NewSessionTicket arrives, which is after the
// handshake -- during an SSL_read -- so it must not assume it is running inside a handshake.
static int new_session_cb(SSL *ssl, SSL_SESSION *sess) {
    Shadow *s = (Shadow *)SSL_get_ex_data(ssl, gSslExIdx);
    if (!s || !s->host[0] || s->clientX509) return 0;
    if (tf_debug()) tf_log("session cached  host=%s", s->host);
    sess_put(s->host, sess);
    return 1;
}

// ---- verified-chain cache --------------------------------------------------
//
// SecTrustEvaluate on this OS re-runs the whole evaluation on every call -- Security caches
// nothing, not even a repeat call on the same object -- and on the ECDSA chains most of the
// modern web now serves, one run is 200-700ms of CryptKit bignum arithmetic on 10.9-era
// hardware. (RSA-2048 chains cost 10-30ms; the split is per signature algorithm, measured
// with tools/trustbench.c.) That cost is the platform's, and the stock stack pays it too.
//
// What this cache removes is paying it *again* for a chain already verified. Keyed on the
// peer name and a SHA-256 over the chain's DER, with a short TTL, it covers the parallel
// connections a browser opens to one host and the reconnections that follow pool expiry.
//
// Only successes are cached. A chain that fails is re-examined at full price every time, so
// nothing an attacker presents is ever answered from here; the TTL bounds how long a
// newly-expired or newly-revoked certificate could ride a cached success, which is the same
// order of exposure a resumed TLS session already carries.
#define MAXCHOK 32
#define CHAIN_OK_TTL 600
typedef struct { unsigned char dg[SHA256_DIGEST_LENGTH]; time_t when; unsigned lastUse; int used; } ChainOkEnt;
static ChainOkEnt gChainOk[MAXCHOK];
static unsigned gChainOkClock = 0;
static pthread_mutex_t gChainOkLock = PTHREAD_MUTEX_INITIALIZER;

// Digest of what the trust decision depends on: the peer name the handshake was bound to
// and every certificate the server sent, in order.
static int chain_ok_digest(STACK_OF(X509) *chain, const char *host, unsigned char *out) {
    if (!chain || sk_X509_num(chain) < 1) return 0;
    SHA256_CTX c; SHA256_Init(&c);
    SHA256_Update(&c, host, strlen(host) + 1);
    for (int i = 0; i < sk_X509_num(chain); i++) {
        unsigned char *der = NULL; int dl = i2d_X509(sk_X509_value(chain, i), &der);
        if (dl <= 0 || !der) { if (der) OPENSSL_free(der); return 0; }
        SHA256_Update(&c, der, (size_t)dl);
        OPENSSL_free(der);
    }
    SHA256_Final(out, &c);
    return 1;
}

static int chain_ok_get(const unsigned char *dg) {
    time_t now = time(NULL);
    int hit = 0;
    pthread_mutex_lock(&gChainOkLock);
    for (int i = 0; i < MAXCHOK; i++) {
        if (gChainOk[i].used && !memcmp(gChainOk[i].dg, dg, SHA256_DIGEST_LENGTH)) {
            if (now - gChainOk[i].when <= CHAIN_OK_TTL) { gChainOk[i].lastUse = ++gChainOkClock; hit = 1; }
            else gChainOk[i].used = 0;               // expired: the next success re-fills it
            break;
        }
    }
    pthread_mutex_unlock(&gChainOkLock);
    return hit;
}

static void chain_ok_put(const unsigned char *dg) {
    pthread_mutex_lock(&gChainOkLock);
    int slot = -1;
    for (int i = 0; i < MAXCHOK; i++) {
        if (gChainOk[i].used && !memcmp(gChainOk[i].dg, dg, SHA256_DIGEST_LENGTH)) { slot = i; break; }
        if (!gChainOk[i].used && slot < 0) slot = i;
    }
    if (slot < 0) {
        slot = 0;
        for (int i = 1; i < MAXCHOK; i++) if (gChainOk[i].lastUse < gChainOk[slot].lastUse) slot = i;
    }
    memcpy(gChainOk[slot].dg, dg, SHA256_DIGEST_LENGTH);
    gChainOk[slot].when = time(NULL);
    gChainOk[slot].lastUse = ++gChainOkClock;
    gChainOk[slot].used = 1;
    pthread_mutex_unlock(&gChainOkLock);
}

static void sh_free_mem(Shadow *s) {
    if (!s) return;
    if (s->ssl) SSL_free(s->ssl);
    if (s->clientX509) X509_free(s->clientX509);
    if (s->clientChain) sk_X509_pop_free(s->clientChain, X509_free);
    if (s->clientKey) CFRelease(s->clientKey);
    if (s->trust) CFRelease(s->trust);
    free(s);
}
void sh_release(Shadow *s) {
    if (!s) return;
    int dead = 0;
    pthread_mutex_lock(&gLock);
    if (--s->refcount == 0) dead = 1;
    pthread_mutex_unlock(&gLock);
    if (dead) sh_free_mem(s);
}
Shadow *sh_get(SSLContextRef c) {
    if (ensure_ready() != 1) return NULL;
    Shadow *r = NULL;
    pthread_mutex_lock(&gLock);
    for (int i = 0; i < MAXSH; i++) if (gTab[i] && gTab[i]->ctx == c) { r = gTab[i]; r->lastUse = ++gClock; r->refcount++; break; }
    pthread_mutex_unlock(&gLock);
    return r;
}
Shadow *sh_create(SSLContextRef c) {
    Shadow *evicted = NULL; int freeEvicted = 0;
    const char *evictedHost = NULL; int evictedState = 0;
    pthread_mutex_lock(&gLock);
    Shadow *s = NULL;
    for (int i = 0; i < MAXSH; i++) if (gTab[i] && gTab[i]->ctx == c) { s = gTab[i]; s->lastUse = ++gClock; s->refcount++; break; }
    if (!s) {
        s = (Shadow *)calloc(1, sizeof(Shadow));
        if (s) {
            s->ctx = c; s->lastUse = ++gClock; s->refcount = 2;
            int slot = -1;
            for (int i = 0; i < MAXSH; i++) if (!gTab[i]) { slot = i; break; }
            if (slot < 0) {
                int lru = 0; for (int i = 1; i < MAXSH; i++) if (gTab[i]->lastUse < gTab[lru]->lastUse) lru = i;
                evicted = gTab[lru]; slot = lru;
                if (--evicted->refcount == 0) freeEvicted = 1;
                evictedHost = evicted->host; evictedState = evicted->state;
            }
            gTab[slot] = s;
        }
    }
    pthread_mutex_unlock(&gLock);
    if (evictedHost && tf_debug())
        tf_log("SHADOW TABLE FULL: evicted host=%s state=%d", evictedHost[0] ? evictedHost : "(none)", evictedState);
    if (freeEvicted) sh_free_mem(evicted);
    return s;
}
void sh_free(SSLContextRef c) {
    if (ensure_ready() != 1) return;
    Shadow *s = NULL; int dead = 0;
    pthread_mutex_lock(&gLock);
    for (int i = 0; i < MAXSH; i++) if (gTab[i] && gTab[i]->ctx == c) { s = gTab[i]; gTab[i] = NULL; if (--s->refcount == 0) dead = 1; break; }
    pthread_mutex_unlock(&gLock);
    if (dead) sh_free_mem(s);
}

static int bio_bwrite(BIO *b, const char *buf, int len) {
    Shadow *s = (Shadow *)BIO_get_data(b);
    size_t n = (size_t)len;
    OSStatus os = s->wf(s->conn, buf, &n);
    BIO_clear_retry_flags(b);
    if (n > 0) return (int)n;
    if (os == errSSLWouldBlock || os == noErr) { BIO_set_retry_write(b); return -1; }
    return -1;
}
static int bio_bread(BIO *b, char *buf, int len) {
    Shadow *s = (Shadow *)BIO_get_data(b);
    size_t n = (size_t)len;
    OSStatus os = s->rf(s->conn, buf, &n);
    BIO_clear_retry_flags(b);
    if (n > 0) return (int)n;
    if (os == errSSLWouldBlock || os == noErr) { BIO_set_retry_read(b); return -1; }
    if (os == ST_ClosedGraceful) return 0;
    return -1;
}
static long bio_ctrl(BIO *b, int cmd, long num, void *ptr) { (void)b; (void)num; (void)ptr; return (cmd == BIO_CTRL_FLUSH) ? 1 : 0; }
static int bio_create(BIO *b) { BIO_set_init(b, 1); return 1; }
static int bio_destroy(BIO *b) { (void)b; return 1; }

// Signs with the Keychain's copy of the private key; the key itself never leaves it.
//
// Two padding modes arrive here, and both are needed. OpenSSL chooses the CertificateVerify
// algorithm from what the server offers, without consulting what this method supports, and
// rsa_pss_rsae_* sits ahead of rsa_pkcs1_* in the modern defaults; TLS 1.3 goes further and
// permits nothing but PSS. So a PKCS#1-only signer would lose the handshake against most
// current servers and every 1.3 one.
//
// SSL_set1_client_sigalgs_list could force PKCS#1 instead -- that is what the iOS original
// does -- but it trades away TLS 1.3 client certificates altogether. Signing PSS properly is
// the better side of that trade, and costs one extra branch here.
//
// PKCS#1 goes to SecKeyRawSign whole. PSS cannot: OpenSSL has already built the padded block
// (rsa_pmeth.c: RSA_padding_add_PKCS1_PSS_mgf1, then RSA_private_encrypt with RSA_NO_PADDING)
// and needs a bare m^d mod n over it, but SecKeyRawSign's kSecPaddingNone still applies PKCS#1
// v1.5 padding on OS X and rejects a full-block input outright. SecKeyDecrypt's kSecPaddingNone
// is the operation we actually want -- an RSA private decrypt with no padding is the same
// modular exponentiation as a raw sign. Measured on 10.9.5 by tools/pssprobe.c, which signs
// through this exact path and verifies the result against the public key.
//
// The key still never leaves the keychain either way.
static int rsa_seckey_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    SecKeyRef key = (SecKeyRef)RSA_get_ex_data(rsa, gRsaExIdx);
    if (!key) return -1;
    size_t blk = SecKeyGetBlockSize(key);
    if (blk == 0 || flen < 0 || (size_t)flen > blk) return -1;
    size_t tlen = blk;
    OSStatus st;
    if (padding == RSA_PKCS1_PADDING) {
        st = SecKeyRawSign(key, kSecPaddingPKCS1, from, (size_t)flen, to, &tlen);
    } else if (padding == RSA_NO_PADDING) {
        if ((size_t)flen != blk) return -1;      // a raw op takes exactly one block
        st = SecKeyDecrypt(key, kSecPaddingNone, from, (size_t)flen, to, &tlen);
    } else {
        return -1;
    }
    if (st != errSecSuccess) return -1;
    if (tlen == 0 || tlen > blk) return -1;
    // The result is m^d mod n, so it carries a leading zero byte about one time in 256, and a
    // CSP that hands back the minimal-length integer would return a short block. OpenSSL uses
    // this return value verbatim as the signature length (rsa_pmeth.c: *siglen = ret), so a
    // short block would be an intermittent malformed signature. Right-align and zero-fill.
    if (tlen < blk) {
        memmove(to + (blk - tlen), to, tlen);
        memset(to, 0, blk - tlen);
        tlen = blk;
    }
    return (int)tlen;
}

void capture_identity(Shadow *s, CFArrayRef certRefs) {
    if (!certRefs || CFArrayGetCount(certRefs) < 1) { s->clientBypass = 1; return; }
    CFTypeRef first = CFArrayGetValueAtIndex(certRefs, 0);
    if (!first || CFGetTypeID(first) != SecIdentityGetTypeID()) { s->clientBypass = 1; return; }
    SecCertificateRef leaf = NULL; SecKeyRef key = NULL;
    if (SecIdentityCopyCertificate((SecIdentityRef)first, &leaf) != errSecSuccess || !leaf ||
        SecIdentityCopyPrivateKey((SecIdentityRef)first, &key) != errSecSuccess || !key) {
        if (leaf) CFRelease(leaf); if (key) CFRelease(key); s->clientBypass = 1; return;
    }
    X509 *x = NULL;
    CFDataRef d = SecCertificateCopyData(leaf);
    if (d) { const unsigned char *p = CFDataGetBytePtr(d); x = d2i_X509(NULL, &p, CFDataGetLength(d)); CFRelease(d); }
    CFRelease(leaf);
    if (!x) { CFRelease(key); s->clientBypass = 1; return; }
    EVP_PKEY *pub = X509_get_pubkey(x);
    int isRSA = (pub && EVP_PKEY_base_id(pub) == EVP_PKEY_RSA);
    if (pub) EVP_PKEY_free(pub);
    if (!isRSA) { X509_free(x); CFRelease(key); s->clientBypass = 1; return; }   // non-RSA -> system stack
    STACK_OF(X509) *chain = NULL;
    for (CFIndex i = 1, n = CFArrayGetCount(certRefs); i < n; i++) {
        SecCertificateRef ic = (SecCertificateRef)CFArrayGetValueAtIndex(certRefs, i);
        if (!ic || CFGetTypeID(ic) != SecCertificateGetTypeID()) continue;
        CFDataRef id = SecCertificateCopyData(ic);
        if (!id) continue;
        const unsigned char *p = CFDataGetBytePtr(id); X509 *ix = d2i_X509(NULL, &p, CFDataGetLength(id)); CFRelease(id);
        if (ix) { if (!chain) chain = sk_X509_new_null(); if (chain) sk_X509_push(chain, ix); else X509_free(ix); }
    }
    s->clientX509 = x; s->clientChain = chain; s->clientKey = key; s->clientBypass = 0;
}

// Provides our client cert during the handshake; -1 suspends before sending it.
//
// Uses the SSL_CTX_set_client_cert_cb contract: hand back owned references in
// *px509 / *ppkey (tls_prepare_client_certificate installs the pair, then calls
// X509_free / EVP_PKEY_free on them) and return 1. Returning -1 sets
// rwstate = SSL_X509_LOOKUP, surfacing as SSL_ERROR_WANT_X509_LOOKUP, which is the
// pause point the pinning path relies on -- and which OpenSSL honours at every TLS
// version, so this one callback covers 1.0 through 1.3.
//
// SSL_set_cert_cb would be the per-SSL alternative, but it has no way to say "suspend",
// so the pinning pause could not be expressed through it.
static int client_cert_cb(SSL *ssl, X509 **px509, EVP_PKEY **ppkey) {
    Shadow *s = (Shadow *)SSL_get_ex_data(ssl, gSslExIdx);
    if (!s || !s->clientX509) return 0;          // no identity -> send no certificate
    if (s->breakAuth && !s->approved) return -1;
    EVP_PKEY *certpub = X509_get_pubkey(s->clientX509);
    if (!certpub) return 0;
    RSA *rpub = EVP_PKEY_get1_RSA(certpub); EVP_PKEY_free(certpub);
    if (!rpub) return 0;
    const BIGNUM *n = NULL, *e = NULL; RSA_get0_key(rpub, &n, &e, NULL);
    RSA *r = RSA_new();
    if (!r || !RSA_set0_key(r, BN_dup(n), BN_dup(e), NULL)) { RSA_free(rpub); if (r) RSA_free(r); return 0; }
    RSA_free(rpub);
    RSA_set_method(r, gRsaMeth);
    RSA_set_ex_data(r, gRsaExIdx, s->clientKey);
    EVP_PKEY *pk = EVP_PKEY_new();
    if (!pk) { RSA_free(r); return 0; }
    EVP_PKEY_assign_RSA(pk, r);
    if (s->clientChain)
        for (int i = 0; i < sk_X509_num(s->clientChain); i++) SSL_add1_chain_cert(ssl, sk_X509_value(s->clientChain, i));
    X509_up_ref(s->clientX509);                  // callee owns both references
    *px509 = s->clientX509;
    *ppkey = pk;
    return 1;
}

int ossl_init(Shadow *s) {
    s->ssl = SSL_new(gCtx);
    if (!s->ssl) return -1;
    SSL_set_ex_data(s->ssl, gSslExIdx, s);
    BIO *bio = BIO_new(gBioMeth);
    if (!bio) { SSL_free(s->ssl); s->ssl = NULL; return -1; }
    BIO_set_data(bio, s);
    BIO_set_init(bio, 1);
    SSL_set_bio(s->ssl, bio, bio);
    if (s->host[0]) { SSL_set_tlsext_host_name(s->ssl, s->host); SSL_set1_host(s->ssl, s->host); }
    // Ask the server to staple its OCSP response into the handshake. A server that does not
    // support this ignores the extension. See attach_stapled_ocsp for what the response saves.
    SSL_set_tlsext_status_type(s->ssl, TLSEXT_STATUSTYPE_ocsp);
    // Offer a cached session for this host, if we have one and this connection is not
    // presenting a client certificate (see the cache comment). OpenSSL checks the session's
    // own validity and falls back to a full handshake if it has expired or the server
    // declines it, so nothing here has to reason about lifetime.
    if (!s->clientX509) {
        SSL_SESSION *cached = sess_get(s->host);
        if (tf_debug()) tf_log("session %s   host=%s", cached ? "offered" : "MISS   ", s->host);
        if (cached) { SSL_set_session(s->ssl, cached); SSL_SESSION_free(cached); }
    }
    SSL_set_connect_state(s->ssl);
    // Client-certificate connections need no version cap. Both halves TLS 1.3 requires are
    // in place: rsa_seckey_priv_enc produces the RSA-PSS signature it mandates, and OpenSSL
    // drives the client certificate from tls_prepare_client_certificate(), which is version
    // agnostic -- it calls client_cert_cb for 1.3 as well, and honours the same -1 ->
    // SSL_X509_LOOKUP suspend the pinning pause depends on. tools/mtlsprobe.c covers this
    // against a tls1_3-only server requiring a client certificate.
    s->inited = 1;
    return 0;
}

// Hands Security the OCSP response the server stapled into the handshake, before it evaluates.
//
// Trust evaluation on OS X checks revocation, and with nothing stapled it asks ocspd, which
// fetches from the CA over the network -- a synchronous round trip sitting on the connection's
// critical path, paid on every chain it has not seen before. Requesting the staple and passing
// it here answers the same question without leaving the machine.
//
// Resolved by name because the deployment range reaches back to 10.6; where it is absent the
// evaluation simply proceeds as it did before.
// Returns the size of the response attached, or 0 if the server stapled nothing.
static long attach_stapled_ocsp(Shadow *s, SecTrustRef t) {
    static OSStatus (*setResp)(SecTrustRef, CFTypeRef);
    static int resolved;
    if (!resolved) {
        resolved = 1;
        setResp = (OSStatus (*)(SecTrustRef, CFTypeRef))dlsym(RTLD_DEFAULT, "SecTrustSetOCSPResponse");
    }
    if (!setResp || !s || !s->ssl) return 0;
    const unsigned char *resp = NULL;
    long n = SSL_get_tlsext_status_ocsp_resp(s->ssl, &resp);
    if (n <= 0 || !resp) return 0;
    CFDataRef d = CFDataCreate(NULL, resp, (CFIndex)n);
    if (!d) return 0;
    setResp(t, d);
    CFRelease(d);
    return n;
}

// verification: the device's own system trust store
static int verify_chain(X509_STORE_CTX *sctx, void *arg) {
    (void)arg;
    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(sctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    Shadow *s = ssl ? (Shadow *)SSL_get_ex_data(ssl, gSslExIdx) : NULL;
    if (s && s->breakAuth) return 1;
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_untrusted(sctx);
    if (!chain || sk_X509_num(chain) < 1) return 0;
    unsigned char dg[SHA256_DIGEST_LENGTH];
    int haveDg = chain_ok_digest(chain, s && s->host[0] ? s->host : "", dg);
    if (haveDg && chain_ok_get(dg)) {
        if (tf_debug()) tf_log("verify_chain host=%s cached ok", s && s->host[0] ? s->host : "?");
        return 1;
    }
    double vt0 = tf_debug() ? tf_now_ms() : 0;
    CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, cf_type_array_cb());
    for (int i = 0; i < sk_X509_num(chain); i++) {
        unsigned char *der = NULL; int dl = i2d_X509(sk_X509_value(chain, i), &der);
        if (dl > 0 && der) {
            CFDataRef d = CFDataCreate(NULL, der, dl);
            SecCertificateRef sc = d ? SecCertificateCreateWithData(NULL, d) : NULL;
            if (sc) { CFArrayAppendValue(arr, sc); CFRelease(sc); }
            if (d) CFRelease(d);
        }
        if (der) OPENSSL_free(der);
    }
    CFStringRef host = (s && s->host[0]) ? CFStringCreateWithCString(NULL, s->host, kCFStringEncodingUTF8) : NULL;
    tf_guard_enter();                       // anything Security opens from here is not ours to hook
    SecPolicyRef pol = SecPolicyCreateSSL(true, host);
    SecTrustRef t = NULL; int ok = 0;
    if (SecTrustCreateWithCertificates(arr, pol, &t) == errSecSuccess && t) {
        attach_stapled_ocsp(s, t);
        SecTrustResultType rr = kSecTrustResultInvalid;
        if (SecTrustEvaluate(t, &rr) == errSecSuccess && (rr == kSecTrustResultProceed || rr == kSecTrustResultUnspecified)) ok = 1;
        CFRelease(t);
    }
    if (pol) CFRelease(pol);
    tf_guard_leave();
    if (ok && haveDg) chain_ok_put(dg);
    if (tf_debug()) tf_log("verify_chain host=%s took %.0f ms certs=%ld ok=%d",
                           s && s->host[0] ? s->host : "?", tf_now_ms() - vt0,
                           (long)CFArrayGetCount(arr), ok);
    if (host) CFRelease(host);
    CFRelease(arr);
    return ok;
}

// peer chain handed back to the app
CFArrayRef sh_cert_array(Shadow *s) {
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(s->ssl);
    if (!chain) return NULL;
    CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, cf_type_array_cb());
    for (int i = 0; i < sk_X509_num(chain); i++) {
        unsigned char *der = NULL; int dl = i2d_X509(sk_X509_value(chain, i), &der);
        if (dl > 0 && der) {
            CFDataRef d = CFDataCreate(NULL, der, dl);
            SecCertificateRef sc = d ? SecCertificateCreateWithData(NULL, d) : NULL;
            if (sc) { CFArrayAppendValue(arr, sc); CFRelease(sc); }
            if (d) CFRelease(d);
        }
        if (der) OPENSSL_free(der);
    }
    return arr;
}
static double tf_now_ms(void){struct timeval t;gettimeofday(&t,NULL);return t.tv_sec*1000.0+t.tv_usec/1000.0;}

// Builds the peer trust CFNetwork evaluates, once per connection.
//
// CFNetwork calls SSLCopyPeerTrust for every *request*, and each fresh SecTrustRef costs a
// fresh SecTrustEvaluate: ~335ms on this hardware, effectively all of it in
// Security.framework's CryptKit bignum routines verifying the chain's signatures. Caching per
// connection is what keeps that off the per-request path, and the system's own caching cannot
// stand in for it, because every call hands it newly created certificates.
//
// Once per connection is also what the stock stack does. Measured, native CPU on 10.9.5,
// same host: one connection serving 6 requests costs 0.595s and 12 requests 0.644s, so
// requests are free; six connections serving one request each cost 2.164s, about 314ms per
// connection. It evaluates per connection and does not carry the result between connections.
//
// The peer chain cannot change within a connection, so the decision cannot either. Each caller
// gets its own reference, because SSLCopyPeerTrust has copy semantics and CFNetwork releases
// what it is given. The cache is dropped whenever the SSL object is re-initialised, since that
// means a new handshake and a new chain.
int sh_build_trust(Shadow *s, SecTrustRef *trust) {
    if (s->trust) { CFRetain(s->trust); *trust = s->trust; return 1; }
    double t0 = tf_debug() ? tf_now_ms() : 0;
    CFArrayRef arr = sh_cert_array(s);
    if (!arr) return 0;
    long ncerts = (long)CFArrayGetCount(arr);
    CFStringRef hostStr = s->host[0] ? CFStringCreateWithCString(NULL, s->host, kCFStringEncodingUTF8) : NULL;
    SecPolicyRef pol = SecPolicyCreateSSL(true, hostStr);
    if (hostStr) CFRelease(hostStr);
    SecTrustRef t = NULL;
    tf_guard_enter();
    OSStatus r = SecTrustCreateWithCertificates(arr, pol, &t);
    if (pol) CFRelease(pol);
    CFRelease(arr);
    if (r != errSecSuccess) { tf_guard_leave(); return 0; }
    long stapled = attach_stapled_ocsp(s, t);
    // Handed back unevaluated, deliberately, so a chain is evaluated exactly once per
    // connection: by verify_chain on the plain path, or by CFNetwork itself on the
    // app-verified path, which is the one CFNetwork takes on nearly every connection.
    //
    // Evaluating here as well would cost a second full evaluation of the same chain on the
    // connection's critical path -- hundreds of milliseconds at best, seconds when it goes
    // to the network -- and buy nothing. The result is not the security decision, so
    // nothing reads it; and CFNetwork calls SecTrustSetKeychains on the object immediately
    // before evaluating, which would discard any result recorded here anyway.
    //
    // Nothing needs the object pre-settled: Security evaluates on demand. Measured on
    // 10.9.5 by tools/trustbench.c, SecTrustCopyExceptions and SecTrustGetCertificateCount
    // both succeed on a trust that has never been evaluated.
    tf_guard_leave();
    if (tf_debug()) tf_log("build_trust host=%s took %.0f ms stapled=%ld certs=%ld resumed=%d", s->host, tf_now_ms() - t0, stapled, ncerts, SSL_session_reused(s->ssl));
    s->trust = t;                 // connection's copy, released with the Shadow
    CFRetain(t);                  // caller's copy: SSLCopyPeerTrust hands out a reference
    *trust = t;
    return 1;
}

static int g_state = 0;                          // 0 unchecked, 1 active, -1 setup failed
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static void do_ready(void) {
    OPENSSL_init_ssl(0, NULL);
    gRsaExIdx = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    gRsaMeth = RSA_meth_dup(RSA_get_default_method());
    if (gRsaMeth) { RSA_meth_set1_name(gRsaMeth, "aquatransport-seckey"); RSA_meth_set_priv_enc(gRsaMeth, rsa_seckey_priv_enc); }
    gCtx = SSL_CTX_new(TLS_client_method());
    if (gCtx) {
        SSL_CTX_set_security_level(gCtx, 0);                          // allow legacy crypto / 1024-bit identities
        SSL_CTX_set_min_proto_version(gCtx, TLS1_VERSION);            // TLS 1.0 .. 1.3
        SSL_CTX_set_max_proto_version(gCtx, TLS1_3_VERSION);
        // Security level 0 permits the old suites but does not offer them: the default list
        // still excludes them, so a TLS 1.0-only server sees nothing it can use and the
        // handshake dies on cipher overlap rather than version. "ALL" restores the legacy
        // suites; level 0 above is what makes them usable once selected. This pair is the
        // whole reason a stock 10.6-era server stays reachable.
        SSL_CTX_set_cipher_list(gCtx, "ALL");
        SSL_CTX_set_verify(gCtx, SSL_VERIFY_PEER, NULL);
        gSslExIdx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        SSL_CTX_set_cert_verify_callback(gCtx, verify_chain, NULL);
        // Client session cache. OpenSSL's own store is server-side only, so the sessions are
        // kept by new_session_cb above; NO_INTERNAL_STORE says so explicitly rather than
        // relying on that. Without CACHE_CLIENT the callback is never invoked at all.
        SSL_CTX_set_session_cache_mode(gCtx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(gCtx, new_session_cb);
        // Frees the 34KB of read/write buffers an idle connection would otherwise hold. A
        // browser keeps many connections open and mostly idle, so this is the difference
        // between tens of KB and a megabyte or two of dirty pages per process.
        SSL_CTX_set_mode(gCtx, SSL_MODE_RELEASE_BUFFERS);
        // Per-context rather than per-SSL. Harmless on connections without a client
        // identity: the callback returns 0 for "no cert".
        SSL_CTX_set_client_cert_cb(gCtx, client_cert_cb);
    }
    gBioMeth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "cfnetwork");
    if (gBioMeth) {
        BIO_meth_set_write(gBioMeth, bio_bwrite);
        BIO_meth_set_read(gBioMeth, bio_bread);
        BIO_meth_set_ctrl(gBioMeth, bio_ctrl);
        BIO_meth_set_create(gBioMeth, bio_create);
        BIO_meth_set_destroy(gBioMeth, bio_destroy);
    }
    g_state = (gCtx && gBioMeth) ? 1 : -1;
}
int ensure_ready(void) { pthread_once(&g_once, do_ready); return g_state; }
