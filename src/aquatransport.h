#ifndef AQUATRANSPORT_H
#define AQUATRANSPORT_H

#include <Security/SecureTransport.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <openssl/ssl.h>

// Secure Transport result codes
#ifndef errSSLWouldBlock
#define errSSLWouldBlock  -9803
#endif
#define ST_ClosedGraceful -9805
#define ST_ClosedAbort    -9806
#define ST_PeerAuth       -9841
#define ST_Internal       -9838
#define ST_Connected       2
#define ST_TLS12           8

// Security.framework on OS X exports SecKeyRawSign -- verified present on both 10.6.8 and
// 10.9.5, in both slices -- but declares it only in the iOS headers, so declare it here for
// the mtls signing path.
extern OSStatus SecKeyRawSign(SecKeyRef key, SecPadding padding,
                              const uint8_t *dataToSign, size_t dataToSignLen,
                              uint8_t *sig, size_t *sigLen);

// Same story for SecKeyDecrypt, which is how the PSS path reaches a bare private-key
// operation -- see rsa_seckey_priv_enc. SecKeyRawSign cannot do it: its kSecPaddingNone
// still applies PKCS#1 v1.5 padding on OS X ("None" means no DigestInfo, not no padding),
// measured as an input cap of blocksize-11 on 10.9.5 -- tools/pssprobe.c reproduces it.
extern OSStatus SecKeyDecrypt(SecKeyRef key, SecPadding padding,
                              const uint8_t *cipherText, size_t cipherTextLen,
                              uint8_t *plainText, size_t *plainTextLen);

typedef struct {
    SSLContextRef    ctx;
    SSLReadFunc      rf;
    SSLWriteFunc     wf;
    SSLConnectionRef conn;
    char             host[256];
    int              inited;
    int              state;
    int              breakAuth;
    int              approved;
    int              clientBypass;
    X509            *clientX509;
    STACK_OF(X509)  *clientChain;
    SecKeyRef        clientKey;
    unsigned         lastUse;
    int              refcount;
    SSL             *ssl;
    // Evaluated peer trust for this connection, built once. CFNetwork asks for it on every
    // request, so it is built per connection rather than per request. See sh_build_trust.
    SecTrustRef      trust;
    // Set once the caller's write callback has reported would-block, and cleared each time
    // the caller re-enters us. See bio_bwrite: the callback must be asked at most once per
    // entry, the way Secure Transport asks it.
    int              wblocked;
    // Plaintext accepted from the caller that the socket has not taken yet -- Secure
    // Transport's write queue. See sh_flush_write.
    unsigned char   *wpend;
    size_t           wpendLen;
} Shadow;

// Re-entrancy guard. Our verify path calls into Security, which may itself open a
// connection (revocation checks); without this, that nested connection would come back
// through our hooks and call Security again. Set around our own Security calls; hooks
// fall through to the system stack while it is set. pthread_specific rather than __thread
// because native TLS needs a 10.7+ deployment target.
void       tf_guard_enter(void);
void       tf_guard_leave(void);
int        tf_reentrant(void);

int        ensure_ready(void);
Shadow    *sh_get(SSLContextRef c);
Shadow    *sh_create(SSLContextRef c);
void       sh_release(Shadow *s);
void       sh_free(SSLContextRef c);
int        ossl_init(Shadow *s);
void       capture_identity(Shadow *s, CFArrayRef certRefs);
int        sh_build_trust(Shadow *s, SecTrustRef *trust);
CFArrayRef sh_cert_array(Shadow *s);
void       sh_unblock_write(Shadow *s);
void       sh_reset_write(Shadow *s);
int        sh_flush_write(Shadow *s);
int        sh_hold_write(Shadow *s, const void *data, size_t len);

// The largest run of a caller's buffer handed to one SSL_read or SSL_write, whose lengths are
// ints where SSLRead's and SSLWrite's dataLength is a size_t. Anything longer is transferred
// in several runs, so a caller may pass a buffer of any size -- as it may to Secure Transport,
// which fragments internally and documents no limit. Bounds the write queue too: a blocked run
// adds at most this much to it.
#define IO_RUN_MAX      ((size_t)65536)

#endif
