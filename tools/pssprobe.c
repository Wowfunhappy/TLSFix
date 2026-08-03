// pssprobe -- does the Keychain sign the way the mTLS path needs it to?
//
// rsa_seckey_priv_enc() needs two things from the Keychain that the OS X headers do not
// document: PKCS#1 signing, and a bare private-key operation for PSS. Both go through APIs
// declared only in the iOS SDK, so this measures the behaviour rather than assuming it.
//
// On OS X, SecKeyRawSign's kSecPaddingNone is not a raw operation -- it still applies PKCS#1
// v1.5 padding, and inputs above blocksize-11 come back errSecInputLengthError, so "None"
// means no DigestInfo rather than no padding. SecKeyDecrypt with kSecPaddingNone is the raw
// operation, taking exactly one block, and is what the PSS path uses.
//
// This drives the production signing callback end to end: build the same public-only RSA with
// the same custom method, sign through EVP exactly as OpenSSL's TLS 1.2 CertificateVerify
// does, then verify against the plain public key. A pass means a real server would have
// accepted the signature. The stress pass covers the short-block guard: a raw result is
// m^d mod n, so it carries a leading zero byte about 1 time in 256, and OpenSSL uses the
// returned length verbatim as the signature length.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Ibuild/openssl/include \
//       -o /tmp/pssprobe tools/pssprobe.c build/openssl/lib/libcrypto.a \
//       -framework Security -framework CoreFoundation

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <string.h>
#include <stdio.h>

extern OSStatus SecKeyRawSign(SecKeyRef key, SecPadding padding,
                              const uint8_t *dataToSign, size_t dataToSignLen,
                              uint8_t *sig, size_t *sigLen);
extern OSStatus SecKeyDecrypt(SecKeyRef key, SecPadding padding,
                              const uint8_t *cipherText, size_t cipherTextLen,
                              uint8_t *plainText, size_t *plainTextLen);

static RSA_METHOD *gRsaMeth;
static int gRsaExIdx;
static unsigned long gShort;   // times the Keychain returned a short block (leading zeros)

// Verbatim copy of src/aquatransport_engine.c -- keep in sync.
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
        if ((size_t)flen != blk) return -1;
        st = SecKeyDecrypt(key, kSecPaddingNone, from, (size_t)flen, to, &tlen);
    } else return -1;
    if (st != errSecSuccess) { fprintf(stderr, "      OSStatus %d\n", (int)st); return -1; }
    if (tlen == 0 || tlen > blk) return -1;
    if (tlen < blk) {
        gShort++;
        memmove(to + (blk - tlen), to, tlen);
        memset(to, 0, blk - tlen);
        tlen = blk;
    }
    return (int)tlen;
}

// The public-only RSA the handshake callback builds, with signing redirected to the Keychain.
static EVP_PKEY *shadow_key(SecKeyRef priv, RSA *pub) {
    const BIGNUM *n = NULL, *e = NULL;
    RSA_get0_key(pub, &n, &e, NULL);
    RSA *r = RSA_new();
    if (!r || !RSA_set0_key(r, BN_dup(n), BN_dup(e), NULL)) return NULL;
    RSA_set_method(r, gRsaMeth);
    RSA_set_ex_data(r, gRsaExIdx, priv);
    EVP_PKEY *pk = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pk, r);
    return pk;
}

static int try_sign_msg(SecKeyRef priv, RSA *pub, int pss,
                        const unsigned char *msg, size_t msglen) {
    EVP_PKEY *shadow = shadow_key(priv, pub), *plain = EVP_PKEY_new();
    RSA *pubdup = RSAPublicKey_dup(pub);
    EVP_PKEY_assign_RSA(plain, pubdup);

    unsigned char sig[1024]; size_t siglen = sizeof(sig);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int ok = 0;

    if (EVP_DigestSignInit(md, &pctx, EVP_sha256(), NULL, shadow) != 1) goto done;
    if (pss) {
        // What OpenSSL sets up for an rsa_pss_rsae_sha256 CertificateVerify.
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) goto done;
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1) goto done;
    }
    if (EVP_DigestSign(md, sig, &siglen, msg, msglen) != 1) goto done;

    EVP_MD_CTX *vmd = EVP_MD_CTX_new();
    EVP_PKEY_CTX *vctx = NULL;
    if (EVP_DigestVerifyInit(vmd, &vctx, EVP_sha256(), NULL, plain) == 1) {
        if (!pss || (EVP_PKEY_CTX_set_rsa_padding(vctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                     EVP_PKEY_CTX_set_rsa_pss_saltlen(vctx, RSA_PSS_SALTLEN_DIGEST) == 1))
            ok = (EVP_DigestVerify(vmd, sig, siglen, msg, msglen) == 1);
    }
    EVP_MD_CTX_free(vmd);
    if (ok && siglen != (size_t)EVP_PKEY_size(plain)) {
        printf("      wrong signature length %zu\n", siglen);
        ok = 0;
    }
done:
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(shadow);
    EVP_PKEY_free(plain);
    return ok;
}

int main(void) {
    gRsaMeth = RSA_meth_dup(RSA_get_default_method());
    RSA_meth_set_priv_enc(gRsaMeth, rsa_seckey_priv_enc);
    gRsaExIdx = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    // Transient keypair -- nothing is written to the user's keychain.
    CFMutableDictionaryRef p = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                                                        &kCFTypeDictionaryValueCallBacks);
    int bits = 2048;
    CFNumberRef nb = CFNumberCreate(NULL, kCFNumberIntType, &bits);
    CFDictionarySetValue(p, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionarySetValue(p, kSecAttrKeySizeInBits, nb);
    CFDictionarySetValue(p, kSecAttrIsPermanent, kCFBooleanFalse);

    SecKeyRef priv = NULL, pubk = NULL;
    OSStatus st = SecKeyGeneratePair(p, &pubk, &priv);
    if (st != errSecSuccess || !priv) { printf("SecKeyGeneratePair failed: %d\n", (int)st); return 2; }
    printf("generated a transient 2048-bit RSA key (block size %zu)\n", SecKeyGetBlockSize(priv));

    // Pull the public half out as DER so OpenSSL can verify independently.
    CFDataRef der = NULL;
    st = SecItemExport(pubk, kSecFormatBSAFE, 0, NULL, &der);
    if (st != errSecSuccess || !der) { printf("SecItemExport failed: %d\n", (int)st); return 2; }
    const unsigned char *dp = CFDataGetBytePtr(der);
    RSA *pub = d2i_RSAPublicKey(NULL, &dp, CFDataGetLength(der));
    if (!pub) { printf("could not parse exported public key\n"); return 2; }

    static const unsigned char msg[] = "aquatransport certificate verify";
    int pkcs1 = try_sign_msg(priv, pub, 0, msg, sizeof(msg) - 1);
    printf("  PKCS#1 v1.5 (SecKeyRawSign, kSecPaddingPKCS1): %s\n", pkcs1 ? "OK" : "FAILED");
    int pss = try_sign_msg(priv, pub, 1, msg, sizeof(msg) - 1);
    printf("  RSA-PSS     (SecKeyDecrypt, kSecPaddingNone): %s\n", pss ? "OK" : "FAILED");

    // Shake out the short-block guard: at ~1/256 a few thousand signatures should trip it.
    const int N = 4000;
    int bad = 0;
    unsigned char m[32];
    for (int i = 0; i < N; i++) {
        memset(m, 0, sizeof(m));
        memcpy(m, &i, sizeof(i));
        if (!try_sign_msg(priv, pub, 1, m, sizeof(m))) bad++;
    }
    printf("\nstress: %d PSS signatures, %d failed to verify, %lu needed left-padding\n",
           N, bad, gShort);

    int ok = pkcs1 && pss && bad == 0;
    printf("\n%s\n", ok
        ? "both paths verify -- mTLS can sign whichever the server picks"
        : "FAILURE: the mTLS signing path would break against a server that picks the failing mode");
    return ok ? 0 : 1;
}
