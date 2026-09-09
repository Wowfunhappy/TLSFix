/* Independent implementation of the wire variant used by GSAPort.
 * See docs/ICLOUD.md for protocol references and validation limits. */
#include "aquatransport_gsa_crypto.h"
#include <openssl/bn.h>
#include <openssl/srp.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

struct aq_srp {
    BIGNUM *a, *A;
    unsigned char key[32], expected[32];
    int challenged;
};

static int hash_bn(SHA256_CTX *h, const BIGNUM *n, int padded) {
    unsigned char b[256];
    int len = padded ? BN_bn2binpad(n, b, sizeof b) : BN_bn2bin(n, b);
    if (len < 0 || len > sizeof b) return 0;
    SHA256_Update(h, b, len);
    OPENSSL_cleanse(b, sizeof b);
    return 1;
}

aq_srp *aq_srp_new(unsigned char public_key[256]) {
    const SRP_gN *group = SRP_get_default_gN("2048");
    aq_srp *s = calloc(1, sizeof *s);
    BN_CTX *ctx = BN_CTX_new();
    if (!s || !ctx || !group) goto fail;
    s->a = BN_secure_new(); s->A = BN_new();
    if (!s->a || !s->A || !BN_priv_rand(s->a, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) goto fail;
    BN_set_flags(s->a, BN_FLG_CONSTTIME);
    if (!BN_mod_exp_mont_consttime(s->A, group->g, s->a, group->N, ctx, NULL) ||
        BN_bn2binpad(s->A, public_key, 256) != 256) goto fail;
    BN_CTX_free(ctx);
    return s;
fail:
    BN_CTX_free(ctx); aq_srp_free(s); return NULL;
}

int aq_srp_challenge(aq_srp *s, const char *user, const void *password, size_t password_len,
                     const char *protocol, const void *salt, size_t salt_len,
                     unsigned iterations, const void *server, size_t server_len,
                     unsigned char proof[32]) {
    const SRP_gN *group = SRP_get_default_gN("2048");
    unsigned char digest[32], derived[32], hn[32], hg[32], mix[32];
    char hex[64];
    SHA256_CTX h;
    int ok = 0;
    BN_CTX *ctx = NULL;
    if (!s || s->challenged || !group || !user || !password || !protocol ||
        !salt || !salt_len || salt_len > 1024 || !server || !server_len || server_len > 256 ||
        !iterations || iterations > 1000000 || password_len > 1024*1024 ||
        (strcmp(protocol, "s2k") && strcmp(protocol, "s2k_fo"))) return 0;
    s->challenged = -1; /* A failed challenge cannot be reused. */
    ctx = BN_CTX_secure_new();
    if (!ctx) return 0;
    BN_CTX_start(ctx);
    BIGNUM *B = BN_CTX_get(ctx), *u = BN_CTX_get(ctx), *x = BN_CTX_get(ctx);
    BIGNUM *k = BN_CTX_get(ctx), *v = BN_CTX_get(ctx), *base = BN_CTX_get(ctx);
    BIGNUM *exponent = BN_CTX_get(ctx), *secret = BN_CTX_get(ctx);
    if (!secret || !BN_bin2bn(server, (int)server_len, B) || BN_is_zero(B) ||
        BN_cmp(B, group->N) >= 0) goto done;

    SHA256(password, password_len, digest);
    for (int i = 0; i < 32; i++) {
        hex[2*i] = "0123456789abcdef"[digest[i] >> 4];
        hex[2*i+1] = "0123456789abcdef"[digest[i] & 15];
    }
    int fo = !strcmp(protocol, "s2k_fo");
    if (!PKCS5_PBKDF2_HMAC(fo ? hex : (char *)digest, fo ? 64 : 32,
                           salt, (int)salt_len, iterations, EVP_sha256(), 32, derived)) goto done;
    SHA256_Init(&h); SHA256_Update(&h, ":", 1); SHA256_Update(&h, derived, 32);
    SHA256_Final(digest, &h);
    /* Salt is an octet string: leading zero bytes must survive. */
    SHA256_Init(&h); SHA256_Update(&h, salt, salt_len); SHA256_Update(&h, digest, 32);
    SHA256_Final(digest, &h);
    if (!BN_bin2bn(digest, 32, x)) goto done;
    BN_set_flags(x, BN_FLG_CONSTTIME);
    SHA256_Init(&h); hash_bn(&h, s->A, 1); hash_bn(&h, B, 1); SHA256_Final(digest, &h);
    if (!BN_bin2bn(digest, 32, u) || BN_is_zero(u)) goto done;
    SHA256_Init(&h); hash_bn(&h, group->N, 1); hash_bn(&h, group->g, 1); SHA256_Final(digest, &h);
    if (!BN_bin2bn(digest, 32, k) ||
        !BN_mod_exp_mont_consttime(v, group->g, x, group->N, ctx, NULL) ||
        !BN_mod_mul(base, k, v, group->N, ctx) ||
        !BN_mod_sub(base, B, base, group->N, ctx) || BN_is_zero(base) ||
        !BN_mul(exponent, u, x, ctx) || !BN_add(exponent, exponent, s->a)) goto done;
    BN_set_flags(exponent, BN_FLG_CONSTTIME);
    if (!BN_mod_exp_mont_consttime(secret, base, exponent, group->N, ctx, NULL) || BN_is_zero(secret)) goto done;
    /* CoreCrypto's SRP6a_HASH variant hashes fixed-width group integers,
     * including S and the A/B values in the authentication proof. */
    SHA256_Init(&h); hash_bn(&h, secret, 1); SHA256_Final(s->key, &h);
    SHA256_Init(&h); hash_bn(&h, group->N, 1); SHA256_Final(hn, &h);
    SHA256_Init(&h); hash_bn(&h, group->g, 1); SHA256_Final(hg, &h);
    for (int i = 0; i < 32; i++) mix[i] = hn[i] ^ hg[i];
    SHA256((const unsigned char *)user, strlen(user), digest);
    SHA256_Init(&h); SHA256_Update(&h, mix, 32); SHA256_Update(&h, digest, 32);
    SHA256_Update(&h, salt, salt_len); hash_bn(&h, s->A, 1); hash_bn(&h, B, 1);
    SHA256_Update(&h, s->key, 32); SHA256_Final(proof, &h);
    SHA256_Init(&h); hash_bn(&h, s->A, 1); SHA256_Update(&h, proof, 32);
    SHA256_Update(&h, s->key, 32); SHA256_Final(s->expected, &h);
    s->challenged = 1; ok = 1;
done:
    OPENSSL_cleanse(digest, sizeof digest); OPENSSL_cleanse(derived, sizeof derived);
    OPENSSL_cleanse(hex, sizeof hex); OPENSSL_cleanse(&h, sizeof h);
    BN_CTX_end(ctx); BN_CTX_free(ctx);
    return ok;
}

int aq_srp_verify(aq_srp *s, const void *proof, size_t len, unsigned char key[32]) {
    if (!s || s->challenged != 1) return 0;
    s->challenged = -1;
    if (!proof || len != 32 || CRYPTO_memcmp(proof, s->expected, 32)) return 0;
    memcpy(key, s->key, 32);
    OPENSSL_cleanse(s->key, sizeof s->key);
    return 1;
}

void aq_srp_free(aq_srp *s) {
    if (!s) return;
    BN_clear_free(s->a); BN_clear_free(s->A);
    OPENSSL_cleanse(s, sizeof *s); free(s);
}
