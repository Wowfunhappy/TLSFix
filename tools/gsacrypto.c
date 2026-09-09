/* Include implementation to set a deterministic private exponent in this test only. */
#include "../src/mac/aquatransport_gsa_crypto.c"
#include <assert.h>
#include <stdio.h>
#include "gsa-vectors.h"

static aq_srp *fixture(void) {
    unsigned char A[256], a[32]; memset(a, 0xdd, sizeof a);
    aq_srp *s = aq_srp_new(A); assert(s);
    BN_CTX *ctx = BN_CTX_new(); assert(ctx);
    const SRP_gN *group = SRP_get_default_gN("2048");
    assert(BN_bin2bn(a, sizeof a, s->a));
    assert(BN_mod_exp(s->A, group->g, s->a, group->N, ctx));
    BN_CTX_free(ctx); return s;
}
static int challenge(aq_srp *s, const char *protocol, const void *salt, size_t sl,
                     const void *B, size_t bl, unsigned rounds, unsigned char M[32]) {
    return aq_srp_challenge(s, "test@example.invalid", "synthetic:password", 18,
                           protocol, salt, sl, rounds, B, bl, M);
}
int main(void) {
    const unsigned char *salts[] = {salt0, salt1, salt2, salt3, salt4}, *servers[] = {B0, B1, B2, B3, B4};
    const unsigned char *proofs[] = {M10, M11, M12, M13, M14}, *replies[] = {M20, M21, M22, M23, M24}, *keys[] = {K0, K1, K2, K3, K4};
    size_t lengths[] = {sizeof salt0, sizeof salt1, sizeof salt2, sizeof salt3, sizeof salt4};
    unsigned char M[32], key[32], bad[257] = {0};
    for (int i = 0; i < 5; i++) {
        aq_srp *s = fixture();
        if (i == 3) { assert(BN_set_word(s->a, 1)); assert(BN_set_word(s->A, 2)); }
        assert(!aq_srp_verify(s, replies[i], 32, key));
        assert(challenge(s, i == 1 ? "s2k_fo" : "s2k", salts[i], lengths[i], servers[i], 256, 5, M));
        assert(!memcmp(M, proofs[i], 32));
        assert(aq_srp_verify(s, replies[i], 32, key)); assert(!memcmp(key, keys[i], 32));
        assert(!aq_srp_verify(s, replies[i], 32, key)); aq_srp_free(s);
    }
    for (int i = 0; i < 7; i++) {
        aq_srp *s = fixture();
        if (i == 0) assert(!challenge(s, "other", salt0, sizeof salt0, B0, 256, 5, M));
        if (i == 1) assert(!challenge(s, "s2k", salt0, sizeof salt0, B0, 256, 0, M));
        if (i == 2) assert(!challenge(s, "s2k", salt0, sizeof salt0, B0, 256, 1000001, M));
        if (i == 3) assert(!challenge(s, "s2k", salt0, sizeof salt0, bad, 256, 5, M));
        if (i == 4) assert(!challenge(s, "s2k", salt0, sizeof salt0, bad, 257, 5, M));
        if (i == 5) {
            BN_bn2binpad(SRP_get_default_gN("2048")->N, bad, 256);
            assert(!challenge(s, "s2k", salt0, sizeof salt0, bad, 256, 5, M));
        }
        if (i == 6) assert(!challenge(s, "s2k", NULL, 0, B0, 256, 5, M));
        aq_srp_free(s);
    }
    for (int i = 0; i < 3; i++) {
        aq_srp *s = fixture(); memset(key, 0xa5, sizeof key);
        assert(challenge(s, "s2k", salt0, sizeof salt0, B0, 256, 5, M));
        assert(!challenge(s, "s2k", salt0, sizeof salt0, B0, 256, 5, M));
        assert(!aq_srp_verify(s, i == 0 ? bad : M20, i == 1 ? 31 : i == 2 ? 33 : 32, key));
        for (int j = 0; j < 32; j++) assert(key[j] == 0xa5);
        assert(!aq_srp_verify(s, M20, 32, key)); aq_srp_free(s);
    }
    puts("PASS: SRP server vectors, s2k/s2k_fo, leading-zero salt/public key/secret, invalid challenges, proof lengths, one-shot verification");
    return 0;
}
