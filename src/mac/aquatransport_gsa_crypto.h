#ifndef AQUATRANSPORT_GSA_CRYPTO_H
#define AQUATRANSPORT_GSA_CRYPTO_H
#include <stddef.h>

/* Apple's SRP-6a variant: RFC 5054 2048-bit group, SHA-256, s2k/s2k_fo.
 * A context is single-use; no session key is exposed before server proof verification. */
typedef struct aq_srp aq_srp;
aq_srp *aq_srp_new(unsigned char public_key[256]);
int aq_srp_challenge(aq_srp *, const char *user, const void *password, size_t password_len,
                     const char *protocol, const void *salt, size_t salt_len,
                     unsigned iterations, const void *server, size_t server_len,
                     unsigned char proof[32]);
int aq_srp_verify(aq_srp *, const void *proof, size_t len, unsigned char key[32]);
void aq_srp_free(aq_srp *);
#endif
