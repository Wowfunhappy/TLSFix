// Certificate-trust hooks for AquaTransport (10.6 - 10.9).
//
// One fishhook interception of SecTrustSetAnchorCertificates serves everything here. That
// call is how a caller restricts an evaluation to a fixed set of anchors -- i.e. how pinning
// is expressed -- and it runs after the trust's certificates and policies are set but before
// SecTrustEvaluate, so at hook time the whole shape of the evaluation is already known.
//
//   disable-certificate-pinning -- for every anchor-restricted evaluation, also honour the
//     system and keychain anchors (SecTrustSetAnchorCertificatesOnly false). This defeats
//     pinning process-wide, which is what someone monitoring their own machine's traffic with
//     a locally trusted proxy root wants. Broad and off by default.
//
// CALLING THE ORIGINAL -- as in the SSL hooks, never call SecTrustSetAnchorCertificates by
// name from here: fishhook has rebound it in every image, including this one, so the name now
// resolves to the replacement. o_SecTrustSetAnchorCertificates comes from dlsym(RTLD_DEFAULT),
// which resolves through the symbol table to the real implementation.

#include "../aquatransport.h"
#include "aquatransport_config.h"
#include "../../deps/fishhook/fishhook.h"
#include <pthread.h>
#include <dlfcn.h>

static OSStatus (*o_SecTrustSetAnchorCertificates)(SecTrustRef, CFArrayRef);
static OSStatus (*o_SecTrustSetAnchorCertificatesOnly)(SecTrustRef, Boolean);

static pthread_once_t g_trust_once = PTHREAD_ONCE_INIT;
static int g_trust_ok = 0;

static void resolve_trust_origs(void) {
    o_SecTrustSetAnchorCertificates =
        (OSStatus (*)(SecTrustRef, CFArrayRef))dlsym(RTLD_DEFAULT, "SecTrustSetAnchorCertificates");
    o_SecTrustSetAnchorCertificatesOnly =
        (OSStatus (*)(SecTrustRef, Boolean))dlsym(RTLD_DEFAULT, "SecTrustSetAnchorCertificatesOnly");
    g_trust_ok = (o_SecTrustSetAnchorCertificates != NULL);
}

// True once the original entry point is resolved. The hook only runs when Security is loaded
// (that is what put the call site there), so this succeeds in practice; the guard keeps the
// original pointer from ever being dereferenced NULL.
static int trust_ready(void) {
    pthread_once(&g_trust_once, resolve_trust_origs);
    return g_trust_ok;
}

static OSStatus my_SecTrustSetAnchorCertificates(SecTrustRef trust, CFArrayRef anchors) {
    if (!trust_ready()) return errSecNotAvailable;

    // Untouched while inside our own trust evaluation, so a verify path that set anchors would
    // not be reshaped by us; and untouched when there is no trust to act on.
    if (!trust || tf_reentrant())
        return o_SecTrustSetAnchorCertificates(trust, anchors);

    OSStatus r = o_SecTrustSetAnchorCertificates(trust, anchors);

    if (tf_flag("disable-certificate-pinning") && o_SecTrustSetAnchorCertificatesOnly)
        o_SecTrustSetAnchorCertificatesOnly(trust, false);

    return r;
}

// Rebinds SecTrustSetAnchorCertificates. Called from the constructor after the process is
// found eligible, so denied processes never carry this hook. Rebinding needs nothing loaded:
// a process that never reaches Security has no call site to rewrite, and fishhook's add-image
// callback rebinds Security whenever it arrives.
void tf_trust_install(void) {
    struct rebinding r[1];
    r[0].name        = "SecTrustSetAnchorCertificates";
    r[0].replacement = (void *)my_SecTrustSetAnchorCertificates;
    r[0].replaced    = NULL;
    rebind_symbols(r, 1);
}
