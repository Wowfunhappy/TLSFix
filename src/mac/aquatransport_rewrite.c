// URL rewriting in pure C, on CFNetwork's own C API.
//
// WHY NOT NSURLProtocol
//
// An Objective-C NSURLProtocol bundle would have to dlopen into each process, pulling
// Foundation and the ObjC runtime in before main() -- fatal to anything that forks without
// exec: sshd's privilege-separation child aborts in libdispatch and every ssh connection
// dies, and loginwindow hits a login-keychain failure. No per-process gate avoids it --
// "a Foundation symbol is resolvable" is true inside sshd, and "the main executable links
// Foundation" excludes Safari and WebProcess (they reach it through WebKit) while including
// loginwindow. Excluding processes by name only hides the fragility. Pure C on CFNetwork's
// own API touches none of that.
//
// Foundation's own URL loading is built on the C API used here (Foundation imports 69 of
// these symbols on 10.9, 53 on 10.6.8), so working at this level covers NSURLConnection,
// NSURLSession and raw CFNetwork clients while touching no Objective-C at all.
//
// WHY fishhook RATHER THAN dyld INTERPOSING
//
// Interposing needs the target symbol's address at link time, which would mean linking
// CFNetwork -- impossible across this version range, because the install name differs:
//
//   10.9  /System/Library/Frameworks/CFNetwork.framework/Versions/A/CFNetwork
//   10.6  /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/...
//
// A dylib linked against either path fails to load at all on the other OS. fishhook rebinds
// by *name* at runtime, so nothing is linked and processes without CFNetwork are untouched.
//
// THE HOOK POINTS come from experiment, not from headers. Sync and async funnel through
// different entry points, and the request argument position is the one found by recording
// pointers returned from the request-creating functions and testing the funnel arguments for
// pointer *equality* -- no guessed pointer is ever dereferenced:
//
//   CFURLConnectionSendSynchronousRequest   arg0 = CFURLRequestRef   (sync)
//   CFURLConnectionCreateWithProperties     arg1 = CFURLRequestRef   (async)

#include "aquatransport_config.h"
#include "../../deps/fishhook/fishhook.h"
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef void *(*fn6)(void *, void *, void *, void *, void *, void *);

// Resolved at first use with dlsym rather than linked. By the time a hook runs we are
// inside a CFNetwork call, so CFNetwork is loaded and these always resolve.
static CFURLRef (*p_GetURL)(void *);
static void    *(*p_MutableCopy)(CFAllocatorRef, void *);
static void     (*p_SetURL)(void *, CFURLRef);
static void     (*p_SetHeader)(void *, CFStringRef, CFStringRef);
static int       g_resolved;
static pthread_once_t g_resolve_once = PTHREAD_ONCE_INIT;

static void resolve_once(void) {
    p_GetURL      = (CFURLRef (*)(void *))dlsym(RTLD_DEFAULT, "CFURLRequestGetURL");
    p_MutableCopy = (void *(*)(CFAllocatorRef, void *))dlsym(RTLD_DEFAULT, "CFURLRequestCreateMutableCopy");
    p_SetURL      = (void (*)(void *, CFURLRef))dlsym(RTLD_DEFAULT, "CFURLRequestSetURL");
    p_SetHeader   = (void (*)(void *, CFStringRef, CFStringRef))dlsym(RTLD_DEFAULT, "CFURLRequestSetHTTPHeaderFieldValue");
    g_resolved = (p_GetURL && p_MutableCopy && p_SetURL && p_SetHeader);
}
static int resolved(void) { pthread_once(&g_resolve_once, resolve_once); return g_resolved; }

static char *cf_to_c(CFStringRef s) {
    if (!s) return NULL;
    CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
    char *buf = (char *)malloc((size_t)max);
    if (!buf) return NULL;
    if (!CFStringGetCString(s, buf, max, kCFStringEncodingUTF8)) { free(buf); return NULL; }
    return buf;
}

static const tf_headerrule *match_headers(const char *url) {
    const tf_headerrule *rules = NULL;
    int n = tf_headerrules(&rules);
    for (int i = 0; i < n; i++)
        if (tf_scope_matches(rules[i].scope) && tf_glob_prefix(rules[i].pattern, url))
            return &rules[i];
    return NULL;
}

// Applies the rules to an already-mutable request, in place. Returns 1 if anything
// changed. Idempotent: an applied redirect leaves a URL the rule's "from" prefix does not
// match, so a second pass over the same request does nothing.
static int apply_rules(void *m) {
    if (!m || !resolved()) return 0;

    CFURLRef url = p_GetURL(m);
    if (!url) return 0;
    char *before = cf_to_c(CFURLGetString(url));
    if (!before) return 0;

    char *after = tf_apply_redirect(before);
    const char *effective = after ? after : before;
    const tf_headerrule *hr = match_headers(effective);
    if (!after && !hr) { free(before); return 0; }

    if (after) {
        CFStringRef s = CFStringCreateWithCString(NULL, after, kCFStringEncodingUTF8);
        CFURLRef nu = s ? CFURLCreateWithString(NULL, s, NULL) : NULL;
        if (nu) {
            p_SetURL(m, nu);
            // Host is derived from the URL; a stale explicit one would follow us to the
            // new host and be wrong.
            //
            // Built rather than written as CFSTR("Host"): a constant CFString is a *data*
            // reference to CoreFoundation (___CFConstantStringClassReference), and the one
            // thing lazy linking does not allow is a data reference. Lazy linking is what
            // lets this library be loaded into a process that has not initialised
            // CoreFoundation, which is what removes the need for any load-time gate.
            CFStringRef hostKey = CFStringCreateWithCString(NULL, "Host", kCFStringEncodingUTF8);
            if (hostKey) { p_SetHeader(m, hostKey, NULL); CFRelease(hostKey); }
            CFRelease(nu);
        }
        if (s) CFRelease(s);
        tf_log("rewrite %s -> %s", before, after);
    }
    if (hr) {
        for (int i = 0; i < hr->nlines; i++) {
            const char *line = hr->lines[i];
            const char *colon = strchr(line, ':');
            if (!colon || colon == line) continue;
            char name[128];
            size_t nl = (size_t)(colon - line);
            if (nl >= sizeof name) continue;
            memcpy(name, line, nl); name[nl] = 0;
            const char *val = colon + 1;
            while (*val == ' ' || *val == '\t') val++;
            CFStringRef cn = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
            CFStringRef cv = CFStringCreateWithCString(NULL, val, kCFStringEncodingUTF8);
            if (cn && cv) { p_SetHeader(m, cn, cv); tf_log("header %s: %s", name, val); }
            if (cn) CFRelease(cn);
            if (cv) CFRelease(cv);
        }
    }
    free(before); free(after);
    return 1;
}

// Copies an immutable request and applies the rules, or returns NULL when nothing matched
// and the caller should use the original untouched. The caller releases the result.
// p_MutableCopy is the real function resolved by dlsym, not our hook, so this does not
// recurse into my_MutableCopy below.
static void *rewritten(void *req) {
    if (!req || !resolved()) return NULL;
    void *m = p_MutableCopy(NULL, req);
    if (!m) return NULL;
    if (apply_rules(m)) return m;
    CFRelease(m);
    return NULL;
}

// Hooks call through to the ORIGINAL captured by fishhook, so a request we rewrote is
// never re-entered through the same hook.
static fn6 o_SendSync, o_CreateWithProps, o_MutableCopy;

static void *my_SendSync(void *a, void *b, void *c, void *d, void *e, void *f) {
    void *m = rewritten(a);
    void *r = o_SendSync(m ? m : a, b, c, d, e, f);
    if (m) CFRelease(m);
    return r;
}

static void *my_CreateWithProps(void *a, void *b, void *c, void *d, void *e, void *f) {
    void *m = rewritten(b);
    void *r = o_CreateWithProps(a, m ? m : b, c, d, e, f);
    if (m) CFRelease(m);
    return r;
}

// The universal funnel. Measured on 10.9: every path makes a mutable copy of the request
// before sending it -- synchronous NSURLConnection, asynchronous NSURLConnection, and
// NSURLSession alike. NSURLSession matters especially because it touches none of the
// CFURLConnection* entry points at all, so without this hook it would go unrewritten.
// The result is already mutable, so the rules are applied to it directly.
static void *my_MutableCopy(void *a, void *b, void *c, void *d, void *e, void *f) {
    void *m = o_MutableCopy(a, b, c, d, e, f);
    if (m) apply_rules(m);
    return m;
}

// Six pointer parameters are declared on purpose. The real arities are 4; on both x86_64
// and i386 passing more arguments than the callee reads is harmless, whereas declaring
// fewer than the real count would make the callee read uninitialised registers or stack.
// This keeps the pass-through safe without depending on private headers being exact.
void tf_rewrite_install(void) {
    struct rebinding r[] = {
        { "CFURLRequestCreateMutableCopy",         (void *)my_MutableCopy,     (void **)&o_MutableCopy },
        { "CFURLConnectionSendSynchronousRequest", (void *)my_SendSync,        (void **)&o_SendSync },
        { "CFURLConnectionCreateWithProperties",   (void *)my_CreateWithProps, (void **)&o_CreateWithProps },
    };
    // Also arms a dyld add-image callback, so CFNetwork loaded later still gets rebound.
    rebind_symbols(r, 3);
}
