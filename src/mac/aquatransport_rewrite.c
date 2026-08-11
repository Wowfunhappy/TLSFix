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
// A __DATA,__interpose section only affects images bound after the interposing library is
// registered, and dyld registers it only for libraries inserted at launch. This library
// arrives as a dependency of Security.framework, which a process may dlopen at any point, and
// an image loaded then changes nothing in a process whose imports are already bound.
//
// Interposing also matches by address rather than by name, so a hook cannot be installed
// until the target library is loaded and its symbols are addressable. Rebinding by name
// needs nothing loaded, so the library sits inert in a process without CFNetwork and starts
// working if and when CFNetwork arrives.
//
// THE HOOK POINTS come from experiment, not from headers. Sync and async funnel through
// different entry points, and the request argument position is the one found by recording
// pointers returned from the request-creating functions and testing the funnel arguments for
// pointer *equality* -- no guessed pointer is ever dereferenced:
//
//   CFURLConnectionSendSynchronousRequest   arg0 = CFURLRequestRef   (sync)
//   CFURLConnectionCreateWithProperties     arg1 = CFURLRequestRef   (async)
//   CFHTTPMessageCreateRequest              arg2 = CFURLRef          (raw stream)
//   CFHTTPMessageSetHeaderFieldValue        arg0 = CFHTTPMessageRef  (raw stream)
//
// A client that builds a CFHTTPMessage and opens a stream on it reaches none of the
// CFURLRequest entry points. Such a message also carries only the headers its author set, so
// the request can go out with no User-Agent at all, which some servers answer with an error
// instead of results.
//
// The message is taken at creation rather than at CFReadStreamCreateForHTTPRequest because that
// function is one applications replace for themselves: Dictionary bundles a ProxyFix.dylib that
// interposes it to route requests through the system proxy. Two hooks on one symbol each call
// what they take to be the original, which is the other, and the pair recurses until the stack
// is gone. Creation is uncontended.
//
// The setter is hooked because a caller may set headers after creating the message --
// DictionaryServices stamps User-Agent: AppleDictionaryService/208 over whatever is there. A
// write to a header a rule owns is dropped, leaving the rule's value; every other header is set
// as the caller asked.

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

// The CFHTTPMessage side, resolved the same way and for the same reason: a direct call would
// make CFNetwork a load-time dependency of this library. Nothing else interposes these, so the
// first definition in load order is CFNetwork's own.
static void *(*p_MsgCreate)(CFAllocatorRef, CFStringRef, CFURLRef, CFStringRef);
static void  (*p_MsgSetHeader)(void *, CFStringRef, CFStringRef);
static CFURLRef (*p_MsgURL)(void *);
static int g_msg_resolved;
static pthread_once_t g_msg_once = PTHREAD_ONCE_INIT;

static void resolve_msg_once(void) {
    p_MsgCreate    = (void *(*)(CFAllocatorRef, CFStringRef, CFURLRef, CFStringRef))
                     dlsym(RTLD_DEFAULT, "CFHTTPMessageCreateRequest");
    p_MsgSetHeader = (void (*)(void *, CFStringRef, CFStringRef))
                     dlsym(RTLD_DEFAULT, "CFHTTPMessageSetHeaderFieldValue");
    p_MsgURL       = (CFURLRef (*)(void *))dlsym(RTLD_DEFAULT, "CFHTTPMessageCopyRequestURL");
    g_msg_resolved = (p_MsgCreate && p_MsgSetHeader && p_MsgURL);
}
static int msg_resolved(void) { pthread_once(&g_msg_once, resolve_msg_once); return g_msg_resolved; }

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

// Both request objects take their headers through a setter of the same shape, so the rule is
// walked once here. A line with nothing after the colon removes the header: the setters take a
// NULL value as removal, where an empty string would send the header with an empty value.
typedef void (*hdr_set)(void *, CFStringRef, CFStringRef);

static void apply_header_rule(const tf_headerrule *hr, void *target, hdr_set set) {
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
        CFStringRef cv = *val ? CFStringCreateWithCString(NULL, val, kCFStringEncodingUTF8) : NULL;
        if (cn) { set(target, cn, cv); tf_log("header %s: %s", name, val); }
        if (cn) CFRelease(cn);
        if (cv) CFRelease(cv);
    }
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
    if (hr) apply_header_rule(hr, m, (hdr_set)p_SetHeader);
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
static fn6 o_SendSync, o_CreateWithProps, o_MutableCopy, o_MsgCreate, o_MsgSetHeader;

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

// The raw-stream path: rules applied to the URL the message is built around, and to the message
// once it exists.
static void *my_MsgCreate(void *alloc, void *method, void *url, void *version, void *e, void *f) {
    (void)e; (void)f;
    if (!msg_resolved() || !url) return o_MsgCreate(alloc, method, url, version, e, f);

    char *before = cf_to_c(CFURLGetString((CFURLRef)url));
    if (!before) return p_MsgCreate((CFAllocatorRef)alloc, (CFStringRef)method,
                                    (CFURLRef)url, (CFStringRef)version);

    char *after = tf_apply_redirect(before);
    const tf_headerrule *hr = match_headers(after ? after : before);

    CFURLRef use = (CFURLRef)url;
    CFStringRef ns = NULL;
    CFURLRef nu = NULL;
    if (after) {
        ns = CFStringCreateWithCString(NULL, after, kCFStringEncodingUTF8);
        nu = ns ? CFURLCreateWithString(NULL, ns, NULL) : NULL;
        if (nu) { use = nu; tf_log("rewrite %s -> %s", before, after); }
    }

    void *msg = p_MsgCreate((CFAllocatorRef)alloc, (CFStringRef)method, use, (CFStringRef)version);
    if (msg && hr) apply_header_rule(hr, msg, (hdr_set)p_MsgSetHeader);

    if (nu) CFRelease(nu);
    if (ns) CFRelease(ns);
    free(before); free(after);
    return msg;
}

// Does this rule set a header of this name? Compared case-insensitively, as header names are.
static int rule_sets_header(const tf_headerrule *hr, const char *name) {
    size_t n = strlen(name);
    for (int i = 0; i < hr->nlines; i++) {
        const char *colon = strchr(hr->lines[i], ':');
        if (!colon) continue;
        if ((size_t)(colon - hr->lines[i]) == n && strncasecmp(hr->lines[i], name, n) == 0) return 1;
    }
    return 0;
}

// A rule beats the application's own header.
//
// Setting headers when the message is created is not enough on its own: the caller sets its
// own afterwards and overwrites them. DictionaryServices does exactly that, stamping
// User-Agent: AppleDictionaryService/208 over the rule -- and that User-Agent is the whole
// reason the request needs rewriting. Dropping the caller's value for a header the rule
// controls leaves the rule's value, set at creation, in place.
//
// This is the setter, not the stream, deliberately: hooking CFReadStreamCreateForHTTPRequest
// would be the natural place to have the last word, and it is the one function another library
// here already interposes. Nothing contends for this one.
static void my_MsgSetHeader(void *msg, void *name, void *value, void *d, void *e, void *f) {
    if (!msg_resolved() || !msg || !name) { o_MsgSetHeader(msg, name, value, d, e, f); return; }

    char *hn = cf_to_c((CFStringRef)name);
    CFURLRef url = p_MsgURL(msg);
    char *before = url ? cf_to_c(CFURLGetString(url)) : NULL;
    if (url) CFRelease(url);
    if (!hn || !before) { free(hn); free(before); p_MsgSetHeader(msg, (CFStringRef)name, (CFStringRef)value); return; }

    char *after = tf_apply_redirect(before);
    const tf_headerrule *hr = match_headers(after ? after : before);
    int ours = (hr && rule_sets_header(hr, hn));
    if (ours) tf_log("header %s kept from rule, caller overruled", hn);
    free(hn); free(before); free(after);

    if (!ours) p_MsgSetHeader(msg, (CFStringRef)name, (CFStringRef)value);
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
        { "CFHTTPMessageCreateRequest",            (void *)my_MsgCreate,       (void **)&o_MsgCreate },
        { "CFHTTPMessageSetHeaderFieldValue",      (void *)my_MsgSetHeader,    (void **)&o_MsgSetHeader },
    };
    // Also arms a dyld add-image callback, so CFNetwork loaded later still gets rebound.
    rebind_symbols(r, 5);
}
