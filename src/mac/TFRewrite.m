// URL rewriting for TLSFix: redirects.txt and headers.txt.
//
// This lives in a separate bundle from tlsfix.dylib, dlopen'd only when Foundation is
// already present in the process. Two reasons:
//
//   * tlsfix.dylib is inserted into *every* process via DYLD_INSERT_LIBRARIES. If it
//     linked Foundation, every daemon on the system would load Foundation too.
//   * dlopen failure is recoverable; a failed dyld insertion is fatal to every process
//     launch. The riskier half of the project belongs on the recoverable side.
//
// Rewriting happens at the request layer rather than in the TLS stream because the
// interesting rules change the destination host, and by the time SSLWrite runs CFNetwork
// has already resolved DNS, connected TCP, and completed a handshake against the original
// host. NSURLProtocol runs before any of that, so CFNetwork performs DNS, SNI and
// certificate validation against the rewritten host -- and http:// rules and http->https
// upgrades work too, which a TLS-layer hook cannot see at all.
//
// Written MRC with explicit ivars: on 10.6 the i386 runtime is the legacy Objective-C
// runtime, which has neither ARC nor non-fragile ivars.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include "tlsfix_config.h"

static NSString *const kTFHandled = @"TLSFixHandled";

@interface TFURLProtocol : NSURLProtocol {
    NSURLConnection *_conn;
}
@end

// Returns the header rule block matching this URL, or NULL.
static const tf_headerrule *tf_match_headers(NSString *url) {
    const tf_headerrule *rules = NULL;
    int n = tf_headerrules(&rules);
    const char *u = [url UTF8String];
    if (!u) return NULL;
    for (int i = 0; i < n; i++)
        if (tf_glob_prefix(rules[i].pattern, u)) return &rules[i];
    return NULL;
}

// Splits "Name: value" into its two halves.
static BOOL tf_split_header(const char *line, NSString **name, NSString **value) {
    const char *colon = strchr(line, ':');
    if (!colon || colon == line) return NO;
    NSString *n = [[[NSString alloc] initWithBytes:line length:(colon - line)
                                          encoding:NSUTF8StringEncoding] autorelease];
    const char *v = colon + 1;
    while (*v == ' ' || *v == '\t') v++;
    NSString *val = [NSString stringWithUTF8String:v];
    if (!n || !val) return NO;
    *name = n; *value = val;
    return YES;
}

@implementation TFURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if (tf_flag("disabled") || tf_flag("disabled-rewrite")) return NO;
    // Our own re-dispatched request must not match again, or we would recurse forever.
    if ([NSURLProtocol propertyForKey:kTFHandled inRequest:request]) return NO;

    NSString *url = [[request URL] absoluteString];
    if (!url) return NO;
    const char *u = [url UTF8String];
    if (!u) return NO;

    char *redirected = tf_apply_redirect(u);
    if (redirected) { free(redirected); return YES; }
    return tf_match_headers(url) != NULL;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }

+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    return [super requestIsCacheEquivalent:a toRequest:b];
}

- (void)startLoading {
    NSMutableURLRequest *req = [[self request] mutableCopy];
    NSString *original = [[[self request] URL] absoluteString];

    // Redirect first: a rewritten URL may match a different header rule than the original.
    const char *u = [original UTF8String];
    char *redirected = u ? tf_apply_redirect(u) : NULL;
    if (redirected) {
        NSString *newURL = [NSString stringWithUTF8String:redirected];
        free(redirected);
        NSURL *nu = newURL ? [NSURL URLWithString:newURL] : nil;
        if (nu) {
            [req setURL:nu];
            // Host-bearing headers set for the old host must not follow us to the new one.
            [req setValue:nil forHTTPHeaderField:@"Host"];
        }
    }

    NSString *effective = [[req URL] absoluteString];
    const tf_headerrule *hr = effective ? tf_match_headers(effective) : NULL;
    if (hr) {
        for (int i = 0; i < hr->nlines; i++) {
            NSString *name = nil, *value = nil;
            if (tf_split_header(hr->lines[i], &name, &value))
                [req setValue:value forHTTPHeaderField:name];
        }
    }

    [NSURLProtocol setProperty:[NSNumber numberWithBool:YES] forKey:kTFHandled inRequest:req];
    _conn = [[NSURLConnection alloc] initWithRequest:req delegate:self startImmediately:YES];
    [req release];
}

- (void)stopLoading {
    [_conn cancel];
    [_conn release];
    _conn = nil;
}

// NSURLConnection informal delegate methods, forwarded to our client. Declared without
// protocol conformance because NSURLConnectionDataDelegate is 10.7+.

- (void)connection:(NSURLConnection *)c didReceiveResponse:(NSURLResponse *)response {
    [[self client] URLProtocol:self didReceiveResponse:response
           cacheStoragePolicy:NSURLCacheStorageNotAllowed];
}

- (void)connection:(NSURLConnection *)c didReceiveData:(NSData *)data {
    [[self client] URLProtocol:self didLoadData:data];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)c {
    [[self client] URLProtocolDidFinishLoading:self];
}

- (void)connection:(NSURLConnection *)c didFailWithError:(NSError *)error {
    [[self client] URLProtocol:self didFailWithError:error];
}

- (NSURLRequest *)connection:(NSURLConnection *)c willSendRequest:(NSURLRequest *)request
            redirectResponse:(NSURLResponse *)response {
    // Server-issued redirects are reported upward so the caller sees the real chain;
    // our own rewrite is not a redirect and arrives with response == nil.
    if (response) {
        [[self client] URLProtocol:self wasRedirectedToRequest:request redirectResponse:response];
    }
    return request;
}

- (void)dealloc {
    [_conn release];
    [super dealloc];
}

@end

// Registered from the bundle's initialiser. tlsfix.dylib only dlopen's this bundle after
// confirming Foundation is loaded, so the runtime is up by the time this runs.
__attribute__((constructor))
static void tf_rewrite_init(void) {
    if (tf_flag("disabled") || tf_flag("disabled-rewrite")) return;
    if (!objc_getClass("NSURLProtocol")) return;
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    [NSURLProtocol registerClass:[TFURLProtocol class]];
    [pool release];
}
