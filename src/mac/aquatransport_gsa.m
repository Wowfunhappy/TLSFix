/* iCloud authentication adapter for OS X 10.7–10.9.
 * Loaded at request time by the C rewriter, never by Security's constructor.
 * Manual retain/release + GC support are intentional (System Preferences uses GC).
 */
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <syslog.h>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include "aquatransport_config.h"
#include "aquatransport_gsa_crypto.h"
#include "aquatransport_gsa_mail.h"

static NSString *const AQHandled = @"AquaTransportGSAHandled";
static NSString *const AQErrorDomain = @"AquaTransport.iCloud";
static NSString *const AQClient = @"<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
static NSOperationQueue *AQQueue;
static NSMutableDictionary *AQPending;

static id aq_dict(id v) { return [v isKindOfClass:[NSDictionary class]] ? v : nil; }
static NSString *aq_string(id v) { return [v isKindOfClass:[NSString class]] && [v length] ? v : nil; }
static NSData *aq_data(id v) { return [v isKindOfClass:[NSData class]] ? v : nil; }
static NSError *aq_error(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:AQErrorDomain code:code
                          userInfo:[NSDictionary dictionaryWithObject:message forKey:NSLocalizedDescriptionKey]];
}
static NSDictionary *aq_plist(NSData *d) {
    if (![d length]) return nil;
    return aq_dict([NSPropertyListSerialization propertyListWithData:d options:0 format:NULL error:NULL]);
}
static NSData *aq_encode(id d) {
    return [NSPropertyListSerialization dataWithPropertyList:d format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
}
/* IDSProfileAuthenticationMessage travels as a gzip-compressed plist. Decode
 * only this bounded request body, never a stream or arbitrary content encoding. */
static NSDictionary *aq_request_plist(NSURLRequest *req) {
    NSData *data = [req HTTPBody];
    if ([req HTTPBodyStream] || ![data length] || [data length] > 1024*1024) return nil;
    NSString *encoding = [[req valueForHTTPHeaderField:@"Content-Encoding"] lowercaseString];
    if (![encoding length] || [encoding isEqual:@"identity"]) return aq_plist(data);
    if (![encoding isEqual:@"gzip"]) return nil;
    z_stream stream; memset(&stream, 0, sizeof stream);
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) return nil;
    NSMutableData *plain = [NSMutableData dataWithLength:1024*1024+1];
    stream.next_in = (Bytef *)[data bytes]; stream.avail_in = (uInt)[data length];
    stream.next_out = [plain mutableBytes]; stream.avail_out = (uInt)[plain length];
    int status = inflate(&stream, Z_FINISH);
    NSDictionary *body = nil;
    if (status == Z_STREAM_END && !stream.avail_in && stream.total_out <= 1024*1024) {
        [plain setLength:stream.total_out]; body = aq_plist(plain);
    }
    inflateEnd(&stream);
    OPENSSL_cleanse([plain mutableBytes], [plain length]);
    return body;
}
static NSString *aq_base64(NSData *d) {
    if (!d || [d length] > 1024*1024) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:4*(([d length]+2)/3)+1];
    int n = EVP_EncodeBlock([out mutableBytes], [d bytes], (int)[d length]);
    return [[[NSString alloc] initWithBytes:[out bytes] length:n encoding:NSASCIIStringEncoding] autorelease];
}
static NSString *aq_basic(NSString *user, NSString *password) {
    return [@"Basic " stringByAppendingString:aq_base64([[NSString stringWithFormat:@"%@:%@", user, password] dataUsingEncoding:NSUTF8StringEncoding])];
}
static NSArray *aq_credentials(NSURLRequest *req) {
    if ([[req HTTPBody] length] > 1024*1024) return nil;
    NSString *auth = [req valueForHTTPHeaderField:@"Authorization"];
    if ([[auth lowercaseString] hasPrefix:@"basic "]) {
        NSData *ascii = [[auth substringFromIndex:6] dataUsingEncoding:NSASCIIStringEncoding];
        NSUInteger n = [ascii length];
        if (!n || n > 16384 || n%4) return nil;
        const unsigned char *in = [ascii bytes];
        NSMutableData *out = [NSMutableData dataWithLength:n];
        int len = EVP_DecodeBlock([out mutableBytes], in, (int)n);
        if (len < 0) return nil;
        if (in[n-1] == '=') len--;
        if (n > 1 && in[n-2] == '=') len--;
        NSString *decoded = [[[NSString alloc] initWithBytes:[out bytes] length:len encoding:NSUTF8StringEncoding] autorelease];
        OPENSSL_cleanse([out mutableBytes], [out length]);
        if (!decoded) return nil;
        NSRange colon = [decoded rangeOfString:@":"];
        if (colon.location != NSNotFound && colon.location && colon.location+1 < [decoded length])
            return [NSArray arrayWithObjects:[decoded substringToIndex:colon.location], [decoded substringFromIndex:colon.location+1], nil];
    }
    NSDictionary *body = aq_request_plist(req);
    NSString *u = aq_string([body objectForKey:@"apple-id"]) ?: aq_string([body objectForKey:@"username"]);
    NSString *p = aq_string([body objectForKey:@"password"]);
    return u && p ? [NSArray arrayWithObjects:u, p, nil] : nil;
}
static BOOL aq_setup_url(NSURL *url) {
    return [[[url scheme] lowercaseString] isEqual:@"https"] &&
        [[[url host] lowercaseString] isEqual:@"setup.icloud.com"] &&
        (![url port] || [[url port] intValue] == 443) && ![url user] && ![url password];
}
static BOOL aq_ids_url(NSURL *url) {
    NSString *host = [[url host] lowercaseString];
    return [[[url scheme] lowercaseString] isEqual:@"https"] &&
        ([host isEqual:@"profile.ess.apple.com"] || [host isEqual:@"service.ess.apple.com"]) &&
        (![url port] || [[url port] intValue] == 443) && ![url user] && ![url password] &&
        ![url query] && ![url fragment] &&
        [[url path] isEqual:@"/WebObjects/VCProfileService.woa/wa/authenticateUser"];
}
static BOOL aq_login_url(NSURL *url) {
    if (!aq_setup_url(url)) return NO;
    NSString *p = [url path];
    return [p isEqual:@"/setup/login_or_create_account"] ||
           [p isEqual:@"/setup/iosbuddy/loginDelegates"] ||
           [p isEqual:@"/setup/authenticate/$APPLE_ID$"] ||
           ([p hasPrefix:@"/setup/authenticate/"] && [p length] > [@"/setup/authenticate/" length]);
}
static BOOL aq_settings_request(NSURLRequest *req, NSArray *credentials) {
    if (!aq_setup_url([req URL]) || ![[[req URL] path] isEqual:@"/setup/get_account_settings"] ||
        ![[[req valueForHTTPHeaderField:@"Authorization"] lowercaseString] hasPrefix:@"basic "] ||
        [credentials count] != 2) return NO;
    NSString *dsid = [credentials objectAtIndex:0], *token = [credentials objectAtIndex:1];
    /* MME tokens are opaque. A prefix observed in one issued token is not a
     * format contract: other tokens also need device headers. Scope this to
     * the settings endpoint and a numeric DSID, never another SRP exchange. */
    return [dsid length] && [token length] &&
        [dsid rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789"] invertedSet]].location == NSNotFound;
}

@interface AQGSAProtocol : NSURLProtocol {
    BOOL stopped;
    NSThread *clientThread;
}
- (BOOL)isStopped;
- (void)work;
- (void)deliver:(NSDictionary *)result;
@end

/* A bounded, cancellable transport. No redirects, cookies, credential storage,
 * automatic authentication retries, or trust exceptions. All I/O is on the worker. */
@interface AQGSAWire : NSObject <NSURLConnectionDelegate> {
@public
    NSMutableData *body;
    NSHTTPURLResponse *response;
    NSError *failure;
    BOOL done;
}
@end
@implementation AQGSAWire
- (id)init { if ((self = [super init])) body = [[NSMutableData alloc] init]; return self; }
- (void)dealloc { [body release]; [response release]; [failure release]; [super dealloc]; }
- (NSURLRequest *)connection:(NSURLConnection *)c willSendRequest:(NSURLRequest *)r redirectResponse:(NSURLResponse *)redirect {
    if (redirect) { failure = [aq_error(2, @"Authentication redirect refused.") retain]; done = YES; [c cancel]; return nil; }
    return r;
}
- (BOOL)connectionShouldUseCredentialStorage:(NSURLConnection *)c { return NO; }
- (void)connection:(NSURLConnection *)c didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if ([[[challenge protectionSpace] authenticationMethod] isEqual:NSURLAuthenticationMethodServerTrust])
        [[challenge sender] performDefaultHandlingForAuthenticationChallenge:challenge];
    else [[challenge sender] continueWithoutCredentialForAuthenticationChallenge:challenge];
}
- (NSCachedURLResponse *)connection:(NSURLConnection *)c willCacheResponse:(NSCachedURLResponse *)r { return nil; }
- (void)connection:(NSURLConnection *)c didReceiveResponse:(NSURLResponse *)r {
    if (![r isKindOfClass:[NSHTTPURLResponse class]]) {
        failure = [aq_error(3, @"Expected an HTTP response.") retain]; done = YES; [c cancel]; return;
    }
    [response release]; response = [(NSHTTPURLResponse *)r retain]; [body setLength:0];
}
- (void)connection:(NSURLConnection *)c didReceiveData:(NSData *)d {
    if ([body length]+[d length] > 4*1024*1024) {
        failure = [aq_error(4, @"Authentication response exceeded the size limit.") retain]; done = YES; [c cancel];
    } else [body appendData:d];
}
- (void)connection:(NSURLConnection *)c didFailWithError:(NSError *)e { [failure release]; failure = [e retain]; done = YES; }
- (void)connectionDidFinishLoading:(NSURLConnection *)c { done = YES; }
@end

static NSData *aq_send(AQGSAProtocol *owner, NSMutableURLRequest *req, NSHTTPURLResponse **response, NSError **error) {
    if ([owner isStopped]) { *error = aq_error(NSUserCancelledError, @"Sign-in cancelled."); return nil; }
    [NSURLProtocol setProperty:[NSNumber numberWithBool:YES] forKey:AQHandled inRequest:req];
    [req setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
    [req setHTTPShouldHandleCookies:NO]; [req setTimeoutInterval:30];
    AQGSAWire *wire = [[[AQGSAWire alloc] init] autorelease];
    NSURLConnection *c = [[NSURLConnection alloc] initWithRequest:req delegate:wire startImmediately:NO];
    if (!c) { *error = aq_error(5, @"Could not start authentication request."); return nil; }
    [c scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode]; [c start];
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:30];
    while (!wire->done && ![owner isStopped] && [deadline timeIntervalSinceNow] > 0)
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    [c cancel]; [c release];
    if (!wire->done) { *error = aq_error([owner isStopped] ? NSUserCancelledError : NSURLErrorTimedOut, @"Authentication cancelled or timed out."); return nil; }
    if (wire->failure) { *error = wire->failure; return nil; }
    if (!wire->response) { *error = aq_error(3, @"Missing HTTP response."); return nil; }
    if (response) *response = wire->response;
    return wire->body;
}

static NSString *aq_md5hex(NSData *data) {
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int count = 0;
    if (!EVP_Digest([data bytes], [data length], digest, &count, EVP_md5(), NULL) || count != 16) return nil;
    char hex[33];
    for (unsigned int i = 0; i < count; i++) snprintf(hex+2*i, 3, "%02x", digest[i]);
    return [NSString stringWithUTF8String:hex];
}

/* GSAPort's provider authenticates its GET using a public protocol key, an expiry
 * and a device identifier. It does not receive Apple account credentials. MD5 is
 * mandated by that service's request format, unrelated to our SRP/TLS crypto. */
static NSMutableURLRequest *aq_gsaport_request(NSString *device, NSTimeInterval now) {
    if (!aq_string(device) || now < 0 || now > UINT32_MAX-180) return nil;
    const char *key = "674822be7c2573ea82ff68e5579f4e5ea770b36609fe7ffe04d983de57fb9607";
    uint32_t expiry = (uint32_t)(now+180);
    unsigned char little[4] = {expiry, expiry >> 8, expiry >> 16, expiry >> 24};
    NSMutableData *signedData = [NSMutableData dataWithBytes:little length:4];
    [signedData appendData:[[NSString stringWithFormat:@"icloud.podpod123.com/anisette.php?%@", device] dataUsingEncoding:NSUTF8StringEncoding]];
    [signedData appendBytes:key length:strlen(key)];
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int len = 0;
    if (!EVP_Digest([signedData bytes], [signedData length], digest, &len, EVP_md5(), NULL) || len != 16) return nil;
    NSMutableData *signature = [NSMutableData dataWithBytes:key length:strlen(key)];
    [signature appendBytes:digest length:len];
    NSString *signatureHex = aq_md5hex(signature), *deviceHash = aq_md5hex([device dataUsingEncoding:NSUTF8StringEncoding]);
    if (!signatureHex || !deviceHash) return nil;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://icloud.podpod123.com/anisette.php"]];
    [req setValue:device forHTTPHeaderField:@"X-Device-Uuid"];
    [req setValue:deviceHash forHTTPHeaderField:@"pk"];
    [req setValue:[NSString stringWithFormat:@"%u_%@", expiry, signatureHex] forHTTPHeaderField:@"podkey"];
    return req;
}

static NSString *aq_device_uuid(void) {
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (!service) return nil;
    CFTypeRef value = IORegistryEntryCreateCFProperty(service, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
    IOObjectRelease(service);
    NSString *device = value && CFGetTypeID(value) == CFStringGetTypeID() ? [NSString stringWithString:(NSString *)value] : nil;
    if (value) CFRelease(value);
    return device;
}

static NSDictionary *aq_remote_anisette(AQGSAProtocol *owner, NSMutableURLRequest *req, NSError **error) {
    NSHTTPURLResponse *r = nil;
    NSData *d = aq_send(owner, req, &r, error);
    if (!d) return nil;
    if ([r statusCode] != 200) {
        *error = aq_error(11, [NSString stringWithFormat:@"The anisette server returned HTTP %ld.", (long)[r statusCode]]); return nil;
    }
    NSDictionary *json = aq_dict([NSJSONSerialization JSONObjectWithData:d options:0 error:NULL]);
    if (!json) { *error = aq_error(11, @"The anisette server did not return a JSON dictionary."); return nil; }
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    /* A provider cannot supply credentials, endpoints or arbitrary protocol fields. */
    for (NSString *key in [NSArray arrayWithObjects:@"X-Apple-I-MD", @"X-Apple-I-MD-M", @"X-Apple-I-MD-LU",
            @"X-Apple-I-MD-RINFO", @"X-Mme-Device-Id", @"X-Apple-I-SRL-NO", @"X-MMe-Client-Info", nil]) {
        id raw = [json objectForKey:key];
        if ([key isEqual:@"X-Apple-I-MD-RINFO"] && [raw isKindOfClass:[NSNumber class]]) raw = [raw stringValue];
        NSString *v = aq_string(raw);
        if (v && [v length] <= 16384 && [v rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location == NSNotFound)
            [headers setObject:v forKey:key];
    }
    return headers;
}

static NSDictionary *aq_anisette(AQGSAProtocol *owner, NSError **error) {
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    NSString *path = [[NSString stringWithUTF8String:tf_dir()] stringByAppendingPathComponent:@"gsa-anisette-url.txt"];
    NSString *endpoint = [[NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL]
                            stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([endpoint length]) {
        NSURL *url = [NSURL URLWithString:endpoint];
        BOOL local = [[url host] isEqual:@"127.0.0.1"] || [[url host] isEqual:@"localhost"] || [[url host] isEqual:@"[::1]"];
        if ((![[url scheme] isEqual:@"https"] && !(local && [[url scheme] isEqual:@"http"])) ||
            ![url host] || [url user] || [url password] || [url fragment]) {
            *error = aq_error(10, @"The anisette server must use HTTPS (HTTP is allowed only on loopback)."); return nil;
        }
        NSDictionary *remote = aq_remote_anisette(owner, [NSMutableURLRequest requestWithURL:url], error);
        if (!remote) return nil;
        [headers addEntriesFromDictionary:remote];
    } else {
        dlopen("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit", RTLD_LAZY | RTLD_LOCAL);
        Class utility = NSClassFromString(@"AOSUtilities");
        SEL otp = NSSelectorFromString(@"retrieveOTPHeadersForDSID:");
        SEL udid = NSSelectorFromString(@"machineUDID");
        if ([utility respondsToSelector:otp] && [utility respondsToSelector:udid]) {
            NSDictionary *d = aq_dict(((id(*)(id,SEL,id))objc_msgSend)(utility, otp, @"-2"));
            NSString *machine = aq_string([d objectForKey:@"X-Apple-MD-M"]);
            NSString *oneTime = aq_string([d objectForKey:@"X-Apple-MD"]);
            NSString *device = aq_string(((id(*)(id,SEL))objc_msgSend)(utility, udid));
            if (machine && oneTime && device) {
                [headers setObject:machine forKey:@"X-Apple-I-MD-M"];
                [headers setObject:oneTime forKey:@"X-Apple-I-MD"];
                [headers setObject:device forKey:@"X-Mme-Device-Id"];
                [headers setObject:aq_base64([device dataUsingEncoding:NSUTF8StringEncoding]) forKey:@"X-Apple-I-MD-LU"];
                [headers setObject:@"84215040" forKey:@"X-Apple-I-MD-RINFO"];
            }
        }
        if (![headers count]) {
            NSMutableURLRequest *req = aq_gsaport_request(aq_device_uuid(), [[NSDate date] timeIntervalSince1970]);
            if (!req) { *error = aq_error(13, @"Could not create the device authentication request."); return nil; }
            NSDictionary *remote = aq_remote_anisette(owner, req, error);
            if (!remote) return nil;
            [headers addEntriesFromDictionary:remote];
        }
    }
    for (NSString *key in [NSArray arrayWithObjects:@"X-Apple-I-MD", @"X-Apple-I-MD-M", @"X-Apple-I-MD-LU", @"X-Apple-I-MD-RINFO", @"X-Mme-Device-Id", nil]) {
        if (!aq_string([headers objectForKey:key])) {
            *error = aq_error(12, @"The anisette provider did not return the required device authentication data."); return nil;
        }
    }
    /* Providers may still advertise the retired Xcode identity. Keep a supported
     * identity consistent between HTTP headers and GrandSlam client data. */
    NSString *client = aq_string([headers objectForKey:@"X-MMe-Client-Info"]);
    if (!client || [client rangeOfString:@"Xcode" options:NSCaseInsensitiveSearch].location != NSNotFound)
        [headers setObject:AQClient forKey:@"X-MMe-Client-Info"];
    NSDateFormatter *date = [[[NSDateFormatter alloc] init] autorelease];
    [date setLocale:[[[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"] autorelease]];
    [date setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];
    [date setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    [headers setObject:[date stringFromDate:[NSDate date]] forKey:@"X-Apple-I-Client-Time"];
    [headers setObject:[[NSTimeZone localTimeZone] name] forKey:@"X-Apple-I-TimeZone"];
    [headers setObject:[[NSLocale currentLocale] localeIdentifier] forKey:@"X-Apple-Locale"];
    return headers;
}

static NSMutableURLRequest *aq_apple_request(NSString *url, NSDictionary *headers) {
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    [r setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Content-Type"];
    [r setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Accept"];
    [r setValue:@"akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0" forHTTPHeaderField:@"User-Agent"];
    [r setValue:AQClient forHTTPHeaderField:@"X-Mme-Client-Info"];
    for (NSString *k in headers) [r setValue:[headers objectForKey:k] forHTTPHeaderField:k];
    return r;
}
static NSDictionary *aq_exchange(AQGSAProtocol *owner, NSMutableDictionary *payload, NSDictionary *headers, NSError **error) {
    NSMutableDictionary *cpd = [[headers mutableCopy] autorelease];
    [cpd setObject:[NSNumber numberWithBool:YES] forKey:@"bootstrap"];
    [cpd setObject:[NSNumber numberWithBool:YES] forKey:@"icscrec"];
    [cpd setObject:[NSNumber numberWithBool:NO] forKey:@"pbe"];
    [cpd setObject:[NSNumber numberWithBool:YES] forKey:@"prkgen"];
    /* svct is the service category; com.apple.gs.xcode.auth belongs to
     * X-Apple-App-Info during verification, not this field. */
    [cpd setObject:@"iCloud" forKey:@"svct"];
    [cpd setObject:@"en_US" forKey:@"loc"];
    [payload setObject:cpd forKey:@"cpd"];
    NSDictionary *outer = [NSDictionary dictionaryWithObjectsAndKeys:
        [NSDictionary dictionaryWithObject:@"1.0.1" forKey:@"Version"], @"Header", payload, @"Request", nil];
    /* GSAPort sends the OTP inside cpd. Its HTTP headers carry only the
     * machine/device identity; don't submit the OTP a second time as a header. */
    NSMutableDictionary *httpHeaders = [NSMutableDictionary dictionary];
    for (NSString *k in [NSArray arrayWithObjects:@"X-Apple-I-MD-M", @"X-Mme-Device-Id", @"X-MMe-Client-Info", nil])
        if ([headers objectForKey:k]) [httpHeaders setObject:[headers objectForKey:k] forKey:k];
    NSMutableURLRequest *req = aq_apple_request(@"https://gsa.apple.com/grandslam/GsService2", httpHeaders);
    [req setValue:@"*/*" forHTTPHeaderField:@"Accept"];
    [req setHTTPMethod:@"POST"]; [req setHTTPBody:aq_encode(outer)];
    NSHTTPURLResponse *r = nil;
    NSData *data = aq_send(owner, req, &r, error);
    if (!data) return nil;
    NSDictionary *result = aq_dict([aq_plist(data) objectForKey:@"Response"]);
    NSDictionary *status = aq_dict([result objectForKey:@"Status"]);
    id ec = [status objectForKey:@"ec"];
    if ([r statusCode] != 200 || !result || !status || ![ec isKindOfClass:[NSNumber class]] || [ec integerValue] != 0) {
        id hsc = [status objectForKey:@"hsc"];
        syslog(LOG_NOTICE, "AquaTransport GrandSlam %s failed (HTTP %ld, hsc %ld, ec %ld)",
            [[payload objectForKey:@"o"] isEqual:@"init"] ? "init" : "complete", (long)[r statusCode],
            [hsc isKindOfClass:[NSNumber class]] ? (long)[hsc integerValue] : -1L,
            [ec isKindOfClass:[NSNumber class]] ? (long)[ec integerValue] : -1L);
        *error = aq_error(20, @"Apple rejected the GrandSlam exchange."); return nil;
    }
    return result;
}
static NSDictionary *aq_decrypt(NSData *encrypted, unsigned char key[32]) {
    if (![encrypted length] || [encrypted length] > 1024*1024 || [encrypted length]%16) return nil;
    unsigned char aes[32], iv[32]; unsigned int len;
    if (!HMAC(EVP_sha256(), key, 32, (unsigned char *)"extra data key:", strlen("extra data key:"), aes, &len) ||
        !HMAC(EVP_sha256(), key, 32, (unsigned char *)"extra data iv:", strlen("extra data iv:"), iv, &len)) {
        OPENSSL_cleanse(aes, sizeof aes); OPENSSL_cleanse(iv, sizeof iv); return nil;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    NSMutableData *plain = [NSMutableData dataWithLength:[encrypted length]+16];
    int a = 0, b = 0;
    int ok = ctx && EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes, iv) &&
        EVP_DecryptUpdate(ctx, [plain mutableBytes], &a, [encrypted bytes], (int)[encrypted length]) &&
        EVP_DecryptFinal_ex(ctx, (unsigned char *)[plain mutableBytes]+a, &b);
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(aes, sizeof aes); OPENSSL_cleanse(iv, sizeof iv);
    NSDictionary *result = nil;
    if (ok) {
        [plain setLength:a+b]; result = aq_plist(plain);
        if (!result) {
            NSMutableData *wrapped = [NSMutableData dataWithData:[@"<plist version=\"1.0\">" dataUsingEncoding:NSUTF8StringEncoding]];
            [wrapped appendData:plain]; [wrapped appendData:[@"</plist>" dataUsingEncoding:NSUTF8StringEncoding]];
            result = aq_plist(wrapped);
            OPENSSL_cleanse([wrapped mutableBytes], [wrapped length]);
        }
    }
    OPENSSL_cleanse([plain mutableBytes], [plain length]);
    return result;
}

static BOOL aq_second_factor(AQGSAProtocol *owner, NSString *identity, NSString *code, NSError **error) {
    NSDictionary *headers = aq_anisette(owner, error);
    if (!headers) return NO;
    NSMutableURLRequest *req = aq_apple_request(code ? @"https://gsa.apple.com/grandslam/GsService2/validate" :
                                                        @"https://gsa.apple.com/auth/verify/trusteddevice", headers);
    [req setValue:identity forHTTPHeaderField:@"X-Apple-Identity-Token"];
    [req setValue:@"com.apple.gs.xcode.auth" forHTTPHeaderField:@"X-Apple-App-Info"];
    [req setValue:@"11.2 (11B41)" forHTTPHeaderField:@"X-Xcode-Version"];
    if (code) [req setValue:code forHTTPHeaderField:@"security-code"];
    NSHTTPURLResponse *r = nil;
    NSData *d = aq_send(owner, req, &r, error);
    if (!d) return NO;
    NSDictionary *status = aq_dict([aq_plist(d) objectForKey:@"Status"]);
    id ec = [status objectForKey:@"ec"];
    if ([r statusCode] != 200 || (ec && (![ec respondsToSelector:@selector(integerValue)] || [ec integerValue] != 0))) {
        *error = aq_error(21, @"Apple rejected the verification request."); return NO;
    }
    return YES;
}

static NSDictionary *aq_login(AQGSAProtocol *owner, NSString *user, NSString *password, NSError **error) {
    /* Runs on the serial worker queue. No passwords are retained between attempts. */
    for (NSString *k in [[[AQPending allKeys] copy] autorelease]) {
        if ([[[AQPending objectForKey:k] objectForKey:@"expires"] timeIntervalSinceNow] <= 0) [AQPending removeObjectForKey:k];
    }
    NSString *account = [user lowercaseString];
    NSDictionary *pending = [AQPending objectForKey:account];
    if (pending) {
        NSString *code = [password length] > 6 ? [password substringFromIndex:[password length]-6] : nil;
        if (!code || [code rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789"] invertedSet]].location != NSNotFound) {
            *error = aq_error(401, @"Enter your password followed by the six-digit verification code."); return nil;
        }
        if (!aq_second_factor(owner, [pending objectForKey:@"identity"], code, error)) return nil;
        password = [password substringToIndex:[password length]-6];
        [AQPending removeObjectForKey:account];
    }
    NSDictionary *headers = aq_anisette(owner, error);
    if (!headers) return nil;
    unsigned char A[256], M[32], key[32] = {0};
    aq_srp *srp = aq_srp_new(A);
    if (!srp) { *error = aq_error(22, @"Could not initialize SRP."); return nil; }
    NSDictionary *spd = nil;
    @try {
        NSMutableDictionary *init = [NSMutableDictionary dictionaryWithObjectsAndKeys:
            [NSData dataWithBytes:A length:sizeof A], @"A2k", [NSArray arrayWithObjects:@"s2k", @"s2k_fo", nil], @"ps", user, @"u", @"init", @"o", nil];
        NSDictionary *challenge = aq_exchange(owner, init, headers, error);
        if (!challenge) return nil;
        NSData *salt = aq_data([challenge objectForKey:@"s"]), *B = aq_data([challenge objectForKey:@"B"]);
        NSString *protocol = aq_string([challenge objectForKey:@"sp"]), *continuation = aq_string([challenge objectForKey:@"c"]);
        id iterations = [challenge objectForKey:@"i"];
        NSData *pw = [password dataUsingEncoding:NSUTF8StringEncoding];
        if (![iterations isKindOfClass:[NSNumber class]] || [iterations longLongValue] < 1 || [iterations longLongValue] > 1000000 ||
            !continuation || !aq_srp_challenge(srp, [user UTF8String], [pw bytes], [pw length], [protocol UTF8String],
                [salt bytes], [salt length], [iterations unsignedIntValue], [B bytes], [B length], M)) {
            *error = aq_error(23, @"Invalid GrandSlam SRP challenge."); return nil;
        }
        NSMutableDictionary *complete = [NSMutableDictionary dictionaryWithObjectsAndKeys:continuation, @"c",
            [NSData dataWithBytes:M length:sizeof M], @"M1", user, @"u", @"complete", @"o", nil];
        syslog(LOG_NOTICE, "AquaTransport GrandSlam challenge accepted (%s); sending iCloud proof (adapter 5)",
            [protocol isEqual:@"s2k_fo"] ? "s2k_fo" : "s2k");
        NSDictionary *reply = aq_exchange(owner, complete, headers, error);
        if (!reply) return nil;
        NSData *M2 = aq_data([reply objectForKey:@"M2"]);
        if (!aq_srp_verify(srp, [M2 bytes], [M2 length], key)) {
            *error = aq_error(24, @"GrandSlam server proof did not verify."); return nil;
        }
        spd = aq_decrypt(aq_data([reply objectForKey:@"spd"]), key);
        if (!spd) { *error = aq_error(25, @"Invalid encrypted GrandSlam session data."); return nil; }
        NSDictionary *status = aq_dict([reply objectForKey:@"Status"]);
        NSString *secondary = aq_string([status objectForKey:@"au"]);
        if ([secondary isEqual:@"trustedDeviceSecondaryAuth"]) {
            NSString *dsid = aq_string([spd objectForKey:@"adsid"]), *token = aq_string([spd objectForKey:@"GsIdmsToken"]);
            if (!dsid || !token) { *error = aq_error(26, @"Missing verification session."); return nil; }
            NSString *identity = aq_base64([[NSString stringWithFormat:@"%@:%@", dsid, token] dataUsingEncoding:NSUTF8StringEncoding]);
            if (!aq_second_factor(owner, identity, nil, error)) return nil;
            if ([AQPending count] >= 32) [AQPending removeAllObjects];
            [AQPending setObject:[NSDictionary dictionaryWithObjectsAndKeys:identity, @"identity",
                [NSDate dateWithTimeIntervalSinceNow:300], @"expires", nil] forKey:account];
            *error = aq_error(401, @"Approve sign-in on your trusted device, then enter your password followed by the six-digit code."); return nil;
        }
        if (secondary || [[status objectForKey:@"hsc"] integerValue] != 200) {
            *error = aq_error(27, @"This account requires an unsupported verification method (such as SMS)."); return nil;
        }
    } @finally { aq_srp_free(srp); OPENSSL_cleanse(key, sizeof key); OPENSSL_cleanse(M, sizeof M); }
    return spd;
}

static NSDictionary *aq_result(NSHTTPURLResponse *response, NSData *data) {
    return [NSDictionary dictionaryWithObjectsAndKeys:response, @"response", data, @"data", nil];
}
static NSDictionary *aq_bridge(AQGSAProtocol *owner, NSURLRequest *original, NSError **error) {
    NSDictionary *idsBody = aq_ids_url([original URL]) ? aq_request_plist(original) : nil;
    NSString *idsUser = aq_string([idsBody objectForKey:@"username"]);
    NSString *idsPassword = aq_string([idsBody objectForKey:@"password"]);
    NSArray *credentials = aq_ids_url([original URL]) ?
        (idsUser && idsPassword ? [NSArray arrayWithObjects:idsUser, idsPassword, nil] : nil) : aq_credentials(original);
    if (!credentials) { *error = aq_error(30, @"Unsupported iCloud credential format."); return nil; }
    if (aq_settings_request(original, credentials)) {
        NSDictionary *headers = aq_anisette(owner, error);
        if (!headers) return nil;
        NSMutableURLRequest *req = [[original mutableCopy] autorelease];
        for (NSString *k in headers) [req setValue:[headers objectForKey:k] forHTTPHeaderField:k];
        NSHTTPURLResponse *response = nil;
        NSData *data = aq_send(owner, req, &response, error);
        if (data) syslog(LOG_NOTICE, "AquaTransport iCloud account refresh completed (HTTP %ld, adapter 11)", (long)[response statusCode]);
        return data ? aq_result(response, data) : nil;
    }
    /* Account lookup ignores case, but M1 hashes the username bytes. Use the
     * same canonical spelling in init, the proof, complete and token exchange.
     * The password remains byte-for-byte as submitted. */
    NSString *submittedUser = [credentials objectAtIndex:0];
    NSString *user = [submittedUser lowercaseString];
    syslog(LOG_NOTICE, "AquaTransport iCloud credentials decoded (source %s, account case normalized %s)",
        [[[original valueForHTTPHeaderField:@"Authorization"] lowercaseString] hasPrefix:@"basic "] ? "Basic" : "plist",
        [submittedUser isEqual:user] ? "no" : "yes");
    NSDictionary *session = aq_login(owner, user, [credentials objectAtIndex:1], error);
    if (!session) return nil;
    NSString *pet = aq_string([aq_dict([aq_dict([session objectForKey:@"t"]) objectForKey:@"com.apple.gs.idms.pet"]) objectForKey:@"token"]);
    if (!pet) { *error = aq_error(31, @"Apple did not issue an iCloud password-equivalent token."); return nil; }
    NSDictionary *headers = aq_anisette(owner, error);
    if (!headers) return nil;
    NSHTTPURLResponse *response = nil;
    if (aq_ids_url([original URL])) {
        /* A PET is not an IDS profile token. Exchange it for the legacy Madrid
         * delegate, then translate only the authenticated service credentials.
         * This avoids the rate-limited profile password endpoint altogether. */
        NSMutableURLRequest *req = aq_apple_request(@"https://setup.icloud.com/setup/iosbuddy/loginDelegates", headers);
        [req setHTTPMethod:@"POST"];
        [req setValue:aq_basic(user, pet) forHTTPHeaderField:@"Authorization"];
        NSString *adsid = aq_string([session objectForKey:@"adsid"]);
        if (adsid) [req setValue:adsid forHTTPHeaderField:@"X-Apple-ADSID"];
        NSDictionary *body = [NSDictionary dictionaryWithObjectsAndKeys:
            user, @"apple-id", pet, @"password", [headers objectForKey:@"X-Mme-Device-Id"], @"client-id",
            [NSDictionary dictionaryWithObject:[NSDictionary dictionary] forKey:@"com.apple.madrid"], @"delegates", nil];
        [req setHTTPBody:aq_encode(body)];
        NSData *data = aq_send(owner, req, &response, error);
        if (!data) return nil;
        NSDictionary *reply = aq_plist(data);
        NSDictionary *delegate = aq_dict([aq_dict([reply objectForKey:@"delegates"]) objectForKey:@"com.apple.madrid"]);
        id status = [reply objectForKey:@"status"], delegateStatus = [delegate objectForKey:@"status"];
        syslog(LOG_NOTICE, "AquaTransport iMessage delegate authentication completed (HTTP %ld, status %ld, delegate status %ld, adapter 10)",
            (long)[response statusCode], [status isKindOfClass:[NSNumber class]] ? (long)[status integerValue] : -1L,
            [delegateStatus isKindOfClass:[NSNumber class]] ? (long)[delegateStatus integerValue] : -1L);
        NSDictionary *service = aq_dict([delegate objectForKey:@"service-data"]);
        NSString *profile = aq_string([service objectForKey:@"profile-id"]), *token = aq_string([service objectForKey:@"auth-token"]);
        if ([response statusCode] != 200 || ![status isKindOfClass:[NSNumber class]] || [status integerValue] != 0 ||
            ![delegateStatus isKindOfClass:[NSNumber class]] || [delegateStatus integerValue] != 0 || !profile || !token) {
            *error = aq_error(45, @"Apple did not issue iMessage service credentials."); return nil;
        }
        NSDictionary *result = [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:0], @"status",
            profile, @"profile-id", token, @"auth-token", nil];
        return aq_result(response, aq_encode(result));
    }
    if ([[[original URL] path] isEqual:@"/setup/iosbuddy/loginDelegates"]) {
        NSMutableDictionary *body = [[aq_plist([original HTTPBody]) mutableCopy] autorelease];
        if (!body) { *error = aq_error(32, @"Unsupported loginDelegates body."); return nil; }
        [body setObject:pet forKey:@"password"];
        NSString *dsid = aq_string([session objectForKey:@"adsid"]);
        if (dsid) [body setObject:dsid forKey:@"apple-id"];
        NSMutableURLRequest *req = [[original mutableCopy] autorelease];
        [req setHTTPBody:aq_encode(body)]; [req setValue:nil forHTTPHeaderField:@"Content-Length"];
        [req setValue:nil forHTTPHeaderField:@"Authorization"];
        for (NSString *k in headers) [req setValue:[headers objectForKey:k] forHTTPHeaderField:k];
        NSData *data = aq_send(owner, req, &response, error);
        return data ? aq_result(response, data) : nil;
    }
    CFStringRef escaped = CFURLCreateStringByAddingPercentEscapes(NULL, (CFStringRef)user, NULL,
        CFSTR("/?#%:@&=+"), kCFStringEncodingUTF8);
    NSString *url = [@"https://setup.icloud.com/setup/authenticate/" stringByAppendingString:(NSString *)escaped];
    CFRelease(escaped);
    NSMutableURLRequest *req = aq_apple_request(url, headers);
    [req setValue:aq_basic(user, pet) forHTTPHeaderField:@"Authorization"];
    NSData *auth = aq_send(owner, req, &response, error);
    if (!auth) return nil;
    if (![[[original URL] path] isEqual:@"/setup/login_or_create_account"] || [response statusCode] != 200)
        return aq_result(response, auth);
    NSDictionary *account = aq_plist(auth);
    NSString *dsid = aq_string([aq_dict([account objectForKey:@"appleAccountInfo"]) objectForKey:@"dsid"]);
    NSString *token = aq_string([aq_dict([account objectForKey:@"tokens"]) objectForKey:@"mmeAuthToken"]);
    if (!dsid || !token) { *error = aq_error(33, @"Apple did not return iCloud account credentials."); return nil; }
    req = aq_apple_request(@"https://setup.icloud.com/setup/get_account_settings", headers);
    [req setHTTPMethod:@"POST"]; [req setValue:aq_basic(dsid, token) forHTTPHeaderField:@"Authorization"];
    for (NSString *k in [NSArray arrayWithObjects:@"User-Agent", @"X-Mme-Client-Info", @"X-Mme-Country", @"X-Mme-Timezone", @"X-APNS-Token", @"Accept-Language", nil]) {
        NSString *v = [original valueForHTTPHeaderField:k]; if (v) [req setValue:v forHTTPHeaderField:k];
    }
    [req setValue:@"false" forHTTPHeaderField:@"X-Aos-Accept-Tos"];
    NSData *data = aq_send(owner, req, &response, error);
    return data ? aq_result(response, data) : nil;
}

@implementation AQGSAProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)req {
    if (tf_flag("disable-icloud-gsa") || [NSURLProtocol propertyForKey:AQHandled inRequest:req]) return NO;
    /* Claim malformed IDS bodies too, so a decoding error cannot fall back to
     * submitting the original password to Apple's legacy endpoint. */
    if (aq_ids_url([req URL])) return [[req HTTPMethod] isEqual:@"POST"];
    if ([req HTTPBodyStream] || !aq_setup_url([req URL])) return NO;
    NSArray *credentials = aq_credentials(req);
    return credentials && (aq_login_url([req URL]) || aq_settings_request(req, credentials));
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)startLoading {
    clientThread = [[NSThread currentThread] retain];
    NSInvocationOperation *op = [[NSInvocationOperation alloc] initWithTarget:self selector:@selector(work) object:nil];
    [AQQueue addOperation:op]; [op release];
}
- (BOOL)isStopped { @synchronized(self) { return stopped; } }
- (void)stopLoading { @synchronized(self) { stopped = YES; } }
- (void)dealloc { [clientThread release]; [super dealloc]; }
- (void)work {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    if (![self isStopped]) {
        NSError *error = nil; NSDictionary *result = nil;
        @try { result = aq_bridge(self, [self request], &error); }
        @catch (NSException *exception) { error = aq_error(40, @"Unexpected authentication response."); }
        if (!result) result = [NSDictionary dictionaryWithObject:error ?: aq_error(41, @"Authentication failed.") forKey:@"error"];
        if (![self isStopped]) [self performSelector:@selector(deliver:) onThread:clientThread withObject:result waitUntilDone:NO
                                              modes:[NSArray arrayWithObjects:NSDefaultRunLoopMode, NSRunLoopCommonModes, nil]];
    }
    [pool drain];
}
- (void)deliver:(NSDictionary *)result {
    @synchronized(self) {
        if (stopped) return;
        NSError *error = [result objectForKey:@"error"];
        if (error) {
            /* Diagnostics deliberately contain no URLs, account names, bodies or headers. */
            syslog(LOG_NOTICE, "AquaTransport iCloud %s failed (code %ld)",
                [[error domain] isEqual:AQErrorDomain] ? "authentication" : "transport", (long)[error code]);
            if (tf_debug()) tf_log("iCloud GSA failed (code %ld)", (long)[error code]);
            if ([[error domain] isEqual:AQErrorDomain] && [error code] == 401) {
                BOOL ids = aq_ids_url([[self request] URL]);
                NSHTTPURLResponse *r = [[[NSHTTPURLResponse alloc] initWithURL:[[self request] URL] statusCode:ids ? 200 : 401 HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
                [[self client] URLProtocol:self didReceiveResponse:r cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                /* Mavericks recognizes profile status 5000 as an authentication
                 * failure and allows the next password+code attempt. */
                if (ids && !stopped) [[self client] URLProtocol:self didLoadData:aq_encode(
                    [NSDictionary dictionaryWithObject:[NSNumber numberWithInt:5000] forKey:@"status"])];
                if (!stopped) [[self client] URLProtocolDidFinishLoading:self];
            } else [[self client] URLProtocol:self didFailWithError:error];
        } else {
            NSHTTPURLResponse *r = [result objectForKey:@"response"];
            /* Changed body/URL: never relay content-length, content-encoding, or cookies. */
            NSDictionary *h = [NSDictionary dictionaryWithObject:@"text/x-xml-plist" forKey:@"Content-Type"];
            NSHTTPURLResponse *mapped = [[[NSHTTPURLResponse alloc] initWithURL:[[self request] URL] statusCode:[r statusCode] HTTPVersion:@"HTTP/1.1" headerFields:h] autorelease];
            [[self client] URLProtocol:self didReceiveResponse:mapped cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            if (!stopped) [[self client] URLProtocol:self didLoadData:[result objectForKey:@"data"]];
            if (!stopped) [[self client] URLProtocolDidFinishLoading:self];
        }
        stopped = YES;
    }
}
@end

/* DAV keeps the native authentication challenge and streaming response paths.
 * Only device headers are supplied here; passwords and service tokens stay with
 * CFNetwork/AOSKit. Each redirected request must pass the host check anew. */
static BOOL aq_dav_url(NSURL *url) {
    if (![[[url scheme] lowercaseString] isEqual:@"https"] || [url password]) return NO;
    NSString *host = [[url host] lowercaseString];
    NSInteger port = [[url port] integerValue];
    NSInteger legacy = [host hasSuffix:@"caldav.icloud.com"] ? 8443 : 8843;
    if ([url port] && port != 443 && port != legacy) return NO;
    if (!host) return NO;
    NSRegularExpression *pattern = [NSRegularExpression regularExpressionWithPattern:
        @"^(p[0-9]+-)?(caldav|contacts)\\.icloud\\.com$" options:0 error:NULL];
    return [pattern numberOfMatchesInString:host options:0 range:NSMakeRange(0,[host length])] == 1;
}
static NSURL *aq_dav_transport_url(NSURL *url) {
    if (!aq_dav_url(url) || ![url port] || [[url port] integerValue] == 443) return url;
    /* Preserve the escaped username and resource path. The validated authority
     * contains only a DNS host, so its last colon introduces the legacy port. */
    NSString *absolute = [url absoluteString];
    NSUInteger start = [absolute rangeOfString:@"://"].location + 3;
    NSRange rest = NSMakeRange(start, [absolute length]-start);
    NSRange delimiter = [absolute rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"/?#"] options:0 range:rest];
    NSUInteger end = delimiter.location == NSNotFound ? [absolute length] : delimiter.location;
    NSRange colon = [absolute rangeOfString:@":" options:NSBackwardsSearch range:NSMakeRange(start,end-start)];
    if (colon.location == NSNotFound) return url;
    return [NSURL URLWithString:[absolute stringByReplacingCharactersInRange:NSMakeRange(colon.location+1,end-colon.location-1) withString:@"443"]];
}
static NSArray *aq_device_header_names(void) {
    return [NSArray arrayWithObjects:@"X-Apple-I-MD", @"X-Apple-I-MD-M", @"X-Apple-I-MD-LU",
        @"X-Apple-I-MD-RINFO", @"X-Mme-Device-Id", @"X-Apple-I-SRL-NO", @"X-MMe-Client-Info",
        @"X-Apple-I-Client-Time", @"X-Apple-I-TimeZone", @"X-Apple-Locale", nil];
}
@interface AQDAVProtocol : NSURLProtocol <NSURLConnectionDelegate> {
    BOOL stopped;
    NSThread *clientThread;
    NSURLConnection *connection;
}
- (BOOL)isStopped;
- (void)prepare;
- (void)begin:(NSDictionary *)result;
@end
@implementation AQDAVProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)r {
    return !tf_flag("disable-icloud-gsa") && ![NSURLProtocol propertyForKey:AQHandled inRequest:r] && aq_dav_url([r URL]);
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (BOOL)isStopped { @synchronized(self) { return stopped; } }
- (void)stopLoading {
    @synchronized(self) { stopped = YES; [connection cancel]; [connection release]; connection = nil; }
}
- (void)dealloc { [connection cancel]; [connection release]; [clientThread release]; [super dealloc]; }
- (void)startLoading {
    clientThread = [[NSThread currentThread] retain];
    NSInvocationOperation *op = [[NSInvocationOperation alloc] initWithTarget:self selector:@selector(prepare) object:nil];
    [AQQueue addOperation:op]; [op release];
}
- (void)prepare {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    /* This runs on the authentication queue, never CFNetwork's callback thread.
     * A short cache avoids an anisette-provider request for every DAV resource. */
    static NSDictionary *cached;
    static NSDate *expires;
    if (![self isStopped]) {
        NSError *error = nil;
        if (!cached || [expires timeIntervalSinceNow] <= 0) {
            NSDictionary *headers = aq_anisette((AQGSAProtocol *)self, &error);
            [cached release]; cached = [headers copy];
            [expires release]; expires = [[NSDate dateWithTimeIntervalSinceNow:60] retain];
        }
        NSDictionary *result = cached ? [NSDictionary dictionaryWithObject:cached forKey:@"headers"] :
            [NSDictionary dictionaryWithObject:error ?: aq_error(42, @"Could not obtain iCloud device authentication.") forKey:@"error"];
        if (![self isStopped]) [self performSelector:@selector(begin:) onThread:clientThread withObject:result waitUntilDone:NO
            modes:[NSArray arrayWithObjects:NSDefaultRunLoopMode, NSRunLoopCommonModes, nil]];
    }
    [pool drain];
}
- (void)begin:(NSDictionary *)result {
    @synchronized(self) {
        if (stopped) return;
        NSError *error = [result objectForKey:@"error"];
        if (error) { [[self client] URLProtocol:self didFailWithError:error]; [self stopLoading]; return; }
        NSMutableURLRequest *r = [[[self request] mutableCopy] autorelease];
        [NSURLProtocol setProperty:[NSNumber numberWithBool:YES] forKey:AQHandled inRequest:r];
        [r setHTTPShouldHandleCookies:NO];
        [r setURL:aq_dav_transport_url([r URL])];
        for (NSString *k in [result objectForKey:@"headers"])
            [r setValue:[[result objectForKey:@"headers"] objectForKey:k] forHTTPHeaderField:k];
        connection = [[NSURLConnection alloc] initWithRequest:r delegate:self startImmediately:NO];
        if (!connection) {
            [[self client] URLProtocol:self didFailWithError:aq_error(43, @"Could not start iCloud service request.")];
            [self stopLoading]; return;
        }
        [connection scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSRunLoopCommonModes];
        [connection start];
    }
}
- (NSURLRequest *)connection:(NSURLConnection *)c willSendRequest:(NSURLRequest *)r redirectResponse:(NSURLResponse *)response {
    if (!response) return r;
    @synchronized(self) {
        if (stopped) return nil;
        NSMutableURLRequest *next = [[r mutableCopy] autorelease];
        [NSURLProtocol removePropertyForKey:AQHandled inRequest:next];
        for (NSString *k in aq_device_header_names()) [next setValue:nil forHTTPHeaderField:k];
        NSURL *from = aq_dav_transport_url([[self request] URL]), *to = [next URL];
        if (![[from host] isEqual:[to host]] || ![[from scheme] isEqual:[to scheme]] ||
            ([to port] && [[to port] integerValue] != 443))
            [next setValue:nil forHTTPHeaderField:@"Authorization"];
        [[self client] URLProtocol:self wasRedirectedToRequest:next redirectResponse:response];
        [self stopLoading];
    }
    return nil;
}
- (void)connection:(NSURLConnection *)c didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    @synchronized(self) {
        if (stopped) return;
        /* Native CoreDAV chooses the credential, including X-MobileMe-AuthToken.
         * Its sender remains the real connection so credential replies reach it. */
        [[self client] URLProtocol:self didReceiveAuthenticationChallenge:challenge];
    }
}
- (void)connection:(NSURLConnection *)c didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    @synchronized(self) { if (!stopped) [[self client] URLProtocol:self didCancelAuthenticationChallenge:challenge]; }
}
- (void)connection:(NSURLConnection *)c didReceiveResponse:(NSURLResponse *)response {
    @synchronized(self) {
        if (stopped) return;
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            static unsigned logged;
            @synchronized([AQDAVProtocol class]) {
                if (logged++ < 8) syslog(LOG_NOTICE, "AquaTransport iCloud DAV response (HTTP %ld, adapter 7)",
                    (long)[(NSHTTPURLResponse *)response statusCode]);
            }
        }
        [[self client] URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    }
}
- (void)connection:(NSURLConnection *)c didReceiveData:(NSData *)data {
    @synchronized(self) { if (!stopped) [[self client] URLProtocol:self didLoadData:data]; }
}
- (NSCachedURLResponse *)connection:(NSURLConnection *)c willCacheResponse:(NSCachedURLResponse *)response { return nil; }
- (void)connection:(NSURLConnection *)c didFailWithError:(NSError *)error {
    @synchronized(self) {
        if (!stopped) { syslog(LOG_NOTICE, "AquaTransport iCloud DAV transport failed (code %ld)", (long)[error code]);
            [[self client] URLProtocol:self didFailWithError:error]; [self stopLoading]; }
    }
}
- (void)connectionDidFinishLoading:(NSURLConnection *)c {
    @synchronized(self) { if (!stopped) { [[self client] URLProtocolDidFinishLoading:self]; [self stopLoading]; } }
}
@end

@interface AQMailTokenAdapter : NSObject
+ (void)install;
@end

static NSData *(*AQMailInitialResponse)(id, SEL);

static NSData *aq_mail_initial_response(id self, SEL selector) {
    NSData *native = AQMailInitialResponse(self, selector);
    if (tf_flag("disable-icloud-gsa") || ![native isKindOfClass:[NSData class]] ||
        [native length] < 5 || [native length] > 1024*1024) return native;
    /* Keep native credential retrieval and the two person-ID fields. MME tokens
     * are opaque, so their first byte cannot decide whether device data is needed. */
    const unsigned char *bytes = [native bytes];
    NSUInteger length = [native length], separators = 0, tokenOffset = 0;
    for (NSUInteger i = 0; i < length; i++) if (!bytes[i]) { separators++; tokenOffset = i+1; }
    if (separators != 2 || tokenOffset >= length) return native;
    SEL accountSelector = NSSelectorFromString(@"account"), hostSelector = NSSelectorFromString(@"hostname");
    if (![self respondsToSelector:accountSelector]) return native;
    id account = ((id(*)(id,SEL))objc_msgSend)(self, accountSelector);
    if (![account respondsToSelector:hostSelector]) return native;
    NSString *hostname = aq_string(((id(*)(id,SEL))objc_msgSend)(account, hostSelector));
    const char *host = [hostname UTF8String];
    if (!host || !aq_mail_host(host, strlen(host))) return native;

    /* Mail asks synchronously on its authentication worker. Serialize and reuse
     * device data briefly for IMAP's connections and SMTP, never account tokens.
     * A provider failure stops this attempt without sending a known-incomplete
     * token response to the mail server. */
    NSDictionary *headers = nil;
    NSError *error = nil;
    @synchronized([AQMailTokenAdapter class]) {
        static NSDictionary *cached;
        static NSDate *expires;
        if (!cached || [expires timeIntervalSinceNow] <= 0) {
            NSDictionary *fresh = aq_anisette(nil, &error);
            [cached release]; cached = [fresh copy];
            [expires release]; expires = [[NSDate dateWithTimeIntervalSinceNow:60] retain];
        }
        headers = [[cached retain] autorelease];
    }
    if (!headers) {
        SEL failed = NSSelectorFromString(@"setAuthenticationState:");
        if ([self respondsToSelector:failed]) ((void(*)(id,SEL,NSInteger))objc_msgSend)(self, failed, 3);
        syslog(LOG_NOTICE, "AquaTransport iCloud Mail device authentication unavailable (%ld)", (long)[error code]);
        return nil;
    }
    NSMutableData *response = [[native mutableCopy] autorelease];
    const unsigned char zero = 0;
    NSArray *fields = [NSArray arrayWithObjects:[headers objectForKey:@"X-Apple-I-MD-M"],
        [headers objectForKey:@"X-Apple-I-MD"], [headers objectForKey:@"X-MMe-Client-Info"] ?: AQClient, nil];
    for (NSString *field in fields) {
        [response appendBytes:&zero length:1];
        [response appendData:[field dataUsingEncoding:NSUTF8StringEncoding]];
    }
    @synchronized([AQMailTokenAdapter class]) {
        static BOOL logged;
        if (!logged) {
            syslog(LOG_NOTICE, "AquaTransport iCloud Mail device fields added (adapter 12)");
            logged = YES;
        }
    }
    return response;
}

@implementation AQMailTokenAdapter
+ (void)install {
    @synchronized(self) {
        if (AQMailInitialResponse || tf_flag("disable-icloud-gsa")) return;
        Class client = NSClassFromString(@"_MCAppleTokenSaslClient");
        SEL selector = NSSelectorFromString(@"initialResponse");
        Method method = class_getInstanceMethod(client, selector);
        char result[8] = {0};
        if (!method || method_getNumberOfArguments(method) != 2) return;
        method_getReturnType(method, result, sizeof result);
        if (strcmp(result, "@")) return;
        AQMailInitialResponse = (void *)method_getImplementation(method);
        if (!class_addMethod(client, selector, (IMP)aq_mail_initial_response, method_getTypeEncoding(method)))
            method_setImplementation(method, (IMP)aq_mail_initial_response);
        syslog(LOG_NOTICE, "AquaTransport iCloud Mail six-field ATOKEN adapter installed");
    }
}
@end

__attribute__((constructor)) static void aq_gsa_register(void) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    AQQueue = [[NSOperationQueue alloc] init]; [AQQueue setMaxConcurrentOperationCount:1];
    AQPending = [[NSMutableDictionary alloc] init];
    [NSURLProtocol registerClass:[AQGSAProtocol class]];
    [NSURLProtocol registerClass:[AQDAVProtocol class]];
    [AQMailTokenAdapter install];
    [pool drain];
}
