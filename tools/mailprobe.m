/* Offline native MailCore integration. Fixtures only; every URL is intercepted. */
#import <Foundation/Foundation.h>
#import <Security/SecureTransport.h>
#import <objc/message.h>
#include <assert.h>
#include <dlfcn.h>

static NSString *mode;
static int providerCalls;
@interface MailMock : NSURLProtocol @end
@implementation MailMock
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading {
    NSURLRequest *r = [self request];
    assert([[[r URL] absoluteString] isEqual:@"http://127.0.0.1:9/anisette"]);
    assert(![r valueForHTTPHeaderField:@"Authorization"] && ![r HTTPBody]);
    providerCalls++;
    NSDictionary *h = [mode hasPrefix:@"missing"] ? @{} : @{
        @"X-Apple-I-MD":@"fixture-otp", @"X-Apple-I-MD-M":@"fixture-machine",
        @"X-Apple-I-MD-LU":@"fixture-user", @"X-Apple-I-MD-RINFO":@"1",
        @"X-Mme-Device-Id":@"fixture-device", @"X-MMe-Client-Info":@"<fixture-client>"};
    NSHTTPURLResponse *response = [[[NSHTTPURLResponse alloc] initWithURL:[r URL] statusCode:200
        HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
    [[self client] URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [[self client] URLProtocol:self didLoadData:[NSJSONSerialization dataWithJSONObject:h options:0 error:NULL]];
    [[self client] URLProtocolDidFinishLoading:self];
}
@end

@interface MailAccountFixture : NSObject {
@public NSString *host; NSString *token;
} @end
@implementation MailAccountFixture
- (NSString *)applePersonID { return @"123456789"; }
- (NSString *)appleAuthenticationToken { return token; }
- (NSString *)hostname { return host; }
@end

static id clientFor(MailAccountFixture *account) {
    Class c = NSClassFromString(@"_MCAppleTokenSaslClient"); assert(c);
    return [((id(*)(id,SEL,id,id))objc_msgSend)([c alloc],
        NSSelectorFromString(@"initWithMechanismName:account:"), @"ATOKEN", account) autorelease];
}
static NSData *response(id client) {
    return ((id(*)(id,SEL))objc_msgSend)(client, NSSelectorFromString(@"initialResponse"));
}
static NSData *joined(NSArray *strings) {
    NSMutableData *d = [NSMutableData data]; unsigned char zero = 0;
    for (NSString *s in strings) { if ([d length]) [d appendBytes:&zero length:1]; [d appendData:[s dataUsingEncoding:NSUTF8StringEncoding]]; }
    return d;
}
static void prepare(NSString *host) {
    /* Context setup invokes the real C hook but opens no socket or TLS session. */
    SSLContextRef ssl = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType); assert(ssl);
    const char *name = [host UTF8String];
    assert(SSLSetPeerDomainName(ssl, name, strlen(name)) == 0); CFRelease(ssl);
}
int main(int argc, char **argv) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    assert(argc == 2); mode = [NSString stringWithUTF8String:argv[1]];
    assert(dlopen("/System/Library/PrivateFrameworks/MailCore.framework/MailCore", RTLD_NOW));
    [NSURLProtocol registerClass:[MailMock class]];
    MailAccountFixture *a = [[[MailAccountFixture alloc] init] autorelease];
    NSString *token = [mode hasSuffix:@"-opaque"] ? @"opaque-fixture-token" : @"E-fixture-token";
    a->host = @"p32-imap.mail.me.com"; a->token = token;
    NSData *native = joined(@[@"123456789", @"123456789", token]);
    assert([response(clientFor(a)) isEqual:native]);
    for (NSString *host in @[@"example.invalid", @"p-imap.mail.me.com", @"p32-imap.mail.me.com.evil.invalid",
            @"imap.mail.me.com:993", @"user@imap.mail.me.com", @"smtp.mail.me.com/", @"p32-other.mail.me.com"])
        prepare(host);
    assert(!NSClassFromString(@"AQMailTokenAdapter"));
    prepare(a->host);
    if ([mode hasPrefix:@"disabled"]) {
        assert(!NSClassFromString(@"AQMailTokenAdapter") && [response(clientFor(a)) isEqual:native]);
        assert(providerCalls == 0);
    } else if ([mode hasPrefix:@"missing"]) {
        id c = clientFor(a); assert(!response(c));
        assert(((NSInteger(*)(id,SEL))objc_msgSend)(c, NSSelectorFromString(@"authenticationState")) == 3);
        assert(providerCalls == 1);
    } else {
        assert(NSClassFromString(@"AQMailTokenAdapter"));
        NSData *expected = joined(@[@"123456789", @"123456789", token,
            @"fixture-machine", @"fixture-otp", @"<fixture-client>"]);
        for (NSString *host in @[@"p32-imap.mail.me.com", @"p32-smtp.mail.me.com", @"imap.mail.me.com",
                @"smtp.mail.me.com", @"imap.mail.icloud.com", @"smtp.mail.icloud.com", @"P32-IMAP.MAIL.ME.COM"]) {
            a->host = host; id c = clientFor(a); assert([response(c) isEqual:expected]);
            assert([((id(*)(id,SEL,id))objc_msgSend)(c, NSSelectorFromString(@"responseForServerData:"), [NSData data]) isEqual:expected]);
        }
        assert(providerCalls == 1); // IMAP, SMTP and challenge replies share device data.
        a->host = @"imap.mail.me.com.evil.invalid";
        assert([response(clientFor(a)) isEqual:native]);
        a->host = @"imap.mail.me.com"; a->token = @"another-opaque-token";
        assert([response(clientFor(a)) isEqual:joined(@[@"123456789", @"123456789", @"another-opaque-token",
            @"fixture-machine", @"fixture-otp", @"<fixture-client>"])]);
        assert(providerCalls == 1);
        NSString *flags = [[NSString stringWithUTF8String:getenv("AQUATRANSPORT_DIR")] stringByAppendingPathComponent:@"flags.txt"];
        [NSThread sleepForTimeInterval:1.1]; // The shared config checks mtime once a second.
        assert([@"disable-icloud-gsa\n" writeToFile:flags atomically:YES encoding:NSUTF8StringEncoding error:NULL]);
        a->token = token;
        assert([response(clientFor(a)) isEqual:native] && providerCalls == 1);
        assert([@"" writeToFile:flags atomically:YES encoding:NSUTF8StringEncoding error:NULL]);
    }
    printf("PASS Mail native ATOKEN %s (%s)\n", argv[1], sizeof(void *) == 8 ? "x86_64" : "i386");
    [pool drain]; return 0;
}
