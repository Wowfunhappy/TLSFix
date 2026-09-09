/* Offline DAV forwarding tests. The catch-all mock owns every URL, so no sockets
 * or real credentials are used. Load through AquaTransport's native C funnel. */
#import <Foundation/Foundation.h>
#import <objc/message.h>
#include <assert.h>
static NSString *mode;
static int providerCalls, davCalls, authCalls, unexpected;
static NSData *data(NSString *s) { return [s dataUsingEncoding:NSUTF8StringEncoding]; }
@interface DAVMock : NSURLProtocol <NSURLAuthenticationChallengeSender> @end
@implementation DAVMock
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)respond {
    NSHTTPURLResponse *r = [[[NSHTTPURLResponse alloc] initWithURL:[[self request] URL] statusCode:207 HTTPVersion:@"HTTP/1.1"
        headerFields:@{@"Content-Type":@"application/xml",@"ETag":@"fixture-etag",@"DAV":@"1, 2, calendar-access"}] autorelease];
    [[self client] URLProtocol:self didReceiveResponse:r cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [[self client] URLProtocol:self didLoadData:data(@"<d:multistatus xmlns:d=\"DAV:\">")];
    [[self client] URLProtocol:self didLoadData:data(@"</d:multistatus>")];
    [[self client] URLProtocolDidFinishLoading:self];
}
- (void)startLoading {
    NSURLRequest *r=[self request]; NSString *host=[[r URL] host];
    if ([host isEqual:@"127.0.0.1"]) {
        providerCalls++;
        assert(![r valueForHTTPHeaderField:@"Authorization"]);
        NSDictionary *h=[mode isEqual:@"missing"]?@{}:@{@"X-Apple-I-MD":@"otp",@"X-Apple-I-MD-M":@"machine",
            @"X-Apple-I-MD-LU":@"user",@"X-Apple-I-MD-RINFO":@"1",@"X-Mme-Device-Id":@"device"};
        NSHTTPURLResponse *response=[[[NSHTTPURLResponse alloc] initWithURL:[r URL] statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
        [[self client] URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        [[self client] URLProtocol:self didLoadData:[NSJSONSerialization dataWithJSONObject:h options:0 error:NULL]];
        [[self client] URLProtocolDidFinishLoading:self];return;
    }
    if ([mode isEqual:@"disabled"]) {
        assert(![r valueForHTTPHeaderField:@"X-Apple-I-MD"]);[self respond];return;
    }
    assert([NSURLProtocol propertyForKey:@"AquaTransportGSAHandled" inRequest:r]);
    assert([[r valueForHTTPHeaderField:@"X-Apple-I-MD"] isEqual:@"otp"]);
    assert([[r valueForHTTPHeaderField:@"X-Apple-I-MD-M"] isEqual:@"machine"]);
    assert([[r valueForHTTPHeaderField:@"Depth"] isEqual:@"0"]);
    assert([[r HTTPMethod] isEqual:@"PROPFIND"] && [[r HTTPBody] isEqual:data(@"fixture-dav-body")]);
    assert(![r HTTPShouldHandleCookies]);
    if (![host isEqual:@"p402-caldav.icloud.com"] && ![host isEqual:@"p402-contacts.icloud.com"]) {unexpected++;return;}
    if ([mode hasPrefix:@"native-"]) assert([[[r URL] port] integerValue]==443 && [[[r URL] user] length]);
    davCalls++;
    if ([mode isEqual:@"auth"]) {
        NSURLProtectionSpace *p=[[[NSURLProtectionSpace alloc] initWithHost:host port:443 protocol:@"https" realm:@"fixture" authenticationMethod:NSURLAuthenticationMethodHTTPBasic] autorelease];
        NSURLAuthenticationChallenge *c=[[[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:p proposedCredential:nil previousFailureCount:0 failureResponse:nil error:nil sender:self] autorelease];
        [[self client] URLProtocol:self didReceiveAuthenticationChallenge:c];return;
    }
    [self respond];
}
- (void)useCredential:(NSURLCredential *)credential forAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    assert([[credential user] isEqual:@"fixture-user"] && [[credential password] isEqual:@"fixture-token"]);
    authCalls++;[self respond];
}
- (void)continueWithoutCredentialForAuthenticationChallenge:(NSURLAuthenticationChallenge *)c { unexpected++; }
- (void)cancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)c { unexpected++; }
@end
@interface DAVClient : NSObject <NSURLConnectionDelegate> {
@public BOOL done; int challenges; NSMutableData *body; NSHTTPURLResponse *response; NSError *error;
} @end
@implementation DAVClient
- (id)init { if((self=[super init]))body=[NSMutableData new];return self; }
- (void)dealloc { [body release];[response release];[error release];[super dealloc]; }
- (void)connection:(NSURLConnection *)c didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    challenges++;
    [[challenge sender] useCredential:[NSURLCredential credentialWithUser:@"fixture-user" password:@"fixture-token" persistence:NSURLCredentialPersistenceNone] forAuthenticationChallenge:challenge];
}
- (void)connection:(NSURLConnection *)c didReceiveResponse:(NSURLResponse *)r {response=[(NSHTTPURLResponse*)r retain];}
- (void)connection:(NSURLConnection *)c didReceiveData:(NSData *)d {[body appendData:d];}
- (void)connection:(NSURLConnection *)c didFailWithError:(NSError *)e {error=[e retain];done=YES;}
- (void)connectionDidFinishLoading:(NSURLConnection *)c {done=YES;}
@end
@interface DAVProtocolClient : NSObject <NSURLProtocolClient> { @public int callbacks; NSURLRequest *redirect; } @end
@implementation DAVProtocolClient
- (void)dealloc { [redirect release];[super dealloc]; }
- (void)URLProtocol:(NSURLProtocol *)p wasRedirectedToRequest:(NSURLRequest *)r redirectResponse:(NSURLResponse *)s { callbacks++;redirect=[r copy]; }
- (void)URLProtocol:(NSURLProtocol *)p cachedResponseIsValid:(NSCachedURLResponse *)r { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p didReceiveResponse:(NSURLResponse *)r cacheStoragePolicy:(NSURLCacheStoragePolicy)s { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p didLoadData:(NSData *)d { callbacks++; }
- (void)URLProtocolDidFinishLoading:(NSURLProtocol *)p { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p didFailWithError:(NSError *)e { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)c { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)c { callbacks++; }
@end
static void checkRedirectsAndCancellation(Class protocol, NSURLRequest *request) {
    for (NSString *target in @[@"https://p402-caldav.icloud.com/new",@"https://example.invalid/new",@"http://p402-caldav.icloud.com/new"]) {
        DAVProtocolClient *client=[DAVProtocolClient new];
        id p=[[protocol alloc] initWithRequest:request cachedResponse:nil client:client];
        NSMutableURLRequest *next=[[request mutableCopy] autorelease];[next setURL:[NSURL URLWithString:target]];
        [next setValue:@"fixture-auth" forHTTPHeaderField:@"Authorization"];
        for(NSString *h in @[@"X-Apple-I-MD",@"X-Apple-I-MD-M",@"X-Mme-Device-Id",@"X-MMe-Client-Info"])
            [next setValue:@"fixture-secret" forHTTPHeaderField:h];
        [NSURLProtocol setProperty:@YES forKey:@"AquaTransportGSAHandled" inRequest:next];
        NSHTTPURLResponse *response=[[[NSHTTPURLResponse alloc] initWithURL:[request URL] statusCode:307 HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
        id result=((id(*)(id,SEL,id,id,id))objc_msgSend)(p,@selector(connection:willSendRequest:redirectResponse:),nil,next,response);
        assert(!result && client->callbacks==1 && client->redirect);
        for(NSString *h in @[@"X-Apple-I-MD",@"X-Apple-I-MD-M",@"X-Mme-Device-Id",@"X-MMe-Client-Info"])
            assert(![client->redirect valueForHTTPHeaderField:h]);
        assert(![NSURLProtocol propertyForKey:@"AquaTransportGSAHandled" inRequest:client->redirect]);
        assert(([client->redirect valueForHTTPHeaderField:@"Authorization"]!=nil)==[target hasPrefix:@"https://p402-caldav.icloud.com/"]);
        [p release];[client release];
    }
    DAVProtocolClient *client=[DAVProtocolClient new];
    NSURLProtocol *p=[[protocol alloc] initWithRequest:request cachedResponse:nil client:client];
    [p startLoading];[p stopLoading];
    NSDate *until=[NSDate dateWithTimeIntervalSinceNow:.1];
    while([until timeIntervalSinceNow]>0) [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:until];
    assert(client->callbacks==0);[p release];[client release];
}
int main(int argc,char **argv) {
    NSAutoreleasePool *pool=[NSAutoreleasePool new];assert(argc==2);mode=[NSString stringWithUTF8String:argv[1]];
    [NSURLProtocol registerClass:[DAVMock class]];
    NSMutableURLRequest *r=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://p402-caldav.icloud.com/"]];
    if([mode isEqual:@"native-calendar"]) [r setURL:[NSURL URLWithString:@"https://fixture%40example.invalid@p402-caldav.icloud.com:8443/resource?query=fixture"]];
    if([mode isEqual:@"native-contacts"]) [r setURL:[NSURL URLWithString:@"https://fixture%40example.invalid@p402-contacts.icloud.com:8843/resource"]];
    [r setHTTPMethod:@"PROPFIND"];[r setHTTPBody:data(@"fixture-dav-body")];[r setValue:@"0" forHTTPHeaderField:@"Depth"];
    DAVClient *client=[DAVClient new];NSURLConnection *c=[[NSURLConnection alloc] initWithRequest:r delegate:client];
    NSDate *until=[NSDate dateWithTimeIntervalSinceNow:5];
    while(!client->done && [until timeIntervalSinceNow]>0) [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:.01]];
    [c cancel];assert(client->done && !unexpected);
    if([mode isEqual:@"missing"]) {assert(client->error && providerCalls==1 && davCalls==0);}
    else {
        assert(!client->error && [client->response statusCode]==207);
        assert([[[client->response allHeaderFields] objectForKey:@"ETag"] isEqual:@"fixture-etag"]);
        assert([client->body isEqual:data(@"<d:multistatus xmlns:d=\"DAV:\"></d:multistatus>")]);
        if([mode isEqual:@"auth"])assert(authCalls==1 && client->challenges==1);
    }
    Class protocol=NSClassFromString(@"AQDAVProtocol");
    if([mode isEqual:@"disabled"])assert(!protocol && providerCalls==0);
    else {
        assert(protocol);
        checkRedirectsAndCancellation(protocol,[NSURLRequest requestWithURL:[NSURL URLWithString:@"https://p402-caldav.icloud.com/"]]);
        for(NSString *url in @[@"https://contacts.icloud.com/",@"https://p402-contacts.icloud.com:443/",@"https://p01-caldav.icloud.com/",@"https://user@p402-caldav.icloud.com/",@"https://user@p402-caldav.icloud.com:8443/",@"https://user@p402-contacts.icloud.com:8843/"])
            assert([protocol canInitWithRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:url]]]);
        for(NSString *url in @[@"http://p402-caldav.icloud.com/",@"https://p402-caldav.icloud.com:8843/",@"https://p402-caldav.icloud.com.evil.invalid/",@"https://evil.invalid/p402-caldav.icloud.com/",@"https://user:password@p402-caldav.icloud.com/",@"https://p402-caldav.icloud.com@evil.invalid/",@"https://p-caldav.icloud.com/"])
            assert(![protocol canInitWithRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:url]]]);
        NSMutableURLRequest *handled=[[r mutableCopy] autorelease];
        [NSURLProtocol setProperty:@YES forKey:@"AquaTransportGSAHandled" inRequest:handled];assert(![protocol canInitWithRequest:handled]);
    }
    printf("PASS: DAV %s (native request path, headers, body, response, scope)\n",[mode UTF8String]);
    [c release];[client release];[pool drain];return 0;
}
