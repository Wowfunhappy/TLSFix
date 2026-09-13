/* Offline: native GeoServices serialization and a catch-all URL protocol.
 * No Calendar accounts/events, location services or Apple requests are used. */
#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <assert.h>
#include <dlfcn.h>

@interface AQMapMock : NSURLProtocol @end
@implementation AQMapMock
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading {
    NSURLRequest *r=[self request];
    assert([[r HTTPMethod] isEqual:@"POST"] && [[r HTTPBody] isEqual:[@"fixture-body" dataUsingEncoding:NSUTF8StringEncoding]]);
    assert([[r valueForHTTPHeaderField:@"X-Fixture"] isEqual:@"retained"]);
    NSData *data=[[[r URL] absoluteString] dataUsingEncoding:NSUTF8StringEncoding];
    NSURLResponse *response=[[[NSHTTPURLResponse alloc] initWithURL:[r URL] statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
    [[self client] URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [[self client] URLProtocol:self didLoadData:data]; [[self client] URLProtocolDidFinishLoading:self];
}
@end
/* GeoServices uses this private asynchronous initializer. Repeating requests is
 * essential: calling a captured lazy binding stub can remove the URL hook after
 * the first request, which synchronous-only probes do not detect. */
@interface AQMapReceiver : NSObject {
@public
    NSMutableData *data;
    NSError *error;
    BOOL done;
}
@end
@implementation AQMapReceiver
- (id)init { if ((self=[super init])) data=[NSMutableData new]; return self; }
- (void)connection:(id)c didReceiveData:(NSData *)d { [data appendData:d]; }
- (void)connectionDidFinishLoading:(id)c { done=YES; }
- (void)connection:(id)c didFailWithError:(NSError *)e { error=[e retain]; done=YES; }
- (void)dealloc { [data release]; [error release]; [super dealloc]; }
@end
static BOOL privateConnection;
static NSString *loadURL(NSString *url) {
    NSMutableURLRequest *r=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    [r setHTTPMethod:@"POST"]; [r setHTTPBody:[@"fixture-body" dataUsingEncoding:NSUTF8StringEncoding]];
    [r setValue:@"retained" forHTTPHeaderField:@"X-Fixture"];
    if (privateConnection) {
        AQMapReceiver *receiver=[AQMapReceiver new];
        id connection=((id(*)(id,SEL,id,id,BOOL,long long,BOOL,id))objc_msgSend)(
            [NSURLConnection alloc],NSSelectorFromString(@"_initWithRequest:delegate:usesCache:maxContentLength:startImmediately:connectionProperties:"),
            r,receiver,NO,0,NO,nil);
        assert(connection);
        [connection scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSRunLoopCommonModes];
        [connection start];
        NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:5];
        while (!receiver->done && [deadline timeIntervalSinceNow]>0)
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
        assert(receiver->done && !receiver->error);
        NSString *result=[[[NSString alloc] initWithData:receiver->data encoding:NSUTF8StringEncoding] autorelease];
        [connection cancel]; [connection release]; [receiver release]; return result;
    }
    NSURLResponse *response=nil; NSError *error=nil;
    NSData *data=[NSURLConnection sendSynchronousRequest:r returningResponse:&response error:&error];
    assert(!error && data && [(NSHTTPURLResponse *)response statusCode]==200);
    return [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];
}
static id instance(NSString *name) { Class cls=NSClassFromString(name); assert(cls); return [[[cls alloc] init] autorelease]; }
static id point(double lat,double lng) { id p=instance(@"GEOLatLng"); [p setValue:[NSNumber numberWithDouble:lat] forKey:@"lat"]; [p setValue:[NSNumber numberWithDouble:lng] forKey:@"lng"]; return p; }
static NSData *serialize(id request) {
    id writer=instance(@"PBDataWriter");
    ((void(*)(id,SEL,id))objc_msgSend)(request,NSSelectorFromString(@"writeTo:"),writer);
    return ((id(*)(id,SEL))objc_msgSend)(writer,NSSelectorFromString(@"data"));
}
int main(int argc,char **argv) {
    NSAutoreleasePool *pool=[NSAutoreleasePool new]; assert(argc==3);
    NSString *mode=[NSString stringWithUTF8String:argv[1]], *output=[NSString stringWithUTF8String:argv[2]];
    BOOL disabled=[mode hasPrefix:@"disabled"], eta=[mode rangeOfString:@"eta"].location!=NSNotFound;
    privateConnection=[mode rangeOfString:@"private"].location!=NSNotFound;
    [NSURLProtocol registerClass:[AQMapMock class]];
    assert(!NSClassFromString(@"AQMapsAdapter"));
    NSMutableDictionary *results=[NSMutableDictionary dictionary];
    if (eta) {
        if (!NSClassFromString(@"GEODirectionsRequest")) assert(dlopen("/System/Library/PrivateFrameworks/GeoServices.framework/GeoServices",RTLD_NOW|RTLD_LOCAL));
        assert(!NSClassFromString(@"AQMapsAdapter"));
        id request=instance(@"GEODirectionsRequest");
        [request setValue:@1234567 forKey:@"departureTime"];
        [request setValue:@5 forKey:@"mainTransportTypeMaxRouteCount"];
        [request setValue:@YES forKey:@"getRouteForZilchPoints"];
        id location=instance(@"GEOLocation"); [location setValue:point(37,-122) forKey:@"latLng"];
        id first=instance(@"GEOWaypoint"); [first setValue:location forKey:@"location"];
        id second=instance(@"GEOWaypoint");
        [second setValue:[NSArray arrayWithObjects:point(38,179),point(40,-179),nil] forKey:@"entryPoints"];
        [request setValue:[NSArray arrayWithObjects:first,second,nil] forKey:@"waypoints"];
        [results setObject:[serialize(request) base64EncodedStringWithOptions:0] forKey:@"directions"];
        [results setObject:[NSNumber numberWithBool:NSClassFromString(@"AQMapsAdapter")!=Nil] forKey:@"moduleLoaded"];
        [results setObject:[serialize(location) base64EncodedStringWithOptions:0] forKey:@"location"];
        id unsupported=instance(@"GEOWaypoint");
        [request setValue:[NSArray arrayWithObjects:first,unsupported,nil] forKey:@"waypoints"];
        [results setObject:[serialize(request) base64EncodedStringWithOptions:0] forKey:@"unsupported"];
        [second setValue:[NSArray arrayWithObject:point(91,0)] forKey:@"entryPoints"];
        [request setValue:[NSArray arrayWithObjects:first,second,nil] forKey:@"waypoints"];
        [results setObject:[serialize(request) base64EncodedStringWithOptions:0] forKey:@"invalid"];
    } else {
        NSMutableArray *rewritten=[NSMutableArray array];
        for (NSString *host in [NSArray arrayWithObjects:@"gspa35-ssl.ls.apple.com",@"gspa21.ls.apple.com",@"gspa19.ls.apple.com",@"gspa12.ls.apple.com",@"gspa11.ls.apple.com",nil]) {
            NSString *url=[NSString stringWithFormat:@"http://%@/tile%%2Fpart%%20one?x=1&tk=old&x=2&mapkey=old&sid=old&accessKey=old&q=a%%2Bb#frag",host];
            NSString *changed=loadURL(url);
            if (disabled) assert([changed isEqual:url]);
            else {
                NSString *expected=[host stringByReplacingOccurrencesOfString:@"gspa" withString:@"gspe"];
                if ([expected rangeOfString:@"-ssl"].location==NSNotFound)
                    expected=[expected stringByReplacingOccurrencesOfString:@".ls.apple.com" withString:@"-ssl.ls.apple.com"];
                assert([[[NSURL URLWithString:changed] host] isEqual:expected]);
            }
            [rewritten addObject:changed];
        }
        [results setObject:rewritten forKey:@"urls"];
        [results setObject:loadURL(@"https://gspa12.ls.apple.com") forKey:@"emptyPath"];
        for (NSString *url in [NSArray arrayWithObjects:@"https://gspa12.ls.apple.com.example.invalid/tile",
            @"https://example.invalid/gspa12.ls.apple.com/tile", @"https://gspa12.ls.apple.com:444/tile",
            @"https://gspe12-ssl.ls.apple.com/tile?accessKey=unchanged",@"https://gspa99.ls.apple.com/tile",nil]) assert([loadURL(url) isEqual:url]);
        CFURLRef url=CFURLCreateWithString(NULL,CFSTR("http://gspa11.ls.apple.com/tile?x=1"),NULL);
        CFHTTPMessageRef message=CFHTTPMessageCreateRequest(NULL,CFSTR("GET"),url,kCFHTTPVersion1_1);
        CFURLRef changed=CFHTTPMessageCopyRequestURL(message);
        [results setObject:(NSString *)CFURLGetString(changed) forKey:@"rawURL"];
        CFRelease(changed); CFRelease(message); CFRelease(url);
        assert((NSClassFromString(@"AQMapsAdapter")!=Nil)==!disabled);
    }
    NSData *json=[NSJSONSerialization dataWithJSONObject:results options:0 error:NULL];
    assert([json writeToFile:output atomically:YES]);
    printf("PASS: offline maps %s\n",[mode UTF8String]); [pool drain]; return 0;
}
