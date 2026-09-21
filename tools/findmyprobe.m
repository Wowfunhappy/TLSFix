/* Offline request rewrite regression test; all requests terminate in this mock. */
#import <Foundation/Foundation.h>
#include <assert.h>
static NSData *expected;
static BOOL changed;
@interface FindMyMock : NSURLProtocol @end
@implementation FindMyMock
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading {
    NSURLRequest *r = [self request];
    if (changed) {
        NSMutableDictionary *json = [NSJSONSerialization JSONObjectWithData:expected options:NSJSONReadingMutableContainers error:NULL];
        [json setObject:@"" forKey:@"positionType"];
        assert([[NSJSONSerialization JSONObjectWithData:[r HTTPBody] options:0 error:NULL] isEqual:json]);
        NSString *length = [r valueForHTTPHeaderField:@"Content-Length"];
        assert(!length || [length integerValue] == [[r HTTPBody] length]);
    } else assert([[r HTTPBody] isEqual:expected] || [r HTTPBodyStream]);
    assert([[r valueForHTTPHeaderField:@"Authorization"] isEqual:@"fixture-token"]);
    NSHTTPURLResponse *response = [[[NSHTTPURLResponse alloc] initWithURL:[r URL] statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
    [[self client] URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [[self client] URLProtocolDidFinishLoading:self];
}
@end
@interface FindMyClient : NSObject <NSURLConnectionDelegate> {
@public BOOL done;
}
@end
@implementation FindMyClient
- (void)connectionDidFinishLoading:(NSURLConnection *)c { done = YES; }
- (void)connection:(NSURLConnection *)c didFailWithError:(NSError *)error { assert(!error); }
@end
int main(int argc, char **argv) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    [NSURLProtocol registerClass:[FindMyMock class]];
    BOOL enabled = argc == 1;
    NSArray *urls = @[@"https://p166-fmip.icloud.com/fmipservice/findme/123/device/currentLocation",
        @"https://p12-fmip.icloud.com:443/fmipservice/findme/123/device/currentLocation",
        @"https://fmip.icloud.com/fmipservice/findme/123/device/currentLocation",
        @"https://p166-fmip.icloud.com.evil.invalid/fmipservice/findme/123/device/currentLocation",
        @"https://p166-fmip.icloud.com/fmipservice/findme/123/device/other",
        @"http://p166-fmip.icloud.com/fmipservice/findme/123/device/currentLocation",
        @"https://p166-fmip.icloud.com:444/fmipservice/findme/123/device/currentLocation"];
    NSArray *bodies = @[@"{\"reason\":1,\"statusCode\":200,\"horizontalAccuracy\":65}",
        @"{\"positionType\":\"GPS\"}", @"{\"positionType\":null}", @"[]", @"invalid"];
    for (NSUInteger u=0; u<[urls count]; u++) for (NSUInteger b=0; b<[bodies count]; b++) {
        for (int kind=0; kind<4; kind++) for (int async=0; async<2; async++) {
            NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[urls objectAtIndex:u]]];
            expected = [[bodies objectAtIndex:b] dataUsingEncoding:NSUTF8StringEncoding];
            [r setHTTPMethod:kind == 1 ? @"GET" : @"POST"];
            [r setHTTPBody:expected];
            [r setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            [r setValue:[NSString stringWithFormat:@"%lu", (unsigned long)[expected length]] forHTTPHeaderField:@"Content-Length"];
            [r setValue:@"fixture-token" forHTTPHeaderField:@"Authorization"];
            if (kind == 2) [r setValue:@"gzip" forHTTPHeaderField:@"Content-Encoding"];
            if (kind == 3) [r setHTTPBodyStream:[NSInputStream inputStreamWithData:expected]];
            changed = enabled && u<3 && b==0 && kind==0;
            NSError *error = nil;
            if (async) {
                FindMyClient *client = [FindMyClient new];
                NSURLConnection *connection = [[NSURLConnection alloc] initWithRequest:r delegate:client];
                NSDate *limit = [NSDate dateWithTimeIntervalSinceNow:5];
                while (!client->done && [limit timeIntervalSinceNow]>0)
                    [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:limit];
                assert(client->done);
                [connection cancel]; [connection release]; [client release];
            } else [NSURLConnection sendSynchronousRequest:r returningResponse:NULL error:&error];
            assert(!error);
            /* The caller's original body remains unchanged. */
            assert(kind == 3 || [[r HTTPBody] isEqual:expected]);
        }
    }
    puts("PASS: Find My request bodies, shards, exclusions and original request preservation (offline)");
    [pool drain]; return 0;
}
