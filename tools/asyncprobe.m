// Async NSURLConnection probe. The synchronous and asynchronous paths funnel through
// different CFNetwork entry points, so both need testing: sendSynchronousRequest goes
// through CFURLConnectionSendSynchronousRequest, while most real apps are async.
//
//   clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 -framework Foundation \
//       -o asyncprobe tools/asyncprobe.m
//
// Prints: <status> final=<url> bytes=<n>   (same shape as urlprobe)

#import <Foundation/Foundation.h>
#include <stdio.h>

static BOOL gDone = NO;
static long gStatus = 0;
static long gBytes = 0;
static NSString *gFinal = nil;

@interface AQAsyncDelegate : NSObject
@end

@implementation AQAsyncDelegate
- (void)connection:(NSURLConnection *)c didReceiveResponse:(NSURLResponse *)r {
    if ([r respondsToSelector:@selector(statusCode)]) gStatus = (long)[(NSHTTPURLResponse *)r statusCode];
    gFinal = [[[r URL] absoluteString] copy];
}
- (void)connection:(NSURLConnection *)c didReceiveData:(NSData *)d { gBytes += [d length]; }
- (void)connectionDidFinishLoading:(NSURLConnection *)c { gDone = YES; }
- (void)connection:(NSURLConnection *)c didFailWithError:(NSError *)e {
    printf("FAIL err=%ld %s\n", (long)[e code], [[e localizedDescription] UTF8String] ?: "");
    gDone = YES; gStatus = -1;
}
@end

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: asyncprobe <url>\n"); return 2; }
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSURL *u = [NSURL URLWithString:[NSString stringWithUTF8String:argv[1]]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
    [req setTimeoutInterval:25.0];

    AQAsyncDelegate *d = [[AQAsyncDelegate alloc] init];
    NSURLConnection *c = [[NSURLConnection alloc] initWithRequest:req delegate:d startImmediately:YES];
    if (!c) { printf("FAIL no-connection\n"); [pool release]; return 1; }

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:30.0];
    while (!gDone && [deadline timeIntervalSinceNow] > 0)
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:
            [NSDate dateWithTimeIntervalSinceNow:0.25]];

    if (gStatus > 0) printf("%ld final=%s bytes=%ld\n", gStatus, [gFinal UTF8String] ?: "?", gBytes);
    else if (gStatus == 0) printf("FAIL timeout\n");
    [pool release];
    return gStatus > 0 ? 0 : 1;
}
