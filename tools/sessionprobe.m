// NSURLSession probe (10.9+ only; NSURLSession does not exist on 10.6-10.8).
//
// NSURLSession may funnel through different CFNetwork entry points than NSURLConnection,
// so it needs its own coverage. Built with a 10.9 deployment target on purpose.
//
//   clang -arch x86_64 -mmacosx-version-min=10.9 -framework Foundation \
//       -o sessionprobe tools/sessionprobe.m
//
// Prints: <status> final=<url> bytes=<n>   (same shape as urlprobe/asyncprobe)

#import <Foundation/Foundation.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: sessionprobe <url>\n"); return 2; }
    @autoreleasepool {
        NSURL *u = [NSURL URLWithString:[NSString stringWithUTF8String:argv[1]]];
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
        cfg.timeoutIntervalForRequest = 25.0;
        NSURLSession *s = [NSURLSession sessionWithConfiguration:cfg];

        __block long status = 0, bytes = 0;
        __block NSString *final = nil;
        __block BOOL done = NO;

        NSURLSessionDataTask *t = [s dataTaskWithURL:u
                completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            if (e) { printf("FAIL err=%ld %s\n", (long)e.code, e.localizedDescription.UTF8String ?: ""); }
            else {
                if ([r respondsToSelector:@selector(statusCode)]) status = (long)[(NSHTTPURLResponse *)r statusCode];
                final = [r.URL.absoluteString copy];
                bytes = (long)d.length;
            }
            done = YES;
        }];
        [t resume];

        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:30.0];
        while (!done && [deadline timeIntervalSinceNow] > 0)
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                     beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];

        if (status > 0) printf("%ld final=%s bytes=%ld\n", status, final.UTF8String ?: "?", bytes);
        else if (!done) printf("FAIL timeout\n");
        return status > 0 ? 0 : 1;
    }
}
