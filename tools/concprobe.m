// A page load, in the shape a browser actually makes one: N requests to N different hosts,
// all in flight at once, repeated for several rounds.
//
// Every other harness here is sequential, and that hides the cost this one exists to
// measure. Trust evaluation is per connection and serializes on CFNetwork's worker thread,
// so a page that opens a dozen connections at once pays a dozen evaluations back to back --
// and on the ECDSA chains most sites now serve, each of those is several hundred
// milliseconds (see tools/trustbench.c). One request at a time never shows it: the cost
// hides behind that request's own network time. A dozen at once cannot hide it, because
// there is nothing else for them to overlap with.
//
// Round 1 is the cold number, and the one that matters: every connection is a fresh
// handshake against a chain this process has not seen. Later rounds report the warm path,
// where session resumption and the verified-chain cache carry it.
//
// Requests are aimed at real sites deliberately -- a mix of certificate chains, CDNs and
// signature algorithms is the point, and a local server would have one chain and prove
// nothing about the arithmetic.
//
//   clang -arch x86_64 -mmacosx-version-min=10.9 -framework Foundation \
//       -o concprobe tools/concprobe.m
//
// Prints one line per round with the wall time, plus a SLOW line for any request over 3 s.

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <sys/time.h>

static double now_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

@interface AQFetch : NSObject {
@public
    double t0, t1;
    long status, bytes;
    BOOL done;
    NSString *url;
}
@end

@implementation AQFetch
- (void)connection:(NSURLConnection *)c didReceiveResponse:(NSURLResponse *)r {
    if ([r respondsToSelector:@selector(statusCode)]) status = (long)[(NSHTTPURLResponse *)r statusCode];
}
- (void)connection:(NSURLConnection *)c didReceiveData:(NSData *)d { bytes += [d length]; }
- (void)connectionDidFinishLoading:(NSURLConnection *)c { t1 = now_ms(); done = YES; }
- (void)connection:(NSURLConnection *)c didFailWithError:(NSError *)e {
    t1 = now_ms(); status = (long)[e code]; done = YES;
}
@end

int main(int argc, char **argv) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    int rounds = argc > 1 ? atoi(argv[1]) : 5;

    NSArray *urls = [NSArray arrayWithObjects:
        @"https://www.google.com/",
        @"https://www.google.com/robots.txt",
        @"https://en.wikipedia.org/wiki/Main_Page",
        @"https://upload.wikimedia.org/wikipedia/commons/6/63/Wikipedia-logo.png",
        @"https://www.bbc.co.uk/",
        @"https://static.files.bbci.co.uk/orbit/2f4c/img/blq-orbit-blocks_grey.svg",
        @"https://github.com/robots.txt",
        @"https://stackoverflow.com/robots.txt",
        @"https://www.cloudflare.com/robots.txt",
        @"https://news.ycombinator.com/",
        @"https://www.apple.com/",
        @"https://duckduckgo.com/robots.txt",
        nil];

    for (int r = 1; r <= rounds; r++) {
        NSAutoreleasePool *p2 = [[NSAutoreleasePool alloc] init];
        NSMutableArray *fs = [NSMutableArray array];
        double bt0 = now_ms();

        for (NSString *s in urls) {
            AQFetch *f = [[[AQFetch alloc] init] autorelease];
            f->url = s; f->t0 = now_ms();
            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:s]];
            [req setTimeoutInterval:30.0];
            // Otherwise round 2 onwards is served from the URL cache and no connection is
            // made at all, which would measure nothing.
            [req setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
            [[[NSURLConnection alloc] initWithRequest:req delegate:f startImmediately:YES] autorelease];
            [fs addObject:f];
        }

        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:45.0];
        for (;;) {
            BOOL all = YES;
            for (AQFetch *f in fs) if (!f->done) { all = NO; break; }
            if (all || [deadline timeIntervalSinceNow] <= 0) break;
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }

        for (AQFetch *f in fs) {
            double ms = f->done ? (f->t1 - f->t0) : -1;
            if (ms < 0 || ms > 3000)
                printf("  SLOW %7.0f ms  rc=%ld  %s\n", ms, f->status, [f->url UTF8String]);
        }
        printf("round %d done in %.0f ms\n", r, now_ms() - bt0);
        fflush(stdout);
        [p2 release];
    }
    [pool release];
    return 0;
}
