// poolprobe -- N sequential NSURLConnection requests to the same host in one process.
//
// NSURLConnection pools and reuses connections, so this exercises the *warm* path: after the
// first request there is no handshake, and what remains is the engine's per-request cost. That
// is the path a browser spends nearly all its time on, loading dozens of small subresources
// over a handful of pooled connections, and it is invisible to any probe that forces a new
// connection per request (CFReadStream-based ones do).
//
// What it guards: a SecTrustEvaluate costs ~335ms on this hardware, so anything that evaluates
// trust per request rather than per connection shows up here as a warm request several times
// the stock stack's ~85ms, and nowhere else.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -framework Foundation -o poolprobe tools/poolprobe.m
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <sys/time.h>
static double now_ms(void){struct timeval t;gettimeofday(&t,NULL);return t.tv_sec*1000.0+t.tv_usec/1000.0;}
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr,"usage: poolprobe <url> <n>\n"); return 2; }
    @autoreleasepool {
        NSURL *u = [NSURL URLWithString:[NSString stringWithUTF8String:argv[1]]];
        int n = atoi(argv[2]);
        for (int i = 0; i < n; i++) {
            double t0 = now_ms();
            NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:u
                cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData timeoutInterval:30];
            NSHTTPURLResponse *resp = nil; NSError *err = nil;
            NSData *d = [NSURLConnection sendSynchronousRequest:r returningResponse:(NSURLResponse **)&resp error:&err];
            printf("  %d  %6.0f ms  status=%ld bytes=%lu\n", i+1, now_ms()-t0,
                   (long)resp.statusCode, (unsigned long)d.length);
            fflush(stdout);
        }
    }
    return 0;
}
