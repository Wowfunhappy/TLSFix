// Test harness for the rewrite bundle. Goes through NSURLConnection, which is the layer
// NSURLProtocol intercepts (raw CFReadStream requests bypass it entirely).
//
// Prints: <status> final=<url-actually-fetched> bytes=<n>
// The final URL is how a redirect rule is verified -- it reflects where the request landed,
// not where it was aimed.
//
//   clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 -framework Foundation \
//       -o urlprobe tools/urlprobe.m

#import <Foundation/Foundation.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: urlprobe <url> [showbody]\n"); return 2; }
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    NSString *s = [NSString stringWithUTF8String:argv[1]];
    NSURL *u = [NSURL URLWithString:s];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
    [req setTimeoutInterval:25.0];

    NSURLResponse *resp = nil;
    NSError *err = nil;
    NSData *body = [NSURLConnection sendSynchronousRequest:req returningResponse:&resp error:&err];

    if (!body) {
        printf("FAIL err=%ld %s\n", (long)[err code],
               [[err localizedDescription] UTF8String] ?: "");
        [pool release];
        return 1;
    }
    long status = [resp respondsToSelector:@selector(statusCode)]
                ? (long)[(NSHTTPURLResponse *)resp statusCode] : 0;
    printf("%ld final=%s bytes=%lu\n", status,
           [[[resp URL] absoluteString] UTF8String] ?: "?", (unsigned long)[body length]);

    if (argc > 2) {
        NSString *t = [[[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding] autorelease];
        if ([t length] > 1200) t = [t substringToIndex:1200];
        printf("%s\n", [t UTF8String] ?: "");
    }
    [pool release];
    return 0;
}
