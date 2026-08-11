// The gate subject that matters most: a CFNetwork client.
//
//   cfclient <port>
//
// Every other subject here calls connect() directly, and on 10.9 that is NOT how the software
// this package exists for reaches the network. CFNetwork -- and therefore NSURLConnection,
// NSURLSession, and every application built on them -- opens a TCP connection with connectx(),
// whose destination address is its FOURTH argument rather than its second. A gate that watches
// connect() alone passes every hand-written test and covers none of the real ones.
//
// So this one goes through CFNetwork, at the lowest level that does: a CFHTTPMessage over a
// CFReadStream. It talks to a local listener rather than a real host, because what is being
// asserted is that the thread was held at the connection and released with the library
// present -- not anything about the response.
//
// Build needs the frameworks:
//   clang -framework CoreFoundation -framework CFNetwork -o cfclient cfclient.c

#include "gatetest.h"

#include <CFNetwork/CFNetwork.h>
#include <CoreFoundation/CoreFoundation.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 2; }

    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%s/", argv[1]);

    printf("before  patched=%d\n", patched());
    fflush(stdout);

    CFStringRef s = CFStringCreateWithCString(NULL, url, kCFStringEncodingUTF8);
    CFURLRef u = CFURLCreateWithString(NULL, s, NULL);
    CFHTTPMessageRef req = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), u, kCFHTTPVersion1_1);
    CFReadStreamRef rs = CFReadStreamCreateForHTTPRequest(NULL, req);

    CFReadStreamOpen(rs);
    // One read is enough to force the connection to be established. The listener closes
    // straight away, so this returns 0 or an error, and neither is what is being tested.
    UInt8 buf[64];
    CFReadStreamRead(rs, buf, sizeof buf);

    printf("after   cfnetwork request done patched=%d\n", patched());
    fflush(stdout);

    CFReadStreamClose(rs);
    CFRelease(rs); CFRelease(req); CFRelease(u); CFRelease(s);
    return 0;
}
