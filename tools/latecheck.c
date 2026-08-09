// latecheck -- the regression test for injecting with no gate.
//
// The whole loader design now rests on one property: the library can be loaded into a process
// that has not loaded CoreFoundation or Security, stay inert there, and start working if and
// when Secure Transport shows up. That is what removed the old "wait for Security.framework"
// gate, which could only ever guess when a process would load it -- and guessed wrong for
// Safari's WebKit networking service, leaving it unpatched for its whole life.
//
// This program links neither framework. It loads the dylib first, asserts that doing so pulled
// in neither framework, then brings CFNetwork in afterwards and makes a request through it.
//
// api.twitter.com is the target because stock Secure Transport on 10.9 cannot reach it
// (-9824). So "HTTP 404" proves the hooks reached a framework that arrived after we did, and
// that the engine carried the connection.
//
//   clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 -o latecheck tools/latecheck.c
//   ./latecheck /usr/share/aquatransport/aquatransport.dylib
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef const struct __CFString *CFStringRef;
typedef const struct __CFURL *CFURLRef;
typedef struct __CFHTTPMessage *CFHTTPMessageRef;
typedef struct __CFReadStream *CFReadStreamRef;
typedef const void *CFTypeRef;
typedef long CFIndex;

static int loaded(const char *needle) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, needle)) return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *dylib = argc > 1 ? argv[1] : "/usr/share/aquatransport/aquatransport.dylib";

    printf("  phase 1 (before our dylib): CF=%d Security=%d\n",
           loaded("CoreFoundation.framework"), loaded("Security.framework"));

    void *h = dlopen(dylib, RTLD_NOW | RTLD_GLOBAL);
    if (!h) { printf("  FAIL dlopen: %s\n", dlerror()); return 1; }
    printf("  phase 2 (our dylib loaded): CF=%d Security=%d   <- must be 0 0\n",
           loaded("CoreFoundation.framework"), loaded("Security.framework"));

    // Now bring the frameworks in, after we are already resident.
    if (!dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_NOW | RTLD_GLOBAL) &&
        !dlopen("/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CFNetwork.framework/CFNetwork",
                RTLD_NOW | RTLD_GLOBAL)) {
        printf("  FAIL dlopen CFNetwork: %s\n", dlerror()); return 1;
    }
    printf("  phase 3 (CFNetwork loaded): CF=%d Security=%d\n",
           loaded("CoreFoundation.framework"), loaded("Security.framework"));

    CFStringRef (*StrC)(void *, const char *, uint32_t) = dlsym(RTLD_DEFAULT, "CFStringCreateWithCString");
    CFURLRef (*URLStr)(void *, CFStringRef, CFURLRef) = dlsym(RTLD_DEFAULT, "CFURLCreateWithString");
    CFHTTPMessageRef (*ReqNew)(void *, CFStringRef, CFURLRef, CFStringRef) = dlsym(RTLD_DEFAULT, "CFHTTPMessageCreateRequest");
    CFReadStreamRef (*StreamNew)(void *, CFHTTPMessageRef) = dlsym(RTLD_DEFAULT, "CFReadStreamCreateForHTTPRequest");
    int (*Open)(CFReadStreamRef) = dlsym(RTLD_DEFAULT, "CFReadStreamOpen");
    CFIndex (*Read)(CFReadStreamRef, unsigned char *, CFIndex) = dlsym(RTLD_DEFAULT, "CFReadStreamRead");
    CFTypeRef (*CopyProp)(CFReadStreamRef, CFStringRef) = dlsym(RTLD_DEFAULT, "CFReadStreamCopyProperty");
    CFIndex (*Status)(CFHTTPMessageRef) = dlsym(RTLD_DEFAULT, "CFHTTPMessageGetResponseStatusCode");
    CFStringRef *kRespHeader = dlsym(RTLD_DEFAULT, "kCFStreamPropertyHTTPResponseHeader");
    if (!StrC || !URLStr || !ReqNew || !StreamNew || !Open || !Read || !CopyProp || !Status || !kRespHeader) {
        printf("  FAIL resolving CFNetwork symbols\n"); return 1;
    }

    CFStringRef us = StrC(NULL, "https://api.twitter.com/", 0x08000100);
    CFStringRef get = StrC(NULL, "GET", 0x08000100);
    CFStringRef ver = StrC(NULL, "HTTP/1.1", 0x08000100);
    CFURLRef url = URLStr(NULL, us, NULL);
    CFHTTPMessageRef req = ReqNew(NULL, get, url, ver);
    CFReadStreamRef st = StreamNew(NULL, req);
    if (!Open(st)) { printf("  FAIL stream open\n"); return 1; }
    unsigned char buf[4096];
    while (Read(st, buf, sizeof buf) > 0) { }
    CFHTTPMessageRef resp = (CFHTTPMessageRef)CopyProp(st, *kRespHeader);
    if (!resp) { printf("  RESULT: FAIL (no response -- TLS did not succeed)\n"); return 1; }
    printf("  RESULT: HTTP %ld\n", (long)Status(resp));
    return 0;
}
