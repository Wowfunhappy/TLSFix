/* Test-only replacement of the native provider boundary. Production has no provider
 * injection or configuration switch. All OTPs and credentials are synthetic;
 * the adapter reads the real local UUID, which is neither printed nor sent over
 * the network (each probe installs a catch-all URL protocol). */
#import <objc/runtime.h>
#include <dlfcn.h>
#include <assert.h>

static NSString *const AQTestClient = @"<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";

static IMP aq_test_install_otp(IMP implementation) {
    Class utility = NSClassFromString(@"AQNativeAnisette");
    if (!utility) {
        const char *loader = getenv("DYLD_INSERT_LIBRARIES"); assert(loader);
        NSString *path = [[[NSString stringWithUTF8String:loader] stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"aquatransport_gsa.dylib"];
        assert(dlopen([path fileSystemRepresentation], RTLD_LAZY | RTLD_LOCAL));
        utility = NSClassFromString(@"AQNativeAnisette");
    }
    Method method = class_getClassMethod(utility, NSSelectorFromString(@"headersForOwner:error:"));
    assert(method && method_getNumberOfArguments(method) == 4);
    char result[8] = {0}, argument[8] = {0};
    method_getReturnType(method, result, sizeof result);
    method_getArgumentType(method, 2, argument, sizeof argument);
    assert(!strcmp(result, "@") && !strcmp(argument, "@"));
    return method_setImplementation(method, implementation);
}
