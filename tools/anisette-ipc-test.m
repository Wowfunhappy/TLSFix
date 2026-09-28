/* IPC fixtures use synthetic headers. --live talks only to the installed local
 * service; it neither reads credentials nor submits account requests. */
#include "../src/mac/aquatransport_gsa.m"
#include <assert.h>
#include <pthread.h>
struct IPCFixture { int socket; const void *bytes; size_t length; uint32_t advertised; };
static void *serveFixture(void *context) {
    struct IPCFixture *f = context;
    int client = accept(f->socket, NULL, NULL); assert(client >= 0);
    int one = 1; setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    unsigned char op; ssize_t n = recv(client, &op, 1, 0);
    if (n == 1) {
        assert(op == 1); uint32_t size = htonl(f->advertised);
        send(client, &size, sizeof size, 0);
        if (f->length) send(client, f->bytes, f->length, 0);
    }
    close(client); return NULL;
}
@interface AQIPCCancelled : AQGSAProtocol @end
@implementation AQIPCCancelled
- (BOOL)isStopped { return YES; }
@end
@interface AQIPCNoHTTP : NSURLProtocol @end
@implementation AQIPCNoHTTP
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading { assert(!"Anisette client must never make HTTP requests"); }
@end
int main(int argc, char **argv) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    [NSURLProtocol registerClass:[AQIPCNoHTTP class]];
    if (argc == 2 && !strcmp(argv[1], "--live")) {
        NSError *error = nil; NSDictionary *headers = aq_anisette(nil, &error);
        if (!headers) { fprintf(stderr, "Local service failed: code=%ld (%s)\n", (long)[error code], [[error localizedDescription] UTF8String]); return 1; }
        puts("PASS: production local IPC returned native Anisette; values withheld");
        [pool drain]; return 0;
    }
    assert(argc == 1);
    char directory[] = "/tmp/aq-ipc.XXXXXX"; assert(mkdtemp(directory));
    struct sockaddr_un address; memset(&address, 0, sizeof address); address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof address.sun_path, "%s/socket", directory);
    for (int mode = 0; mode < 8; mode++) {
        NSData *data = aq_encode(mode == 1 ? @{@"error":@17, @"message":@"fixture cooldown"} : @{@"headers":@{@"X-Apple-MD":@"otp"}});
        if (mode == 2) data = [@"malformed" dataUsingEncoding:NSUTF8StringEncoding];
        struct IPCFixture f = { socket(AF_UNIX, SOCK_STREAM, 0), [data bytes], [data length], (uint32_t)[data length] };
        if (mode == 3) f.advertised = 65537;
        if (mode == 4) f.length = 2;
        assert(f.socket >= 0 && !bind(f.socket, (struct sockaddr *)&address, sizeof address) && !listen(f.socket, 1));
        pthread_t thread;
        if (mode == 6) close(f.socket);
        else assert(!pthread_create(&thread, NULL, serveFixture, &f));
        NSError *error = nil;
        AQIPCCancelled *cancelled = mode == 5 ? [[[AQIPCCancelled alloc] init] autorelease] : nil;
        NSDictionary *headers = aq_adi_client(cancelled, &error, address.sun_path, mode == 7 ? geteuid()+1 : geteuid());
        if (!mode) assert(headers && !error && [[headers objectForKey:@"X-Apple-MD"] isEqual:@"otp"]);
        else assert(!headers && [error code] == (mode == 1 ? 17 : mode == 5 ? NSUserCancelledError : mode >= 6 ? 10 : 19));
        if (mode != 6) { pthread_join(thread, NULL); close(f.socket); }
        unlink(address.sun_path);
    }
    rmdir(directory);
    puts("PASS: local IPC framing, errors, malformed/oversized/truncated replies, cancellation, unavailable service and wrong peer identity (8 cases)");
    [pool drain]; return 0;
}
