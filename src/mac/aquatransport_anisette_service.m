/* Socket-activated native Anisette generator. Clients can request only one operation:
 * generate device headers. Account identities/passwords/tokens never cross IPC.
 * Apple's provisioning HTTPS exchange runs only for missing native state. */
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <openssl/evp.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <signal.h>
#include <launch.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <mach/mach_time.h>
#include "aquatransport_anisette_service.h"

static NSString *const AQErrorDomain = @"AquaTransport.iCloud";
static NSString *const AQClient = @"<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
/* The shared generator accepts cancellation owners in the adapter/diagnostic;
 * the service always passes nil. No implementation of this client class here. */
@interface AQGSAProtocol : NSObject
- (BOOL)isStopped;
@end
static id aq_dict(id v) { return [v isKindOfClass:[NSDictionary class]] ? v : nil; }
static NSString *aq_string(id v) { return [v isKindOfClass:[NSString class]] && [v length] ? v : nil; }
static NSError *aq_error(NSInteger code, NSString *message) {
    return [NSError errorWithDomain:AQErrorDomain code:code userInfo:[NSDictionary dictionaryWithObject:message forKey:NSLocalizedDescriptionKey]];
}
static NSDictionary *aq_plist(NSData *d) {
    return [d length] ? aq_dict([NSPropertyListSerialization propertyListWithData:d options:0 format:NULL error:NULL]) : nil;
}
static NSData *aq_encode(id d) {
    return [NSPropertyListSerialization dataWithPropertyList:d format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
}
static NSString *aq_base64(NSData *d) {
    if (!d || [d length] > 1024*1024) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:4*(([d length]+2)/3)+1];
    int n = EVP_EncodeBlock([out mutableBytes], [d bytes], (int)[d length]);
    return [[[NSString alloc] initWithBytes:[out bytes] length:n encoding:NSASCIIStringEncoding] autorelease];
}
static NSString *aq_device_uuid(void) {
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (!service) return nil;
    CFTypeRef value = IORegistryEntryCreateCFProperty(service, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
    IOObjectRelease(service);
    NSString *device = value && CFGetTypeID(value) == CFStringGetTypeID() ? [NSString stringWithString:(NSString *)value] : nil;
    if (value) CFRelease(value);
    return device;
}
static NSString *aq_device_field(id value) {
    NSString *s = aq_string(value);
    return s && [s length] <= 16384 && [s rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location == NSNotFound ? s : nil;
}
static NSMutableURLRequest *aq_apple_request(NSString *url, NSDictionary *headers) {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    [req setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Accept"];
    [req setValue:@"akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0" forHTTPHeaderField:@"User-Agent"];
    [req setValue:AQClient forHTTPHeaderField:@"X-Mme-Client-Info"];
    for (NSString *key in headers) [req setValue:[headers objectForKey:key] forHTTPHeaderField:key];
    return req;
}
@interface AQADIWire : NSObject <NSURLConnectionDelegate> {
@public
    NSMutableData *body;
    NSHTTPURLResponse *response;
    NSError *failure;
    BOOL done;
}
@end
@implementation AQADIWire
- (id)init { if ((self = [super init])) body = [NSMutableData new]; return self; }
- (void)dealloc { [body release]; [response release]; [failure release]; [super dealloc]; }
- (NSURLRequest *)connection:(NSURLConnection *)c willSendRequest:(NSURLRequest *)req redirectResponse:(NSURLResponse *)redirect {
    if (redirect) { failure = [aq_error(15, @"Device provisioning redirect refused.") retain]; done = YES; [c cancel]; return nil; } return req;
}
- (BOOL)connectionShouldUseCredentialStorage:(NSURLConnection *)c { return NO; }
- (void)connection:(NSURLConnection *)c didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if ([[[challenge protectionSpace] authenticationMethod] isEqual:NSURLAuthenticationMethodServerTrust])
        [[challenge sender] performDefaultHandlingForAuthenticationChallenge:challenge];
    else [[challenge sender] continueWithoutCredentialForAuthenticationChallenge:challenge];
}
- (NSCachedURLResponse *)connection:(NSURLConnection *)c willCacheResponse:(NSCachedURLResponse *)r { return nil; }
- (void)connection:(NSURLConnection *)c didReceiveResponse:(NSURLResponse *)r {
    if (![r isKindOfClass:[NSHTTPURLResponse class]]) { failure = [aq_error(15, @"Invalid device provisioning response.") retain]; done = YES; [c cancel]; return; }
    [response release]; response = [(NSHTTPURLResponse *)r retain]; [body setLength:0];
}
- (void)connection:(NSURLConnection *)c didReceiveData:(NSData *)d {
    if ([body length]+[d length] > 4*1024*1024) { failure = [aq_error(15, @"Device provisioning response is too large.") retain]; done = YES; [c cancel]; }
    else [body appendData:d];
}
- (void)connection:(NSURLConnection *)c didFailWithError:(NSError *)e { failure = [aq_error(15, @"Device provisioning transport failed.") retain]; done = YES; }
- (void)connectionDidFinishLoading:(NSURLConnection *)c { done = YES; }
@end
static NSData *aq_send(AQGSAProtocol *owner, NSMutableURLRequest *req, NSHTTPURLResponse **response, NSError **error) {
    [NSURLProtocol setProperty:@YES forKey:@"AquaTransportGSAHandled" inRequest:req];
    [req setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData]; [req setHTTPShouldHandleCookies:NO]; [req setTimeoutInterval:30];
    AQADIWire *wire = [[[AQADIWire alloc] init] autorelease];
    NSURLConnection *c = [[NSURLConnection alloc] initWithRequest:req delegate:wire startImmediately:NO];
    if (!c) { *error = aq_error(15, @"Device provisioning could not start."); return nil; }
    [c scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode]; [c start];
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:30];
    while (!wire->done && [deadline timeIntervalSinceNow] > 0)
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:.05]];
    [c cancel]; [c release];
    if (!wire->done || wire->failure || !wire->response) { *error = wire->failure ?: aq_error(15, @"Device provisioning timed out or returned no response."); return nil; }
    *response = wire->response; return wire->body;
}
#include "aquatransport_anisette.inc"

static volatile sig_atomic_t stopping;
static void stopService(int sig) { stopping = 1; }
static BOOL sendAll(int fd, const void *bytes, size_t length) {
    while (length) {
        ssize_t n = send(fd, bytes, length, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return NO;
        bytes = (const char *)bytes + n; length -= n;
    }
    return YES;
}
/* A fresh, unprivileged process owns Foundation and Apple's native state.
 * The broker gets the identity from the kernel, never from client input. */
static int runWorker(void) {
    uid_t uid; gid_t gid;
    if (geteuid() < 500 || getuid() != geteuid() ||
        getpeereid(STDIN_FILENO, &uid, &gid) || uid != geteuid()) return 2;
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    struct timeval limit = {3, 0};
    setsockopt(STDIN_FILENO, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof limit);
    setsockopt(STDIN_FILENO, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof limit);
    unsigned char operation = 0;
    if (recv(STDIN_FILENO, &operation, 1, 0) != 1 || operation != 1) { [pool drain]; return 2; }
    NSError *error = nil; NSDictionary *headers = nil;
    @try { headers = [AQNativeAnisetteGenerator headersForOwner:nil error:&error]; }
    @catch (NSException *e) { error = aq_error(11, @"Local device authentication failed inside Apple's framework."); }
    NSDictionary *reply = headers ? [NSDictionary dictionaryWithObject:headers forKey:@"headers"] :
        [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInteger:[error code]], @"error",
            [error localizedDescription] ?: @"Local device authentication failed.", @"message", nil];
    NSData *data = aq_encode(reply); uint32_t length = htonl((uint32_t)[data length]);
    BOOL sent = [data length] && [data length] <= 65536 && sendAll(STDIN_FILENO, &length, sizeof length) &&
        sendAll(STDIN_FILENO, [data bytes], [data length]);
    [pool drain]; return sent ? 0 : 1;
}
static double serviceTime(void) {
    mach_timebase_info_data_t scale; mach_timebase_info(&scale);
    return (double)mach_absolute_time()*scale.numer/scale.denom/1e9;
}
static pid_t startWorker(int client, int listener) {
    uid_t uid; gid_t peerGroup;
    if (getpeereid(client, &uid, &peerGroup) || uid < 500 || uid == (uid_t)-1) return -1;
    struct passwd entry, *user = NULL; char buffer[16384];
    if (getpwuid_r(uid, &entry, buffer, sizeof buffer, &user) || !user ||
        user->pw_uid != uid || !user->pw_name[0] || user->pw_dir[0] != '/') return -1;
    /* Resolve groups and construct strings before fork. Only system calls
     * and exec are used in the child, with no Foundation calls after fork. */
    int groups[NGROUPS_MAX], count = NGROUPS_MAX;
    if (getgrouplist(user->pw_name, user->pw_gid, groups, &count) < 0 || count < 1 || count > NGROUPS_MAX) return -1;
    gid_t supplementary[NGROUPS_MAX];
    for (int i = 0; i < count; i++) supplementary[i] = (gid_t)groups[i];
    char home[PATH_MAX+6], name[1024], login[1024];
    if (snprintf(home, sizeof home, "HOME=%s", user->pw_dir) >= sizeof home ||
        snprintf(name, sizeof name, "USER=%s", user->pw_name) >= sizeof name ||
        snprintf(login, sizeof login, "LOGNAME=%s", user->pw_name) >= sizeof login) return -1;
    char *arguments[] = {AQ_ANISETTE_EXECUTABLE, "--worker", NULL};
    char *environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", home, name, login, NULL};
    gid_t primary = user->pw_gid;
    pid_t child = fork();
    if (!child) {
        close(listener);
        if (setgroups(count, supplementary) || setgid(primary) || setuid(uid) ||
            getuid() != uid || geteuid() != uid || chdir("/") || dup2(client, STDIN_FILENO) < 0) _exit(126);
        if (client != STDIN_FILENO) close(client);
        execve(AQ_ANISETTE_EXECUTABLE, arguments, environment);
        _exit(127);
    }
    return child;
}
static void finishWorker(pid_t child) {
    if (child <= 0) return;
    double deadline = serviceTime()+95;
    while (!stopping && serviceTime() < deadline) {
        pid_t result = waitpid(child, NULL, WNOHANG);
        if (result == child || (result < 0 && errno != EINTR)) return;
        usleep(50000);
    }
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
}
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    umask(077);
    if (argc == 2 && !strcmp(argv[1], "--worker")) return runWorker();
    if (argc != 1 || geteuid()) return 2;
    struct sigaction action; memset(&action, 0, sizeof action); action.sa_handler = stopService;
    sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL);
    launch_data_t request = launch_data_new_string(LAUNCH_KEY_CHECKIN);
    launch_data_t response = launch_msg(request); launch_data_free(request);
    if (!response || launch_data_get_type(response) != LAUNCH_DATA_DICTIONARY) {
        if (response) launch_data_free(response); return 3;
    }
    launch_data_t sockets = launch_data_dict_lookup(response, LAUNCH_JOBKEY_SOCKETS);
    launch_data_t entries = sockets && launch_data_get_type(sockets) == LAUNCH_DATA_DICTIONARY ?
        launch_data_dict_lookup(sockets, "Listener") : NULL;
    if (!entries || launch_data_get_type(entries) != LAUNCH_DATA_ARRAY || launch_data_array_get_count(entries) != 1) {
        launch_data_free(response); return 4;
    }
    launch_data_t entry = launch_data_array_get_index(entries, 0);
    int inherited = launch_data_get_type(entry) == LAUNCH_DATA_FD ? launch_data_get_fd(entry) : -1;
    int listener = inherited >= 0 ? dup(inherited) : -1;
    launch_data_free(response);
    if (listener < 0 || listener >= FD_SETSIZE) { if (listener >= 0) close(listener); return 5; }
    fcntl(listener, F_SETFD, FD_CLOEXEC);
    /* launchd keeps the socket open while this job is idle or not running. */
    double lastActivity = serviceTime();
    while (!stopping && serviceTime() < lastActivity+30) {
        fd_set ready; FD_ZERO(&ready); FD_SET(listener, &ready);
        struct timeval tick = {1, 0};
        if (select(listener+1, &ready, NULL, NULL, &tick) <= 0) continue;
        int client = accept(listener, NULL, NULL); if (client < 0) continue;
        fcntl(client, F_SETFD, FD_CLOEXEC);
        pid_t child = startWorker(client, listener);
        close(client);
        finishWorker(child);
        lastActivity = serviceTime();
    }
    close(listener); return 0;
}
