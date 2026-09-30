/* Live launchd fixture: exercises production XPC consumption/idle exit while
 * disabling both optional features. Run as a temporary user launchd job. */
#import <Foundation/Foundation.h>
#include <unistd.h>
#include <dlfcn.h>
#include <xpc/xpc.h>
#include <string.h>
static uid_t testEuid(void) { return 0; }
int tf_flag(const char *name) { (void)name; return 1; }
static void testSetHandler(const char *stream,dispatch_queue_t queue,xpc_handler_t handler) {
    xpc_set_event_stream_handler(stream,queue,^(xpc_object_t event) {
        const char *name=xpc_dictionary_get_string(event,XPC_EVENT_KEY_NAME);
        printf("consumed %s\n",name ? name : "unnamed"); fflush(stdout);
        handler(event);
    });
}
static void *testDlsym(void *handle,const char *symbol) {
    return !strcmp(symbol,"xpc_set_event_stream_handler") ? (void *)testSetHandler : dlsym(handle,symbol);
}
#define geteuid testEuid
#define dlsym testDlsym
#include "../src/mac/aquatransport_bootstrap.m"
