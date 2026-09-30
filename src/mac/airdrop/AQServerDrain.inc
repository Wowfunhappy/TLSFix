/* Mavericks starts a replacement receiver only after the stopped server's
 * CFHTTPServer reports that its last connection has closed. A modern peer that
 * leaves mid-exchange can hold its connection open with nothing left to send,
 * and receiving would stay unavailable until sharingd exits. Once a grace period
 * has passed and no receive is running, close what the stopped server still
 * holds. Native close handling, unpublication and the waiting receiver's start
 * then run unchanged. */
#ifndef AQ_SERVER_DRAIN_NS
#define AQ_SERVER_DRAIN_NS (5*NSEC_PER_SEC)
#endif
#define AQ_SERVER_DRAIN_ATTEMPTS 12
static ptrdiff_t server_http_offset,server_connections_offset;
static Ivar server_queue_ivar;
static void (*server_connection_invalidate)(const void *);
static char server_drain_key;
@interface AQServerDrainState : NSObject
@property(weak) id server;
@property NSUInteger generation;
@end
@implementation AQServerDrainState
@end
static void prepare_server_drain(id server) {
    AQServerDrainState *state=objc_getAssociatedObject(server,&server_drain_key);
    if(!state) {
        state=[AQServerDrainState new]; state.server=server;
        objc_setAssociatedObject(server,&server_drain_key,state,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    ++state.generation;
}
static void drain_server(AQServerDrainState *state,NSUInteger generation,NSUInteger attempt) {
    id server=state.server;
    if(!server || state.generation!=generation) return;
    dispatch_queue_t queue=object_getIvar(server,server_queue_ivar);
    if(!queue) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,AQ_SERVER_DRAIN_NS),queue,^{
        // stop is also called from native dealloc. Never capture/retain a
        // receiver there: its ivars can be destroyed before this callback.
        id server=state.server;
        if(!server || state.generation!=generation) return;
        char *base=(char *)(__bridge void *)server;
        // A restarted server owns its connection table again.
        if(*(void **)(base+server_http_offset)) return;
        CFDictionaryRef connections=*(CFDictionaryRef *)(base+server_connections_offset);
        CFIndex count=connections ? CFDictionaryGetCount(connections) : 0;
        if(!count) return;
        if(attempt>=AQ_SERVER_DRAIN_ATTEMPTS) {
            NSLog(@"AquaTransport AirDrop: stopped receiver still holds %ld connection(s)",(long)count);
            return;
        }
        const void **keys=receive_in_progress() ? NULL : calloc((size_t)count,sizeof(*keys));
        if(keys) {
            // Invalidation can remove entries; act on a retained snapshot.
            CFDictionaryGetKeysAndValues(connections,keys,NULL);
            for(CFIndex i=0;i<count;i++) CFRetain(keys[i]);
            NSLog(@"AquaTransport AirDrop: closing %ld connection(s) held by a stopped receiver",(long)count);
            for(CFIndex i=0;i<count;i++) { server_connection_invalidate(keys[i]); CFRelease(keys[i]); }
            free(keys);
        }
        drain_server(state,generation,attempt+1);
    });
}
static void drain_after_stop(id server) {
    AQServerDrainState *state=objc_getAssociatedObject(server,&server_drain_key);
    if(state) drain_server(state,state.generation,0);
}
