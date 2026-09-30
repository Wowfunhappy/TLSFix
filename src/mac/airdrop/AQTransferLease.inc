/* Native operations own the transport independently of Finder browsing. */
#include "AQModeScope.h"
static void (*original_transfer_start)(id,SEL),(*original_transfer_stop)(id,SEL);
static void (*original_transfer_event)(id,SEL,NSInteger,void *);
static void (*original_receive_event)(id,SEL,NSInteger),(*original_receive_stop)(id,SEL);
static ptrdiff_t receive_ask_offset;
static char transfer_lease_key;
static NSUInteger receiving_transfers;
static NSUInteger active_transfers;
static NSMutableSet *deferred_transfer_servers;
static NSHashTable *transfer_servers;
static NSCountedSet *leased_transfer_servers;
@interface AQTransferLease : NSObject
@property(strong) NSObject *token;
@property BOOL active;
@property BOOL incoming;
@property(copy) NSArray *servers;
- (void)finish;
@end
static void drain_after_stop(id server);
static BOOL receive_in_progress(void) {
    @synchronized([AQTransferLease class]) { return receiving_transfers!=0; }
}
static void flush_transfer_servers(void) {
    dispatch_async(dispatch_get_main_queue(),^{
        @synchronized([AQTransferLease class]) {
            if(receiving_transfers) return;
            NSArray *servers=[deferred_transfer_servers allObjects];
            [deferred_transfer_servers removeAllObjects];
            for(id server in servers) { [transfer_servers removeObject:server]; original_stop(server,@selector(stop)); drain_after_stop(server); release_radio(server); }
        }
    });
}
@implementation AQTransferLease
- (void)finish {
    @synchronized(self) {
        if(!_active) return;
        _active=NO;
        if(_token) { release_radio(_token); _token=nil; }
        @synchronized([AQTransferLease class]) { --active_transfers; }
        AQ_APPLY_PENDING_MODE();
        if(_incoming) {
            @synchronized([AQTransferLease class]) {
                --receiving_transfers;
                for(id server in _servers) [leased_transfer_servers removeObject:server];
            }
            _servers=nil;
            flush_transfer_servers();
        }
    }
}
- (void)dealloc { [self finish]; }
@end
static void begin_transfer(id operation,BOOL incoming) {
    @synchronized(operation) {
        if(objc_getAssociatedObject(operation,&transfer_lease_key)) return;
        AQTransferLease *lease=[AQTransferLease new];
        BOOL native;
        @synchronized([AQTransferLease class]) {
            native=AQ_NATIVE_MODE;
            ++active_transfers;
        }
        if(!native) {
            NSObject *token=[NSObject new];
            if(!acquire_radio(token)) {
                @synchronized([AQTransferLease class]) { --active_transfers; }
                AQ_APPLY_PENDING_MODE();
                return;
            }
            lease.token=token;
        }
        lease.active=YES; lease.incoming=incoming && !native;
        if(lease.incoming) @synchronized([AQTransferLease class]) {
            ++receiving_transfers;
            if(!leased_transfer_servers) leased_transfer_servers=[NSCountedSet new];
            lease.servers=[transfer_servers allObjects];
            for(id server in lease.servers) [leased_transfer_servers addObject:server];
        }
        objc_setAssociatedObject(operation,&transfer_lease_key,lease,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        NSLog(@"AquaTransport AirDrop: %@ %@ transfer started",native ? @"native" : @"modern",incoming ? @"incoming" : @"outgoing");
    }
}
static void end_transfer(id operation) {
    @synchronized(operation) {
        AQTransferLease *lease=objc_getAssociatedObject(operation,&transfer_lease_key);
        if(!lease) return;
        [lease finish];
        objc_setAssociatedObject(operation,&transfer_lease_key,nil,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        NSLog(@"AquaTransport AirDrop: transfer finished");
    }
}
static BOOL defer_transfer_server_stop(id server) {
    @synchronized([AQTransferLease class]) {
        if(![leased_transfer_servers countForObject:server]) return NO;
        if(!deferred_transfer_servers) deferred_transfer_servers=[NSMutableSet new];
        [deferred_transfer_servers addObject:server];
        return YES;
    }
}
static void forget_transfer_server(id server) {
    @synchronized([AQTransferLease class]) { [transfer_servers removeObject:server]; }
}
static void resume_transfer_server(id server) {
    @synchronized([AQTransferLease class]) {
        if(!transfer_servers) transfer_servers=[NSHashTable weakObjectsHashTable];
        [transfer_servers addObject:server];
        [deferred_transfer_servers removeObject:server];
    }
}
/* Mavericks itself treats 4 (cancel), 9 (finished), and 10 (error) as
 * terminal in both native notification methods. Progress/Ask are not terminal. */
static BOOL transfer_terminal(NSInteger event) { return event==4 || event==9 || event==10; }
static void transfer_start(id operation,SEL selector) {
    begin_transfer(operation,NO);
    @try { original_transfer_start(operation,selector); }
    @catch(id error) { end_transfer(operation); @throw; }
}
static void transfer_stop(id operation,SEL selector) {
    @try { original_transfer_stop(operation,selector); } @finally { end_transfer(operation); }
}
static void transfer_event(id operation,SEL selector,NSInteger event,void *property) {
    @try { original_transfer_event(operation,selector,event,property); }
    @finally { if(transfer_terminal(event)) end_transfer(operation); }
}
static void receive_event(id operation,SEL selector,NSInteger event) {
    @try { original_receive_event(operation,selector,event); }
    @finally { if(transfer_terminal(event)) end_transfer(operation); }
}
static void receive_stop(id operation,SEL selector) {
    @try { original_receive_stop(operation,selector); }
    @finally {
        // Native stop can defer until its decline response has been sent.
        if(!*(void **)((char *)(__bridge void *)operation+receive_ask_offset)) end_transfer(operation);
    }
}
