#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <assert.h>
#include <stdint.h>
static NSLock *radio_lock;
static dispatch_source_t heartbeat;
static BOOL radio_running;
static uint64_t radio_release_generation;
static NSHashTable *radio_owners;
static NSDictionary *helper(NSString *cmd){return @{@"ok":@YES};}
static BOOL wifi_powered(void){return YES;}
static unsigned test_interface(const char*n){return radio_running?10:0;}
#define if_nametoindex test_interface
#define AQ_RADIO_RELEASE_NS (20*NSEC_PER_MSEC)
#include "../src/mac/airdrop/AQRadio.inc"
static void (*original_stop)(id,SEL);
#include "../src/mac/airdrop/AQTransferLease.inc"
#define AQ_SERVER_DRAIN_NS (20*NSEC_PER_MSEC)
#include "../src/mac/airdrop/AQServerDrain.inc"
@interface Server : NSObject { @public void *_server; CFMutableDictionaryRef _connections; id _queue; }
@end
@implementation Server
- (void)dealloc { drain_after_stop(self); if(_connections) CFRelease(_connections); }
@end
@interface Operation : NSObject { @public void *_askRequest; }
@end
@implementation Operation
@end
static Server *current;
static int invalidations;
static BOOL stubborn;
// Native close handling removes the connection from its stopped server.
static void invalidate(const void *connection){invalidations++;if(!stubborn)CFDictionaryRemoveValue(current->_connections,connection);}
static void noop(id p,SEL s){}
static void receive(id p,SEL s,NSInteger e){}
static void wait_ms(int ms){[[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:ms/1000.0]];}
static Server *stopped_server(int connections){
 Server *server=[Server new];server->_queue=dispatch_get_main_queue();
 server->_connections=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 for(int i=0;i<connections;i++)CFDictionarySetValue(server->_connections,(__bridge const void *)[NSObject new],(__bridge const void *)@YES);
 prepare_server_drain(server);
 current=server;invalidations=0;return server;
}
int main(void){@autoreleasepool {
 radio_lock=[NSLock new];radio_owners=[NSHashTable weakObjectsHashTable];
 original_receive_event=receive;original_receive_stop=noop;original_stop=noop;
 receive_ask_offset=ivar_getOffset(class_getInstanceVariable([Operation class],"_askRequest"));
 server_http_offset=ivar_getOffset(class_getInstanceVariable([Server class],"_server"));
 server_connections_offset=ivar_getOffset(class_getInstanceVariable([Server class],"_connections"));
 server_queue_ivar=class_getInstanceVariable([Server class],"_queue");
 server_connection_invalidate=invalidate;
 // Connections left open on a stopped server are closed after the grace period.
 Server *server=stopped_server(2);drain_after_stop(server);
 wait_ms(5);assert(!invalidations);
 wait_ms(80);assert(invalidations==2 && !CFDictionaryGetCount(server->_connections));
 wait_ms(80);assert(invalidations==2);
 // A server whose connections closed natively is left alone.
 server=stopped_server(0);drain_after_stop(server);wait_ms(80);assert(!invalidations);
 // A restarted server owns its connections again.
 server=stopped_server(1);server->_server=(void *)1;drain_after_stop(server);wait_ms(80);
 assert(!invalidations && CFDictionaryGetCount(server->_connections)==1);
 // An active receive postpones closing until it ends.
 Operation *incoming=[Operation new];acquire_radio(incoming);begin_transfer(incoming,YES);
 server=stopped_server(1);drain_after_stop(server);wait_ms(80);assert(!invalidations);
 receive_event(incoming,NULL,9);wait_ms(80);assert(invalidations==1 && !CFDictionaryGetCount(server->_connections));
 release_radio(incoming);
 // A connection that never closes is retried a bounded number of times.
 stubborn=YES;server=stopped_server(1);drain_after_stop(server);wait_ms(600);
 assert(invalidations==AQ_SERVER_DRAIN_ATTEMPTS);
 server=nil;current=nil;stubborn=NO;
 // Native dealloc calls stop again. Queued cleanup must not retain a receiver
 // through that path or touch the connection dictionary after it is destroyed.
 __weak Server *released;
 @autoreleasepool {
   Server *temporary=stopped_server(1);released=temporary;
   drain_after_stop(temporary);current=nil;
 }
 assert(!released);wait_ms(80);assert(!invalidations);
 puts("PASS: stopped-server drain, native close, restart, active receive, bounded retries and receiver destruction before cleanup");
}return 0;}
