#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <assert.h>
#include <stdint.h>
static NSLock *radio_lock;
static dispatch_source_t heartbeat;
static BOOL radio_running,helper_ok=YES;
static uint64_t radio_release_generation;
static NSHashTable *radio_owners;
static int radio_stops,server_stops;
static NSDictionary *helper(NSString *cmd){if([cmd isEqual:@"stop"])radio_stops++;return @{@"ok":@(helper_ok)};}
static unsigned test_interface(const char*n){return radio_running?10:0;}
#define if_nametoindex test_interface
#define AQ_RADIO_RELEASE_NS (20*NSEC_PER_MSEC)
#include "../src/mac/airdrop/AQRadio.inc"
static void (*original_stop)(id,SEL);
#include "../src/mac/airdrop/AQTransferLease.inc"
@interface Operation : NSObject { @public void *_askRequest; }
@end
@implementation Operation
@end
static void noop(id p,SEL s){}
static void event(id p,SEL s,NSInteger e,void*v){}
static void receive(id p,SEL s,NSInteger e){}
static void server_stop(id p,SEL s){assert(!receiving_transfers);server_stops++;}
static void wait_release(void){[[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.08]];}
int main(void){@autoreleasepool {
 radio_lock=[NSLock new];radio_owners=[NSHashTable weakObjectsHashTable];
 original_transfer_start=noop;original_transfer_stop=noop;original_transfer_event=event;
 original_receive_event=receive;original_receive_stop=noop;original_stop=server_stop;
 receive_ask_offset=ivar_getOffset(class_getInstanceVariable([Operation class],"_askRequest"));
 NSObject *browser=[NSObject new];Operation *send=[Operation new];
 assert(acquire_radio(browser));transfer_start(send,NULL);transfer_start(send,NULL);assert(radio_owners.count==2);
 release_radio(browser);wait_release();assert(radio_running && radio_stops==0);
 transfer_event(send,NULL,5,NULL);wait_release();assert(radio_running);
 transfer_event(send,NULL,9,NULL);wait_release();assert(!radio_running && radio_stops==1);
 // Simultaneous operations; failure of one cannot stop the other's transfer.
 Operation *other=[Operation new];transfer_start(send,NULL);transfer_start(other,NULL);
 transfer_event(send,NULL,10,NULL);wait_release();assert(radio_running);
 transfer_stop(other,NULL);wait_release();assert(!radio_running && radio_stops==2);
 // An abandoned operation releases its token even without a terminal callback.
 @autoreleasepool { Operation *abandoned=[Operation new];transfer_start(abandoned,NULL); }
 wait_release();assert(!radio_running && radio_stops==3);
 // Receive retains the server through its native terminal response/notification.
 NSObject *server=[NSObject new];Operation *incoming=[Operation new];acquire_radio(server);resume_transfer_server(server);begin_transfer(incoming,YES);
 assert(defer_transfer_server_stop(server));wait_release();assert(radio_running && !server_stops);
 incoming->_askRequest=(void*)1;receive_stop(incoming,NULL);assert(receiving_transfers==1);
 incoming->_askRequest=NULL;receive_event(incoming,NULL,9);wait_release();assert(!radio_running && server_stops==1);
 // Reopening cancels deferred shutdown, and completion must preserve that owner.
 acquire_radio(server);resume_transfer_server(server);begin_transfer(incoming,YES);assert(defer_transfer_server_stop(server));resume_transfer_server(server);
 receive_event(incoming,NULL,4);wait_release();assert(radio_running && server_stops==1);release_radio(server);wait_release();assert(!radio_running);
 // Never defer an unrelated/deallocating server just because another receives.
 assert(!defer_transfer_server_stop([NSObject new]));
 // Multiple receives keep a deferred server until the last transfer completes.
 acquire_radio(server);resume_transfer_server(server);begin_transfer(incoming,YES);begin_transfer(other,YES);assert(defer_transfer_server_stop(server));
 receive_event(incoming,NULL,10);wait_release();assert(radio_running && receiving_transfers==1);
 receive_stop(other,NULL);wait_release();assert(!radio_running && !receiving_transfers && server_stops==2);
 helper_ok=NO;transfer_start(send,NULL);assert(!objc_getAssociatedObject(send,&transfer_lease_key) && !radio_owners.count);
 puts("PASS: navigation, progress, finish, cancel, failure, parallel sends/receives, abandoned operation, deferred receive stop, reopen and helper failure");
}return 0;}
