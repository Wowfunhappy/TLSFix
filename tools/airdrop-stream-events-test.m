#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#include <assert.h>
#include "../src/mac/airdrop/AQStreamEvents.inc"
static volatile int ends,other;
static void original(id p,SEL s,CFReadStreamRef r,CFStreamEventType e){if(e==kCFStreamEventEndEncountered)__sync_fetch_and_add(&ends,1);else __sync_fetch_and_add(&other,1);}
int main(void){@autoreleasepool {
 original_offer_stream_event=original;NSObject *p=[NSObject new];
 CFReadStreamRef a=CFReadStreamCreateWithBytesNoCopy(NULL,(const UInt8*)"a",1,kCFAllocatorNull),b=CFReadStreamCreateWithBytesNoCopy(NULL,(const UInt8*)"b",1,kCFAllocatorNull);
 offer_stream_event(p,NULL,a,kCFStreamEventOpenCompleted);
 dispatch_apply(16,dispatch_get_global_queue(0,0),^(size_t i){offer_stream_event(p,NULL,a,kCFStreamEventEndEncountered);});assert(ends==1);
 offer_stream_event(p,NULL,a,kCFStreamEventOpenCompleted);offer_stream_event(p,NULL,a,kCFStreamEventEndEncountered);assert(ends==2);
 offer_stream_event(p,NULL,b,kCFStreamEventEndEncountered);assert(ends==3);
 offer_stream_event([NSObject new],NULL,b,kCFStreamEventEndEncountered);assert(ends==4 && other==2);
 CFRelease(a);CFRelease(b);puts("PASS: concurrent duplicate EOF once, reopened/replaced streams and independent connections preserved");
}return 0;}
