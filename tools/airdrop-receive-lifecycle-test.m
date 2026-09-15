#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#include <assert.h>
#include "../src/mac/airdrop/AQIncoming.inc"
@interface TestZipper : NSObject {
@public id _compressionEngine; CFReadStreamRef input; BOOL decompress;
}
-(BOOL)isDecompressor;
-(CFReadStreamRef)copyReadStream;
@end
@implementation TestZipper
-(BOOL)isDecompressor {return decompress;}
-(CFReadStreamRef)copyReadStream {return input ? (CFReadStreamRef)CFRetain(input) : NULL;}
@end
static int native_result, foreign_owner;
static void *owner(void *copier) {return foreign_owner?NULL:copier;}
static int native_copy(void *copier,const char *source,const char *destination,CFDictionaryRef options) {
    (void)source;(void)destination;(void)options;
    TestZipper *zipper=(__bridge TestZipper *)copier;
    assert(CFReadStreamGetStatus(zipper->input)==kCFStreamStatusOpen);
    return native_result;
}
static int native_zipper(id zipper,SEL selector,id source,id destination,id options) {
    (void)selector;(void)source;(void)destination;(void)options;
    return incoming_bom_copy((__bridge void *)zipper,NULL,"test",NULL);
}
int main(void) { @autoreleasepool {
    original_bom_copy=native_copy;original_zipper_copy=native_zipper;bom_user_data=owner;
    zipper_compression_engine=class_getInstanceVariable([TestZipper class],"_compressionEngine");
    for(int scenario=0;scenario<6;scenario++) {
        TestZipper *zipper=[TestZipper new];zipper->_compressionEngine=[NSObject new];zipper->decompress=YES;
        const UInt8 data[]="test";zipper->input=CFReadStreamCreateWithBytesNoCopy(NULL,data,4,kCFAllocatorNull);CFReadStreamOpen(zipper->input);
        CFReadStreamRef outer=CFReadStreamCreateWithBytesNoCopy(NULL,data,4,kCFAllocatorNull);
        incoming_consumed_stream=outer;incoming_zipper=(void *)1;
        native_result=scenario==1?23:0;foreign_owner=scenario==4;
        if(scenario==3)zipper->_compressionEngine=nil;
        if(scenario==5)zipper->decompress=NO;
        int result=incoming_copy(zipper,@selector(bomCopierCopy:destination:options:),scenario==2?@"source":nil,@"destination",nil);
        assert(result==native_result);
        assert(CFReadStreamGetStatus(zipper->input)==(scenario<=1?kCFStreamStatusClosed:kCFStreamStatusOpen));
        assert(incoming_consumed_stream==outer && incoming_zipper==(void *)1);
        CFReadStreamClose(zipper->input);CFRelease(zipper->input);CFRelease(outer);
    }
    incoming_consumed_stream=NULL;incoming_zipper=NULL;
    puts("PASS: native result preserved, input closed after copier returns, outgoing/unrelated paths unchanged, nested scope restored");
} }
