/* A native offer body must launch its asynchronous parser only once.
 * CF stream completion can be reported again while the first parser is busy.
 * Retain native parsing/UI, but make EOF delivery idempotent per stream open. */
static void (*original_offer_stream_event)(id,SEL,CFReadStreamRef,CFStreamEventType);
static char offer_stream_state_key;
@interface AQOfferStreamState : NSObject
@property uintptr_t stream;
@property BOOL ended;
@end
@implementation AQOfferStreamState
@end
static void offer_stream_event(id connection,SEL selector,CFReadStreamRef stream,CFStreamEventType event) {
    @synchronized(connection) {
        AQOfferStreamState *state=objc_getAssociatedObject(connection,&offer_stream_state_key);
        if(!state) {
            state=[AQOfferStreamState new];
            objc_setAssociatedObject(connection,&offer_stream_state_key,state,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        if(state.stream!=(uintptr_t)stream || event==kCFStreamEventOpenCompleted) {
            state.stream=(uintptr_t)stream;
            state.ended=NO;
        }
        if(event==kCFStreamEventEndEncountered) {
            if(state.ended) {
                NSLog(@"AquaTransport AirDrop: ignored repeated offer-stream completion");
                return;
            }
            state.ended=YES;
        }
    }
    original_offer_stream_event(connection,selector,stream,event);
}
