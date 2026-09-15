#ifndef AQ_RADIO_RELEASE_NS
#define AQ_RADIO_RELEASE_NS (3*NSEC_PER_SEC)
#endif
static uint32_t ensure_radio(void) {
    [radio_lock lock];
    if(!radio_running) {
        radio_running=[helper(@"start")[@"ok"] boolValue];
        if(radio_running && !heartbeat) {
            heartbeat=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0));
            dispatch_source_set_timer(heartbeat,dispatch_time(DISPATCH_TIME_NOW,15*NSEC_PER_SEC),15*NSEC_PER_SEC,NSEC_PER_SEC);
            dispatch_source_set_event_handler(heartbeat,^{
                [radio_lock lock];
                if(radio_running && ![helper(@"heartbeat")[@"ok"] boolValue]) {
                    radio_running=NO;
                    NSLog(@"AquaTransport AirDrop: radio lease lost");
                }
                // A surviving browser/server must recover after helper exit or lease
                // expiry. Keep retrying on this timer if the first start fails.
                if(!radio_running && radio_owners.count) {
                    radio_running=[helper(@"start")[@"ok"] boolValue];
                    if(radio_running) NSLog(@"AquaTransport AirDrop: radio lease recovered");
                }
                [radio_lock unlock];
            }); dispatch_resume(heartbeat);
        }
    }
    uint32_t interface=radio_running ? if_nametoindex("tap0") : 0;
    [radio_lock unlock]; return interface;
}
static BOOL acquire_radio(id owner) {
    [radio_lock lock]; ++radio_release_generation; [radio_owners addObject:owner]; [radio_lock unlock];
    if(ensure_radio()) return YES;
    [radio_lock lock]; [radio_owners removeObject:owner]; [radio_lock unlock]; return NO;
}
static void release_radio(id owner) {
    [radio_lock lock]; [radio_owners removeObject:owner];
    if(!radio_owners.count) {
        uint64_t generation=++radio_release_generation;
        // Native browser/receiver replacement briefly has no owners. Keep TAP
        // intact across that handoff; a real exit still restores Wi-Fi shortly.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,AQ_RADIO_RELEASE_NS),dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{
            [radio_lock lock];
            if(generation==radio_release_generation && !radio_owners.count) {
                if(heartbeat) { dispatch_source_cancel(heartbeat); heartbeat=nil; }
                if(radio_running) helper(@"stop"); radio_running=NO;
            }
            [radio_lock unlock];
        });
    }
    [radio_lock unlock];
}
