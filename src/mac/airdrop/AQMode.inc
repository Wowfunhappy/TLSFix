/* AirDrop protocol choice is confined to the current Finder AirDrop visit.
 * UI requests are per-user distributed notifications; sharingd owns the actual
 * transition and waits for native transfer leases before changing transport. */
static NSInteger requested_mode=-1;
static BOOL mode_transition_queued;
static CFAbsoluteTime mode_heartbeat_at;
static NSString *const AQModeRequest=@"org.aquatransport.airdrop.mode.request";
static NSString *const AQModeChanged=@"org.aquatransport.airdrop.mode.changed";
static NSString *const AQModeHeartbeat=@"org.aquatransport.airdrop.mode.heartbeat";

static void apply_pending_mode(void) {
    @synchronized([AQTransferLease class]) {
        if(mode_transition_queued || requested_mode<0 || active_transfers) return;
        mode_transition_queued=YES;
    }
    dispatch_async(dispatch_get_main_queue(),^{
        @synchronized([AQTransferLease class]) {
            mode_transition_queued=NO;
            if(requested_mode<0 || active_transfers) return;
            NSInteger next=requested_mode;
            requested_mode=-1;
            if(native_mode==(BOOL)next) return;
            NSArray *browsers=[active_browsers allObjects];
            NSArray *servers=[active_servers allObjects];
            for(id browser in browsers) stop_browser(browser,@selector(stop));
            for(id server in servers) stop_server(server,@selector(stop));
            // SDBonjourBrowser's stop clears its services but does not tell
            // Finder that the previously published nodes have disappeared.
            for(id browser in browsers) {
                SEL notify=@selector(clearCacheAndNotify);
                ((void (*)(id,SEL))[browser methodForSelector:notify])(browser,notify);
            }
            if(next) force_stop_radio();
            native_mode=(BOOL)next;
            for(id server in servers) start_server(server,@selector(startHTTPServer));
            for(id browser in browsers) start_browser(browser,@selector(start));
            [[NSDistributedNotificationCenter defaultCenter] postNotificationName:AQModeChanged
                object:@"org.aquatransport.airdrop" userInfo:@{@"native":@(native_mode)}
                deliverImmediately:YES];
            NSLog(@"AquaTransport AirDrop: %@ protocol selected",native_mode ? @"native" : @"modern");
        }
        apply_pending_mode();
    });
}

@interface AQModeObserver : NSObject
- (void)modeRequested:(NSNotification *)notification;
- (void)modeHeartbeat:(NSNotification *)notification;
@end
@implementation AQModeObserver
- (void)modeRequested:(NSNotification *)notification {
    id value=notification.userInfo[@"native"];
    if(![value isKindOfClass:[NSNumber class]]) return;
    @synchronized([AQTransferLease class]) {
        requested_mode=[value boolValue] ? 1 : 0;
        if(requested_mode==1) mode_heartbeat_at=CFAbsoluteTimeGetCurrent();
    }
    apply_pending_mode();
}
- (void)modeHeartbeat:(NSNotification *)notification {
    (void)notification;
    @synchronized([AQTransferLease class]) { mode_heartbeat_at=CFAbsoluteTimeGetCurrent(); }
}
@end
static AQModeObserver *mode_observer;
static void expire_mode_owner(void) {
    @synchronized([AQTransferLease class]) {
        if(!(native_mode || requested_mode==1) ||
           CFAbsoluteTimeGetCurrent()-mode_heartbeat_at<10) return;
        requested_mode=0;
    }
    apply_pending_mode();
}
static void install_mode_observer(void) {
    mode_observer=[AQModeObserver new];
    [[NSDistributedNotificationCenter defaultCenter] addObserver:mode_observer
        selector:@selector(modeRequested:) name:AQModeRequest object:@"org.aquatransport.airdrop"
        suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
    [[NSDistributedNotificationCenter defaultCenter] addObserver:mode_observer
        selector:@selector(modeHeartbeat:) name:AQModeHeartbeat object:@"org.aquatransport.airdrop"
        suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
}
