#import <Foundation/Foundation.h>
#include <assert.h>
static BOOL native_mode;
static NSUInteger active_transfers;
static NSHashTable *active_browsers,*active_servers;
static NSHashTable *pending_browsers,*pending_servers;
static NSMutableArray *events;
@interface CachedBrowser : NSObject
@property(copy) NSArray *services;
@property(copy) NSArray *published;
- (void)clearCacheAndNotify;
@end
@implementation CachedBrowser
- (void)clearCacheAndNotify {
    [events addObject:@"browser notify"];
    dispatch_async(dispatch_get_main_queue(),^{ self.published=self.services; });
}
@end
@interface AQTransferLease : NSObject @end
@implementation AQTransferLease @end
static void stop_browser(id browser,SEL selector) { (void)selector; [events addObject:@"browser stop"]; [(CachedBrowser *)browser setServices:@[]]; [active_browsers removeObject:browser]; }
static void stop_server(id server,SEL selector) { (void)selector; [events addObject:@"server stop"]; [active_servers removeObject:server]; }
static void start_browser(id browser,SEL selector) { (void)selector; [events addObject:@"browser start"]; [active_browsers addObject:browser]; }
static void start_server(id server,SEL selector) { (void)selector; [events addObject:@"server start"]; [active_servers addObject:server]; }
static void force_stop_radio(void) { [events addObject:@"radio stop"]; }
#include "../src/mac/airdrop/AQMode.inc"
#include "../src/mac/airdrop/AQPendingRetry.inc"
static void drain(void) { [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]]; }
int main(void) { @autoreleasepool {
    events=[NSMutableArray array]; active_browsers=[NSHashTable weakObjectsHashTable]; active_servers=[NSHashTable weakObjectsHashTable];
    pending_browsers=[NSHashTable weakObjectsHashTable]; pending_servers=[NSHashTable weakObjectsHashTable];
    CachedBrowser *browser=[CachedBrowser new]; browser.services=@[@"Test iPhone"]; browser.published=browser.services;
    NSObject *server=[NSObject new]; [active_browsers addObject:browser]; [active_servers addObject:server];
    install_mode_observer();
    active_transfers=1;
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:AQModeRequest
        object:@"org.aquatransport.airdrop" userInfo:@{@"native":@YES} deliverImmediately:YES];
    drain(); assert(!native_mode && !events.count);
    active_transfers=0; apply_pending_mode(); drain();
    assert(native_mode);
    assert(browser.published.count==0);
    assert(([events isEqual:@[@"browser stop",@"server stop",@"browser notify",@"radio stop",@"server start",@"browser start"]]));
    [events removeAllObjects];
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:AQModeRequest
        object:@"org.aquatransport.airdrop" userInfo:@{@"native":@NO} deliverImmediately:YES];
    drain(); assert(!native_mode);
    assert(([events isEqual:@[@"browser stop",@"server stop",@"browser notify",@"server start",@"browser start"]]));
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:AQModeRequest
        object:@"org.aquatransport.airdrop" userInfo:@{@"native":@YES} deliverImmediately:YES];
    drain(); assert(native_mode);
    mode_heartbeat_at=0; expire_mode_owner(); drain(); assert(!native_mode);
    [events removeAllObjects];
    [pending_servers addObject:server];
    retry_pending_radio(YES);
    assert(([events isEqual:@[@"server start"]]));
    [events removeAllObjects];
    [active_browsers removeObject:browser]; // Finder closed while the receiver was still pending.
    retry_pending_radio(YES);
    assert(!events.count);
    [active_browsers addObject:browser];
    retry_pending_radio(NO);
    assert(!events.count);
    puts("PASS: mode changes defer during transfers, clear Finder's stale peers, restart native owners, and restore modern discovery on request or expired Finder session");
    puts("PASS: pending receiver retries stop when Finder closes or Bluetooth or Wi-Fi is off");
    return 0;
} }
