#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#include <assert.h>
static BOOL airDrop=YES;
static BOOL is_airdrop_browser(id browser) { (void)browser; return airDrop; }
#include "../src/mac/airdrop/AQDiscovery.inc"
@interface CachedBrowser : NSObject
@property(copy) NSArray *backing;
@property(copy) NSArray *cache;
@property(copy) NSArray *published;
- (NSArray *)nodes;
- (void)notifyClient;
- (void)clearCacheAndNotify;
@end
@implementation CachedBrowser
- (NSArray *)nodes { if(!self.cache) self.cache=self.backing; return self.cache; }
- (void)notifyClient { self.published=[self nodes]; }
- (void)clearCacheAndNotify { dispatch_async(dispatch_get_main_queue(),^{ self.cache=nil; [self notifyClient]; }); }
@end
static id observed_email;
static NSString *removed_name;
static void update_person(id browser,SEL selector,id service,id flags,id name,id picture,id email) {
    (void)selector; (void)service; (void)flags; (void)picture; (void)email;
    observed_email=email;
    [(CachedBrowser *)browser setBacking:name ? @[name] : @[]];
}
static void remove_person(id browser,SEL selector,id name,id type,id domain) {
    (void)selector; (void)type; (void)domain;
    removed_name=name;
    [(CachedBrowser *)browser setBacking:@[]];
}
int main(void) { @autoreleasepool {
    original_person=update_person;
    original_remove_service=remove_person;
    CachedBrowser *browser=[CachedBrowser new]; browser.backing=@[];
    [browser notifyClient]; assert(browser.published.count==0);
    AQDiscoveryProbe *probe=[AQDiscoveryProbe new]; probe.browser=browser;
    probe.service=[[NSNetService alloc] initWithDomain:@"local." type:@"_airdrop._tcp." name:@"001122334455"];
    probe.status=200; probe.data=[[NSPropertyListSerialization dataWithPropertyList:@{@"ReceiverComputerName":@"Test iPhone"} format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL] mutableCopy];
    NSURLConnection *connection=(id)[NSObject new]; probe.connection=connection;
    [probe connectionDidFinishLoading:connection];
    NSDate *end=[NSDate dateWithTimeIntervalSinceNow:1];
    while(!browser.published.count && end.timeIntervalSinceNow>0) [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    assert([browser.published isEqual:@[@"Test iPhone"]]);
    SEL changed=@selector(personInfoChanged:flags:cname:phash:ehash:);
    person_changed(browser,changed,probe.service,@"136",@"Other Mac",nil,@"legacy-hash");
    assert(!observed_email && [browser.backing isEqual:@[@"Other Mac"]]);
    // Clear a previously identified peer through the native update callback.
    observed_email=@"cached-hash";
    person_changed(browser,changed,probe.service,@"136",@"Other Mac",nil,@"legacy-hash");
    assert(!observed_email);
    airDrop=NO;
    person_changed(browser,changed,probe.service,@"3",@"Unrelated service",nil,@"preserved-hash");
    assert([observed_email isEqual:@"preserved-hash"]);
    airDrop=YES;
    browser.backing=@[@"Test iPhone"]; [browser notifyClient];
    probes(browser)[probe.service.name.lowercaseString]=probe;
    remove_service(browser,@selector(removeService:type:domain:),probe.service.name,probe.service.type,probe.service.domain);
    end=[NSDate dateWithTimeIntervalSinceNow:1];
    while(browser.published.count && end.timeIntervalSinceNow>0) [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    assert([removed_name isEqualToString:probe.service.name]);
    assert(probe.cancelled && !probes(browser).count && !browser.published.count);
    puts("PASS: late HTTP metadata replaces a previously cached empty native peer list");
    puts("PASS: named AirDrop peers do not seed Apple ID claims; unrelated discovery is unchanged");
    puts("PASS: removed iPhone identities clear Finder's cached peer list");
} }
