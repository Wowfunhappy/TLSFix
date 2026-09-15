#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <assert.h>
static BOOL is_airdrop_browser(id browser) { (void)browser; return YES; }
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
static void update_person(id browser,SEL selector,id service,id flags,id name,id picture,id email) {
    (void)selector; (void)service; (void)flags; (void)picture; (void)email;
    [(CachedBrowser *)browser setBacking:@[name]];
}
int main(void) { @autoreleasepool {
    original_person=update_person;
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
    puts("PASS: late HTTP metadata replaces a previously cached empty native peer list");
} }
