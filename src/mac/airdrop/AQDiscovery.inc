/* HTTP discovery fills the original Bonjour node; Finder still owns its UI. */
#include <arpa/inet.h>
#include <dlfcn.h>
#include "AQSocket.inc"
@interface NSURLConnection (AQScopedConnection)
- (instancetype)_initWithRequest:(NSURLRequest *)request delegate:(id)delegate usesCache:(BOOL)cache maxContentLength:(NSInteger)limit startImmediately:(BOOL)start connectionProperties:(NSDictionary *)properties;
@end
static void (*original_person)(id,SEL,id,id,id,id,id);
static void (*original_remove_service)(id,SEL,id,id,id);
static char discovery_key;
@interface AQDiscoveryProbe : NSObject <NSNetServiceDelegate,NSURLConnectionDataDelegate>
@property(weak) id browser;
@property(strong) NSNetService *service;
@property(strong) NSURLConnection *connection;
@property(strong) NSMutableData *data;
@property(copy) NSString *name;
@property BOOL cancelled;
@property NSInteger status;
@property NSUInteger attempts;
@property unsigned endpointToken;
@property BOOL retryScheduled;
- (void)start;
- (void)cancel;
@end
static NSMutableDictionary *probes(id browser) {
    NSMutableDictionary *items=objc_getAssociatedObject(browser,&discovery_key);
    if(!items) { items=[NSMutableDictionary dictionary]; objc_setAssociatedObject(browser,&discovery_key,items,OBJC_ASSOCIATION_RETAIN_NONATOMIC); }
    return items;
}
@implementation AQDiscoveryProbe
- (void)cancel { self.cancelled=YES; [self.service stop]; self.service.delegate=nil; [self.connection cancel]; self.connection=nil; release_endpoint(self.endpointToken); self.endpointToken=0; }
- (void)dealloc { release_endpoint(_endpointToken); }
- (void)retry {
    [self.service stop]; self.service.delegate=nil; [self.connection cancel]; self.connection=nil;
    if(self.cancelled || !self.browser || self.retryScheduled) return;
    self.retryScheduled=YES;
    int delay=self.attempts>=3 ? 30 : 2;
    if(self.attempts>=3) self.attempts=0;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,delay*NSEC_PER_SEC),dispatch_get_main_queue(),^{ self.retryScheduled=NO; [self start]; });
}
- (void)start {
    if(self.cancelled || !self.browser) return;
    self.attempts++; self.service.delegate=self;
    NSLog(@"AquaTransport AirDrop: resolving modern peer (attempt %lu)",(unsigned long)self.attempts);
    [self.service resolveWithTimeout:4];
}
- (void)netService:(NSNetService *)service didNotResolve:(NSDictionary *)error { (void)service; (void)error; [self retry]; }
- (void)netServiceDidResolveAddress:(NSNetService *)service {
    if(self.cancelled) return;
    NSString *host=nil;
    for(NSData *address in service.addresses) {
        if(address.length<sizeof(struct sockaddr_in6)) continue;
        struct sockaddr_in6 endpoint; memcpy(&endpoint,address.bytes,sizeof(endpoint));
        if(endpoint.sin6_family!=AF_INET6 || !IN6_IS_ADDR_LINKLOCAL(&endpoint.sin6_addr)) continue;
        endpoint.sin6_addr.s6_addr[2]=endpoint.sin6_addr.s6_addr[3]=0;
        char literal[INET6_ADDRSTRLEN]; if(!inet_ntop(AF_INET6,&endpoint.sin6_addr,literal,sizeof(literal))) continue;
        release_endpoint(self.endpointToken); self.endpointToken=retain_endpoint(endpoint.sin6_addr,htons((uint16_t)service.port));
        host=[NSString stringWithFormat:@"[%s]",literal]; break;
    }
    [service stop]; service.delegate=nil;
    if(!host || service.port<=0 || service.port>65535) { [self retry]; return; }
    NSURL *url=[NSURL URLWithString:[NSString stringWithFormat:@"https://%@:%ld/Discover",host,(long)service.port]];
    NSMutableURLRequest *request=[NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:12];
    SEL bind=@selector(setBoundInterfaceIdentifier:);
    if(![request respondsToSelector:bind]) { [self cancel]; return; }
    ((void (*)(id,SEL,id))[request methodForSelector:bind])(request,bind,@"tap0");
    request.HTTPMethod=@"POST";
    request.HTTPBody=[NSPropertyListSerialization dataWithPropertyList:@{} format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    [request setValue:@"application/octet-stream" forHTTPHeaderField:@"Content-Type"];
    self.data=[NSMutableData data]; self.status=0;
    CFStringRef *streamKey=dlsym(RTLD_DEFAULT,"kCFURLConnectionSocketStreamProperties");
    CFStringRef *interfaceKey=dlsym(RTLD_DEFAULT,"kCFStreamPropertyBoundInterfaceIdentifier");
    CFStringRef *socketInterfaceKey=dlsym(RTLD_DEFAULT,"kCFStreamPropertyInterfaceIdentifier");
    if(!streamKey || !interfaceKey || ![NSURLConnection instancesRespondToSelector:@selector(_initWithRequest:delegate:usesCache:maxContentLength:startImmediately:connectionProperties:)]) { [self cancel]; return; }
    if(!socketInterfaceKey) { [self cancel]; return; }
    NSDictionary *properties=@{(__bridge NSString *)*streamKey:@{(__bridge NSString *)*interfaceKey:@"tap0",(__bridge NSString *)*socketInterfaceKey:@"tap0"}};
    self.connection=[[NSURLConnection alloc] _initWithRequest:request delegate:self usesCache:NO maxContentLength:1024*1024 startImmediately:YES connectionProperties:properties];
}
- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)response {
    (void)connection; return response ? nil : request;
}
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if(connection!=self.connection || self.cancelled) { [challenge.sender cancelAuthenticationChallenge:challenge]; return; }
    /* Everyone-mode AirDrop uses self-signed peer certificates. This exception
     * belongs only to this link-local discovery connection, never global trust. */
    if([challenge.protectionSpace.authenticationMethod isEqual:NSURLAuthenticationMethodServerTrust] && challenge.protectionSpace.serverTrust && challenge.previousFailureCount==0)
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
    else [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
}
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    if(connection!=self.connection || self.cancelled) return;
    self.status=[response isKindOfClass:[NSHTTPURLResponse class]] ? [(NSHTTPURLResponse *)response statusCode] : 0;
    if(self.status!=200 || response.expectedContentLength>1024*1024) [self retry];
}
- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    if(connection!=self.connection || self.cancelled) return;
    if(self.data.length+data.length>1024*1024) { [self retry]; return; } [self.data appendData:data];
}
- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error { if(connection!=self.connection || self.cancelled) return; NSLog(@"AquaTransport AirDrop: discovery failed %@/%ld",error.domain,(long)error.code); [self retry]; }
- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    if(connection!=self.connection || self.cancelled) return; self.connection=nil;
    id plist=[NSPropertyListSerialization propertyListWithData:self.data options:0 format:NULL error:NULL];
    id name=[plist isKindOfClass:[NSDictionary class]] ? plist[@"ReceiverComputerName"] : nil;
    if(self.status!=200 || ![name isKindOfClass:[NSString class]] || ![name length] || [name length]>256) { [self retry]; return; }
    id browser=self.browser; if(self.cancelled || !browser) return;
    self.name=name;
    original_person(browser,@selector(personInfoChanged:flags:cname:phash:ehash:),self.service,@"3",name,nil,nil);
    // HTTP completes after the original TXT callback has already cached its
    // empty peer list. Use the native cache invalidation + notification path.
    SEL notify=@selector(clearCacheAndNotify);
    if([browser respondsToSelector:notify]) ((void (*)(id,SEL))[browser methodForSelector:notify])(browser,notify);
    NSLog(@"AquaTransport AirDrop: modern peer metadata received");
}
@end
static void person_changed(id browser,SEL selector,NSNetService *service,id flags,id name,id picture,id email) {
    if(!is_airdrop_browser(browser)) { original_person(browser,selector,service,flags,name,picture,email); return; }
    // A named Bonjour peer can otherwise seed the native cache with an Apple
    // ID claim before /Ask arrives. TAP discovery provides no verified identity.
    email=nil;
    if([name length]) { original_person(browser,selector,service,flags,name,picture,email); return; }
    NSMutableDictionary *items=probes(browser); NSString *key=service.name.lowercaseString;
    AQDiscoveryProbe *probe=items[key];
    if(probe.name) { original_person(browser,selector,service,@"3",probe.name,nil,nil); return; }
    original_person(browser,selector,service,flags,name,picture,email);
    if(!probe && items.count<64) {
        probe=[AQDiscoveryProbe new]; probe.browser=browser;
        probe.service=[[NSNetService alloc] initWithDomain:service.domain type:service.type name:service.name]; items[key]=probe;
        dispatch_async(dispatch_get_main_queue(),^{ [probe start]; });
    }
}
static void cancel_discovery(id browser) {
    NSMutableDictionary *items=objc_getAssociatedObject(browser,&discovery_key);
    for(AQDiscoveryProbe *probe in items.allValues) [probe cancel]; [items removeAllObjects];
}
static void remove_service(id browser,SEL selector,NSString *name,id type,id domain) {
    if(is_airdrop_browser(browser)) {
        NSMutableDictionary *items=objc_getAssociatedObject(browser,&discovery_key);
        [items[name.lowercaseString] cancel]; [items removeObjectForKey:name.lowercaseString];
    }
    original_remove_service(browser,selector,name,type,domain);
}
