static NSData *modern_txt(NSData *data) {
    NSMutableDictionary *txt=data ? [[NSNetService dictionaryFromTXTRecordData:data] mutableCopy] : nil;
    if(!txt) txt=[NSMutableDictionary dictionary];
    txt[@"flags"]=[@"136" dataUsingEncoding:NSUTF8StringEncoding];
    // Do not publish a legacy Apple ID claim with Everyone-mode discovery.
    [txt removeObjectForKey:@"ehash"];
    return [NSNetService dataFromTXTRecordDictionary:txt];
}

/* Keep the native receiver discoverable after missed AWDL announcements.
 * Reconfirm only our own PTR on TAP. mDNSResponder supplies the authoritative
 * response, including the original identity/port/TXT. No second registration,
 * or listener replacement is performed here. */
static void (*original_publication_callback)(id,SEL,CFStreamError *);
static void (*original_publication_stop)(id,SEL);
static ptrdiff_t publication_service_offset;
static char publication_key;
static DNSServiceErrorType (*publication_reconfirm)(DNSServiceFlags,uint32_t,const char *,uint16_t,uint16_t,uint16_t,const void *)=DNSServiceReconfirmRecord;
#ifndef AQ_PUBLICATION_FIRST_NS
#define AQ_PUBLICATION_FIRST_NS (3*NSEC_PER_SEC)
#define AQ_PUBLICATION_INTERVAL_NS (5*NSEC_PER_SEC)
#endif
@interface AQPublicationProbe : NSObject
@property(weak) id publisher;
@property(copy) NSData *record;
@property(strong) dispatch_source_t timer;
@property BOOL cancelled;
@property NSUInteger attempts;
- (void)check;
- (void)cancel;
@end
@implementation AQPublicationProbe
- (void)check {
    if(self.cancelled || !self.publisher) return;
    uint32_t interface=if_nametoindex("tap0");
    if(!interface) return;
    DNSServiceErrorType error=publication_reconfirm(0,interface,"_airdrop._tcp.local.",kDNSServiceType_PTR,kDNSServiceClass_IN,(uint16_t)self.record.length,self.record.bytes);
    if(error) NSLog(@"AquaTransport AirDrop: publication check failed (%d)",error);
    // Fast, bounded startup retries bridge radio convergence and lost initial
    // announcements. Established sessions need only a low-rate liveness check.
    if(++_attempts==12 && _timer)
        dispatch_source_set_timer(_timer,dispatch_time(DISPATCH_TIME_NOW,30*NSEC_PER_SEC),30*NSEC_PER_SEC,NSEC_PER_SEC);
}
- (void)cancel { self.cancelled=YES; if(_timer) { dispatch_source_cancel(_timer); _timer=nil; } }
- (void)dealloc { if(_timer) dispatch_source_cancel(_timer); }
@end
static void stop_publication_probe(id publisher) {
    AQPublicationProbe *probe=objc_getAssociatedObject(publisher,&publication_key);
    [probe cancel];
    objc_setAssociatedObject(publisher,&publication_key,nil,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}
static void publication_callback(id publisher,SEL selector,CFStreamError *error) {
    original_publication_callback(publisher,selector,error);
    stop_publication_probe(publisher);
    if(!error || error->error) return;
    CFNetServiceRef service=*(CFNetServiceRef *)((char *)(__bridge void *)publisher+publication_service_offset);
    if(!service) return;
    NSString *type=(__bridge NSString *)CFNetServiceGetType(service);
    NSString *domain=(__bridge NSString *)CFNetServiceGetDomain(service);
    if(!air_drop_type(type.UTF8String) || [domain caseInsensitiveCompare:@"local."]!=NSOrderedSame) return;
    NSData *name=[(__bridge NSString *)CFNetServiceGetName(service) dataUsingEncoding:NSUTF8StringEncoding];
    if(!name.length || name.length>63) return;
    uint8_t size=(uint8_t)name.length;
    NSMutableData *record=[NSMutableData dataWithBytes:&size length:1]; [record appendData:name];
    static const char suffix[]="\x08" "_airdrop" "\x04" "_tcp" "\x05" "local" "\0";
    [record appendBytes:suffix length:sizeof(suffix)-1];
    AQPublicationProbe *probe=[AQPublicationProbe new]; probe.publisher=publisher; probe.record=record;
    probe.timer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,dispatch_get_main_queue());
    __weak AQPublicationProbe *weakProbe=probe;
    dispatch_source_set_event_handler(probe.timer,^{ [weakProbe check]; });
    dispatch_source_set_timer(probe.timer,dispatch_time(DISPATCH_TIME_NOW,AQ_PUBLICATION_FIRST_NS),AQ_PUBLICATION_INTERVAL_NS,NSEC_PER_SEC);
    objc_setAssociatedObject(publisher,&publication_key,probe,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    dispatch_resume(probe.timer);
}
static void publication_stop(id publisher,SEL selector) {
    stop_publication_probe(publisher);
    original_publication_stop(publisher,selector);
}
