#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#include <dns_sd.h>
#include <assert.h>
#include <net/if.h>
static uint32_t interface_index=10;
static unsigned test_interface(const char *name){assert(!strcmp(name,"tap0"));return interface_index;}
#define if_nametoindex test_interface
static BOOL air_drop_type(const char *s){return s && (!strcmp(s,"_airdrop._tcp.")||!strcmp(s,"_airdrop._tcp"));}
#include "../src/mac/airdrop/AQPublication.inc"
@interface Publisher : NSObject { @public CFNetServiceRef _service; }
@end
@implementation Publisher
- (void)dealloc { if(_service) CFRelease(_service); }
@end
static int checks, callbacks, stops;
static DNSServiceErrorType check_record(DNSServiceFlags f,uint32_t i,const char*n,uint16_t t,uint16_t c,uint16_t len,const void*d) {
 assert(!f && i==10 && !strcmp(n,"_airdrop._tcp.local.") && t==12 && c==1);
 static const unsigned char expected[]="\x04" "test" "\x08" "_airdrop" "\x04" "_tcp" "\x05" "local" "\0";
 assert(len==sizeof(expected)-1 && !memcmp(d,expected,len));checks++;return 0;
}
static void callback(id p,SEL s,CFStreamError*e){callbacks++;}
static void stopped(id p,SEL s){stops++;}
int main(void){@autoreleasepool {
    NSData *name=[@"Sending Mac" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *hash=[@"legacy-hash" dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *legacy=@{@"cname":name,@"ehash":hash,@"phash":hash,@"flags":hash};
    NSData *input=[NSNetService dataFromTXTRecordDictionary:legacy];
    NSDictionary *txt=[NSNetService dictionaryFromTXTRecordData:modern_txt(input)];
    assert(!txt[@"ehash"] && [txt[@"cname"] isEqual:name] && [txt[@"phash"] isEqual:hash]);
    assert([txt[@"flags"] isEqual:[@"136" dataUsingEncoding:NSUTF8StringEncoding]]);
    assert([[NSNetService dictionaryFromTXTRecordData:input] isEqual:legacy]);
    assert([[NSNetService dictionaryFromTXTRecordData:modern_txt(modern_txt(input))] isEqual:txt]);
 publication_reconfirm=check_record;original_publication_callback=callback;original_publication_stop=stopped;
 publication_service_offset=ivar_getOffset(class_getInstanceVariable([Publisher class],"_service"));
 Publisher *p=[Publisher new];p->_service=CFNetServiceCreate(NULL,CFSTR("local."),CFSTR("_airdrop._tcp."),CFSTR("test"),1234);
 CFStreamError e={0,0};publication_callback(p,NULL,&e);
 AQPublicationProbe *probe=objc_getAssociatedObject(p,&publication_key);assert(probe);
 [probe check];assert(checks==1);interface_index=0;[probe check];assert(checks==1);interface_index=10;
 publication_stop(p,NULL);[probe check];assert(checks==1 && stops==1 && !objc_getAssociatedObject(p,&publication_key));
 e.error=-1;publication_callback(p,NULL,&e);assert(!objc_getAssociatedObject(p,&publication_key));
 e.error=0;publication_callback(p,NULL,&e);AQPublicationProbe *old=objc_getAssociatedObject(p,&publication_key);
 publication_callback(p,NULL,&e);[old check];assert(checks==1 && old.cancelled);
 probe=objc_getAssociatedObject(p,&publication_key);[probe check];assert(checks==2);
 __weak AQPublicationProbe *weak=probe;probe=nil;p=nil;assert(!weak);assert(callbacks==4);
 puts("PASS: exact local PTR, missing interface, failed publication, cancellation, replacement and owner cleanup");
}return 0;}
