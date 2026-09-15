/* Mavericks sharingd transport adapter. Finder and SDFileZipper remain native.
 * Loaded by the AquaTransport gate at sharingd's pre-daemon startup boundary. */
#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#include <dns_sd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <dlfcn.h>
#include "../../../deps/fishhook/fishhook.h"

typedef const void *AQRequest;
static void (*original_start)(id,SEL),(*original_stop)(id,SEL),(*original_request)(id,SEL,AQRequest);
static void (*original_browser_start)(id,SEL),(*original_browser_stop)(id,SEL);
static BOOL (*original_valid_interface)(id,SEL,uint32_t);
static ptrdiff_t browser_airdrop_offset;
static CFTypeRef (*request_property)(AQRequest,CFStringRef);
static CFTypeRef (*original_response)(AQRequest,CFHTTPMessageRef,CFDataRef);
static CFStringRef request_url;
static DNSServiceErrorType (*original_browse)(DNSServiceRef *,DNSServiceFlags,uint32_t,const char *,const char *,DNSServiceBrowseReply,void *);
static DNSServiceErrorType (*original_resolve)(DNSServiceRef *,DNSServiceFlags,uint32_t,const char *,const char *,const char *,DNSServiceResolveReply,void *);
static DNSServiceErrorType (*original_register)(DNSServiceRef *,DNSServiceFlags,uint32_t,const char *,const char *,const char *,const char *,uint16_t,uint16_t,const void *,DNSServiceRegisterReply,void *);
static DNSServiceErrorType (*original_query)(DNSServiceRef *,DNSServiceFlags,uint32_t,const char *,uint16_t,uint16_t,DNSServiceQueryRecordReply,void *);
static Boolean (*original_net_register)(CFNetServiceRef,CFOptionFlags,CFStreamError *);
static Boolean (*original_set_txt)(CFNetServiceRef,CFDataRef);
static NSLock *radio_lock;
static dispatch_source_t heartbeat;
static BOOL radio_running;
static uint64_t radio_release_generation;
static NSHashTable *radio_owners;
static int adapter_installed;
__attribute__((visibility("default"))) int AQAirDropInstalled(void) { return adapter_installed; }

static NSDictionary *helper(NSString *command) {
    int fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0) return nil;
    struct sockaddr_un address; memset(&address,0,sizeof(address)); address.sun_len=sizeof(address); address.sun_family=AF_UNIX;
    strlcpy(address.sun_path,"/var/run/org.aquatransport.airdrop.sock",sizeof(address.sun_path));
    struct timeval timeout={8,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)); setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    int one=1; setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    NSDictionary *reply=nil;
    if(!connect(fd,(struct sockaddr *)&address,sizeof(address))) {
        NSMutableData *data=[[NSJSONSerialization dataWithJSONObject:@{@"command":command} options:0 error:NULL] mutableCopy]; [data appendBytes:"\n" length:1];
        const char *p=data.bytes; size_t left=data.length;
        while(left) { ssize_t n=write(fd,p,left); if(n<=0) break; p+=n; left-=n; }
        if(!left) {
            NSMutableData *response=[NSMutableData data]; char byte;
            while(response.length<4096 && read(fd,&byte,1)==1) { if(byte=='\n') { id object=[NSJSONSerialization JSONObjectWithData:response options:0 error:NULL]; if([object isKindOfClass:[NSDictionary class]]) reply=object; break; } [response appendBytes:&byte length:1]; }
        }
    }
    close(fd); return reply;
}
#include "AQRadio.inc"
#include "AQTransferLease.inc"
static BOOL is_airdrop_browser(id browser) {
    return *((const unsigned char *)(__bridge const void *)browser+browser_airdrop_offset)!=0;
}
#include "AQDiscovery.inc"
static BOOL valid_interface(id browser,SEL selector,uint32_t index) {
    if(is_airdrop_browser(browser)) { uint32_t tap=if_nametoindex("tap0"); return tap && index==tap; }
    return original_valid_interface(browser,selector,index);
}
static void start_browser(id browser,SEL selector) {
    if(is_airdrop_browser(browser) && !acquire_radio(browser)) return;
    original_browser_start(browser,selector);
}
static void stop_browser(id browser,SEL selector) {
    if(is_airdrop_browser(browser)) cancel_discovery(browser);
    original_browser_stop(browser,selector);
    if(is_airdrop_browser(browser)) release_radio(browser);
}
static BOOL air_drop_type(const char *type) { return type && (!strcasecmp(type,"_airdrop._tcp") || !strcasecmp(type,"_airdrop._tcp.")); }
static DNSServiceFlags modern_flags(DNSServiceFlags flags) { return flags & ~(0x20000U|0x100000U); }
#include "AQPublication.inc"
static Boolean set_txt(CFNetServiceRef service,CFDataRef data) {
    NSString *type=(__bridge NSString *)CFNetServiceGetType(service);
    if(air_drop_type(type.UTF8String)) return original_set_txt(service,(__bridge CFDataRef)modern_txt((__bridge NSData *)data));
    return original_set_txt(service,data);
}
static DNSServiceErrorType browse(DNSServiceRef *ref,DNSServiceFlags flags,uint32_t index,const char *type,const char *domain,DNSServiceBrowseReply callback,void *context) {
    if(air_drop_type(type)) { index=ensure_radio(); if(!index) return kDNSServiceErr_NotInitialized; flags=modern_flags(flags); }
    return original_browse(ref,flags,index,type,domain,callback,context);
}
static DNSServiceErrorType resolve(DNSServiceRef *ref,DNSServiceFlags flags,uint32_t index,const char *name,const char *type,const char *domain,DNSServiceResolveReply callback,void *context) {
    if(air_drop_type(type)) { index=ensure_radio(); if(!index) return kDNSServiceErr_NotInitialized; flags=modern_flags(flags); }
    return original_resolve(ref,flags,index,name,type,domain,callback,context);
}
static DNSServiceErrorType register_service(DNSServiceRef *ref,DNSServiceFlags flags,uint32_t index,const char *name,const char *type,const char *domain,const char *host,uint16_t port,uint16_t length,const void *txt,DNSServiceRegisterReply callback,void *context) {
    NSData *modern=nil;
    if(air_drop_type(type)) { index=ensure_radio(); if(!index) return kDNSServiceErr_NotInitialized; flags=modern_flags(flags); modern=modern_txt([NSData dataWithBytes:txt length:length]); length=(uint16_t)modern.length; txt=modern.bytes; }
    return original_register(ref,flags,index,name,type,domain,host,port,length,txt,callback,context);
}
static DNSServiceErrorType query(DNSServiceRef *ref,DNSServiceFlags flags,uint32_t index,const char *name,uint16_t type,uint16_t dnsclass,DNSServiceQueryRecordReply callback,void *context) {
    if(name && strstr(name,"._airdrop._tcp.")) { index=ensure_radio(); if(!index) return kDNSServiceErr_NotInitialized; flags=modern_flags(flags); }
    return original_query(ref,flags,index,name,type,dnsclass,callback,context);
}
static Boolean register_net_service(CFNetServiceRef service,CFOptionFlags flags,CFStreamError *error) {
    CFStringRef type=CFNetServiceGetType(service);
    if(type && (CFEqual(type,CFSTR("_airdrop._tcp.")) || CFEqual(type,CFSTR("_airdrop._tcp")))) {
        if(!ensure_radio()) { if(error) { error->domain=kCFStreamErrorDomainNetServices; error->error=kCFNetServicesErrorNotFound; } return false; }
        flags&=~(0x20000UL|0x100000UL);
        set_txt(service,CFNetServiceGetTXTData(service));
    }
    return original_net_register(service,flags,error);
}
static NSString *path_for_request(AQRequest request) {
    id url=CFBridgingRelease(request_property(request,request_url)); return [url isKindOfClass:[NSURL class]] ? [url path] : nil;
}
static NSDictionary *capabilities(void) {
    char model[128]={0}; size_t size=sizeof(model); if(sysctlbyname("hw.model",model,&size,NULL,0)) model[0]=0;
    return @{@"ReceiverComputerName":[[NSHost currentHost] localizedName] ?: @"Mac",@"ReceiverModelName":model[0] ? [NSString stringWithUTF8String:model] : @"Mac",@"ReceiverMediaCapabilities":[@"{\"Version\":1}" dataUsingEncoding:NSUTF8StringEncoding]};
}
#include "AQOutgoing.inc"
static CFTypeRef response(AQRequest request,CFHTTPMessageRef message,CFDataRef body) {
    if(CFHTTPMessageGetResponseStatusCode(message)==200 && [[path_for_request(request) lastPathComponent] isEqual:@"Ask"] && body) {
        // The native offer/acceptance state belongs to this HTTP connection.
        // Mavericks labels every response "close"; modern CFNetwork then opens
        // a new connection for Upload, which has no accepted offer. Keep the
        // successful Ask connection available for its matching upload.
        CFHTTPMessageSetHeaderFieldValue(message,CFSTR("Connection"),CFSTR("keep-alive"));
        id plist=[NSPropertyListSerialization propertyListWithData:(__bridge NSData *)body options:NSPropertyListMutableContainers format:NULL error:NULL];
        if([plist isKindOfClass:[NSMutableDictionary class]]) {
            [plist addEntriesFromDictionary:capabilities()];
            NSData *data=[NSPropertyListSerialization dataWithPropertyList:plist format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
            if(data) return original_response(request,message,(__bridge CFDataRef)data);
        }
    }
    return original_response(request,message,body);
}
static void received_request(id connection,SEL selector,AQRequest request) {
    NSString *path=path_for_request(request);
    if([path isEqual:@"/Discover"]) {
        NSData *data=[NSPropertyListSerialization dataWithPropertyList:capabilities() format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
        SEL reply=@selector(enqueueResponse:code:body:);
        ((void (*)(id,SEL,AQRequest,NSInteger,CFDataRef))[connection methodForSelector:reply])(connection,reply,request,200,(__bridge CFDataRef)data);
        return;
    }
    if([path isEqual:@"/Ask"]) begin_transfer(connection,YES);
    original_request(connection,selector,request);
}
static void start_server(id server,SEL selector) {
    if(!acquire_radio(server)) { NSLog(@"AquaTransport AirDrop: radio unavailable"); return; }
    resume_transfer_server(server);
    original_start(server,selector);
}
static void stop_server(id server,SEL selector) {
    if(defer_transfer_server_stop(server)) return;
    forget_transfer_server(server);
    original_stop(server,selector);
    release_radio(server);
}
static Method checked_method(NSString *class_name,const char *selector,const char *encoding) {
    Method method=class_getInstanceMethod(NSClassFromString(class_name),sel_registerName(selector));
    if(!method || strcmp(method_getTypeEncoding(method),encoding)) return NULL;
    Dl_info owner; if(!dladdr((void *)method_getImplementation(method),&owner) || !owner.dli_fname || strcmp(owner.dli_fname,"/usr/libexec/sharingd")) return NULL;
    return method;
}
#include "AQIncoming.inc"
#include "AQStreamEvents.inc"

__attribute__((constructor)) static void install_airdrop(void) { @autoreleasepool {
    Method publication=checked_method(@"SDBonjourPublisher","publishCallBack:","v24@0:8^{?=qi}16");
    Method publication_end=checked_method(@"SDBonjourPublisher","stop","v16@0:8");
    Ivar service_ivar=class_getInstanceVariable(NSClassFromString(@"SDBonjourPublisher"),"_service");
    if(!publication || !publication_end || !service_ivar || strcmp(ivar_getTypeEncoding(service_ivar),"^{__CFNetService=}")) return;
    publication_service_offset=ivar_getOffset(service_ivar);
    Method transfer_begin=checked_method(@"SDWormholeClient","start","v16@0:8");
    Method transfer_end=checked_method(@"SDWormholeClient","stop","v16@0:8");
    Method transfer_notify=checked_method(@"SDWormholeClient","notifyClientForEvent:withProperty:","v32@0:8q16^v24");
    Method receive_notify=checked_method(@"SDWormholeConnection","notifyClientForEvent:","v24@0:8q16");
    Method receive_end=checked_method(@"SDWormholeConnection","stop","v16@0:8");
    Ivar receive_ask=class_getInstanceVariable(NSClassFromString(@"SDWormholeConnection"),"_askRequest");
    if(!transfer_begin || !transfer_end || !transfer_notify || !receive_notify || !receive_end || !receive_ask || strcmp(ivar_getTypeEncoding(receive_ask),"^{_CFHTTPServerRequest=}")) return;
    receive_ask_offset=ivar_getOffset(receive_ask);
    Method start=checked_method(@"SDWormholeServer","startHTTPServer","v16@0:8"),stop=checked_method(@"SDWormholeServer","stop","v16@0:8");
    Method request=checked_method(@"SDWormholeConnection","didReceiveRequest:","v24@0:8^{_CFHTTPServerRequest=}16");
    Method offer_event=checked_method(@"SDWormholeConnection","handleReadStreamEvent:event:","v32@0:8^{__CFReadStream=}16Q24");
    if(!offer_event) return;
    Method browser_start=checked_method(@"SDBonjourBrowser","start","v16@0:8"),browser_stop=checked_method(@"SDBonjourBrowser","stop","v16@0:8");
    Method person=checked_method(@"SDBonjourBrowser","personInfoChanged:flags:cname:phash:ehash:","v56@0:8@16@24@32@40@48");
    Method valid=checked_method(@"SDBonjourBrowser","validAirDropInterface:","c20@0:8I16");
    Method ask=checked_method(@"SDWormholeClient","askBodyDataInFormat:","@24@0:8q16");
    Method send=checked_method(@"SDWormholeClient","sendRequest:","v24@0:8^{__CFString=}16");
    Method gotResponse=checked_method(@"SDWormholeClient","didReceiveResponse:","v24@0:8^{_CFURLResponse=}16");
    if(!ask || !send || !gotResponse) return;
    Method zipper_copy=checked_method(@"SDFileZipper","bomCopierCopy:destination:options:","i40@0:8@16@24@32");
    zipper_compression_engine=class_getInstanceVariable(NSClassFromString(@"SDFileZipper"),"_compressionEngine");
    if(!zipper_copy || !zipper_compression_engine || strcmp(ivar_getTypeEncoding(zipper_compression_engine),"@\"SDAdaptiveCompressor\"") ||
       !checked_method(@"SDFileZipper","isDecompressor","c16@0:8") ||
       !checked_method(@"SDFileZipper","copyReadStream","^{__CFReadStream=}16@0:8")) return;

    Method remove=checked_method(@"SDBonjourBrowser","removeService:type:domain:","v40@0:8@16@24@32");
    if(!person || !remove || !valid || !checked_method(@"SDBonjourBrowser","clearCacheAndNotify","v16@0:8")) return;
    Ivar air_drop=class_getInstanceVariable(NSClassFromString(@"SDBonjourBrowser"),"_isAirDrop");
    if(!start || !stop || !request || !browser_start || !browser_stop || !air_drop || strcmp(ivar_getTypeEncoding(air_drop),"c") || !checked_method(@"SDWormholeConnection","enqueueResponse:code:body:","v40@0:8^{_CFHTTPServerRequest=}16q24^{__CFData=}32")) return;
    browser_airdrop_offset=ivar_getOffset(air_drop);
#define RESOLVE(variable,symbol) variable=dlsym(RTLD_DEFAULT,symbol); if(!variable) return
    RESOLVE(original_browse,"DNSServiceBrowse"); RESOLVE(original_resolve,"DNSServiceResolve"); RESOLVE(original_register,"DNSServiceRegister"); RESOLVE(original_query,"DNSServiceQueryRecord");
    RESOLVE(original_net_register,"CFNetServiceRegisterWithOptions"); RESOLVE(request_property,"_CFHTTPServerRequestCopyProperty"); RESOLVE(original_response,"_CFHTTPServerResponseCreateWithData");
    RESOLVE(original_set_txt,"CFNetServiceSetTXTData");
    RESOLVE(original_bom_copy,"BOMCopierCopyWithOptions"); RESOLVE(bom_user_data,"BOMCopierUserData");
    RESOLVE(original_connect,"connect"); RESOLVE(original_connectx,"connectx");
    RESOLVE(original_create_connection,"CFURLConnectionCreateWithProperties");
    RESOLVE(copy_mutable_request,"CFURLRequestCreateMutableCopy"); RESOLVE(set_request_header,"CFURLRequestSetHTTPHeaderFieldValue");
    RESOLVE(response_message,"CFURLResponseGetHTTPResponse");
    CFStringRef *url=dlsym(RTLD_DEFAULT,"_kCFHTTPServerRequestURL"); if(!url) return; request_url=*url;
#undef RESOLVE
    radio_lock=[NSLock new];
    radio_owners=[NSHashTable weakObjectsHashTable];
    struct rebinding hooks[]={ {"DNSServiceBrowse",(void *)&browse,NULL},{"DNSServiceResolve",(void *)&resolve,NULL},{"DNSServiceRegister",(void *)&register_service,NULL},{"DNSServiceQueryRecord",(void *)&query,NULL},{"CFNetServiceRegisterWithOptions",(void *)&register_net_service,NULL},{"CFNetServiceSetTXTData",(void *)&set_txt,NULL},{"_CFHTTPServerResponseCreateWithData",(void *)&response,NULL},{"connect",(void *)&scoped_connect,NULL},{"connectx",(void *)&scoped_connectx,NULL} };
    if(rebind_symbols(hooks,sizeof(hooks)/sizeof(hooks[0]))) return;
    struct rebinding outgoing={"CFURLConnectionCreateWithProperties",(void *)&create_connection,NULL};
    if(rebind_symbols(&outgoing,1)) return;
    struct rebinding incoming={"BOMCopierCopyWithOptions",(void *)&incoming_bom_copy,NULL};
    if(rebind_symbols(&incoming,1)) return;
    original_zipper_copy=(void *)method_setImplementation(zipper_copy,(IMP)incoming_copy);
    original_publication_callback=(void *)method_setImplementation(publication,(IMP)publication_callback);
    original_publication_stop=(void *)method_setImplementation(publication_end,(IMP)publication_stop);
    original_offer_stream_event=(void *)method_setImplementation(offer_event,(IMP)offer_stream_event);
    original_transfer_start=(void *)method_setImplementation(transfer_begin,(IMP)transfer_start);
    original_transfer_stop=(void *)method_setImplementation(transfer_end,(IMP)transfer_stop);
    original_transfer_event=(void *)method_setImplementation(transfer_notify,(IMP)transfer_event);
    original_receive_event=(void *)method_setImplementation(receive_notify,(IMP)receive_event);
    original_receive_stop=(void *)method_setImplementation(receive_end,(IMP)receive_stop);
    original_start=(void *)method_setImplementation(start,(IMP)start_server); original_stop=(void *)method_setImplementation(stop,(IMP)stop_server); original_request=(void *)method_setImplementation(request,(IMP)received_request);
    original_browser_start=(void *)method_setImplementation(browser_start,(IMP)start_browser); original_browser_stop=(void *)method_setImplementation(browser_stop,(IMP)stop_browser);
    original_person=(void *)method_setImplementation(person,(IMP)person_changed);
    original_remove_service=(void *)method_setImplementation(remove,(IMP)remove_service);
    original_valid_interface=(void *)method_setImplementation(valid,(IMP)valid_interface);
    original_ask_body=(void *)method_setImplementation(ask,(IMP)ask_body);
    original_send_request=(void *)method_setImplementation(send,(IMP)send_request);
    original_received_response=(void *)method_setImplementation(gotResponse,(IMP)received_response);
    adapter_installed=1;
    NSLog(@"AquaTransport AirDrop: native daemon transport adapter installed");
} }
