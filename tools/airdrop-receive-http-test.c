// Mavericks-only localhost CFHTTPServer/BOM completion regression probe.
// A pass-through stream pump represents the adaptive decompressor's lifetime;
// Apple's real BOM copier consumes a generated CPIO archive. No radio or Finder.
// Run with tools/test-airdrop-receive-lifecycle.sh (creates isolated fixtures).
#include <CFNetwork/CFNetwork.h>
#include <dispatch/dispatch.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <Security/Security.h>
#include <openssl/ssl.h>
typedef const void *Ref;
typedef struct { long version; void *info; void *retain; void *release; void *description; } Client;
typedef struct { long version; void (*invalid)(void*); void (*error)(void*,CFErrorRef); void (*accept)(void*,Ref); void (*closed)(void*,Ref); } ServerCallbacks;
typedef struct { long version; void (*invalid)(void*); void (*error)(void*,CFErrorRef); void (*request)(void*,Ref); void *sent; void *failed; } ConnectionCallbacks;
extern Ref _CFHTTPServerCreateWithAcceptedSocket(CFAllocatorRef,const Client*,const ServerCallbacks*,int);
extern void _CFHTTPServerSetDispatchQueue(Ref,dispatch_queue_t);
extern Boolean _CFHTTPServerConnectionSetClient(Ref,const Client*,const ConnectionCallbacks*);
extern void _CFHTTPServerConnectionSetDispatchQueue(Ref,dispatch_queue_t);
extern CFReadStreamRef _CFHTTPServerRequestCopyBodyStream(Ref);
extern CFHTTPMessageRef _CFHTTPServerRequestCreateResponseMessage(Ref,long);
extern Ref _CFHTTPServerResponseCreateWithData(Ref,CFHTTPMessageRef,CFDataRef);
extern void _CFHTTPServerResponseEnqueue(Ref);
static SSL *tls;
static int use_tls;
static int slow, coalesce;
static unsigned char *archive;
static int hold_open, close_after_copy;
static char *pending;
static size_t pending_len;
static SecKeychainRef scratch;
static const char *test_dir;
static void cleanup_identity(void) {if(scratch){SecKeychainDelete(scratch);CFRelease(scratch);scratch=NULL;}}
static SecIdentityRef load_identity(const char *p12path, const char *pass, SecKeychainRef *out_kc) {
    char kcpath[1024];
    snprintf(kcpath, sizeof(kcpath), "%s/identity-%d.keychain", test_dir, (int)getpid());
    unlink(kcpath);
    SecKeychainRef kc = NULL;
    if (SecKeychainCreate(kcpath, (UInt32)strlen("test"), "test", false, NULL, &kc) != errSecSuccess) {
        fprintf(stderr, "could not create scratch keychain\n");
        return NULL;
    }
    *out_kc = kc;

    CFDataRef blob = NULL;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)p12path,
                                                          (CFIndex)strlen(p12path), false);
    SInt32 err = 0;
    CFURLCreateDataAndPropertiesFromResource(NULL, url, &blob, NULL, NULL, &err);
    CFRelease(url);
    if (!blob) { fprintf(stderr, "could not read %s\n", p12path); return NULL; }

    CFStringRef pw = CFStringCreateWithCString(NULL, pass, kCFStringEncodingUTF8);
    const void *k[] = { kSecImportExportPassphrase, kSecImportExportKeychain };
    const void *v[] = { pw, kc };
    CFDictionaryRef opts = CFDictionaryCreate(NULL, k, v, 2, &kCFTypeDictionaryKeyCallBacks,
                                              &kCFTypeDictionaryValueCallBacks);
    CFArrayRef items = NULL;
    OSStatus st = SecPKCS12Import(blob, opts, &items);
    CFRelease(opts); CFRelease(pw); CFRelease(blob);
    if (st != errSecSuccess || !items || CFArrayGetCount(items) < 1) {
        fprintf(stderr, "SecPKCS12Import failed: %d\n", (int)st);
        return NULL;
    }
    CFDictionaryRef item = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef ident = (SecIdentityRef)CFDictionaryGetValue(item, kSecImportItemIdentity);
    if (ident) CFRetain(ident);
    CFRelease(items);
    return ident;
}

static size_t expected;
static int split;
static void fail(void *x, CFErrorRef e) { (void)x; CFShow(e); exit(2); }
static void request(void *x, Ref r) {
    (void)x; CFRetain(r);
    dispatch_async(dispatch_get_global_queue(0,0), ^{
        CFReadStreamRef b = _CFHTTPServerRequestCopyBodyStream(r);
        if(slow)usleep(250000);
        CFReadStreamOpen(b);
        __block size_t total=0;
        __block CFIndex last=0;
        CFWriteStreamRef pipeWriter=NULL;
        CFReadStreamRef pipeReader=NULL;
        if(archive) {
            CFStreamCreateBoundPair(NULL,&pipeReader,&pipeWriter,128*1024);
            CFReadStreamOpen(pipeReader); CFWriteStreamOpen(pipeWriter);
        }
        dispatch_group_t group=dispatch_group_create();
        dispatch_group_async(group,dispatch_get_global_queue(0,0), ^{
            unsigned char buf[32768];CFIndex n;
            while ((n=CFReadStreamRead(b,buf,sizeof(buf)))>0) {
                for(CFIndex i=0;i<n;i++) if(total+i>=expected || buf[i]!=(archive?archive[total+i]:'x')) { fprintf(stderr,"BAD DATA\n"); exit(3); }
                total+=n;
                if(pipeWriter) {CFIndex off=0;while(off<n){CFIndex k=CFWriteStreamWrite(pipeWriter,buf+off,n-off);if(k<=0)exit(16);off+=k;}}
                if(slow)usleep(1000);
            }
            last=n;
            if(pipeWriter)CFWriteStreamClose(pipeWriter);
        });
        int bom_status=0;
        if(archive) {
            void *lib=dlopen("/System/Library/PrivateFrameworks/Bom.framework/Bom",RTLD_NOW);
            void *(*newCopier)(void)=dlsym(lib,"BOMCopierNew");
            int (*copy)(void*,const char*,const char*,CFDictionaryRef)=dlsym(lib,"BOMCopierCopyWithOptions");
            void (*freeCopier)(void*)=dlsym(lib,"BOMCopierFree");
            if(!newCopier||!copy||!freeCopier)exit(17);
            const void *keys[]={CFSTR("extractCPIO"),CFSTR("inputStream")};
            const void *values[]={kCFBooleanTrue,pipeReader};
            CFDictionaryRef options=CFDictionaryCreate(NULL,keys,values,2,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
            void *copier=newCopier();
            bom_status=copy(copier,NULL,getenv("AQ_TEST_DESTINATION"),options);
            fprintf(stderr,"Native BOM returned=%d HTTP stream status=%ld\n",bom_status,CFReadStreamGetStatus(b));
            if(close_after_copy)CFReadStreamClose(b);
            if(dispatch_group_wait(group,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC))) {fprintf(stderr,"REPRODUCED: BOM finished but producer join stalled\n");exit(20);}
            freeCopier(copier);CFRelease(options);CFRelease(pipeReader);CFRelease(pipeWriter);
        } else dispatch_group_wait(group,DISPATCH_TIME_FOREVER);
        fprintf(stderr,"body EOF total=%lu expected=%lu status=%ld last=%ld\n",total,expected,CFReadStreamGetStatus(b),last);
        // Closing a stream while its read is pending may return either EOF or
        // -1. After successful BOM completion this is intentional cancellation
        // of an unused producer, not a change to the native copy result.
        int consumed_close=archive && close_after_copy && !bom_status && CFReadStreamGetStatus(b)==kCFStreamStatusClosed;
        if(total!=expected || (last<0 && !consumed_close) || bom_status) exit(4);

        CFHTTPMessageRef m=_CFHTTPServerRequestCreateResponseMessage(r,200);
        CFHTTPMessageSetHeaderFieldValue(m,CFSTR("Connection"),CFSTR("close"));
        CFDataRef d=CFDataCreate(NULL,NULL,0);
        Ref response=_CFHTTPServerResponseCreateWithData(r,m,d);
        _CFHTTPServerResponseEnqueue(response);
        CFRelease(response);CFRelease(d);CFRelease(m);CFRelease(b);CFRelease(r);
    });
}
static void accepted(void *x, Ref c) {
    (void)x; Client client={0,NULL,NULL,NULL,NULL}; ConnectionCallbacks cb={1,NULL,fail,request,NULL,NULL};
    _CFHTTPServerConnectionSetClient(c,&client,&cb);
    _CFHTTPServerConnectionSetDispatchQueue(c,dispatch_get_main_queue());
}
static void rawput(int fd,const void *p,size_t n) { const char *b=p; while(n) { ssize_t k=tls ? SSL_write(tls,b,(int)n) : write(fd,b,n); if(k<=0) exit(5); b+=k;n-=k; } }
static void put(int fd,const void *p,size_t n) {
    if(coalesce) {pending=realloc(pending,pending_len+n);if(!pending)exit(15);memcpy(pending+pending_len,p,n);pending_len+=n;}
    else rawput(fd,p,n);
}
int main(int argc,char **argv) {
    test_dir=getenv("AQ_TEST_DIR");if(!test_dir)return 21;atexit(cleanup_identity);
    slow=getenv("AQ_TEST_SLOW")!=NULL;coalesce=getenv("AQ_TEST_COALESCE")!=NULL;

    signal(SIGPIPE,SIG_IGN); use_tls=argc>3; expected=argc>1?strtoul(argv[1],NULL,10):4602084; split=argc>2?atoi(argv[2]):0;
    hold_open=getenv("AQ_TEST_HOLD_OPEN")!=NULL;close_after_copy=getenv("AQ_TEST_CLOSE_AFTER_COPY")!=NULL;
    if(getenv("AQ_TEST_ARCHIVE")) {
        FILE *f=fopen(getenv("AQ_TEST_ARCHIVE"),"rb");if(!f)return 18;
        fseek(f,0,SEEK_END);expected=ftell(f);rewind(f);archive=malloc(expected);
        if(fread(archive,1,expected,f)!=expected)return 19;fclose(f);
    }
    int listener=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a;memset(&a,0,sizeof(a)); a.sin_len=sizeof(a);a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(listener,(void*)&a,sizeof(a)) || listen(listener,1)) return 6;
    socklen_t alen=sizeof(a);getsockname(listener,(void*)&a,&alen);
    int sender=socket(AF_INET,SOCK_STREAM,0);if(connect(sender,(void*)&a,sizeof(a)))return 7;
    int receiver=accept(listener,NULL,NULL);close(listener);
    Client client={0,NULL,NULL,NULL,NULL}; ServerCallbacks cb={1,NULL,fail,accepted,NULL};
    Ref server=_CFHTTPServerCreateWithAcceptedSocket(NULL,&client,&cb,receiver);
    if(!server) return 8;
    if(use_tls) {
        SecKeychainSetUserInteractionAllowed(false);
        SecIdentityRef identity=load_identity(getenv("AQ_TEST_IDENTITY"),"test123",&scratch);
        if(!identity)return 12;
        CFArrayRef chain=CFArrayCreate(NULL,(const void **)&identity,1,&kCFTypeArrayCallBacks);
        extern const CFStringRef _kCFHTTPServerSSLSettings, _kCFHTTPServerServerTrustChain, _kCFHTTPServerRequireClientCertificate;
        extern void _CFHTTPServerSetProperty(Ref,CFStringRef,CFTypeRef);
        const void *keys[]={_kCFHTTPServerServerTrustChain,_kCFHTTPServerRequireClientCertificate};
        const void *vals[]={chain,kCFBooleanFalse};
        CFDictionaryRef settings=CFDictionaryCreate(NULL,keys,vals,2,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        _CFHTTPServerSetProperty(server,_kCFHTTPServerSSLSettings,settings);
        CFRelease(settings); CFRelease(chain); CFRelease(identity);
    }
    if(getenv("AQ_TEST_PAUSE")){fprintf(stderr,"TRACE_READY pid=%d\n",getpid());sleep(20);}
    _CFHTTPServerSetDispatchQueue(server,dispatch_get_main_queue());

    dispatch_async(dispatch_get_global_queue(0,0), ^{
        if(use_tls) {
            SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
            tls=SSL_new(ctx);SSL_set_fd(tls,sender);
            if(SSL_connect(tls)!=1){fprintf(stderr,"TLS handshake failed\n");exit(14);}
            fprintf(stderr,"TLS version=%s\n",SSL_get_version(tls));
        }
        const char *h="POST /Upload HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-cpio\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n";
        put(sender,h,strlen(h)); char data[16384];memset(data,'x',sizeof(data));size_t left=expected;
        while(left) {size_t n=left>sizeof(data)?sizeof(data):left;char h[32];int k=snprintf(h,sizeof(h),"%lx\r\n",n);put(sender,h,k);put(sender,archive?archive+expected-left:(unsigned char *)data,n);put(sender,"\r\n",2);left-=n;}
        const char *end="0\r\n\r\n";
        if(hold_open) { /* Sender awaits response without terminal HTTP chunk. */ } else if(split>0&&split<5) {put(sender,end,split);usleep(20000);put(sender,end+split,5-split);} else put(sender,end,5);
        if(coalesce)rawput(sender,pending,pending_len);
        char answer[1024];ssize_t n=tls ? SSL_read(tls,answer,sizeof(answer)-1) : read(sender,answer,sizeof(answer)-1);
        if(n<=0)exit(9);answer[n]=0;
        if(!strstr(answer,"200 OK")) {fprintf(stderr,"bad response %s\n",answer);exit(10);}
        fprintf(stderr,"PASS split=%d HTTP 200 before socket close\n",split);exit(0);
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC),dispatch_get_main_queue(),^{fprintf(stderr,"TIMEOUT split=%d\n",split);exit(11);});
    dispatch_main();
}
