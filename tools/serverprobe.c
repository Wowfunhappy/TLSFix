// mtlsprobe -- a Secure Transport client that presents a client certificate.
//
// This is the shape of a real mTLS app: import a .p12, hand the identity to
// SSLSetCertificate, handshake. Run it once bare and once under
// DYLD_INSERT_LIBRARIES=aquatransport.dylib to compare the stock stack against the engine.
//
// kSSLSessionOptionBreakOnServerAuth is set because that is what CFNetwork does on nearly
// every connection, and because the test CA is not in the system trust store. It also puts
// the interesting path under test: with the break set, the engine must suspend before
// sending the client certificate, hand the server chain to us, and only then continue.
// errSSLPeerAuthCompleted (-9841) is that pause; calling SSLHandshake again resumes.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
//       -o mtlsprobe tools/mtlsprobe.c -framework Security -framework CoreFoundation
//
//   ./mtlsprobe 127.0.0.1 4443 client.p12 test123

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static OSStatus sock_read(SSLConnectionRef c, void *data, size_t *len) {
    int fd = (int)(long)c; size_t want = *len, got = 0;
    while (got < want) {
        ssize_t n = read(fd, (char *)data + got, want - got);
        if (n > 0) { got += n; continue; }
        *len = got;
        return n == 0 ? errSSLClosedGraceful : errSSLWouldBlock;
    }
    *len = got;
    return noErr;
}
static OSStatus sock_write(SSLConnectionRef c, const void *data, size_t *len) {
    int fd = (int)(long)c; size_t want = *len, put = 0;
    while (put < want) {
        ssize_t n = write(fd, (const char *)data + put, want - put);
        if (n > 0) { put += n; continue; }
        *len = put;
        return errSSLWouldBlock;
    }
    *len = put;
    return noErr;
}

// Import into a scratch keychain so the user's own keychain is never touched.
static SecIdentityRef load_identity(const char *p12path, const char *pass, SecKeychainRef *out_kc) {
    char kcpath[1024];
    snprintf(kcpath, sizeof(kcpath), "/tmp/aqserver-%d.keychain", (int)getpid());
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

int main(int argc,char **argv) {
    if(argc!=4 && argc!=5) { fprintf(stderr,"usage: serverprobe port identity.p12 password\n"); return 2; }
    SecKeychainSetUserInteractionAllowed(false);
    SecKeychainRef keychain=NULL; SecIdentityRef identity=load_identity(argv[2],argv[3],&keychain);
    int result=1,listener=-1,client=-1; SSLContextRef context=NULL;
    if(!identity) goto done;
    listener=socket(AF_INET,SOCK_STREAM,0); if(listener<0) goto done;
    int one=1; setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    struct sockaddr_in address; memset(&address,0,sizeof(address)); address.sin_len=sizeof(address); address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(atoi(argv[1]));
    if(bind(listener,(struct sockaddr *)&address,sizeof(address)) || listen(listener,1)) goto done;
    puts("READY"); fflush(stdout);
    client=accept(listener,NULL,NULL); if(client<0) goto done;
    struct timeval timeout={10,0}; setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)); setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)); setsockopt(client,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    if(SSLNewContext(true,&context)!=noErr) goto done;
    SSLSetIOFuncs(context,sock_read,sock_write); SSLSetConnection(context,(SSLConnectionRef)(long)client);
    CFArrayRef certificates=CFArrayCreate(NULL,(const void **)&identity,1,&kCFTypeArrayCallBacks);
    OSStatus status=SSLSetCertificate(context,certificates); CFRelease(certificates);
    if(status!=noErr) goto done;
    SSLSetClientSideAuthenticate(context,argc==5 ? kAlwaysAuthenticate : kNeverAuthenticate);
    do { status=SSLHandshake(context); } while(status==errSSLWouldBlock);
    if(status!=noErr) { printf("FAIL: handshake %d\n",(int)status); goto done; }
    size_t received=0; char bytes[4]; status=SSLRead(context,bytes,sizeof(bytes),&received);
    if(status!=noErr || received!=4 || (memcmp(bytes,"ping",4) && memcmp(bytes,"GET ",4))) { printf("FAIL: read %d %lu\n",(int)status,(unsigned long)received); goto done; }
    const char *response=!memcmp(bytes,"GET ",4) ? "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK" : "pong";
    size_t written=0; status=SSLWrite(context,response,strlen(response),&written);
    if(status!=noErr || written!=strlen(response)) goto done;
    puts("PASS: native SecureTransport server API exchanged authenticated TLS data"); result=0;
done:
    if(context) { SSLClose(context); SSLDisposeContext(context); }
    if(client>=0) close(client); if(listener>=0) close(listener);
    if(identity) CFRelease(identity);
    if(keychain) { SecKeychainDelete(keychain); CFRelease(keychain); }
    return result;
}
