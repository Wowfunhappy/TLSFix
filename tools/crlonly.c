// Evaluate <host> under exactly ONE revocation policy, chosen on the command line, so a cold
// CRL is not warmed by an earlier row. Reports time and CRL-cache growth.
//
// revprobe and revcheck both run several policies in one process, which is enough for timing
// but hides anything that happens only on the first evaluation of a chain: whichever policy
// runs first does the CRL fetch, and every later row sees it cached. One policy per process
// is what separates them.
//
// What it establishes: no explicit revocation policy fetches a CRL. On github.com, whose
// issuer publishes no CRL distribution point at all, OCSP costs 320 ms, CRL 321 ms and
// OCSP|CRL 340 ms against 540 ms with no revocation policy named -- so that ~1.7x is the
// legacy code path, not revocation data. On hosts whose issuer CRL is not yet cached, only
// the no-policy case fetches it.
//
//   ./crlonly <host> <none|ocsp|crl|both>
//
//   clang -arch x86_64 -mmacosx-version-min=10.9 -framework CoreFoundation \
//       -framework CFNetwork -framework Security -o crlonly tools/crlonly.c
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/time.h>

static double now_ms(void){struct timeval tv;gettimeofday(&tv,NULL);return tv.tv_sec*1000.0+tv.tv_usec/1000.0;}
static int crl_count(void){DIR*d=opendir("/var/db/crls");if(!d)return -1;int n=0;struct dirent*e;
  while((e=readdir(d)))if(strstr(e->d_name,".crl"))n++;closedir(d);return n;}

static CFArrayRef fetch_chain(const char *host){
    char u[512];snprintf(u,sizeof u,"https://%s/",host);
    CFStringRef us=CFStringCreateWithCString(NULL,u,kCFStringEncodingUTF8);
    CFURLRef url=CFURLCreateWithString(NULL,us,NULL);CFRelease(us);if(!url)return NULL;
    CFHTTPMessageRef req=CFHTTPMessageCreateRequest(NULL,CFSTR("GET"),url,kCFHTTPVersion1_1);
    CFReadStreamRef st=CFReadStreamCreateForHTTPRequest(NULL,req);
    CFArrayRef out=NULL;
    if(CFReadStreamOpen(st)){UInt8 b[8192];while(CFReadStreamRead(st,b,sizeof b)>0){}
        SecTrustRef t=(SecTrustRef)CFReadStreamCopyProperty(st,kCFStreamPropertySSLPeerTrust);
        if(t){CFMutableArrayRef a=CFArrayCreateMutable(NULL,0,&kCFTypeArrayCallBacks);
            for(CFIndex i=0,n=SecTrustGetCertificateCount(t);i<n;i++)
                CFArrayAppendValue(a,SecTrustGetCertificateAtIndex(t,i));
            CFRelease(t);out=a;}}
    CFReadStreamClose(st);CFRelease(st);CFRelease(req);CFRelease(url);return out;
}

int main(int argc,char**argv){
    if(argc<3){fprintf(stderr,"usage: crlonly <host> <none|ocsp|crl|both>\n");return 2;}
    const char *host=argv[1],*mode=argv[2];
    CFArrayRef chain=fetch_chain(host);
    if(!chain){printf("no chain\n");return 1;}
    CFStringRef h=CFStringCreateWithCString(NULL,host,kCFStringEncodingUTF8);
    SecPolicyRef ssl=SecPolicyCreateSSL(true,h);CFRelease(h);
    SecTrustRef t=NULL;SecTrustCreateWithCertificates(chain,ssl,&t);
    if(strcmp(mode,"none")){
        CFOptionFlags f = !strcmp(mode,"ocsp") ? kSecRevocationOCSPMethod
                        : !strcmp(mode,"crl")  ? kSecRevocationCRLMethod
                        : kSecRevocationUseAnyAvailableMethod;
        SecPolicyRef rp=SecPolicyCreateRevocation(f);
        if(rp){const void*p[2]={ssl,rp};CFArrayRef a=CFArrayCreate(NULL,p,2,&kCFTypeArrayCallBacks);
               SecTrustSetPolicies(t,a);CFRelease(a);CFRelease(rp);}
    }
    int before=crl_count();
    SecTrustResultType r=kSecTrustResultInvalid;
    double t0=now_ms();SecTrustEvaluate(t,&r);double ms=now_ms()-t0;
    int after=crl_count();
    printf("%-22s policy=%-5s %8.0f ms  result=%d  crl-cache %+d\n",host,mode,ms,(int)r,after-before);
    return 0;
}
