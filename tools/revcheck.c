// Every revocation policy 10.9 offers, against one host, with the verdict for each.
//
// The row that matters is RequirePositiveResponse: it turns "could not determine" into a
// failure, so a chain that passes it has been confirmed unrevoked rather than merely
// not-known-to-be-revoked.
//
// Run against revoked.badssl.com -- a real, unexpired, revoked certificate -- and every row
// says ACCEPTED, require-positive included. That is not because revocation checking is
// broken here: tools/crltest/ shows the platform fetching a CRL and correctly rejecting a
// revoked certificate. It is specific to this issuer.
//
// 10.9 has both mechanisms and uses both. What it does not do is fall back from one to the
// other. Watching the wire during an evaluation:
//
//   leaf WITH an OCSP responder URI (github.com)      -> 30 packets to ocsp.sectigo.com
//   leaf with NO responder URI, only a CRL DP         -> 0 packets, nothing attempted
//     (revoked.badssl.com, Let's Encrypt)
//
// A certificate carrying no OCSP URI gets no revocation processing at all, and the CRL named
// in its own distribution point is never fetched. Not a format problem: that CRL is 37 KB,
// current, lists the serial, and is structurally identical to Amazon's -- same version, same
// ecdsa-with-SHA384, same critical Issuing Distribution Point -- which 10.9 caches happily.
//
// The coverage this leaves is split down the middle, and it is upstream of the OS. Every
// issuer whose CRL 10.9 fetches also publishes OCSP; every issuer that has dropped OCSP
// (Let's Encrypt, Google Trust Services -- between them a large share of the web) is one
// whose CRL it does not fetch. So revocation is checked for traditional CAs and undetermined
// for the modern ones, and no policy available at this layer changes that.
//
//   clang -arch x86_64 -mmacosx-version-min=10.9 -framework CoreFoundation \
//       -framework CFNetwork -framework Security -o revcheck tools/revcheck.c
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <Security/Security.h>
#include <stdio.h>
#include <sys/time.h>

static double now_ms(void){struct timeval tv;gettimeofday(&tv,NULL);return tv.tv_sec*1000.0+tv.tv_usec/1000.0;}

static CFArrayRef fetch_chain(const char *host) {
    char u[512]; snprintf(u,sizeof u,"https://%s/",host);
    CFStringRef us=CFStringCreateWithCString(NULL,u,kCFStringEncodingUTF8);
    CFURLRef url=CFURLCreateWithString(NULL,us,NULL); CFRelease(us);
    if(!url) return NULL;
    CFHTTPMessageRef req=CFHTTPMessageCreateRequest(NULL,CFSTR("GET"),url,kCFHTTPVersion1_1);
    CFReadStreamRef st=CFReadStreamCreateForHTTPRequest(NULL,req);
    CFArrayRef out=NULL;
    if(CFReadStreamOpen(st)){
        UInt8 b[8192]; while(CFReadStreamRead(st,b,sizeof b)>0){}
        SecTrustRef t=(SecTrustRef)CFReadStreamCopyProperty(st,kCFStreamPropertySSLPeerTrust);
        if(t){
            CFMutableArrayRef a=CFArrayCreateMutable(NULL,0,&kCFTypeArrayCallBacks);
            for(CFIndex i=0,n=SecTrustGetCertificateCount(t);i<n;i++)
                CFArrayAppendValue(a,SecTrustGetCertificateAtIndex(t,i));
            CFRelease(t); out=a;
        }
    }
    CFReadStreamClose(st); CFRelease(st); CFRelease(req); CFRelease(url);
    return out;
}

static void run(const char *label, CFArrayRef chain, const char *host, CFOptionFlags rev, int useRev){
    CFStringRef h=CFStringCreateWithCString(NULL,host,kCFStringEncodingUTF8);
    SecPolicyRef ssl=SecPolicyCreateSSL(true,h); CFRelease(h);
    SecTrustRef t=NULL;
    SecTrustCreateWithCertificates(chain,ssl,&t);
    if(useRev){
        SecPolicyRef rp=SecPolicyCreateRevocation(rev);
        if(rp){ const void*p[2]={ssl,rp}; CFArrayRef a=CFArrayCreate(NULL,p,2,&kCFTypeArrayCallBacks);
                SecTrustSetPolicies(t,a); CFRelease(a); CFRelease(rp); }
        else { printf("  %-26s (policy unavailable)\n",label); CFRelease(ssl); CFRelease(t); return; }
    }
    SecTrustResultType r=kSecTrustResultInvalid;
    double t0=now_ms(); SecTrustEvaluate(t,&r); double ms=now_ms()-t0;
    const char *verdict = (r==kSecTrustResultProceed||r==kSecTrustResultUnspecified)?"ACCEPTED":"REJECTED";
    printf("  %-26s %8.0f ms  result=%d  %s\n",label,ms,(int)r,verdict);
    CFRelease(ssl); CFRelease(t);
}

int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"usage: revcheck <host>...\n");return 2;}
    for(int i=1;i<argc;i++){
        CFArrayRef chain=fetch_chain(argv[i]);
        if(!chain){printf("%s: no chain\n",argv[i]);continue;}
        printf("%s (%ld certs)\n",argv[i],(long)CFArrayGetCount(chain));
        run("no revocation policy",  chain,argv[i],0,0);
        run("OCSP",                  chain,argv[i],kSecRevocationOCSPMethod,1);
        run("CRL",                   chain,argv[i],kSecRevocationCRLMethod,1);
        run("OCSP+CRL",              chain,argv[i],kSecRevocationUseAnyAvailableMethod,1);
        run("CRL + require-positive",chain,argv[i],kSecRevocationCRLMethod|kSecRevocationRequirePositiveResponse,1);
        run("any + require-positive",chain,argv[i],kSecRevocationUseAnyAvailableMethod|kSecRevocationRequirePositiveResponse,1);
        CFRelease(chain);
    }
    return 0;
}
