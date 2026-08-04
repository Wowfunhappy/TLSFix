// Does 10.9 actually REJECT a certificate its CRL says is revoked?
//
// It does, and only when no explicit revocation policy is named. Run via make.sh, which
// builds a private CA, issues a good leaf and a revoked one, and publishes the CRL locally:
//
//   good     SSL policy alone   ACCEPTED
//   REVOKED  SSL policy alone   REJECTED, and the CRL is fetched
//   REVOKED  explicit CRL       ACCEPTED
//   REVOKED  explicit OCSP|CRL  ACCEPTED
//   REVOKED  explicit OCSP      ACCEPTED
//
// That is why the engine builds its trusts with the SSL policy alone: naming any revocation
// policy is faster (see tools/crlonly.c) but switches the check off, including one that
// names kSecRevocationCRLMethod.
//
// Everything here is local and nothing is installed. The test CA is made an anchor with
// SecTrustSetAnchorCertificates + SecTrustSetAnchorCertificatesOnly, which applies to this
// one SecTrustRef inside this one process; the system trust store and every keychain are
// untouched. The CRL is served from a local HTTP server named by the leaf's CRL
// distribution point, so a fetch is visible in that server's log.
//
//   ./crltest <leaf.der> <ca.der> <none|ocsp|crl|both>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

static double now_ms(void){struct timeval tv;gettimeofday(&tv,NULL);return tv.tv_sec*1000.0+tv.tv_usec/1000.0;}

static SecCertificateRef load(const char *p){
    FILE *f=fopen(p,"rb"); if(!f) return NULL;
    unsigned char b[65536]; size_t n=fread(b,1,sizeof b,f); fclose(f);
    CFDataRef d=CFDataCreate(NULL,b,n);
    SecCertificateRef c=SecCertificateCreateWithData(NULL,d);
    CFRelease(d); return c;
}

static const char *name_of(SecTrustResultType r){
    switch(r){
      case kSecTrustResultProceed: return "Proceed";
      case kSecTrustResultDeny: return "Deny";
      case kSecTrustResultUnspecified: return "Unspecified";
      case kSecTrustResultRecoverableTrustFailure: return "RecoverableTrustFailure";
      case kSecTrustResultFatalTrustFailure: return "FatalTrustFailure";
      case kSecTrustResultOtherError: return "OtherError";
      default: return "Invalid";
    }
}

int main(int argc,char**argv){
    if(argc<4){fprintf(stderr,"usage: crltest <leaf.der> <ca.der> <none|ocsp|crl|both>\n");return 2;}
    SecCertificateRef leaf=load(argv[1]), ca=load(argv[2]);
    if(!leaf||!ca){fprintf(stderr,"could not load certs\n");return 1;}

    const void *chain[2]={leaf,ca};
    CFArrayRef certs=CFArrayCreate(NULL,chain,2,&kCFTypeArrayCallBacks);
    CFArrayRef anchors=CFArrayCreate(NULL,(const void**)&ca,1,&kCFTypeArrayCallBacks);

    CFStringRef host=CFStringCreateWithCString(NULL,"crltest.local",kCFStringEncodingUTF8);
    SecPolicyRef ssl=SecPolicyCreateSSL(true,host); CFRelease(host);

    SecTrustRef t=NULL;
    SecTrustCreateWithCertificates(certs,ssl,&t);
    // Trust the test CA for THIS evaluation only. Nothing is added to any keychain.
    SecTrustSetAnchorCertificates(t,anchors);
    SecTrustSetAnchorCertificatesOnly(t,true);

    const char *mode=argv[3];
    if(strcmp(mode,"none")){
        CFOptionFlags f = !strcmp(mode,"ocsp") ? kSecRevocationOCSPMethod
                        : !strcmp(mode,"crl")  ? kSecRevocationCRLMethod
                        : kSecRevocationUseAnyAvailableMethod;
        SecPolicyRef rp=SecPolicyCreateRevocation(f);
        if(rp){const void*p[2]={ssl,rp};CFArrayRef a=CFArrayCreate(NULL,p,2,&kCFTypeArrayCallBacks);
               SecTrustSetPolicies(t,a);
               SecTrustSetAnchorCertificates(t,anchors);
               SecTrustSetAnchorCertificatesOnly(t,true);
               CFRelease(a);CFRelease(rp);}
        else printf("  (SecPolicyCreateRevocation unavailable)\n");
    }

    SecTrustResultType r=kSecTrustResultInvalid;
    double t0=now_ms(); OSStatus st=SecTrustEvaluate(t,&r); double ms=now_ms()-t0;
    int accepted=(r==kSecTrustResultProceed||r==kSecTrustResultUnspecified);
    printf("  %-8s policy=%-5s %7.0f ms  result=%-24s %s\n",
           strstr(argv[1],"revoked")?"REVOKED":"good", mode, ms, name_of(r),
           accepted?"ACCEPTED":"*** REJECTED ***");
    (void)st;
    return 0;
}
