/* Offline end-to-end tests. The catch-all NSURLProtocol ensures no request reaches
 * a socket; every credential, anisette value and server key below is synthetic. */
#import <Foundation/Foundation.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <assert.h>
#include <zlib.h>
#include <openssl/bn.h>
#include <openssl/srp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

static NSString *mode;
static int unexpected, anisetteCalls, initCalls, completeCalls, accountCalls, codeCalls;
static NSData *serverB, *serverKey, *serverProof;
static BOOL verified;
static BOOL fixture(NSString *name) { return [mode isEqual:name] || [mode isEqual:[@"ids-" stringByAppendingString:name]]; }
static BOOL opaqueSettings(void) { return [mode hasSuffix:@"-opaque"]; }
static NSString *settingsAuth(void) {
    return opaqueSettings() ? @"Basic MTIzNDU6b3BhcXVlLWZpeHR1cmU=" : @"Basic MTIzNDU6RS1maXh0dXJlLW1tZQ==";
}

static NSString *expectedClient(void) {
    return ([mode isEqual:@"old-client"] || [mode isEqual:@"missing-client"]) ?
        @"<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>" :
        @"<fixture-device> <fixture-os> <fixture-client>";
}

static NSData *plist(id obj) { return [NSPropertyListSerialization dataWithPropertyList:obj format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL]; }
static id parse(NSData *d) { return [NSPropertyListSerialization propertyListWithData:d options:0 format:NULL error:NULL]; }
static NSData *hash(NSData *data) { unsigned char h[32]; SHA256([data bytes], [data length], h); return [NSData dataWithBytes:h length:32]; }
static NSData *cat(NSArray *parts) { NSMutableData *out = [NSMutableData data]; for (NSData *p in parts) [out appendData:p]; return out; }
static NSData *bytes(NSString *s) { return [s dataUsingEncoding:NSUTF8StringEncoding]; }
static NSData *gzip(NSData *data) {
    z_stream stream; memset(&stream, 0, sizeof stream);
    assert(deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16+MAX_WBITS, 8, Z_DEFAULT_STRATEGY) == Z_OK);
    NSMutableData *out = [NSMutableData dataWithLength:deflateBound(&stream, (uLong)[data length])];
    stream.next_in = (Bytef *)[data bytes]; stream.avail_in = (uInt)[data length];
    stream.next_out = [out mutableBytes]; stream.avail_out = (uInt)[out length];
    assert(deflate(&stream, Z_FINISH) == Z_STREAM_END);
    [out setLength:stream.total_out]; deflateEnd(&stream); return out;
}
static NSData *bnbytes(const BIGNUM *b, BOOL pad) {
    unsigned char buf[256]; int n = pad ? BN_bn2binpad(b, buf, 256) : BN_bn2bin(b, buf);
    return [NSData dataWithBytes:buf length:n];
}
static BIGNUM *number(NSData *d) { return BN_bin2bn([d bytes], (int)[d length], NULL); }
static void server_start(NSData *clientA) {
    const SRP_gN *gn = SRP_get_default_gN("2048"); BN_CTX *ctx = BN_CTX_new();
    BIGNUM *A = number(clientA), *b = BN_new(), *v = BN_new(), *B = BN_new(), *tmp = BN_new(), *S = BN_new();
    BN_set_word(b, 1234567);
    unsigned char derived[32]; NSData *password = hash(bytes(@"Synthetic:PassWord"));
    PKCS5_PBKDF2_HMAC([password bytes], 32, (unsigned char *)"ordinarysalt1234", 16, 5, EVP_sha256(), 32, derived);
    NSData *inner = hash(cat([NSArray arrayWithObjects:bytes(@":"), [NSData dataWithBytes:derived length:32], nil]));
    BIGNUM *x = number(hash(cat([NSArray arrayWithObjects:bytes(@"ordinarysalt1234"), inner, nil])));
    BIGNUM *k = number(hash(cat([NSArray arrayWithObjects:bnbytes(gn->N, YES), bnbytes(gn->g, YES), nil])));
    BN_mod_exp(v, gn->g, x, gn->N, ctx); BN_mod_exp(B, gn->g, b, gn->N, ctx);
    BN_mod_mul(tmp, k, v, gn->N, ctx); BN_mod_add(B, B, tmp, gn->N, ctx);
    BIGNUM *u = number(hash(cat([NSArray arrayWithObjects:bnbytes(A, YES), bnbytes(B, YES), nil])));
    BN_mod_exp(tmp, v, u, gn->N, ctx); BN_mod_mul(tmp, A, tmp, gn->N, ctx); BN_mod_exp(S, tmp, b, gn->N, ctx);
    [serverB release]; serverB = [bnbytes(B, YES) retain];
    [serverKey release]; serverKey = [hash(bnbytes(S, YES)) retain];
    NSData *hn = hash(bnbytes(gn->N, YES)), *hg = hash(bnbytes(gn->g, YES)); unsigned char xor[32];
    for (int i = 0; i < 32; i++) xor[i] = ((unsigned char *)[hn bytes])[i] ^ ((unsigned char *)[hg bytes])[i];
    NSData *m = hash(cat([NSArray arrayWithObjects:[NSData dataWithBytes:xor length:32], hash(bytes(@"test@example.invalid")),
        bytes(@"ordinarysalt1234"), bnbytes(A, YES), bnbytes(B, YES), serverKey, nil]));
    [serverProof release]; serverProof = [cat([NSArray arrayWithObjects:m,
        hash(cat([NSArray arrayWithObjects:bnbytes(A, YES), m, serverKey, nil])), nil]) retain];
    BN_free(A); BN_free(b); BN_free(v); BN_free(B); BN_free(tmp); BN_free(S); BN_free(x); BN_free(k); BN_free(u); BN_CTX_free(ctx);
}
static NSData *encrypted_session(void) {
    NSDictionary *session = [NSDictionary dictionaryWithObjectsAndKeys:@"12345", @"adsid", @"fake-idms", @"GsIdmsToken",
        [NSDictionary dictionaryWithObject:[NSDictionary dictionaryWithObject:@"fake-pet" forKey:@"token"] forKey:@"com.apple.gs.idms.pet"], @"t", nil];
    NSData *plain = plist(session); unsigned char aes[32], iv[32]; unsigned int len;
    HMAC(EVP_sha256(), [serverKey bytes], 32, (unsigned char *)"extra data key:", 15, aes, &len);
    HMAC(EVP_sha256(), [serverKey bytes], 32, (unsigned char *)"extra data iv:", 14, iv, &len);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); NSMutableData *out = [NSMutableData dataWithLength:[plain length]+16]; int a,b;
    assert(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes, iv));
    assert(EVP_EncryptUpdate(ctx, [out mutableBytes], &a, [plain bytes], (int)[plain length]));
    assert(EVP_EncryptFinal_ex(ctx, (unsigned char *)[out mutableBytes]+a, &b));
    [out setLength:a+b]; EVP_CIPHER_CTX_free(ctx); return out;
}

@interface AQMock : NSURLProtocol @end
@implementation AQMock
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading {
    NSURLRequest *req = [self request]; NSString *host = [[req URL] host], *path = [[req URL] path];
    NSData *data = nil; NSDictionary *result = nil; int status = 200;
    if (fixture(@"disabled")) {
        assert(![NSURLProtocol propertyForKey:@"AquaTransportGSAHandled" inRequest:req]);
        assert([[[parse([req HTTPBody]) objectForKey:@"password"] description] isEqual:@"Synthetic:PassWord"]);
        NSHTTPURLResponse *r = [[[NSHTTPURLResponse alloc] initWithURL:[req URL] statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
        [[self client] URLProtocol:self didReceiveResponse:r cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        [[self client] URLProtocol:self didLoadData:plist([NSDictionary dictionaryWithObject:@"native" forKey:@"fixture"])];
        [[self client] URLProtocolDidFinishLoading:self]; return;
    }
    assert([NSURLProtocol propertyForKey:@"AquaTransportGSAHandled" inRequest:req]);
    assert(![req HTTPShouldHandleCookies]);
    if ([host isEqual:@"127.0.0.1"]) {
        anisetteCalls++;
        assert(![req valueForHTTPHeaderField:@"Authorization"] && ![req HTTPBody]);
        NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithObjectsAndKeys:@"fake-otp", @"X-Apple-I-MD", @"fake-machine", @"X-Apple-I-MD-M",
            @"fake-local", @"X-Apple-I-MD-LU", @"84215040", @"X-Apple-I-MD-RINFO", @"fake-device", @"X-Mme-Device-Id",
            @"<fixture-device> <fixture-os> <fixture-client>", @"X-MMe-Client-Info", @"MUST-NOT-BE-FORWARDED", @"Authorization", nil];
        if ([mode isEqual:@"old-client"]) [headers setObject:@"<fixture> <com.apple.dt.Xcode/3594.4.19>" forKey:@"X-MMe-Client-Info"];
        if ([mode isEqual:@"missing-client"]) [headers removeObjectForKey:@"X-MMe-Client-Info"];
        data = [NSJSONSerialization dataWithJSONObject:headers options:0 error:NULL];
        if (fixture(@"missing-anisette") || [mode isEqual:@"settings-missing"]) data = bytes(@"{}");
    } else if ([host isEqual:@"gsa.apple.com"] && [path isEqual:@"/grandslam/GsService2"]) {
        assert(![req valueForHTTPHeaderField:@"Authorization"]);
        assert(![req valueForHTTPHeaderField:@"X-Apple-I-MD"]);
        assert([[req valueForHTTPHeaderField:@"Accept"] isEqual:@"*/*"]);
        NSDictionary *payload = [parse([req HTTPBody]) objectForKey:@"Request"];
        assert([[payload objectForKey:@"u"] isEqual:@"test@example.invalid"]);
        assert([[[payload objectForKey:@"cpd"] objectForKey:@"X-Apple-I-MD"] isEqual:@"fake-otp"]);
        assert(![[payload objectForKey:@"cpd"] objectForKey:@"Authorization"]);
        NSDictionary *cpd = [payload objectForKey:@"cpd"];
        assert([[cpd objectForKey:@"svct"] isEqual:@"iCloud"] && [[cpd objectForKey:@"prkgen"] boolValue]);
        assert([[cpd objectForKey:@"X-MMe-Client-Info"] isEqual:expectedClient()]);
        assert([[req valueForHTTPHeaderField:@"X-Mme-Client-Info"] isEqual:[cpd objectForKey:@"X-MMe-Client-Info"]]);
        if ([[payload objectForKey:@"o"] isEqual:@"init"]) {
            initCalls++; server_start([payload objectForKey:@"A2k"]);
            result = [NSDictionary dictionaryWithObjectsAndKeys:@"s2k", @"sp", @5, @"i", bytes(@"ordinarysalt1234"), @"s",
                [mode isEqual:@"malformed"] ? bytes(@"oversized-invalid") : serverB, @"B", @"continuation", @"c", nil];
            if ([mode isEqual:@"malformed"]) result = [NSDictionary dictionaryWithObject:@"invalid" forKey:@"s"];
        } else {
            completeCalls++;
            assert([[payload objectForKey:@"M1"] isEqual:[serverProof subdataWithRange:NSMakeRange(0,32)]]);
            NSMutableData *m2 = [[[serverProof subdataWithRange:NSMakeRange(32,32)] mutableCopy] autorelease];
            if (fixture(@"bad-proof")) ((unsigned char *)[m2 mutableBytes])[0] ^= 1;
            if ([mode isEqual:@"short-proof"]) [m2 setLength:1];
            result = [NSDictionary dictionaryWithObjectsAndKeys:m2, @"M2", encrypted_session(), @"spd", nil];
        }
        NSMutableDictionary *r = [[result mutableCopy] autorelease];
        NSMutableDictionary *s = [NSMutableDictionary dictionaryWithObjectsAndKeys:@0, @"ec", @200, @"hsc", nil];
        if (completeCalls && fixture(@"2fa") && !verified) { [s setObject:@"trustedDeviceSecondaryAuth" forKey:@"au"]; [s setObject:@409 forKey:@"hsc"]; }
        [r setObject:s forKey:@"Status"]; result = [NSDictionary dictionaryWithObject:r forKey:@"Response"];
    } else if ([host isEqual:@"gsa.apple.com"] && [path isEqual:@"/auth/verify/trusteddevice"]) {
        codeCalls++; assert([req valueForHTTPHeaderField:@"X-Apple-Identity-Token"]);
        result = [NSDictionary dictionary];
    } else if ([host isEqual:@"gsa.apple.com"] && [path isEqual:@"/grandslam/GsService2/validate"]) {
        codeCalls++; assert([[req valueForHTTPHeaderField:@"security-code"] isEqual:@"123456"]); verified = YES;
        result = [NSDictionary dictionaryWithObject:[NSDictionary dictionaryWithObject:@0 forKey:@"ec"] forKey:@"Status"];
    } else if ([host isEqual:@"setup.icloud.com"] && [path isEqual:@"/setup/iosbuddy/loginDelegates"]) {
        accountCalls++;
        NSDictionary *body = parse([req HTTPBody]);
        assert([[body objectForKey:@"apple-id"] isEqual:@"test@example.invalid"]);
        assert([[body objectForKey:@"password"] isEqual:@"fake-pet"]);
        assert([[body objectForKey:@"client-id"] isEqual:@"fake-device"]);
        NSDictionary *delegates = [body objectForKey:@"delegates"];
        assert([delegates count] == 1 && [[delegates objectForKey:@"com.apple.madrid"] isKindOfClass:[NSDictionary class]]);
        assert([[req valueForHTTPHeaderField:@"Authorization"] isEqual:@"Basic dGVzdEBleGFtcGxlLmludmFsaWQ6ZmFrZS1wZXQ="]);
        assert([[req valueForHTTPHeaderField:@"X-Apple-I-MD"] isEqual:@"fake-otp"]);
        assert([[req valueForHTTPHeaderField:@"X-Apple-I-MD-M"] isEqual:@"fake-machine"]);
        assert([[req valueForHTTPHeaderField:@"X-Apple-ADSID"] isEqual:@"12345"]);
        assert(![req valueForHTTPHeaderField:@"Content-Encoding"]);
        NSMutableDictionary *service = [NSMutableDictionary dictionaryWithObjectsAndKeys:
            @"D:12345", @"profile-id", @"fixture-ids-token", @"auth-token", nil];
        if (fixture(@"missing-token")) [service removeObjectForKey:@"auth-token"];
        if (fixture(@"missing-profile")) [service removeObjectForKey:@"profile-id"];
        id delegateStatus = fixture(@"bad-delegate") ? (id)@5000 : fixture(@"bad-status-type") ? (id)@"0" : (id)@0;
        NSDictionary *delegate = [NSDictionary dictionaryWithObjectsAndKeys:delegateStatus, @"status", service, @"service-data", nil];
        result = [NSDictionary dictionaryWithObjectsAndKeys:fixture(@"rejected") ? @5068 : @0, @"status",
            [NSDictionary dictionaryWithObject:delegate forKey:@"com.apple.madrid"], @"delegates", nil];
    } else if ([host isEqual:@"setup.icloud.com"] && [path hasPrefix:@"/setup/authenticate/"]) {
        accountCalls++;
        assert([[req valueForHTTPHeaderField:@"Authorization"] isEqual:@"Basic dGVzdEBleGFtcGxlLmludmFsaWQ6ZmFrZS1wZXQ="]);
        result = [NSDictionary dictionaryWithObjectsAndKeys:[NSDictionary dictionaryWithObject:@"12345" forKey:@"dsid"], @"appleAccountInfo",
            [NSDictionary dictionaryWithObject:@"fake-mme" forKey:@"mmeAuthToken"], @"tokens", nil];
    } else if ([host isEqual:@"setup.icloud.com"] && [path isEqual:@"/setup/get_account_settings"]) {
        accountCalls++;
        if ([mode rangeOfString:@"settings"].location != NSNotFound) {
            assert([[req valueForHTTPHeaderField:@"Authorization"] isEqual:settingsAuth()]);
            assert([[req valueForHTTPHeaderField:@"X-Apple-I-MD"] isEqual:@"fake-otp"]);
            assert([[req valueForHTTPHeaderField:@"X-Apple-I-MD-M"] isEqual:@"fake-machine"]);
            assert([[req valueForHTTPHeaderField:@"X-Mme-Device-Id"] isEqual:@"fake-device"]);
            assert([[req valueForHTTPHeaderField:@"X-Mme-Client-Info"] isEqual:expectedClient()]);
            assert([[req HTTPMethod] isEqual:@"POST"] && [[req HTTPBody] isEqual:bytes(@"refresh-body-fixture")]);
        } else assert([[req valueForHTTPHeaderField:@"Authorization"] isEqual:@"Basic MTIzNDU6ZmFrZS1tbWU="]);
        result = [NSDictionary dictionaryWithObject:@"ok" forKey:@"fixture"];
    } else { unexpected++; status = 599; result = [NSDictionary dictionary]; }
    if (!data) data = plist(result);
    if (([mode isEqual:@"redirect"] && initCalls) || (([mode isEqual:@"settings-redirect"] || [mode isEqual:@"ids-redirect"]) && accountCalls)) {
        NSHTTPURLResponse *r = [[[NSHTTPURLResponse alloc] initWithURL:[req URL] statusCode:302 HTTPVersion:@"HTTP/1.1"
            headerFields:[NSDictionary dictionaryWithObject:@"https://example.invalid/collect" forKey:@"Location"]] autorelease];
        [[self client] URLProtocol:self wasRedirectedToRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"https://example.invalid/collect"]] redirectResponse:r];
        return;
    }
    NSHTTPURLResponse *r = [[[NSHTTPURLResponse alloc] initWithURL:[req URL] statusCode:status HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
    [[self client] URLProtocol:self didReceiveResponse:r cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [[self client] URLProtocol:self didLoadData:data]; [[self client] URLProtocolDidFinishLoading:self];
}
@end

@interface AQCancelClient : NSObject <NSURLProtocolClient> { @public int callbacks; } @end
@implementation AQCancelClient
- (void)URLProtocol:(NSURLProtocol *)p wasRedirectedToRequest:(NSURLRequest *)r redirectResponse:(NSURLResponse *)s { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p cachedResponseIsValid:(NSCachedURLResponse *)r { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p didReceiveResponse:(NSURLResponse *)r cacheStoragePolicy:(NSURLCacheStoragePolicy)s { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p didLoadData:(NSData *)d { callbacks++; }
- (void)URLProtocolDidFinishLoading:(NSURLProtocol *)p { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p didFailWithError:(NSError *)e { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)c { callbacks++; }
- (void)URLProtocol:(NSURLProtocol *)p didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)c { callbacks++; }
@end

static NSMutableURLRequest *login(NSString *password) {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://setup.icloud.com/setup/login_or_create_account"]];
    [req setHTTPMethod:@"POST"];
    [req setHTTPBody:plist([NSDictionary dictionaryWithObjectsAndKeys:@"test@example.invalid", @"username", password, @"password", nil])];
    return req;
}
static NSMutableURLRequest *settings(void) {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://setup.icloud.com/setup/get_account_settings"]];
    [req setHTTPMethod:@"POST"]; [req setHTTPBody:bytes(@"refresh-body-fixture")];
    [req setValue:settingsAuth() forHTTPHeaderField:@"Authorization"];
    return req;
}
static NSMutableURLRequest *idsLogin(NSString *password) {
    NSMutableURLRequest *req = login(password);
    [req setURL:[NSURL URLWithString:@"https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser"]];
    [req setValue:@"application/x-apple-plist" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"fixture-client-id" forHTTPHeaderField:@"x-ds-client-id"];
    [req setValue:@"7" forHTTPHeaderField:@"x-protocol-version"];
    if (fixture(@"gzip") || fixture(@"2fa") || fixture(@"bad-gzip") || fixture(@"gzip-limit") || fixture(@"gzip-trailing")) {
        NSData *plain = fixture(@"gzip-limit") ? [NSMutableData dataWithLength:1024*1024+1] : [req HTTPBody];
        NSMutableData *compressed = [[gzip(plain) mutableCopy] autorelease];
        if (fixture(@"bad-gzip")) [compressed setLength:[compressed length]-4];
        if (fixture(@"gzip-trailing")) [compressed appendData:bytes(@"trailing")];
        [req setHTTPBody:compressed]; [req setValue:@"gzip" forHTTPHeaderField:@"Content-Encoding"];
    }
    return req;
}
int main(int argc, char **argv) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new]; mode = argc > 1 ? [NSString stringWithUTF8String:argv[1]] : @"success";
#if __OBJC_GC__
    assert([NSGarbageCollector defaultCollector] != nil);
#endif
    [NSURLProtocol registerClass:[AQMock class]];
    if ([mode hasPrefix:@"ids-"]) {
        NSURLResponse *response = nil; NSError *error = nil;
        NSData *data = [NSURLConnection sendSynchronousRequest:idsLogin(@"Synthetic:PassWord") returningResponse:&response error:&error];
        if (fixture(@"disabled")) {
            assert(!error && [[parse(data) objectForKey:@"fixture"] isEqual:@"native"]);
            assert(anisetteCalls == 0 && initCalls == 0 && NSClassFromString(@"AQGSAProtocol") == Nil);
        } else if (fixture(@"bad-gzip") || fixture(@"gzip-limit") || fixture(@"gzip-trailing")) {
            assert(error && !anisetteCalls && !initCalls && !accountCalls);
        } else if (fixture(@"bad-proof") || fixture(@"missing-anisette") || fixture(@"redirect")) {
            assert(error && accountCalls == (fixture(@"redirect") ? 1 : 0));
        } else if (fixture(@"rejected") || fixture(@"bad-delegate") || fixture(@"missing-token") || fixture(@"missing-profile") || fixture(@"bad-status-type")) {
            assert(error && accountCalls == 1 && !data);
        } else {
            if (fixture(@"2fa")) {
                assert(!error && [[parse(data) objectForKey:@"status"] integerValue] == 5000 && codeCalls == 1 && !accountCalls);
                response = nil; error = nil;
                data = [NSURLConnection sendSynchronousRequest:idsLogin(@"Synthetic:PassWord123456") returningResponse:&response error:&error];
                assert(verified && codeCalls == 2);
            }
            assert(!error && [(NSHTTPURLResponse *)response statusCode] == 200 && accountCalls == 1);
            NSDictionary *body = parse(data);
            assert([[body objectForKey:@"status"] integerValue] == 0);
            assert([[body objectForKey:@"auth-token"] isEqual:@"fixture-ids-token"] && [[body objectForKey:@"profile-id"] isEqual:@"D:12345"]);
            Class protocol = NSClassFromString(@"AQGSAProtocol"); assert(protocol);
            for (NSString *url in [NSArray arrayWithObjects:
                @"http://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser",
                @"https://profile.ess.apple.com.example.invalid/WebObjects/VCProfileService.woa/wa/authenticateUser",
                @"https://profile.ess.apple.com:444/WebObjects/VCProfileService.woa/wa/authenticateUser",
                @"https://user@profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser",
                @"https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser?extra=1",
                @"https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/getHandles", nil]) {
                NSMutableURLRequest *r = idsLogin(@"Synthetic:PassWord"); [r setURL:[NSURL URLWithString:url]];
                assert(![protocol canInitWithRequest:r]);
            }
            NSMutableURLRequest *r = idsLogin(@"Synthetic:PassWord");
            [r setURL:[NSURL URLWithString:@"https://service.ess.apple.com:443/WebObjects/VCProfileService.woa/wa/authenticateUser"]];
            assert([protocol canInitWithRequest:r]);
            [r setHTTPMethod:@"GET"]; assert(![protocol canInitWithRequest:r]);
        }
        assert(!unexpected);
        printf("PASS: offline %s through iMessage profile authentication\n", [mode UTF8String]);
        [pool drain]; return 0;
    }
    if ([mode hasPrefix:@"settings"]) {
        NSURLResponse *response = nil; NSError *error = nil;
        NSData *data = [NSURLConnection sendSynchronousRequest:settings() returningResponse:&response error:&error];
        assert(initCalls == 0 && completeCalls == 0 && codeCalls == 0 && unexpected == 0 && anisetteCalls == 1);
        if ([mode isEqual:@"settings"] || [mode isEqual:@"settings-opaque"]) {
            assert(!error && [(NSHTTPURLResponse *)response statusCode] == 200 && accountCalls == 1);
            assert([[parse(data) objectForKey:@"fixture"] isEqual:@"ok"]);
            Class protocol = NSClassFromString(@"AQGSAProtocol"); assert(protocol);
            NSMutableURLRequest *legacy = settings();
            [legacy setValue:@"Basic MTIzNDU6ZmFrZS1tbWU=" forHTTPHeaderField:@"Authorization"];
            assert([protocol canInitWithRequest:legacy]);
            // Token spelling is opaque; email/password and empty credentials
            // still must not enter the saved-account refresh path.
            [legacy setValue:@"Basic dGVzdEBleGFtcGxlLmludmFsaWQ6ZmFrZS1tbWU=" forHTTPHeaderField:@"Authorization"];
            assert(![protocol canInitWithRequest:legacy]);
            [legacy setValue:@"Basic MTIzNDU6" forHTTPHeaderField:@"Authorization"];
            assert(![protocol canInitWithRequest:legacy]);
            NSMutableURLRequest *foreign = settings();
            [foreign setURL:[NSURL URLWithString:@"https://setup.icloud.com.example.invalid/setup/get_account_settings"]];
            assert(![protocol canInitWithRequest:foreign]);
        } else assert(error && accountCalls == ([mode isEqual:@"settings-redirect"] ? 1 : 0));
        printf("PASS: offline %s without password authentication\n", [mode UTF8String]);
        [pool drain]; return 0;
    }
    if ([mode isEqual:@"aos"] || [mode isEqual:@"aos-basic"] || [mode isEqual:@"aos-mixed"] || [mode hasPrefix:@"aos-settings"]) {
        BOOL refresh = [mode hasPrefix:@"aos-settings"];
        BOOL basic = ![mode isEqual:@"aos"];
        assert(dlopen("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit", RTLD_LAZY | RTLD_LOCAL));
        Class cls = NSClassFromString(@"AOSRequest"); assert(cls);
        id request = ((id(*)(id,SEL,id,id,id,id))objc_msgSend)([cls alloc],
            NSSelectorFromString(@"initWithMessage:usingMethod:headers:url:"), refresh ? [settings() HTTPBody] : basic ? nil : [login(@"Synthetic:PassWord") HTTPBody],
            @"POST", [NSDictionary dictionary], refresh ? [settings() URL] : [login(@"Synthetic:PassWord") URL]);
        assert(request);
        if (basic) {
            ((void(*)(id,SEL,id,id))objc_msgSend)(request, NSSelectorFromString(@"setUsername:andPassword:"),
                refresh ? @"12345" : [mode isEqual:@"aos-mixed"] ? @"TeSt@Example.Invalid" : @"test@example.invalid",
                refresh ? (opaqueSettings() ? @"opaque-fixture" : @"E-fixture-mme") : @"Synthetic:PassWord");
            ((void(*)(id,SEL))objc_msgSend)(request, NSSelectorFromString(@"addBasicAuth"));
        }
        ((void(*)(id,SEL))objc_msgSend)(request, NSSelectorFromString(@"sendSynchronously"));
        int status = ((int(*)(id,SEL))objc_msgSend)(request, NSSelectorFromString(@"httpStatusCode"));
        NSData *data = ((id(*)(id,SEL))objc_msgSend)(request, NSSelectorFromString(@"responseData"));
        assert(status == 200 && [[parse(data) objectForKey:@"fixture"] isEqual:@"ok"]);
        assert(accountCalls == (refresh ? 1 : 2) && unexpected == 0);
        if (refresh) assert(initCalls == 0 && completeCalls == 0 && codeCalls == 0);
        [request release];
        puts("PASS: offline sign-in via native AOSRequest / CFURLConnection"); [pool drain]; return 0;
    }
    NSURLResponse *response = nil; NSError *error = nil;
    NSData *data = [NSURLConnection sendSynchronousRequest:login(@"Synthetic:PassWord") returningResponse:&response error:&error];
    if ([mode isEqual:@"disabled"]) {
        assert(!error && [[parse(data) objectForKey:@"fixture"] isEqual:@"native"]);
        assert(anisetteCalls == 0 && initCalls == 0 && NSClassFromString(@"AQGSAProtocol") == Nil);
        puts("PASS: disable-icloud-gsa preserves native requests and leaves the module unloaded");
        [pool drain]; return 0;
    }
    if ([mode isEqual:@"2fa"]) {
        /* CFNetwork may surface a synthetic 401 as NSURLErrorUserCancelledAuthentication. */
        assert(([(NSHTTPURLResponse *)response statusCode] == 401 || [error code] == NSURLErrorUserCancelledAuthentication) && codeCalls == 1 && accountCalls == 0);
        error = nil; response = nil;
        data = [NSURLConnection sendSynchronousRequest:login(@"Synthetic:PassWord123456") returningResponse:&response error:&error];
        assert(verified && codeCalls == 2);
    }
    BOOL success = [mode isEqual:@"success"] || [mode isEqual:@"2fa"] ||
        [mode isEqual:@"old-client"] || [mode isEqual:@"missing-client"];
    if (error) fprintf(stderr, "fixture error: %s (%ld), init=%d complete=%d account=%d\n", [[error localizedDescription] UTF8String], (long)[error code], initCalls, completeCalls, accountCalls);
    if (success) {
        assert(!error && [(NSHTTPURLResponse *)response statusCode] == 200);
        assert([[parse(data) objectForKey:@"fixture"] isEqual:@"ok"] && accountCalls == 2);
        Class protocol = NSClassFromString(@"AQGSAProtocol"); assert(protocol);
        for (NSString *url in [NSArray arrayWithObjects:@"http://setup.icloud.com/setup/login_or_create_account",
            @"https://setup.icloud.com.example.invalid/setup/login_or_create_account", @"https://setup.icloud.com:444/setup/login_or_create_account",
            @"https://setup.icloud.com/setup/get_account_settings", @"https://setup.icloud.com/unrelated", nil]) {
            NSMutableURLRequest *r = login(@"Synthetic:PassWord"); [r setURL:[NSURL URLWithString:url]];
            assert(![protocol canInitWithRequest:r]);
        }
        NSMutableURLRequest *r = login(@"Synthetic:PassWord");
        [NSURLProtocol setProperty:@YES forKey:@"AquaTransportGSAHandled" inRequest:r];
        assert(![protocol canInitWithRequest:r]);
        r = login(@"Synthetic:PassWord"); [r setHTTPBody:nil];
        [r setValue:@"Basic !!!=" forHTTPHeaderField:@"Authorization"];
        assert(![protocol canInitWithRequest:r]);
        AQCancelClient *client = [AQCancelClient new];
        NSURLProtocol *cancel = [[protocol alloc] initWithRequest:login(@"Synthetic:PassWord") cachedResponse:nil client:client];
        [cancel startLoading]; [cancel stopLoading];
        NSDate *limit = [NSDate dateWithTimeIntervalSinceNow:0.2];
        while ([limit timeIntervalSinceNow] > 0) [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:limit];
        assert(client->callbacks == 0); [cancel release]; [client release];
    } else { assert(error && accountCalls == 0); }
    assert(anisetteCalls && (initCalls || [mode isEqual:@"missing-anisette"]) && unexpected == 0);
    printf("PASS: offline %s via lazy module and NSURLConnection\n", [mode UTF8String]);
    [pool drain]; return 0;
}
