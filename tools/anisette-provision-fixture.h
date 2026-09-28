/* Offline coverage of the production provisioning/state machine. Only native
 * cryptographic calls and HTTPS responses are replaced; metadata uses scratch
 * files. No Apple framework, account, keychain or real device state is touched. */
static int adiMode, adiRequests, adiStarts, adiFinishes, adiDestroys, adiOTPs, adiState;
static int fakeState(uint64_t dsid) { assert(dsid == UINT64_MAX-1); return adiState; }
static int fakeDispose(void *p) { free(p); return 0; }
static int fakeStart(uint64_t dsid, const void *p, uint32_t n, void **out, uint32_t *size, uint32_t *session) {
    assert(dsid == UINT64_MAX-1 && n == 4 && !memcmp(p, "spim", 4)); adiStarts++;
    if (adiMode == 3) return -1;
    *out = strdup("cpim"); *size = 4; *session = 7; return 0;
}
static int fakeFinish(uint32_t session, const void *p, uint32_t n, const void *key, uint32_t length) {
    assert(session == 7 && n == 3 && !memcmp(p, "ptm", 3) && length == 2 && !memcmp(key, "tk", 2)); adiFinishes++;
    if (adiMode == 6) return -1;
    adiState = 0; return 0;
}
static int fakeDestroy(uint32_t session) { assert(session == 7); adiDestroys++; return 0; }
static int fakeOTP(uint64_t dsid, void **machine, uint32_t *ml, void **otp, uint32_t *ol) {
    assert(dsid == UINT64_MAX-1); adiOTPs++;
    *machine = strdup("machine"); *ml = 7; *otp = strdup("otp"); *ol = 3; return 0;
}
@interface AQProvisionFixture : NSURLProtocol @end
@implementation AQProvisionFixture
+ (BOOL)canInitWithRequest:(NSURLRequest *)req { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)req { return req; }
- (void)stopLoading {}
- (void)startLoading {
    NSURLRequest *req = [self request]; adiRequests++;
    assert(adiRequests <= 3 && aq_adi_url([[req URL] absoluteString]));
    assert(![req valueForHTTPHeaderField:@"Authorization"] && ![req valueForHTTPHeaderField:@"X-Apple-I-MD"]);
    NSDictionary *result = nil; NSInteger status = 200;
    switch (adiRequests) {
        case 1:
            assert([[req HTTPMethod] isEqual:@"GET"]);
            result = adiMode == 1 ? @{} : @{@"urls": @{
                @"midStartProvisioning": @"https://gsa.apple.com/grandslam/start",
                @"midFinishProvisioning": adiMode == 7 ? @"https://other.invalid/grandslam/finish" : @"https://gsa.apple.com/grandslam/finish"}};
            break;
        case 2:
            assert([[req HTTPMethod] isEqual:@"POST"] && [[aq_plist([req HTTPBody]) objectForKey:@"Request"] count] == 0);
            status = adiMode == 2 ? 503 : 200;
            result = @{@"Response": @{@"spim": @"c3BpbQ=="}};
            break;
        case 3:
            assert([[req HTTPMethod] isEqual:@"POST"] && [[[[aq_plist([req HTTPBody]) objectForKey:@"Request"] objectForKey:@"cpim"] description] isEqual:@"Y3BpbQ=="]);
            status = adiMode == 4 ? 503 : 200;
            result = @{@"Response": @{@"ptm": @"cHRt", @"tk": @"dGs=", @"X-Apple-I-MD-RINFO": adiMode == 5 ? @"bad\r\nroute" : @"12345"}};
            break;
    }
    NSHTTPURLResponse *response = [[[NSHTTPURLResponse alloc] initWithURL:[req URL] statusCode:status HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
    [[self client] URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [[self client] URLProtocol:self didLoadData:aq_encode(result)];
    [[self client] URLProtocolDidFinishLoading:self];
}
@end
static void testProvisioning(void) {
    AQADI.state = fakeState; AQADI.otp = fakeOTP; AQADI.start = fakeStart;
    AQADI.finish = fakeFinish; AQADI.destroy = fakeDestroy; AQADI.dispose = fakeDispose;
    [NSURLProtocol registerClass:[AQProvisionFixture class]];
    for (adiMode = 0; adiMode <= 9; adiMode++) {
        adiRequests = adiStarts = adiFinishes = adiDestroys = adiOTPs = 0;
        adiState = adiMode == 8 ? -1 : adiMode == 9 ? 0 : -45061;
        char path[] = "/tmp/aquatransport-adi.XXXXXX"; int fd = mkstemp(path); assert(fd >= 0); unlink(path);
        NSError *error = nil;
        NSDictionary *headers = aq_adi_headers(nil, @"fixture-device", fd, &error);
        if (!adiMode) {
            assert(headers && !error && adiRequests == 3 && adiStarts == 1 && adiFinishes == 1 && !adiDestroys && adiOTPs == 1);
            assert([[headers objectForKey:@"X-Apple-I-MD-RINFO"] isEqual:@"12345"]);
            assert([[aq_adi_read(fd) objectForKey:@"routing"] isEqual:@"12345"]);
            assert(aq_adi_headers(nil, @"fixture-device", fd, &error) && adiRequests == 3 && adiOTPs == 2);
            assert(!aq_adi_headers(nil, @"different-device", fd, &error) && [error code] == 18 && adiRequests == 3);
        } else {
            const int expected[] = {3,1,2,2,3,3,3,1,0,0};
            assert(!headers && error && adiRequests == expected[adiMode] && !adiOTPs);
            assert(adiDestroys == (adiMode >= 4 && adiMode <= 6 ? 1 : 0));
            error = nil;
            assert(!aq_adi_headers(nil, @"fixture-device", fd, &error));
            assert([error code] == (adiMode == 8 ? 12 : adiMode == 9 ? 18 : 17) && adiRequests == expected[adiMode]);
        }
        close(fd);
    }
    adiState = -45061; adiRequests = 0;
    int readonly = open("/dev/null", O_RDONLY); assert(readonly >= 0);
    NSError *error = nil;
    assert(!aq_adi_headers(nil, @"fixture-device", readonly, &error) && [error code] == 14 && !adiRequests); close(readonly);
    for (NSString *route in @[@"0", @"-1", @"123\r\n", @"18446744073709551616", @"１２３", @""])
        assert(!aq_adi_routing(route));
    [NSURLProtocol unregisterClass:[AQProvisionFixture class]];
    memset(&AQADI, 0, sizeof AQADI);
    puts("PASS: native provisioning, 64-bit DSID, routing persistence, failed-session cleanup, cooldown and request bounds (11 cases)");
}
