/* Native backend diagnostic. Never reads credentials or signs in. The normal
 * adapter uses IPC; this diagnostic directly checks the helper's shared backend. */
#define AQ_NATIVE_DIAGNOSTIC 1
#include "../src/mac/aquatransport_gsa.m"
#include "local-anisette-fixture.h"

static int scenario, calls;
static id localOTP(id self, SEL selector, id owner, NSError **error) {
    calls++;
    switch (scenario) {
        case 1: return nil;
        case 2: return @[];
        case 3: return @{};
        case 4: return @{@"X-Apple-MD": @"otp", @"X-Apple-I-MD-RINFO": @"12345"};
        case 5: return @{@"X-Apple-MD": @42, @"X-Apple-MD-M": @"machine", @"X-Apple-I-MD-RINFO": @"12345"};
        case 6: return @{@"X-Apple-MD": @"", @"X-Apple-MD-M": @"machine", @"X-Apple-I-MD-RINFO": @"12345"};
        case 7: return @{@"X-Apple-MD": @"otp\r\ninjected", @"X-Apple-MD-M": @"machine", @"X-Apple-I-MD-RINFO": @"12345"};
        case 8: return @{@"X-Apple-MD": [@"x" stringByPaddingToLength:16385 withString:@"x" startingAtIndex:0], @"X-Apple-MD-M": @"machine", @"X-Apple-I-MD-RINFO": @"12345"};
        case 9: [NSException raise:@"FixtureException" format:@"must not escape or be logged"]; return nil;
        case 10: return @{@"X-Apple-MD": @"otp", @"X-Apple-MD-M": @"bad\nmachine", @"X-Apple-I-MD-RINFO": @"12345"};
    }
    return @{@"X-Apple-MD": @"otp", @"X-Apple-MD-M": @"machine", @"X-Apple-I-MD-RINFO": @"12345",
        @"Authorization": @"must-not-forward", @"X-MMe-Client-Info": @"must-not-forward"};
}

@interface AQNoNetwork : NSURLProtocol @end
@implementation AQNoNetwork
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading { assert(!"Local Anisette must not make HTTP requests"); }
@end

#include "anisette-provision-fixture.h"

int main(int argc, char **argv) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    [NSURLProtocol registerClass:[AQNoNetwork class]];
    if (argc == 2 && !strcmp(argv[1], "--selftest")) {
        IMP original = aq_test_install_otp((IMP)localOTP);
        for (scenario = 0; scenario <= 10; scenario++) {
            NSError *error = nil;
            NSDictionary *headers = aq_anisette(nil, &error);
            assert(calls == scenario+1);
            if (scenario) {
                assert(!headers && [[error domain] isEqual:AQErrorDomain]);
                assert([error code] == (scenario == 9 ? 11 : 12));
            } else {
                assert(!error && [headers count] == 9);
                assert([[headers objectForKey:@"X-Apple-I-MD"] isEqual:@"otp"]);
                assert([[headers objectForKey:@"X-Apple-I-MD-M"] isEqual:@"machine"]);
                assert([[headers objectForKey:@"X-Apple-I-MD-RINFO"] isEqual:@"12345"]);
                NSString *device = aq_device_uuid();
                assert([device length] && [[headers objectForKey:@"X-Mme-Device-Id"] isEqual:device]);
                assert([[headers objectForKey:@"X-Apple-I-MD-LU"] isEqual:aq_base64([device dataUsingEncoding:NSUTF8StringEncoding])]);
                assert([[headers objectForKey:@"X-MMe-Client-Info"] isEqual:AQTestClient]);
                assert(![headers objectForKey:@"Authorization"]);
            }
        }
        aq_test_install_otp(original);
        puts("PASS: local Anisette mapping, validation, exceptions and no HTTP (11 cases)");
        testProvisioning();
        [pool drain]; return 0;
    }
    /* Recovery for a successfully completed provisioning transaction whose
     * routing metadata was not saved. Use only the value from that transaction;
     * never guess a routing value or overwrite an existing record. */
    if (argc == 3 && !strcmp(argv[1], "--record-routing")) {
        NSError *error = nil;
        NSString *routing = aq_adi_routing([NSString stringWithUTF8String:argv[2]]);
        if (!routing || !aq_adi_load() || AQADI.state((uint64_t)-2)) return 2;
        int fd = aq_adi_lock(&error); if (fd < 0) return 1;
        NSMutableDictionary *record = aq_adi_read(fd);
        NSString *device = aq_device_uuid();
        BOOL ok = device && ![record objectForKey:@"routing"];
        if (ok) {
            [record setObject:device forKey:@"device"]; [record setObject:routing forKey:@"routing"];
            ok = aq_adi_save(fd, record);
        }
        flock(fd, LOCK_UN); close(fd);
        if (!ok) return 1;
        puts("Saved routing metadata for the existing native device state.");
    } else if (argc != 1) { fprintf(stderr, "Usage: gsa-diagnose [--selftest | --record-routing VALUE]\n"); [pool drain]; return 2; }
    if (!aq_adi_load() || AQADI.state((uint64_t)-2)) {
        fprintf(stderr, "Native device state is not ready; offline diagnostic will not provision.\n");
        [pool drain]; return 1;
    }
    NSError *error = nil;
    NSDictionary *headers = aq_anisette(nil, &error);
    if (!headers) {
        /* Only our own fixed error messages are printed; transport errors can embed URLs. */
        fprintf(stderr, "Anisette failed: domain=%s code=%ld\n", [[error domain] UTF8String], (long)[error code]);
        if ([[error domain] isEqual:AQErrorDomain]) fprintf(stderr, "%s\n", [[error localizedDescription] UTF8String]);
        [pool drain]; return 1;
    }
    printf("PASS: native AOSKit generated local Anisette (%lu fields); values withheld\n", (unsigned long)[headers count]);
    [pool drain]; return 0;
}
