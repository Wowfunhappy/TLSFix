/* Device authentication only. Never reads a password or starts Apple sign-in.
 * Including the adapter lets this probe use exactly the production provider path. */
#include "../src/mac/aquatransport_gsa.m"
#include <assert.h>
int main(int argc, char **argv) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    if (argc == 2 && !strcmp(argv[1], "--request-vector")) {
        NSMutableURLRequest *r = aq_gsaport_request(@"00000000-0000-0000-0000-000000000000", 1700000000);
        assert(r && ![r HTTPBody] && ![r valueForHTTPHeaderField:@"Authorization"]);
        /* Independently generated with Python hashlib/struct, fixed UUID and time. */
        assert([[r valueForHTTPHeaderField:@"pk"] isEqual:@"9f89c84a559f573636a47ff8daed0d33"]);
        assert([[r valueForHTTPHeaderField:@"podkey"] isEqual:@"1700000180_650f4a0d8c1a4adab2e4cb8a5c182d4d"]);
        assert(!aq_gsaport_request(nil, 1700000000));
        assert(!aq_gsaport_request(@"fixture", -1));
        assert(!aq_gsaport_request(@"fixture", UINT32_MAX));
        puts("PASS: GSAPort request signature vector and invalid-input checks (offline)");
        [pool drain]; return 0;
    }
    NSError *error = nil;
    NSDictionary *headers = aq_anisette(nil, &error);
    if (!headers) {
        /* Only our own fixed error messages are printed; transport errors can embed URLs. */
        fprintf(stderr, "Anisette failed: domain=%s code=%ld\n", [[error domain] UTF8String], (long)[error code]);
        if ([[error domain] isEqual:AQErrorDomain]) fprintf(stderr, "%s\n", [[error localizedDescription] UTF8String]);
        [pool drain]; return 1;
    }
    printf("PASS: live anisette provider returned all required headers (%lu fields); values withheld\n", (unsigned long)[headers count]);
    [pool drain]; return 0;
}
