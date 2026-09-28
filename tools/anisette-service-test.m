/* Exercise the actual helper's HTTPS transport and provisioning code offline. */
#include <assert.h>
#define main aq_service_main
#include "../src/mac/aquatransport_anisette_service.m"
#undef main
#include "anisette-provision-fixture.h"
int main(void) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    testProvisioning();
    [pool drain]; return 0;
}
