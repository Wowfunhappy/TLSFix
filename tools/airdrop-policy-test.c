#include <stdio.h>
#include "../src/mac/aquatransport_airdrop_policy.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); return 1; } } while(0)
int main(void) {
    const char *daemon="/usr/libexec/sharingd";
    CHECK(aq_airdrop_platform_supported(13,8,daemon,1));
    for(unsigned os=10;os<=30;os++) {
        if(os!=13) CHECK(!aq_airdrop_platform_supported(os,8,daemon,1));
        CHECK(!aq_airdrop_platform_supported(os,4,daemon,1));
        CHECK(!aq_airdrop_platform_supported(os,8,daemon,0));
        CHECK(!aq_airdrop_platform_supported(os,8,"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",1));
    }
    CHECK(!aq_airdrop_platform_supported(13,8,NULL,1));
    CHECK(!aq_airdrop_platform_supported(13,8,"/tmp/sharingd",1));
    CHECK(aq_airdrop_interface_supported("en0"));
    CHECK(aq_airdrop_interface_supported("en1"));
    CHECK(aq_airdrop_interface_supported("en7"));
    CHECK(!aq_airdrop_interface_supported(""));
    CHECK(!aq_airdrop_interface_supported(NULL));
    unsigned char features[8]={0x87,0x7b,0xff,0xdb,0xfe,0xcf,0xfe,0xbf};
    CHECK(aq_airdrop_bluetooth_supported(features,8));
    features[4]&=~0x40;
    CHECK(!aq_airdrop_bluetooth_supported(features,8));
    CHECK(!aq_airdrop_bluetooth_supported(NULL,8));
    for(unsigned n=0;n<8;n++) CHECK(!aq_airdrop_bluetooth_supported(features,n));
    puts("PASS: platform, process, TAP, radio and Bluetooth eligibility boundaries");
    return 0;
}
