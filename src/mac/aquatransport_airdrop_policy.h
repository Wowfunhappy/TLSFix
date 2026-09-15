#ifndef AQUATRANSPORT_AIRDROP_POLICY_H
#define AQUATRANSPORT_AIRDROP_POLICY_H
#include <string.h>
/* Native API compatibility remains separate from radio capability. */
static inline int aq_airdrop_platform_supported(unsigned darwin, unsigned pointer_bytes,
                                       const char *executable, int tap_character_device) {
    return darwin == 13 && pointer_bytes == 8 && tap_character_device && executable &&
           !strcmp(executable,"/usr/libexec/sharingd");
}
static inline int aq_airdrop_interface_supported(const char *bsd_name) {
    /* Called only for an IO80211Interface, not an arbitrary network device. */
    return bsd_name && bsd_name[0];
}
static inline int aq_airdrop_bluetooth_supported(const unsigned char *features, unsigned length) {
    /* Bluetooth.h: byte 4, kBluetoothFeatureLESupportedController. */
    return features && length == 8 && (features[4] & 0x40) != 0;
}
#endif
