#import <Foundation/Foundation.h>
#import <IOBluetooth/IOBluetooth.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

/* These selectors and signatures are present in Mavericks' IOBluetooth binary.
 * Only standard LE advertising commands are used; no controller reset. */
@interface IOBluetoothHostController (AirDropAdvertising)
- (int)BluetoothHCILESetAdvertisingParameters:(unsigned short)minimum
    advertisingIntervalMax:(unsigned short)maximum advertisingType:(unsigned char)type
    ownAddressType:(unsigned char)ownType directAddressType:(unsigned char)directType
    directAddress:(BluetoothDeviceAddress *)address
    advertisingChannelMap:(unsigned char)channels advertisingFilterPolicy:(unsigned char)policy;
- (int)BluetoothHCILESetAdvertisingData:(unsigned char)length advertsingData:(char *)data;
- (int)BluetoothHCILESetAdvertiseEnable:(unsigned char)enabled;
@end

static volatile sig_atomic_t stopped;
static void stop(int sig) { (void)sig; stopped = 1; }

int main(int argc, char **argv)
{
    char *end = NULL;
    long duration = argc > 1 ? strtol(argv[1], &end, 10) : 120;
    if (argc > 2 || (end && *end) || duration < 1 || duration > 600) {
        fprintf(stderr, "usage: %s [seconds: 1..600]\n", argv[0]); return 1;
    }
    @autoreleasepool {
        IOBluetoothHostController *controller = [IOBluetoothHostController defaultController];
        if (![controller respondsToSelector:@selector(BluetoothHCILESetAdvertiseEnable:)] || ![controller respondsToSelector:@selector(BluetoothHCILESetAdvertisingData:advertsingData:)] || ![controller respondsToSelector:@selector(BluetoothHCILESetAdvertisingParameters:advertisingIntervalMax:advertisingType:ownAddressType:directAddressType:directAddress:advertisingChannelMap:advertisingFilterPolicy:)]) {
            fprintf(stderr, "Mavericks LE advertising API unavailable\n"); return 1;
        }
        BluetoothDeviceAddress direct = {{0}};
        // Nonconnectable advertisement every 100 ms, on all three LE channels.
        int status = [controller BluetoothHCILESetAdvertisingParameters:160 advertisingIntervalMax:160
            advertisingType:3 ownAddressType:0 directAddressType:0 directAddress:&direct
            advertisingChannelMap:7 advertisingFilterPolicy:0];
        if (status) { fprintf(stderr, "advertising parameters failed: %#x\n", status); return 1; }
        // Anonymous AirDrop discovery announcement; no contact identifiers.
        char data[31] = {2, 1, 6, 0x17, (char)0xff, 0x4c, 0, 5, 0x12,
                        0,0,0,0,0,0,0,0, 1, 0,0,0,0,0,0,0,0, 0};
        status = [controller BluetoothHCILESetAdvertisingData:27 advertsingData:data];
        if (status) { fprintf(stderr, "advertising data failed: %#x\n", status); return 1; }
        signal(SIGINT, stop); signal(SIGTERM, stop); signal(SIGALRM, stop);
        status = [controller BluetoothHCILESetAdvertiseEnable:1];
        if (status) { fprintf(stderr, "advertising enable failed: %#x\n", status); return 1; }
        printf("AirDrop sender announcement enabled for %ld seconds\n", duration); fflush(stdout);
        alarm((unsigned int)duration);
        while (!stopped) pause();
        status = [controller BluetoothHCILESetAdvertiseEnable:0];
        printf("AirDrop sender announcement stopped (%#x)\n", status);
        return status ? 1 : 0;
    }
}
