#import "AQWiFiLease.h"
#import "AQHelperSupport.h"
@interface FakeWiFi : NSObject <AQWiFiInterface>
@property BOOL powerOn;
@property(copy) NSString *ssid;
@property BOOL refuseDisconnect;
@property int disconnects;
@end
@implementation FakeWiFi
- (NSString *)interfaceName { return @"en7"; }
- (BOOL)setPower:(BOOL)power error:(NSError **)error { self.powerOn=power; return YES; }
- (void)disassociate { self.disconnects++; if(!self.refuseDisconnect) self.ssid=nil; }
@end
int main(void) { @autoreleasepool { @try {
    for(int scenario=0;scenario<4;scenario++) {
        FakeWiFi *wifi=[FakeWiFi new]; wifi.powerOn=scenario!=2; wifi.ssid=(scenario==0 || scenario==3) ? @"Saved test network" : nil; wifi.refuseDisconnect=scenario==3;
        __block int joins=0;
        AQWiFiLease *lease=[[AQWiFiLease alloc] initWithInterface:wifi autoJoin:^int(NSString *name){ AQRequire([name isEqual:@"en7"],@"Wrong interface restored"); joins++; return 0; }];
        BOOL failed=NO; @try { [lease begin]; } @catch(NSException *e) { failed=YES; }
        AQRequire(failed==(scenario==3),@"Unexpected takeover result");
        if(!failed) { AQRequire(wifi.powerOn && !wifi.ssid.length,@"Radio not acquired"); [lease begin]; AQRequire(wifi.disconnects==1,@"Repeated start lost saved state"); }
        [lease restore]; [lease restore];
        AQRequire(wifi.powerOn==(scenario!=2),@"Prior power state not restored");
        AQRequire(joins==((scenario==0 || scenario==3) ? 1 : 0),@"Incorrect automatic rejoin behavior");
    }
    puts("Wi-Fi takeover, connected/disconnected/off restoration, rollback, and idempotence passed."); return 0;
} @catch(NSException *e) { fprintf(stderr,"%s\n",e.reason.UTF8String); return 1; } } }
