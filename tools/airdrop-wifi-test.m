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
- (void)disassociate { self.disconnects++; if(!self.refuseDisconnect) self.ssid=nil; }
@end
int main(void) { @autoreleasepool { @try {
    // 0: connected, 1: on and disconnected, 2: off, 3: refuses to disconnect,
    // 4: connected, then turned off during the session.
    for(int scenario=0;scenario<5;scenario++) {
        FakeWiFi *wifi=[FakeWiFi new]; wifi.powerOn=scenario!=2; wifi.ssid=(scenario==0 || scenario==3 || scenario==4) ? @"Saved test network" : nil; wifi.refuseDisconnect=scenario==3;
        __block int joins=0;
        AQWiFiLease *lease=[[AQWiFiLease alloc] initWithInterface:wifi autoJoin:^int(NSString *name){ AQRequire([name isEqual:@"en7"],@"Wrong interface restored"); joins++; return 0; }];
        BOOL failed=NO; NSString *reason=nil; @try { [lease begin]; } @catch(NSException *e) { failed=YES; reason=e.reason; }
        AQRequire(failed==(scenario==2 || scenario==3),@"Unexpected takeover result");
        if(scenario==2) AQRequire([reason isEqual:@"Turn on Wi-Fi to use AirDrop."] && !wifi.powerOn && !wifi.disconnects,@"Wi-Fi off was not left alone");
        if(!failed) { AQRequire(wifi.powerOn && !wifi.ssid.length,@"Radio not acquired"); [lease begin]; AQRequire(wifi.disconnects==1,@"Repeated start lost saved state"); }
        if(scenario==4) wifi.powerOn=NO;
        [lease restore]; [lease restore];
        AQRequire(wifi.powerOn==(scenario!=2 && scenario!=4),@"Wi-Fi power changed");
        AQRequire(joins==((scenario==0 || scenario==3) ? 1 : 0),@"Incorrect automatic rejoin behavior");
    }
    puts("Wi-Fi takeover, connected/disconnected restoration, Wi-Fi off before and during the session, rollback, and idempotence passed."); return 0;
} @catch(NSException *e) { fprintf(stderr,"%s\n",e.reason.UTF8String); return 1; } } }
