#import "AQWiFiLease.h"
#import "AQHelperSupport.h"
#include <unistd.h>
@implementation AQWiFiLease {
    id<AQWiFiInterface> _interface;
    int (^_autoJoin)(NSString *);
    BOOL _active, _wasPowered, _wasConnected;
}
- (instancetype)initWithInterface:(id<AQWiFiInterface>)interface autoJoin:(int (^)(NSString *))autoJoin {
    if((self=[super init])) { _interface=interface; _autoJoin=[autoJoin copy]; } return self;
}
- (void)begin {
    if(_active) return;
    AQRequire(_interface!=nil,@"The supported Wi-Fi interface is unavailable.");
    _wasPowered=_interface.powerOn; _wasConnected=_interface.ssid.length>0;
    AQRequire(!_wasConnected || _autoJoin!=nil,@"The system Wi-Fi reconnection API is unavailable.");
    _active=YES;
    @try {
        NSError *error=nil;
        if(!_wasPowered) AQRequire([_interface setPower:YES error:&error],error.localizedDescription ?: @"Could not enable Wi-Fi for AirDrop.");
        [_interface disassociate];
        for(int i=0;i<20 && _interface.ssid.length;i++) usleep(100000);
        AQRequire(!_interface.ssid.length,@"Wi-Fi did not disconnect for AirDrop.");
    } @catch(NSException *exception) { [self restore]; @throw; }
}
- (void)restore {
    if(!_active) return; _active=NO;
    if(!_wasPowered) {
        NSError *error=nil;
        if(![_interface setPower:NO error:&error]) NSLog(@"AquaTransport AirDrop: Wi-Fi power restoration failed: %@",error.localizedDescription);
    } else if(_wasConnected && _autoJoin) {
        // Let airportd use the user's saved networks and credentials. Never
        // copy a Wi-Fi password or change the preferred-network configuration.
        int error=_autoJoin(_interface.interfaceName);
        if(error) NSLog(@"AquaTransport AirDrop: automatic Wi-Fi rejoin failed (%d)",error);
    }
}
@end
