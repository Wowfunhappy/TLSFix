#import <Foundation/Foundation.h>
@protocol AQWiFiInterface <NSObject>
- (BOOL)powerOn;
- (NSString *)ssid;
- (NSString *)interfaceName;
- (void)disassociate;
@end
@interface AQWiFiLease : NSObject
- (instancetype)initWithInterface:(id<AQWiFiInterface>)interface autoJoin:(int (^)(NSString *))autoJoin;
// Requires Wi-Fi to be powered on; the lease never changes Wi-Fi power.
- (void)begin;
- (void)restore;
@end
