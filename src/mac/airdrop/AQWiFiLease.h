#import <Foundation/Foundation.h>
@protocol AQWiFiInterface <NSObject>
- (BOOL)powerOn;
- (NSString *)ssid;
- (NSString *)interfaceName;
- (BOOL)setPower:(BOOL)power error:(NSError **)error;
- (void)disassociate;
@end
@interface AQWiFiLease : NSObject
- (instancetype)initWithInterface:(id<AQWiFiInterface>)interface autoJoin:(int (^)(NSString *))autoJoin;
- (void)begin;
- (void)restore;
@end
