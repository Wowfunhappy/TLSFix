/* Finder is the user's radio UI host. ShareKit is sandboxed, so it asks
 * Finder for status and the single fixed power-on operation. Notifications
 * stay in the current login session; no paths or executable arguments cross. */
static NSString *const AQRadioUIRequest=@"org.aquatransport.airdrop.radio.request";
static NSString *const AQRadioUIStatus=@"org.aquatransport.airdrop.radio.status";
static BOOL ui_is_finder,ui_wifi_on,ui_bluetooth_off;
static BOOL ui_modern=YES;
static NSTimeInterval bluetooth_request_deadline;
static BOOL bluetooth_off(void) {
    if(!ui_is_finder) return ui_bluetooth_off;
    IOBluetoothHostController *controller=[IOBluetoothHostController defaultController];
    return controller && controller.powerState==kBluetoothHCIPowerStateOFF;
}
static BOOL wifi_on(void) { return ui_is_finder ? [CWInterface interface].powerOn : ui_wifi_on; }
static void radio_ui_request(NSString *command) {
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:AQRadioUIRequest
        object:@"org.aquatransport.airdrop" userInfo:@{@"command":command} deliverImmediately:YES];
}
static BOOL turn_on_bluetooth(void) {
    bluetooth_request_deadline=[NSDate timeIntervalSinceReferenceDate]+8;
    if(!ui_is_finder) { radio_ui_request(@"on"); return YES; }
    int (*setPower)(int)=dlsym(RTLD_DEFAULT,"IOBluetoothPreferenceSetControllerPowerState");
    return setPower && !setPower(kBluetoothHCIPowerStateON);
}
static BOOL bluetooth_request_failed(void) {
    if(!bluetooth_off()) { bluetooth_request_deadline=0; return NO; }
    return bluetooth_request_deadline && [NSDate timeIntervalSinceReferenceDate]>=bluetooth_request_deadline;
}
@interface AQRadioUIObserver : NSObject
- (void)request:(NSNotification *)notification;
- (void)status:(NSNotification *)notification;
@end
@implementation AQRadioUIObserver
- (void)request:(NSNotification *)notification {
    id command=notification.userInfo[@"command"];
    if(![command isKindOfClass:[NSString class]] ||
       (![command isEqual:@"status"] && ![command isEqual:@"on"])) return;
    if([command isEqual:@"on"]) turn_on_bluetooth();
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:AQRadioUIStatus
        object:@"org.aquatransport.airdrop"
        userInfo:@{@"wifi":@(wifi_on()),@"bluetoothOff":@(bluetooth_off()),@"modern":@(!finder_native)} deliverImmediately:YES];
}
- (void)status:(NSNotification *)notification {
    id wifi=notification.userInfo[@"wifi"],off=notification.userInfo[@"bluetoothOff"],modern=notification.userInfo[@"modern"];
    if(![wifi isKindOfClass:[NSNumber class]] || ![off isKindOfClass:[NSNumber class]] ||
       ![modern isKindOfClass:[NSNumber class]]) return;
    ui_wifi_on=[wifi boolValue]; ui_bluetooth_off=[off boolValue];
    ui_modern=[modern boolValue];
}
@end
static AQRadioUIObserver *radio_ui_observer;
static void install_radio_ui(BOOL finder) {
    ui_is_finder=finder;
    radio_ui_observer=[AQRadioUIObserver new];
    [[NSDistributedNotificationCenter defaultCenter] addObserver:radio_ui_observer
        selector:finder ? @selector(request:) : @selector(status:)
        name:finder ? AQRadioUIRequest : AQRadioUIStatus object:@"org.aquatransport.airdrop"
        suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
    if(!finder) radio_ui_request(@"status");
}
