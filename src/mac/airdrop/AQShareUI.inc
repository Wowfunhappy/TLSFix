/* ShareKit embeds a FIAirDropView subclass. Reuse FinderKit's native message,
 * action button, sizing and Cancel button rather than covering the sheet. */
@interface NSObject (AQShareController)
- (id)controller;
- (void)updateExplanationText;
- (void)updateOKButtonTitle;
- (BOOL)enableOKButton;
- (BOOL)hideExplanationTextFld;
@end
static Ivar share_message_ivar,share_button_ivar;
static char share_state_key;
static void (*share_original_message)(id,SEL),(*share_original_title)(id,SEL);
static BOOL (*share_original_enabled)(id,SEL),(*share_original_hidden)(id,SEL);
static void (*share_original_pressed)(id,SEL,id);
static BOOL share_needs_bluetooth(void) { return ui_modern && wifi_on() && bluetooth_off(); }
@interface AQShareUIState : NSObject
@property(weak) id controller;
@property(strong) NSTimer *timer;
@property(copy) NSString *status;
@property BOOL wasOff;
- (void)tick:(NSTimer *)timer;
@end
@implementation AQShareUIState
- (void)tick:(NSTimer *)timer {
    (void)timer;
    id controller=_controller;
    if(!controller) { [_timer invalidate]; _timer=nil; return; }
    radio_ui_request(@"status");
    if(bluetooth_request_failed()) {
        _status=AQText(@"Could not turn on Bluetooth.");
        [controller updateExplanationText];
    }
    BOOL off=share_needs_bluetooth();
    if(off==_wasOff) return;
    _wasOff=off; _status=nil;
    [controller updateExplanationText];
    [controller updateOKButtonTitle];
    [(NSButton *)object_getIvar(controller,share_button_ivar) setEnabled:[controller enableOKButton]];
    [(NSTextField *)object_getIvar(controller,share_message_ivar) setHidden:[controller hideExplanationTextFld]];
}
- (void)dealloc { [_timer invalidate]; }
@end
static void share_update_message(id controller,SEL selector) {
    share_original_message(controller,selector);
    if(!share_needs_bluetooth()) return;
    AQShareUIState *state=objc_getAssociatedObject(controller,&share_state_key);
    NSTextField *field=object_getIvar(controller,share_message_ivar);
    field.stringValue=state.status ?: share_native_bluetooth_text(@"MR9",@"Turn on Bluetooth to use AirDrop.");
    field.hidden=NO;
}
static void share_update_title(id controller,SEL selector) {
    share_original_title(controller,selector);
    if(!share_needs_bluetooth()) return;
    NSButton *button=object_getIvar(controller,share_button_ivar);
    NSRect frame=button.frame;
    button.title=share_native_bluetooth_text(@"MR9.1",@"Turn On Bluetooth");
    [button sizeToFit];
    // Preserve the native trailing edge; FinderKit's layout binder moves Cancel.
    [button setFrameOrigin:NSMakePoint(NSMaxX(frame)-NSWidth(button.frame),NSMinY(frame))];
    button.enabled=YES;
}
static BOOL share_button_enabled(id controller,SEL selector) {
    return share_needs_bluetooth() ? YES : share_original_enabled(controller,selector);
}
static BOOL share_message_hidden(id controller,SEL selector) {
    return share_needs_bluetooth() ? NO : share_original_hidden(controller,selector);
}
static void share_button_pressed(id controller,SEL selector,id sender) {
    NSButton *button=object_getIvar(controller,share_button_ivar);
    // Honor the visible action even if the radio changed since the last tick.
    if(![button.title isEqualToString:share_native_bluetooth_text(@"MR9.1",@"Turn On Bluetooth")]) {
        share_original_pressed(controller,selector,sender); return;
    }
    if(!share_needs_bluetooth()) {
        [controller updateExplanationText]; [controller updateOKButtonTitle]; return;
    }
    AQShareUIState *state=objc_getAssociatedObject(controller,&share_state_key);
    state.status=AQText(turn_on_bluetooth() ? @"Turning on Bluetooth…" : @"Could not turn on Bluetooth.");
    [controller updateExplanationText];
}
static void attach_share_controller(id controller) {
    if(!controller || objc_getAssociatedObject(controller,&share_state_key)) return;
    AQShareUIState *state=[AQShareUIState new]; state.controller=controller;
    state.wasOff=!share_needs_bluetooth();
    objc_setAssociatedObject(controller,&share_state_key,state,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    state.timer=[NSTimer scheduledTimerWithTimeInterval:1 target:state selector:@selector(tick:) userInfo:nil repeats:YES];
    [state tick:nil];
}
