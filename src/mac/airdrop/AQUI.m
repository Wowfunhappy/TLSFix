/* UI for the two distinct Mavericks AirDrop hosts. Finder owns its browser;
 * ShareKit's AirDrop plug-in owns FIAirDropView in FinderKit. Keep the hooks
 * scoped to those exact classes and leave their actual Wi-Fi prompt alone. */
#import <AppKit/AppKit.h>
#import <CoreWLAN/CoreWLAN.h>
#import <IOBluetooth/IOBluetooth.h>
#import <objc/runtime.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

static NSString *const AQModeRequest=@"org.aquatransport.airdrop.mode.request";
static NSString *const AQModeChanged=@"org.aquatransport.airdrop.mode.changed";
static NSString *const AQModeHeartbeat=@"org.aquatransport.airdrop.mode.heartbeat";
static BOOL finder_native;
static BOOL finder_requested;
static __weak id finder_owner;
static char controls_key;
static void (*finder_info_moved)(id,SEL);
static void (*share_view_loaded)(id,SEL);
static void reset_finder_mode(id owner);

#include "AQBluetoothUI.inc"
#include "AQFinderDescription.inc"
#include "AQLocalization.inc"
#include "AQFinderBluetooth.inc"
static void request_mode(BOOL native) {
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:AQModeRequest
        object:@"org.aquatransport.airdrop" userInfo:@{@"native":@(native)} deliverImmediately:YES];
}
static void send_mode_heartbeat(void) {
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:AQModeHeartbeat
        object:@"org.aquatransport.airdrop" userInfo:nil deliverImmediately:YES];
}

@interface AQAirDropControls : NSView
@property(strong) id bluetoothController;
@property(copy) NSAttributedString *bluetoothExplanation;
@property(strong) NSButton *olderButton;
@property(strong) NSButton *helpButton;
@property(strong) NSPopover *olderPopover;
@property(strong) NSTimer *timer;
@property(weak) NSView *anchor;
@property(weak) NSTextField *infoField;
@property BOOL finder;
- (instancetype)initWithFrame:(NSRect)frame finder:(BOOL)finder;
- (void)refresh;
- (void)tick:(NSTimer *)timer;
@end
@implementation AQAirDropControls
- (instancetype)initWithFrame:(NSRect)frame finder:(BOOL)finder {
    if(!(self=[super initWithFrame:frame])) return nil;
    _finder=finder;
    self.autoresizingMask=NSViewWidthSizable|NSViewHeightSizable;
    if(finder) {
        _helpButton=[NSButton new];
        _helpButton.bordered=NO;
        _helpButton.attributedTitle=[[NSAttributedString alloc]
            initWithString:AQText(@"Don't see who you're looking for?")
            attributes:@{NSFontAttributeName:[NSFont systemFontOfSize:12],
                NSForegroundColorAttributeName:[NSColor colorWithCalibratedRed:0.12 green:0.40 blue:0.68 alpha:1]}];
        _helpButton.target=self; _helpButton.action=@selector(showOlderPopover:);
        [self addSubview:_helpButton];

        NSViewController *content=[NSViewController new];
        NSTextField *explanation=[NSTextField new];
        explanation.bezeled=NO; explanation.editable=NO; explanation.drawsBackground=NO;
        explanation.alignment=NSCenterTextAlignment; explanation.font=[NSFont systemFontOfSize:12];
        explanation.attributedStringValue=help_text();
        [explanation.cell setWraps:YES];
        _olderButton=[NSButton new]; _olderButton.title=AQText(@"Searching for older Macs…");
        _olderButton.bezelStyle=NSRoundedBezelStyle;
        [_olderButton sizeToFit];
        CGFloat buttonWidth=MAX(220,NSWidth(_olderButton.frame));
        _olderButton.title=AQText(@"Search for an Older Mac"); [_olderButton sizeToFit];
        buttonWidth=MAX(buttonWidth,NSWidth(_olderButton.frame));
        CGFloat bodyWidth=MAX(270,buttonWidth);
        CGFloat textHeight=ceil([explanation.cell cellSizeForBounds:NSMakeRect(0,0,bodyWidth,1000)].height);
        content.view=[[NSView alloc] initWithFrame:NSMakeRect(0,0,bodyWidth+28,textHeight+64)];
        explanation.frame=NSMakeRect(14,50,bodyWidth,textHeight);
        [content.view addSubview:explanation];
        _olderButton.target=self; _olderButton.action=@selector(searchOlder:);
        _olderButton.frame=NSMakeRect((bodyWidth+28-buttonWidth)/2,12,buttonWidth,28);
        [content.view addSubview:_olderButton];
        _olderPopover=[NSPopover new]; _olderPopover.behavior=NSPopoverBehaviorTransient;
        _olderPopover.contentViewController=content;
    }
    [self refresh]; return self;
}
- (void)dealloc { [_timer invalidate]; }
- (NSView *)hitTest:(NSPoint)point {
    NSView *hit=[super hitTest:point];
    return hit==self ? nil : hit;
}
- (void)viewDidMoveToWindow {
    [super viewDidMoveToWindow];
    if(!self.window) {
        [[_bluetoothController view] removeFromSuperview];
        [_olderPopover close];
        [_timer invalidate]; _timer=nil;
        if(_finder) reset_finder_mode(self);
    } else if(!_timer) {
        _timer=[NSTimer scheduledTimerWithTimeInterval:1 target:self selector:@selector(tick:)
            userInfo:nil repeats:YES];
        [self refresh];
    }
}
- (void)layout {
    [super layout];
    CGFloat width=NSWidth(self.bounds);
    if(_helpButton) {
        [_helpButton sizeToFit];
        NSRect fieldFrame=_infoField ? [_infoField convertRect:_infoField.bounds toView:self] : NSMakeRect(0,38,width,16);
        CGFloat linkHeight=MAX(18,NSHeight(_helpButton.frame));
        _helpButton.frame=NSMakeRect(floor((width-NSWidth(_helpButton.frame))/2),
            MAX(6,NSMinY(fieldFrame)-linkHeight-2),NSWidth(_helpButton.frame),linkHeight);
    }
}
- (void)resizeWithOldSuperviewSize:(NSSize)oldSize {
    [super resizeWithOldSuperviewSize:oldSize];
    [self layout];
}
- (void)refreshBluetoothView {
    BOOL off=bluetooth_off();
    if(!off) bluetooth_request_deadline=0;
    BOOL show=_finder && !finder_native && wifi_on() && off && _anchor.window;
    for(NSView *view=_anchor;view;view=view.superview) if([view isHidden]) show=NO;
    if(!show) {
        [[_bluetoothController view] removeFromSuperview];
        _helpButton.hidden=NO;
        return;
    }
    if(!_bluetoothController) {
        _bluetoothController=[[(id)objc_getClass("TAirDropNotAvailableViewController") alloc] initForNoWiFi];
        // Loading this view loads Finder's localized AirDropNotAvailableView nib.
        (void)[_bluetoothController view];
        NSTextField *message=object_getIvar(_bluetoothController,finder_unavailable_message_ivar);
        NSButton *button=object_getIvar(_bluetoothController,finder_unavailable_button_ivar);
        _bluetoothExplanation=bluetooth_in_native_text(message.attributedStringValue);
        message.attributedStringValue=_bluetoothExplanation;
        button.attributedTitle=bluetooth_in_native_text(button.attributedTitle);
        [button sizeToFit];
        button.target=self; button.action=@selector(turnOnBluetooth:);
        [_bluetoothController manuallyLayoutContentView];
        [_bluetoothController adjustContentViewHeightToFit];
    }
    NSView *native=[_bluetoothController view],*pane=_anchor.superview;
    if(!native || !pane || !self.superview) return;
    native.frame=[pane convertRect:pane.bounds toView:self.superview];
    native.autoresizingMask=NSViewWidthSizable|NSViewHeightSizable;
    if(native.superview!=self.superview) {
        NSTextField *message=object_getIvar(_bluetoothController,finder_unavailable_message_ivar);
        message.attributedStringValue=_bluetoothExplanation;
        [self.superview addSubview:native positioned:NSWindowAbove relativeTo:self];
        // Finder's AirDrop canvas has its own backing surface.
        native.wantsLayer=YES;
    }
    if(bluetooth_request_failed()) {
        NSTextField *message=object_getIvar(_bluetoothController,finder_unavailable_message_ivar);
        message.stringValue=AQText(@"Could not turn on Bluetooth.");
    }
    [_olderPopover close];
    _helpButton.hidden=YES;
}
- (void)refresh {
    if(_finder && _anchor.window && self.superview)
        self.frame=[_anchor convertRect:_anchor.bounds toView:self.superview];
    [self refreshBluetoothView];
    _olderButton.hidden=NO;
    _olderButton.enabled=!finder_native && !finder_requested;
    if(_olderButton) _olderButton.title=AQText(finder_native ? @"Searching for older Macs…" : @"Search for an Older Mac");
    // Mavericks' manually laid out Finder views do not run an automatic
    // layout pass for these controls. Set their frames synchronously.
    [self layout];
    self.needsDisplay=YES;
}
- (void)tick:(NSTimer *)timer {
    (void)timer;
    if(_finder && (!_anchor.window || _anchor.window.contentView!=self.superview)) {
        [self removeFromSuperview];
        return;
    }
    if(_finder && finder_owner==self)
        for(NSView *view=self.superview;view;view=view.superview)
            if([view isHidden]) { reset_finder_mode(self); break; }
    if(_finder && finder_owner==self && (finder_native || finder_requested)) send_mode_heartbeat();
    [self refresh];
}
- (void)turnOnBluetooth:(id)sender {
    (void)sender;
    NSTextField *message=object_getIvar(_bluetoothController,finder_unavailable_message_ivar);
    // The controller's raw setPowerState: requires kernel privileges. The
    // preference API sends the user's request through the Bluetooth daemon.
    if(!turn_on_bluetooth()) {
        message.stringValue=AQText(@"Could not turn on Bluetooth.");
        return;
    }
    message.stringValue=AQText(@"Turning on Bluetooth…");
}
- (void)searchOlder:(id)sender {
    (void)sender;
    if(finder_native || finder_requested) return;
    finder_requested=YES;
    finder_owner=self;
    request_mode(YES);
    send_mode_heartbeat();
    [self refresh];
}
- (void)showOlderPopover:(id)sender {
    (void)sender;
    if(_olderPopover.shown) { [_olderPopover close]; return; }
    [_olderPopover showRelativeToRect:_helpButton.bounds ofView:_helpButton
        preferredEdge:_helpButton.isFlipped ? NSMaxYEdge : NSMinYEdge];
}
@end

static void attach_controls(NSView *view,BOOL finder) {
    if(!view) return;
    NSView *host=finder ? view.window.contentView : view;
    if(!host || (finder && !view.window)) return;
    AQAirDropControls *controls=objc_getAssociatedObject(view,&controls_key);
    NSRect frame=finder ? [view convertRect:view.bounds toView:host] : view.bounds;
    if(!controls) controls=[[AQAirDropControls alloc] initWithFrame:frame finder:finder];
    controls.anchor=view;
    if(finder) for(NSView *child in view.subviews) if([child isKindOfClass:[NSTextField class]]) {
        controls.infoField=(NSTextField *)child;
        shorten_info_field(controls.infoField);
        if([view respondsToSelector:@selector(invalidateInfoViewImage)]) [(id)view invalidateInfoViewImage];
        break;
    }
    if(finder) controls.autoresizingMask=NSViewWidthSizable|NSViewMaxYMargin;
    // Finder renders its info view into a cached image and gives its canvas
    // a separate backing surface. Keep controls above that entire container.
    [host addSubview:controls positioned:NSWindowAbove relativeTo:nil];
    controls.frame=frame;
    controls.wantsLayer=YES;
    [controls refresh];
    objc_setAssociatedObject(view,&controls_key,controls,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}
static void finder_info_view_moved(id view,SEL selector) {
    finder_info_moved(view,selector);
    if([view window]) dispatch_async(dispatch_get_main_queue(),^{ attach_controls(view,YES); });
    else [(AQAirDropControls *)objc_getAssociatedObject(view,&controls_key) removeFromSuperview];
}
static void reset_finder_mode(id owner) {
    if(finder_owner!=owner) return;
    finder_owner=nil;
    if(!finder_native && !finder_requested) return;
    finder_native=NO;
    finder_requested=NO;
    request_mode(NO);
}
@interface AQModeUIObserver : NSObject
- (void)modeChanged:(NSNotification *)notification;
@end
@implementation AQModeUIObserver
- (void)modeChanged:(NSNotification *)notification {
    if(!finder_requested && !finder_native) return;
    id value=notification.userInfo[@"native"];
    if(![value isKindOfClass:[NSNumber class]]) return;
    finder_native=[value boolValue];
    finder_requested=NO;
}
@end
static AQModeUIObserver *mode_ui_observer;
#include "AQShareUI.inc"
static void share_airdrop_view_loaded(id controller,SEL selector) {
    share_view_loaded(controller,selector);
    attach_share_controller(controller);
}
static void scan_views(NSView *view,BOOL finder) {
    Class target=objc_getClass(finder ? "TMeetingRoomInfoView" : "FIAirDropView");
    if(target && [view isKindOfClass:target]) {
        if(finder) attach_controls(view,YES);
        else attach_share_controller([(id)view controller]);
    }
    for(NSView *child in [view.subviews copy]) scan_views(child,finder);
}
static void scan_existing_windows(BOOL finder) {
    for(NSWindow *window in [NSApp windows]) scan_views(window.contentView,finder);
}
static BOOL path_matches(const char *actual,const char *expected) {
    char resolved[PATH_MAX];
    return actual && (!strcmp(actual,expected) || (realpath(actual,resolved) && !strcmp(resolved,expected)));
}
static BOOL image_matches(const char *path,const unsigned char uuid[16]) {
    for(uint32_t i=0;i<_dyld_image_count();i++) {
        const char *name=_dyld_get_image_name(i);
        if(!path_matches(name,path)) continue;
        const struct mach_header *header=_dyld_get_image_header(i);
        if(!header || header->magic!=MH_MAGIC_64) return NO;
        const struct load_command *command=(const void *)((const struct mach_header_64 *)header+1);
        for(uint32_t n=0;n<header->ncmds;n++,command=(const void *)((const char *)command+command->cmdsize))
            if(command->cmd==LC_UUID && command->cmdsize==sizeof(struct uuid_command))
                return !memcmp(((const struct uuid_command *)command)->uuid,uuid,16);
    }
    return NO;
}
static Method method_in_image(const char *className,const char *selector,const char *encoding,const char *image) {
    Class cls=objc_getClass(className);
    Method method=cls ? class_getInstanceMethod(cls,sel_registerName(selector)) : NULL;
    if(!method || strcmp(method_getTypeEncoding(method),encoding)) return NULL;
    Dl_info owner;
    if(!dladdr((void *)method_getImplementation(method),&owner) || !path_matches(owner.dli_fname,image)) return NULL;
    return method;
}
__attribute__((constructor)) static void install_airdrop_ui(void) { @autoreleasepool {
    static const char finder[]="/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder";
    static const char finderkit[]="/System/Library/PrivateFrameworks/FinderKit.framework/Versions/A/FinderKit";
    static const char plugin[]="/System/Library/PrivateFrameworks/ShareKit.framework/Versions/A/PlugIns/AirDrop.sharingservice/Contents/MacOS/AirDrop";
    static const unsigned char finder_uuid[16]={0x96,0xc9,0x18,0x04,0xb7,0x5f,0x3e,0x8f,0xb1,0x57,0xc8,0x2c,0x03,0x2c,0x63,0x53};
    static const unsigned char finderkit_uuid[16]={0x3c,0x42,0xc9,0x9f,0x8c,0x22,0x32,0x59,0xa7,0x33,0x2c,0x55,0xdc,0x94,0x33,0x64};
    static const unsigned char plugin_uuid[16]={0x50,0x9f,0xe8,0x6d,0xab,0x85,0x3f,0x47,0xb4,0x45,0xa0,0x80,0x88,0xba,0xc8,0x52};
    if(image_matches(finder,finder_uuid)) {
        Method info=method_in_image("TMeetingRoomInfoView","viewDidMoveToWindow","v16@0:8",finder);
        Method text=method_in_image("TMeetingRoomInfoViewController","updateInfoText","v16@0:8",finder);
        Method invalidate=method_in_image("TMeetingRoomInfoViewController","invalidateInfoViewImage","v16@0:8",finder);
        Method invalidateView=method_in_image("TMeetingRoomInfoView","invalidateInfoViewImage","v16@0:8",finder);
        Method unavailableInit=method_in_image("TAirDropNotAvailableViewController","initForNoWiFi","@16@0:8",finder);
        Method unavailableLayout=method_in_image("TAirDropNotAvailableViewController","manuallyLayoutContentView","v16@0:8",finder);
        Method unavailableHeight=method_in_image("TAirDropNotAvailableViewController","adjustContentViewHeightToFit","v16@0:8",finder);
        Class unavailable=objc_getClass("TAirDropNotAvailableViewController");
        finder_unavailable_message_ivar=class_getInstanceVariable(unavailable,"_explanationTextFld");
        finder_unavailable_button_ivar=class_getInstanceVariable(unavailable,"_actionButton");
        finder_info_text_ivar=class_getInstanceVariable(objc_getClass("TMeetingRoomInfoViewController"),"_infoTextField");
        if(!info || !text || !invalidate || !invalidateView || !finder_info_text_ivar ||
           strcmp(ivar_getTypeEncoding(finder_info_text_ivar),"@\"TTextField\"") ||
           !unavailableInit || !unavailableLayout || !unavailableHeight ||
           !finder_unavailable_message_ivar || strcmp(ivar_getTypeEncoding(finder_unavailable_message_ivar),"@\"TTextField\"") ||
           !finder_unavailable_button_ivar || strcmp(ivar_getTypeEncoding(finder_unavailable_button_ivar),"@\"TButton\"")) return;
        install_radio_ui(YES);
        finder_original_info_text=(void *)method_setImplementation(text,(IMP)finder_update_info_text);
        finder_info_moved=(void *)method_setImplementation(info,(IMP)finder_info_view_moved);
        mode_ui_observer=[AQModeUIObserver new];
        [[NSDistributedNotificationCenter defaultCenter] addObserver:mode_ui_observer
            selector:@selector(modeChanged:) name:AQModeChanged object:@"org.aquatransport.airdrop"
            suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
        scan_existing_windows(YES);
    } else if(image_matches(plugin,plugin_uuid) && image_matches(finderkit,finderkit_uuid)) {
        Method loaded=method_in_image("FIAirDropViewGutsController","viewLoaded","v16@0:8",finderkit);
        Method view=method_in_image("FIAirDropView","controller","@16@0:8",finderkit);
        Method message=method_in_image("FIAirDropViewGutsController","updateExplanationText","v16@0:8",finderkit);
        Method title=method_in_image("FIAirDropViewGutsController","updateOKButtonTitle","v16@0:8",finderkit);
        Method enabled=method_in_image("FIAirDropViewGutsController","enableOKButton","c16@0:8",finderkit);
        Method hidden=method_in_image("FIAirDropViewGutsController","hideExplanationTextFld","c16@0:8",finderkit);
        Method pressed=method_in_image("FIAirDropViewGutsController","okButtonPressed:","v24@0:8@16",finderkit);
        Class cls=objc_getClass("FIAirDropViewGutsController");
        share_message_ivar=class_getInstanceVariable(cls,"_explanationTextFld");
        share_button_ivar=class_getInstanceVariable(cls,"_okButton");
        if(!loaded || !view || !message || !title || !enabled || !hidden || !pressed ||
           !share_message_ivar || strcmp(ivar_getTypeEncoding(share_message_ivar),"@\"FI_TTextField\"") ||
           !share_button_ivar || strcmp(ivar_getTypeEncoding(share_button_ivar),"@\"FI_TButton\"")) return;
        install_radio_ui(NO);
        share_original_message=(void *)method_setImplementation(message,(IMP)share_update_message);
        share_original_title=(void *)method_setImplementation(title,(IMP)share_update_title);
        share_original_enabled=(void *)method_setImplementation(enabled,(IMP)share_button_enabled);
        share_original_hidden=(void *)method_setImplementation(hidden,(IMP)share_message_hidden);
        share_original_pressed=(void *)method_setImplementation(pressed,(IMP)share_button_pressed);
        share_view_loaded=(void *)method_setImplementation(loaded,(IMP)share_airdrop_view_loaded);
        scan_existing_windows(NO);
    }
} }
