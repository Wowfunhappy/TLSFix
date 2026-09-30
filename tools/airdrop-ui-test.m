#include "../src/mac/airdrop/AQUI.m"
#include <assert.h>

@interface ShareFixture : NSObject
@property(strong) NSButton *button;
@end
@implementation ShareFixture
- (void)updateExplanationText {}
- (void)updateOKButtonTitle { _button.title=@"Send"; }
@end
static unsigned nativeActions;
static void native_pressed(id controller,SEL selector,id sender) {
    (void)controller; (void)selector; (void)sender; ++nativeActions;
}

int main(int argc,const char **argv) { @autoreleasepool {
    [NSApplication sharedApplication];
    for(NSString *radio in @[@"Wi‑Fi",@"Wi-Fi",@"WLAN"]) {
        NSString *source=[@"Turn on " stringByAppendingString:radio];
        NSAttributedString *native=[[NSAttributedString alloc] initWithString:source
            attributes:@{NSForegroundColorAttributeName:[NSColor grayColor]}];
        NSAttributedString *adapted=bluetooth_in_native_text(native);
        assert([adapted.string isEqualToString:@"Turn on Bluetooth"]);
        assert([native.string isEqualToString:source]);
        assert([[adapted attribute:NSForegroundColorAttributeName atIndex:8 effectiveRange:NULL] isEqual:[NSColor grayColor]]);
    }
    assert(argc==2);
    NSBundle *translations=[NSBundle bundleWithPath:[NSString stringWithUTF8String:argv[1]]];
    assert(translations && translations.localizations.count==8);
    ui_text_bundle_loaded=YES;
    NSDictionary *english=[NSDictionary dictionaryWithContentsOfFile:
        [translations pathForResource:@"Localizable" ofType:@"strings" inDirectory:nil forLocalization:@"en"]];
    assert(english.count==8);
    for(NSString *locale in translations.localizations) {
        ui_text_bundle=ui_localization(translations,@[locale]);
        NSDictionary *strings=[NSDictionary dictionaryWithContentsOfFile:[ui_text_bundle pathForResource:@"Localizable" ofType:@"strings"]];
        assert(strings.count==english.count);
        for(NSString *key in english) assert([AQText(key) isEqualToString:strings[key]] && [strings[key] length]);
        NSAttributedString *body=help_text();
        assert([body.string rangeOfString:@"*"].location==NSNotFound);
        assert([body.string isEqualToString:AQText(AQHelpText)]);
        AQAirDropControls *localized=[[AQAirDropControls alloc] initWithFrame:NSMakeRect(0,0,577,146) finder:YES];
        assert(NSWidth(localized.olderButton.frame)>=[localized.olderButton.cell cellSize].width);
        assert(NSWidth(localized.helpButton.frame)<=553);
        localized.olderButton.title=AQText(@"Searching for older Macs…");
        assert(NSWidth(localized.olderButton.frame)>=[localized.olderButton.cell cellSize].width);
    }
    ui_text_bundle=ui_localization(translations,@[@"es-MX"]);
    assert([AQText(@"Turn On Bluetooth") isEqualToString:@"Activar Bluetooth"]);
    ui_text_bundle=ui_localization(translations,@[@"pt"]);
    assert([AQText(@"Turn On Bluetooth") isEqualToString:@"Ativar Bluetooth"]);
    ui_text_bundle=ui_localization(translations,@[@"zh_CN"]);
    assert([AQText(@"Turn On Bluetooth") isEqualToString:@"打开蓝牙"]);
    ui_text_bundle=ui_localization(translations,@[@"xx-YY"]);
    assert([AQText(@"Turn On Bluetooth") isEqualToString:@"Turn On Bluetooth"]);
    ui_text_bundle=nil;
    assert([AQText(@"Turn On Bluetooth") isEqualToString:@"Turn On Bluetooth"]);
    ui_text_bundle=ui_localization(translations,@[@"English"]);
    NSArray *sentences=@[@"AirDrop lets you share wirelessly with others nearby.",
        @"AirDrop vous permet d’envoyer sans fil des fichiers à des utilisateurs situés à proximité.",
        @"AirDrop を使うと、近くにいる人とワイヤレスで共有できます。"];
    NSArray *tails=@[@"  Other people will see your name.",@" Les personnes verront votre nom.",@"その人の連絡先にあなたが登録されていない場合。"];
    for(NSUInteger i=0;i<sentences.count;i++) {
        NSAttributedString *localized=[[NSAttributedString alloc] initWithString:[sentences[i] stringByAppendingString:tails[i]]
            attributes:@{NSForegroundColorAttributeName:[NSColor grayColor]}];
        NSAttributedString *first=first_info_sentence(localized);
        assert([first.string isEqualToString:sentences[i]]);
        assert([[first attribute:NSForegroundColorAttributeName atIndex:0 effectiveRange:NULL] isEqual:[NSColor grayColor]]);
    }
    NSWindow *window=[[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,770,400)
        styleMask:NSBorderlessWindowMask backing:NSBackingStoreBuffered defer:NO];
    NSView *root=window.contentView;
    NSView *pane=[[NSView alloc] initWithFrame:NSMakeRect(193,0,577,400)];
    [root addSubview:pane];
    NSView *info=[[NSView alloc] initWithFrame:NSMakeRect(0,0,577,146)];
    [pane addSubview:info];
    attach_controls(info,YES);
    AQAirDropControls *controls=objc_getAssociatedObject(info,&controls_key);
    assert(controls && controls.superview==root && !info.subviews.count);
    assert(NSMinX(controls.frame)==193 && NSWidth(controls.frame)==577);
    assert(NSWidth(controls.olderButton.frame)>0 && NSHeight(controls.olderButton.frame)>0);
    assert(controls.olderButton.superview==controls.olderPopover.contentViewController.view);
    assert(controls.helpButton.superview==controls && NSWidth(controls.helpButton.frame)>0);
    assert(!controls.bluetoothController);
    assert([root.subviews lastObject]==controls);
    [info removeFromSuperview]; [controls tick:nil];
    assert(!controls.superview);

    ShareFixture *share=[ShareFixture new]; share.button=[NSButton new];
    share_button_ivar=class_getInstanceVariable([ShareFixture class],"_button");
    share_original_pressed=native_pressed;
    // A radio-state change between display and click must never turn a
    // Bluetooth action into Send. The next explicitly labeled Send is native.
    ui_wifi_on=YES; ui_bluetooth_off=NO;
    share.button.title=@"Turn On Bluetooth";
    share_button_pressed(share,@selector(okButtonPressed:),share.button);
    assert(nativeActions==0 && [share.button.title isEqualToString:@"Send"]);
    share_button_pressed(share,@selector(okButtonPressed:),share.button);
    assert(nativeActions==1);
    puts("PASS: eight UI locales, regional/English fallback, plain popover text and translated button sizes; native sentences, Finder layout/navigation and Share action race");
    return 0;
} }
