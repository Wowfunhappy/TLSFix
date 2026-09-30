/* Instantiate Finder's own Wi-Fi-unavailable controller. Its nib, artwork,
 * fields, button and layout remain native; only the radio name/action differ. */
@interface NSObject (AQNativeUnavailable)
- (id)initForNoWiFi;
- (NSView *)view;
- (void)manuallyLayoutContentView;
- (void)adjustContentViewHeightToFit;
@end
static Ivar finder_unavailable_message_ivar,finder_unavailable_button_ivar;
static NSAttributedString *bluetooth_in_native_text(NSAttributedString *native) {
    if(!native.length) return native;
    NSMutableAttributedString *text=[native mutableCopy];
    for(NSString *wifi in @[@"Wi‑Fi",@"Wi-Fi",@"WLAN",@"无线局域网",@"無線網路",@"תקשורת אלחוטית"]) {
        NSRange range=[text.string rangeOfString:wifi];
        while(range.location!=NSNotFound) {
            [text replaceCharactersInRange:range withString:@"Bluetooth"];
            range=[text.string rangeOfString:wifi];
        }
    }
    return text;
}
static NSString *share_native_bluetooth_text(NSString *key,NSString *fallback) {
    NSBundle *finderkit=[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/FinderKit.framework"];
    NSString *native=[finderkit localizedStringForKey:key value:@"" table:nil];
    if(!native.length || [native isEqualToString:key]) return AQText(fallback);
    return bluetooth_in_native_text([[NSAttributedString alloc] initWithString:native]).string;
}
