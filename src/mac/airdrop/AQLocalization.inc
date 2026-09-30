static NSString *const AQHelpText=@"To share with someone using iOS, ask them to open Control Center and set AirDrop to Everyone. On a Mac, ask them to go to AirDrop in the Finder.";
static NSBundle *ui_text_bundle;
static BOOL ui_text_bundle_loaded;
static NSBundle *ui_localization(NSBundle *bundle,NSArray *preferences) {
    NSArray *languages=[NSBundle preferredLocalizationsFromArray:bundle.localizations
        forPreferences:[preferences arrayByAddingObject:@"en"]];
    NSString *path=[bundle pathForResource:languages.firstObject ofType:@"lproj"];
    return path ? [NSBundle bundleWithPath:path] : nil;
}
static NSString *AQText(NSString *english) {
    if(!ui_text_bundle_loaded) {
        ui_text_bundle_loaded=YES;
        NSBundle *bundle=[NSBundle bundleWithPath:@"/usr/share/aquatransport/airdrop/AirDropUI.bundle"];
        // Select from Finder's languages in both UI hosts, including its
        // legacy language names, so the added labels agree with Finder.
        NSBundle *finder=[NSBundle bundleWithPath:@"/System/Library/CoreServices/Finder.app"];
        if(bundle) ui_text_bundle=ui_localization(bundle,finder.preferredLocalizations ?: @[@"en"]);
    }
    return [ui_text_bundle localizedStringForKey:english value:english table:nil] ?: english;
}
static NSAttributedString *help_text(void) {
    NSFont *font=[NSFont systemFontOfSize:12];
    NSMutableParagraphStyle *paragraph=[NSMutableParagraphStyle new];
    paragraph.alignment=NSCenterTextAlignment;
    return [[NSAttributedString alloc] initWithString:AQText(AQHelpText)
        attributes:@{NSFontAttributeName:font,NSParagraphStyleAttributeName:paragraph}];
}
