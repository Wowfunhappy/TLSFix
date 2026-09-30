/* Keep the first sentence of the text loaded from Finder's localized nib,
 * including its native attributes. Sentence boundaries are locale aware. */
static Ivar finder_info_text_ivar;
static void (*finder_original_info_text)(id,SEL);
@interface NSObject (AQFinderInfo)
- (void)invalidateInfoViewImage;
@end
static NSAttributedString *first_info_sentence(NSAttributedString *text) {
    NSString *string=text.string;
    __block NSRange first=NSMakeRange(0,string.length);
    [string enumerateSubstringsInRange:first options:NSStringEnumerationBySentences|NSStringEnumerationLocalized
        usingBlock:^(NSString *substring,NSRange range,NSRange enclosing,BOOL *stop) {
            (void)substring; (void)enclosing; first=range; *stop=YES;
        }];
    NSCharacterSet *space=[NSCharacterSet whitespaceAndNewlineCharacterSet];
    while(first.length && [space characterIsMember:[string characterAtIndex:NSMaxRange(first)-1]]) --first.length;
    return [text attributedSubstringFromRange:first];
}
static void shorten_info_field(NSTextField *field) {
    if(!field || !field.stringValue.length) return;
    field.attributedStringValue=first_info_sentence(field.attributedStringValue);
    NSRect frame=field.frame;
    CGFloat height=ceil([field.cell cellSizeForBounds:NSMakeRect(0,0,NSWidth(frame),1000)].height);
    frame.origin.y=NSMaxY(frame)-height; frame.size.height=height;
    field.frame=frame;
}
static void finder_update_info_text(id controller,SEL selector) {
    finder_original_info_text(controller,selector);
    shorten_info_field(object_getIvar(controller,finder_info_text_ivar));
    [controller invalidateInfoViewImage];
}
