/* Adapted from the user's MapsURLFix-2.m and CalendarETAFix.m.
 * Loaded only while handling a map request or serializing a directions request.
 * No MapKit/GeoServices dependency and no location/request logging. */
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonCrypto.h>
#include <math.h>
#include <stdint.h>

static NSString *const AQMapSession = @"6942069420694206942069420694206942067676";
static NSData *aq_map_bytes(NSString *s) { return [s dataUsingEncoding:NSUTF8StringEncoding]; }
static NSString *aq_map_nonce(void) {
    const char chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char nonce[17];
    for (unsigned i=0; i<16; i++) nonce[i] = chars[arc4random_uniform(62)];
    nonce[16]=0;
    return [NSString stringWithUTF8String:nonce];
}
static NSString *aq_map_escape(NSString *s) {
    /* The input is base64: these are its only non-alphanumeric characters.
     * Foundation-owned strings work in both retain/release and GC processes. */
    return [[[s stringByReplacingOccurrencesOfString:@"+" withString:@"%2B"]
        stringByReplacingOccurrencesOfString:@"/" withString:@"%2F"]
        stringByReplacingOccurrencesOfString:@"=" withString:@"%3D"];
}
static NSURL *aq_map_url(NSURL *original, long long expiry, NSString *nonce) {
    NSString *host = [[original host] lowercaseString], *scheme = [[original scheme] lowercaseString];
    NSArray *hosts = [NSArray arrayWithObjects:@"gspa35-ssl.ls.apple.com", @"gspa21.ls.apple.com",
        @"gspa19.ls.apple.com", @"gspa12.ls.apple.com", @"gspa11.ls.apple.com", nil];
    if (![hosts containsObject:host] || (![scheme isEqual:@"http"] && ![scheme isEqual:@"https"]) ||
        [original user] || [original password] ||
        ([original port] && [[original port] intValue] != ([scheme isEqual:@"http"] ? 80 : 443))) return nil;
    /* Work with the escaped path/query bytes. NSURL.path decodes %2F and spaces,
     * which would change both the request and the plaintext being signed. */
    NSString *absolute = [original absoluteString];
    if ([absolute length]>65536) return nil;
    NSRange authority = [absolute rangeOfString:@"://"];
    if (authority.location == NSNotFound) return nil;
    NSUInteger start = NSMaxRange(authority);
    NSRange rest = [absolute rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"/?#"]
        options:0 range:NSMakeRange(start, [absolute length]-start)];
    NSString *tail = rest.location == NSNotFound ? @"" : [absolute substringFromIndex:rest.location];
    NSRange hash = [tail rangeOfString:@"#"];
    NSString *fragment = hash.location == NSNotFound ? @"" : [tail substringFromIndex:hash.location];
    if (hash.location != NSNotFound) tail = [tail substringToIndex:hash.location];
    NSRange question = [tail rangeOfString:@"?"];
    NSString *path = question.location == NSNotFound ? tail : [tail substringToIndex:question.location];
    if (![path length]) path = @"/";
    NSString *query = question.location == NSNotFound ? @"" : [tail substringFromIndex:question.location+1];
    NSMutableArray *kept = [NSMutableArray array];
    NSArray *removed = [NSArray arrayWithObjects:@"tk", @"mapkey", @"sid", @"accessKey", nil];
    for (NSString *pair in [query componentsSeparatedByString:@"&"]) {
        if (![pair length]) continue;
        NSString *key = [[pair componentsSeparatedByString:@"="] objectAtIndex:0];
        key = [key stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
        if (![removed containsObject:key ?: @""]) [kept addObject:pair];
    }
    NSString *clean = [kept componentsJoinedByString:@"&"];
    NSString *newHost = [host stringByReplacingOccurrencesOfString:@"gspa" withString:@"gspe"];
    if ([newHost rangeOfString:@"-ssl"].location == NSNotFound)
        newHost = [newHost stringByReplacingOccurrencesOfString:@".ls.apple.com" withString:@"-ssl.ls.apple.com"];
    if (![host isEqual:@"gspa35-ssl.ls.apple.com"]) {
        if ([nonce length] != 16 || [nonce rangeOfCharacterFromSet:[[NSCharacterSet alphanumericCharacterSet] invertedSet]].location != NSNotFound) return nil;
        NSString *token = [@"4cjLaD4jGRwlQ9U72xIzEBe0vHBmf9" stringByAppendingString:nonce];
        NSData *tokenBytes = aq_map_bytes(token);
        unsigned char key[CC_SHA256_DIGEST_LENGTH], iv[kCCBlockSizeAES128] = {0};
        CC_SHA256([tokenBytes bytes], (CC_LONG)[tokenBytes length], key);
        NSString *pathQuery = [clean length] ? [NSString stringWithFormat:@"%@?%@&", path, clean] : [path stringByAppendingString:@"?"];
        NSData *plain = aq_map_bytes([NSString stringWithFormat:@"%@sid=%@%lld%@", pathQuery, AQMapSession, expiry, nonce]);
        NSMutableData *encrypted = [NSMutableData dataWithLength:[plain length]+kCCBlockSizeAES128];
        size_t length = 0;
        CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
            key, sizeof key, iv, [plain bytes], [plain length], [encrypted mutableBytes], [encrypted length], &length);
        if (status != kCCSuccess) return nil;
        [encrypted setLength:length];
        NSString *access = [NSString stringWithFormat:@"%lld_%@_%@", expiry, nonce,
            aq_map_escape([encrypted base64EncodedStringWithOptions:0])];
        clean = [NSString stringWithFormat:@"%@%@sid=%@&accessKey=%@", clean, [clean length] ? @"&" : @"", AQMapSession, access];
    }
    return [NSURL URLWithString:[NSString stringWithFormat:@"https://%@%@%@%@%@", newHost, path,
        [clean length] ? @"?" : @"", clean, fragment]];
}

/* Small protobuf encoder/parser. Preserve the native request verbatim except its
 * old waypoint field (2), which becomes typed-waypoint field 22. */
static void aq_varint(NSMutableData *out, uint64_t value) {
    do { unsigned char byte = value & 127; value >>= 7; if (value) byte |= 128; [out appendBytes:&byte length:1]; } while (value);
}
static void aq_uint(NSMutableData *out, unsigned tag, uint64_t value) { aq_varint(out, (uint64_t)tag<<3); aq_varint(out, value); }
static void aq_field(NSMutableData *out, unsigned tag, NSData *data) {
    aq_varint(out, ((uint64_t)tag<<3)|2); aq_varint(out, [data length]); [out appendData:data];
}
static void aq_double(NSMutableData *out, unsigned tag, double value) {
    aq_varint(out, ((uint64_t)tag<<3)|1);
    uint64_t bits; memcpy(&bits, &value, sizeof bits);
    for (unsigned i=0; i<8; i++) { unsigned char byte = bits >> (8*i); [out appendBytes:&byte length:1]; }
}
static BOOL aq_read_varint(NSData *data, NSUInteger *offset, uint64_t *value) {
    const unsigned char *p=[data bytes]; *value=0;
    for (unsigned shift=0; shift<64 && *offset<[data length]; shift+=7) {
        unsigned char b=p[(*offset)++];
        if (shift==63 && b>1) return NO;
        *value |= (uint64_t)(b&127)<<shift;
        if (!(b&128)) return YES;
    }
    return NO;
}
static NSMutableData *aq_without_waypoints(NSData *data, NSUInteger expected, BOOL *hasCount) {
    NSMutableData *out=[NSMutableData data]; NSUInteger offset=0, count=0; *hasCount=NO;
    while (offset<[data length]) {
        NSUInteger start=offset; uint64_t tag, length=0;
        if (!aq_read_varint(data,&offset,&tag) || !(tag>>3) || (tag>>3)>0x1fffffff || (tag>>3)==22) return nil;
        switch (tag&7) {
            case 0: if (!aq_read_varint(data,&offset,&length)) return nil; length=0; break;
            case 1: length=8; break;
            case 2: if (!aq_read_varint(data,&offset,&length)) return nil; break;
            case 5: length=4; break;
            default: return nil;
        }
        if (length>[data length]-offset) return nil;
        offset+=(NSUInteger)length;
        if ((tag>>3)==2) { if ((tag&7)!=2) return nil; count++; }
        else { [out appendData:[data subdataWithRange:NSMakeRange(start,offset-start)]]; if ((tag>>3)==3) *hasCount=YES; }
    }
    return count==expected ? out : nil;
}
static id aq_value(id object, NSString *key) { return [object valueForKey:key]; }
static NSData *aq_native_data(id object) {
    Class writerClass=NSClassFromString(@"PBDataWriter");
    if (!writerClass || ![object respondsToSelector:NSSelectorFromString(@"writeTo:")]) return nil;
    id writer=[[[writerClass alloc] init] autorelease];
    ((void(*)(id,SEL,id))objc_msgSend)(object, NSSelectorFromString(@"writeTo:"),writer);
    id result=((id(*)(id,SEL))objc_msgSend)(writer,NSSelectorFromString(@"data"));
    return [result isKindOfClass:[NSData class]] && [result length]<=4*1024*1024 ? result : nil;
}
static NSData *aq_typed_waypoint(id waypoint) {
    NSMutableData *typed=[NSMutableData data];
    id location=aq_value(waypoint,@"location");
    if (location) {
        NSData *payload=aq_native_data(location); if (!payload) return nil;
        NSMutableData *wrapped=[NSMutableData data]; aq_field(wrapped,1,payload);
        aq_uint(typed,1,4); aq_field(typed,4,wrapped); aq_uint(typed,5,1);
    } else {
        NSArray *points=aq_value(waypoint,@"entryPoints");
        if (![points isKindOfClass:[NSArray class]] || ![points count] || [points count]>4096) return nil;
        double lat=0, sinLng=0, cosLng=0;
        for (id point in points) {
            id y=aq_value(point,@"lat"), x=aq_value(point,@"lng");
            if (![x isKindOfClass:[NSNumber class]] || ![y isKindOfClass:[NSNumber class]]) return nil;
            double a=[y doubleValue], b=[x doubleValue];
            if (!isfinite(a) || !isfinite(b) || fabs(a)>90 || fabs(b)>180) return nil;
            lat+=a; sinLng+=sin(b*M_PI/180); cosLng+=cos(b*M_PI/180);
        }
        if (hypot(sinLng,cosLng)<1e-12) return nil;
        /* Circular longitude averaging keeps locations near +/-180 together. */
        double lng=atan2(sinLng,cosLng)*180/M_PI; lat/=[points count];
        NSMutableData *coordinate=[NSMutableData data], *identifier=[NSMutableData data];
        aq_double(coordinate,1,lat); aq_double(coordinate,2,lng);
        aq_field(identifier,3,coordinate); aq_uint(identifier,7,16);
        aq_uint(typed,1,2); aq_field(typed,2,identifier);
    }
    return typed;
}

@interface AQMapsAdapter : NSObject
+ (CFURLRef)copyRewrittenURL:(CFURLRef)url;
+ (BOOL)writeDirections:(id)request writer:(id)writer original:(void(*)(id,SEL,id))original;
@end
@implementation AQMapsAdapter
+ (CFURLRef)copyRewrittenURL:(CFURLRef)url {
    NSAutoreleasePool *pool=[[NSAutoreleasePool alloc] init]; CFURLRef result=NULL;
    @try {
        NSURL *mapped=aq_map_url((NSURL *)url,(long long)[[NSDate date] timeIntervalSince1970]+4200,aq_map_nonce());
        if (mapped) result=(CFURLRef)CFRetain((CFTypeRef)mapped);
    } @catch (NSException *e) { /* Leave unsupported URLs unchanged. */ }
    [pool drain]; return result;
}
+ (BOOL)writeDirections:(id)request writer:(id)writer original:(void(*)(id,SEL,id))original {
    NSAutoreleasePool *pool=[[NSAutoreleasePool alloc] init]; NSData *encoded=nil;
    @try {
        NSArray *waypoints=aq_value(request,@"waypoints");
        Class cls=NSClassFromString(@"PBDataWriter");
        if ([waypoints isKindOfClass:[NSArray class]] && [waypoints count] && [waypoints count]<=64 && [writer isKindOfClass:cls]) {
            NSMutableArray *typed=[NSMutableArray array];
            for (id waypoint in waypoints) { NSData *data=aq_typed_waypoint(waypoint); if (!data) break; [typed addObject:data]; }
            if ([typed count]==[waypoints count]) {
                id temporary=[[[cls alloc] init] autorelease];
                original(request,NSSelectorFromString(@"writeTo:"),temporary);
                NSData *native=((id(*)(id,SEL))objc_msgSend)(temporary,NSSelectorFromString(@"data"));
                BOOL hasCount=NO;
                NSMutableData *output=[native length]<=4*1024*1024 ? aq_without_waypoints(native,[typed count],&hasCount) : nil;
                if (output) {
                    if (!hasCount) aq_uint(output,3,3);
                    for (NSData *data in typed) aq_field(output,22,data);
                    encoded=[output retain];
                }
            }
        }
    } @catch (NSException *e) { /* A schema we cannot translate keeps native serialization. */ }
    BOOL handled=encoded!=nil;
    if (handled) ((BOOL(*)(id,SEL,id))objc_msgSend)(writer,NSSelectorFromString(@"writeData:"),encoded);
    [encoded release]; [pool drain]; return handled;
}
@end
