/* Included by the lazily loaded iCloud module. CF requests are opaque, not
 * toll-free bridged NSURLRequests. Never consume a body stream or log locations. */
@interface AQFindMyAdapter : NSObject
+ (BOOL)rewriteRequest:(void *)request;
@end
@implementation AQFindMyAdapter
+ (BOOL)rewriteRequest:(void *)request {
    CFURLRef (*getURL)(void *) = dlsym(RTLD_DEFAULT, "CFURLRequestGetURL");
    CFStringRef (*copyMethod)(void *) = dlsym(RTLD_DEFAULT, "CFURLRequestCopyHTTPRequestMethod");
    CFDataRef (*copyBody)(void *) = dlsym(RTLD_DEFAULT, "CFURLRequestCopyHTTPRequestBody");
    CFReadStreamRef (*copyStream)(void *) = dlsym(RTLD_DEFAULT, "CFURLRequestCopyHTTPRequestBodyStream");
    CFStringRef (*copyHeader)(void *, CFStringRef) = dlsym(RTLD_DEFAULT, "CFURLRequestCopyHTTPHeaderFieldValue");
    void (*setBody)(void *, CFDataRef) = dlsym(RTLD_DEFAULT, "CFURLRequestSetHTTPRequestBody");
    void (*setHeader)(void *, CFStringRef, CFStringRef) = dlsym(RTLD_DEFAULT, "CFURLRequestSetHTTPHeaderFieldValue");
    if (!request || !getURL || !copyMethod || !copyBody || !copyStream || !copyHeader || !setBody || !setHeader) return NO;
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    BOOL changed = NO;
    NSURL *url = (NSURL *)getURL(request);
    NSArray *path = [[url path] componentsSeparatedByString:@"/"];
    /* /fmipservice/findme/<dsprsid>/<hardware-udid>/currentLocation */
    if ([path count] != 6 || ![[path objectAtIndex:1] isEqual:@"fmipservice"] ||
        ![[path objectAtIndex:2] isEqual:@"findme"] || ![[path objectAtIndex:3] length] ||
        ![[path objectAtIndex:4] length] || ![[path objectAtIndex:5] isEqual:@"currentLocation"] ||
        [url user] || [url password] || [url query] || [url fragment]) { [pool drain]; return NO; }
    CFStringRef method = copyMethod(request);
    BOOL post = method && [(NSString *)method isEqual:@"POST"];
    if (method) CFRelease(method);
    CFReadStreamRef stream = copyStream(request);
    if (stream) CFRelease(stream);
    CFStringRef encoding = copyHeader(request, CFSTR("Content-Encoding"));
    BOOL plain = !encoding || ![(NSString *)encoding length] || [[(NSString *)encoding lowercaseString] isEqual:@"identity"];
    if (encoding) CFRelease(encoding);
    if (post && !stream && plain) {
        CFDataRef data = copyBody(request);
        if (data && CFDataGetLength(data) > 0 && CFDataGetLength(data) <= 1024*1024) {
            id json = [NSJSONSerialization JSONObjectWithData:(NSData *)data options:NSJSONReadingMutableContainers error:NULL];
            if ([json isKindOfClass:[NSMutableDictionary class]] && ![json objectForKey:@"positionType"]) {
                [json setObject:@"" forKey:@"positionType"];
                NSData *body = [NSJSONSerialization dataWithJSONObject:json options:0 error:NULL];
                if (body) {
                    setBody(request, (CFDataRef)body);
                    setHeader(request, CFSTR("Content-Length"), NULL);
                    changed = YES;
                }
            }
        }
        if (data) CFRelease(data);
    }
    [pool drain];
    return changed;
}
@end
