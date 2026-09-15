/* Keep native sender/archive operations; adapt only modern wire metadata. */
static NSData *(*original_ask_body)(id,SEL,NSInteger);
static void (*original_send_request)(id,SEL,CFStringRef);
static void (*original_received_response)(id,SEL,const void *);
static const void *(*original_create_connection)(CFAllocatorRef,const void *,const void *,CFDictionaryRef);
static const void *(*copy_mutable_request)(CFAllocatorRef,const void *);
static void (*set_request_header)(const void *,CFStringRef,CFStringRef);
static CFHTTPMessageRef (*response_message)(const void *);
static __thread void *outgoing_client;
static char transfer_key;
static NSString *transfer_id(id client) {
    NSString *identifier=objc_getAssociatedObject(client,&transfer_key);
    if(!identifier) { identifier=[[NSUUID UUID] UUIDString]; objc_setAssociatedObject(client,&transfer_key,identifier,OBJC_ASSOCIATION_COPY_NONATOMIC); }
    return identifier;
}
static NSData *ask_body(id client,SEL selector,NSInteger format) {
    NSData *native=original_ask_body(client,selector,format);
    id fields=[NSPropertyListSerialization propertyListWithData:native options:NSPropertyListMutableContainers format:NULL error:NULL];
    if(![fields isKindOfClass:[NSMutableDictionary class]]) return native;
    // Modern discovery here advertises Everyone mode without an Apple ID
    // identity. A legacy email hash makes Mavericks demand client-certificate
    // proof and reject the offer before the ordinary acceptance prompt.
    [fields removeObjectForKey:@"SenderEmailHash"];
    fields[@"SenderModelName"]=capabilities()[@"ReceiverModelName"];
    fields[@"ConvertMediaFormats"]=@NO;
    fields[@"TransferID"]=@{@"id":transfer_id(client)};
    fields[@"TransferType"]=@{@"files":@{}};
    NSLog(@"AquaTransport AirDrop: native outgoing offer prepared (%lu files)",(unsigned long)[fields[@"Files"] count]);
    return [NSPropertyListSerialization dataWithPropertyList:fields format:(NSPropertyListFormat)format options:0 error:NULL] ?: native;
}
static void send_request(id client,SEL selector,CFStringRef operation) {
    void *previous=outgoing_client; outgoing_client=(__bridge void *)client;
    @try { original_send_request(client,selector,operation); } @finally { outgoing_client=previous; }
}
static const void *create_connection(CFAllocatorRef allocator,const void *request,const void *callbacks,CFDictionaryRef nativeProperties) {
    if(!outgoing_client) return original_create_connection(allocator,request,callbacks,nativeProperties);
    id client=(__bridge id)outgoing_client;
    const void *modified=copy_mutable_request(allocator,request);
    if(!modified) return original_create_connection(allocator,request,callbacks,nativeProperties);
    set_request_header(modified,CFSTR("TransferID"),(__bridge CFStringRef)transfer_id(client));
    CFStringRef *streams=dlsym(RTLD_DEFAULT,"kCFURLConnectionSocketStreamProperties");
    CFStringRef *bound=dlsym(RTLD_DEFAULT,"kCFStreamPropertyBoundInterfaceIdentifier");
    CFStringRef *interface=dlsym(RTLD_DEFAULT,"kCFStreamPropertyInterfaceIdentifier");
    NSMutableDictionary *properties=nativeProperties ? [(__bridge NSDictionary *)nativeProperties mutableCopy] : [NSMutableDictionary dictionary];
    if(streams && bound && interface) {
        NSMutableDictionary *socket=[properties[(__bridge NSString *)*streams] mutableCopy] ?: [NSMutableDictionary dictionary];
        socket[(__bridge NSString *)*bound]=@"tap0"; socket[(__bridge NSString *)*interface]=@"tap0";
        properties[(__bridge NSString *)*streams]=socket;
    }
    const void *connection=original_create_connection(allocator,modified,callbacks,(__bridge CFDictionaryRef)properties);
    CFRelease(modified); return connection;
}
static void received_response(id client,SEL selector,const void *response) {
    CFHTTPMessageRef message=response_message(response);
    NSLog(@"AquaTransport AirDrop: native outgoing HTTP %ld",message ? (long)CFHTTPMessageGetResponseStatusCode(message) : 0);
    original_received_response(client,selector,response);
}
