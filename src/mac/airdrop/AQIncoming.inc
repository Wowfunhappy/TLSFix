/* The native archive copier recognizes archive completion before HTTP EOF.
 * Modern senders can leave the chunked upload open awaiting our response.
 * Mavericks otherwise joins its adaptive decompression worker first, which
 * waits forever for another HTTP chunk. Once BOM has returned, nobody consumes
 * that worker's output: close its input, then let the original join, status,
 * file placement, metadata, and response code run unchanged. */
static int (*original_zipper_copy)(id,SEL,id,id,id);
static int (*original_bom_copy)(void *,const char *,const char *,CFDictionaryRef);
static void *(*bom_user_data)(void *);
static Ivar zipper_compression_engine;
static __thread CFReadStreamRef incoming_consumed_stream;
static __thread void *incoming_zipper;

static int incoming_bom_copy(void *copier,const char *source,const char *destination,CFDictionaryRef options) {
    int result=original_bom_copy(copier,source,destination,options);
    if(incoming_consumed_stream && incoming_zipper && bom_user_data(copier)==incoming_zipper) {
        // Also release the producer on a native copy error; retain that error.
        CFReadStreamClose(incoming_consumed_stream);
        NSLog(@"AquaTransport AirDrop: native archive copier finished (%d); released receive stream",result);
    }
    return result;
}
static int incoming_copy(id zipper,SEL selector,id source,id destination,id options) {
    CFReadStreamRef previous_stream=incoming_consumed_stream;
    void *previous_zipper=incoming_zipper;
    CFReadStreamRef stream=NULL;
    // Scope the C hook to this native inbound adaptive-copy invocation only.
    if(!source && destination && object_getIvar(zipper,zipper_compression_engine)) {
        SEL is_decompressor=@selector(isDecompressor);
        if(((BOOL (*)(id,SEL))[zipper methodForSelector:is_decompressor])(zipper,is_decompressor)) {
            SEL copy_stream=@selector(copyReadStream);
            stream=((CFReadStreamRef (*)(id,SEL))[zipper methodForSelector:copy_stream])(zipper,copy_stream);
        }
    }
    incoming_consumed_stream=stream;
    incoming_zipper=stream ? (__bridge void *)zipper : NULL;
    int result;
    @try { result=original_zipper_copy(zipper,selector,source,destination,options); }
    @finally {
        incoming_consumed_stream=previous_stream;
        incoming_zipper=previous_zipper;
        if(stream) CFRelease(stream);
    }
    return result;
}
