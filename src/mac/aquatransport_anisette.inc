/* Native device authentication. Apple owns the cryptography and ADI storage.
 * Our per-user file contains only the hardware UUID, routing and retry time.
 * Never reset existing ADI state or fetch code/device headers from a server. */
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static struct {
    int (*otp)(uint64_t, void **, uint32_t *, void **, uint32_t *);
    int (*start)(uint64_t, const void *, uint32_t, void **, uint32_t *, uint32_t *);
    int (*finish)(uint32_t, const void *, uint32_t, const void *, uint32_t);
    int (*destroy)(uint32_t);
    int (*dispose)(void *);
    int (*state)(uint64_t);
} AQADI;

/* These named AOSKit wrappers have identical ABIs in both Intel slices.
 * They are local Mach-O symbols, so dlsym cannot retrieve them. Resolve only
 * defined functions in Apple's loaded framework; never patch the framework.
 * Missing/stripped symbols fail closed. No offsets or alternate providers. */
static void *aq_adi_symbol(const char *wanted) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *path = _dyld_get_image_name(i);
        const char *prefix = "/System/Library/PrivateFrameworks/AOSKit.framework/";
        if (!path || strncmp(path, prefix, strlen(prefix))) continue;
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h->magic != MH_MAGIC && h->magic != MH_MAGIC_64) return NULL;
        BOOL wide = h->magic == MH_MAGIC_64;
        uintptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const char *begin = (const char *)h + (wide ? sizeof(struct mach_header_64) : sizeof(*h));
        const char *end = begin + h->sizeofcmds;
        const struct symtab_command *symbols = NULL;
        uint64_t vm = 0, offset = 0, size = 0, textStart = 0, textEnd = 0;
        const struct load_command *c = (const void *)begin;
        for (uint32_t j = 0; j < h->ncmds; j++) {
            if ((const char *)c > end - sizeof(*c) || c->cmdsize < sizeof(*c) || c->cmdsize > (size_t)(end - (const char *)c)) return NULL;
            if (c->cmd == LC_SYMTAB && c->cmdsize >= sizeof(*symbols)) symbols = (const void *)c;
            uint64_t addr = 0, length = 0, fileOffset = 0, fileSize = 0;
            const char *name = NULL; vm_prot_t protection = 0;
            if (c->cmd == LC_SEGMENT_64 && c->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *s = (const void *)c;
                addr = s->vmaddr; length = s->vmsize; fileOffset = s->fileoff; fileSize = s->filesize; name = s->segname; protection = s->initprot;
            } else if (c->cmd == LC_SEGMENT && c->cmdsize >= sizeof(struct segment_command)) {
                const struct segment_command *s = (const void *)c;
                addr = s->vmaddr; length = s->vmsize; fileOffset = s->fileoff; fileSize = s->filesize; name = s->segname; protection = s->initprot;
            }
            if (name && !strncmp(name, SEG_LINKEDIT, 16)) { vm = addr; offset = fileOffset; size = MIN(length, fileSize); }
            if (name && !strncmp(name, SEG_TEXT, 16) && (protection & VM_PROT_EXECUTE)) { textStart = addr; textEnd = addr + length; }
            c = (const void *)((const char *)c + c->cmdsize);
        }
        uint64_t stride = wide ? sizeof(struct nlist_64) : sizeof(struct nlist);
        if (!symbols || !vm || !textEnd || symbols->symoff < offset || symbols->stroff < offset ||
            (uint64_t)symbols->symoff + stride * symbols->nsyms > offset + size ||
            (uint64_t)symbols->stroff + symbols->strsize > offset + size) return NULL;
        uintptr_t base = slide + (uintptr_t)vm - (uintptr_t)offset;
        const char *strings = (const void *)(base + symbols->stroff);
        for (uint32_t j = 0; j < symbols->nsyms; j++) {
            uint32_t name; uint64_t value; uint8_t type;
            if (wide) {
                const struct nlist_64 *n = (const void *)(base + symbols->symoff);
                name = n[j].n_un.n_strx; value = n[j].n_value; type = n[j].n_type;
            } else {
                const struct nlist *n = (const void *)(base + symbols->symoff);
                name = n[j].n_un.n_strx; value = n[j].n_value; type = n[j].n_type;
            }
            size_t length = strlen(wanted) + 1;
            if (!(type & N_STAB) && (type & N_TYPE) == N_SECT && value >= textStart && value < textEnd &&
                name < symbols->strsize && length <= symbols->strsize - name && !memcmp(strings + name, wanted, length))
                return (void *)(slide + (uintptr_t)value);
        }
    }
    return NULL;
}

static BOOL aq_adi_load(void) {
    static void *framework;
    if (!framework) framework = dlopen("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit", RTLD_LAZY | RTLD_LOCAL);
    if (!framework) return NO;
    /* Trigger +initialize, without the broken 32-bit DSID conversion in
     * retrieveOTPHeadersForDSID:. Always pass the full uint64_t -2 below. */
    [NSClassFromString(@"AOSUtilities") class];
    if (!AQADI.otp) {
        AQADI.otp = aq_adi_symbol("_qi864985u0");
        AQADI.start = aq_adi_symbol("_rsegvyrt87");
        AQADI.finish = aq_adi_symbol("_uv5t6nhkui");
        AQADI.destroy = aq_adi_symbol("_fy34trz2st");
        AQADI.dispose = aq_adi_symbol("_jk24uiwqrg");
        AQADI.state = aq_adi_symbol("_aslgmuibau");
    }
    return AQADI.otp && AQADI.start && AQADI.finish && AQADI.destroy && AQADI.dispose && AQADI.state;
}

static NSString *aq_adi_routing(id value) {
    NSString *s = [value isKindOfClass:[NSNumber class]] ? [value stringValue] : aq_string(value);
    if (![s length] || [s length] > 20 || [s rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789"] invertedSet]].location != NSNotFound) return nil;
    errno = 0;
    if (!strtoull([s UTF8String], NULL, 10) || errno == ERANGE) return nil;
    return s;
}

static int aq_adi_lock(NSError **error) {
    NSString *directory = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/AquaTransport"];
    struct stat st;
    if (mkdir([directory fileSystemRepresentation], 0700) && errno != EEXIST) goto failed;
    if (lstat([directory fileSystemRepresentation], &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077)) goto failed;
    NSString *path = [directory stringByAppendingPathComponent:@"anisette.plist"];
    int fd = open([path fileSystemRepresentation], O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) goto failed;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 || (st.st_mode & 077) || st.st_size > 4096) { close(fd); goto failed; }
    if (flock(fd, LOCK_EX | LOCK_NB)) {
        close(fd); *error = aq_error(14, @"Local device authentication is in use by another process. Try again shortly."); return -1;
    }
    return fd;
failed:
    *error = aq_error(14, @"Cannot securely open local device authentication metadata."); return -1;
}
static NSMutableDictionary *aq_adi_read(int fd) {
    unsigned char data[4096]; ssize_t n = pread(fd, data, sizeof data, 0);
    NSDictionary *d = n > 0 ? aq_plist([NSData dataWithBytes:data length:n]) : nil;
    return d ? [[d mutableCopy] autorelease] : [NSMutableDictionary dictionary];
}
static BOOL aq_adi_save(int fd, NSDictionary *record) {
    NSData *data = aq_encode(record);
    return [data length] && [data length] <= 4096 && pwrite(fd, [data bytes], [data length], 0) == (ssize_t)[data length] &&
        !ftruncate(fd, [data length]) && !fsync(fd);
}
static NSData *aq_adi_decode(id value) {
    NSString *s = aq_string(value);
    NSData *ascii = [s dataUsingEncoding:NSASCIIStringEncoding]; NSUInteger n = [ascii length];
    if (!n || n % 4 || n > 1024*1024) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:n];
    const unsigned char *p = [ascii bytes];
    int length = EVP_DecodeBlock([out mutableBytes], p, (int)n);
    if (length <= 0) return nil;
    if (p[n-1] == '=') length--;
    if (p[n-2] == '=') length--;
    [out setLength:length]; return length ? out : nil;
}
static BOOL aq_adi_url(NSString *s) {
    NSURL *u = s ? [NSURL URLWithString:s] : nil;
    return [[u scheme] isEqual:@"https"] && [[u host] isEqual:@"gsa.apple.com"] &&
        (![u port] || [[u port] intValue] == 443) && ![u user] && ![u password] && ![u query] && ![u fragment] &&
        [[u path] hasPrefix:@"/grandslam/"];
}
static NSDictionary *aq_adi_request(AQGSAProtocol *owner, NSString *url, NSDictionary *payload, NSString *device, NSError **error) {
    if (!aq_adi_url(url)) { *error = aq_error(15, @"Apple returned an invalid device provisioning URL."); return nil; }
    NSMutableURLRequest *req = aq_apple_request(url, [NSDictionary dictionaryWithObjectsAndKeys:
        device, @"X-Mme-Device-Id", aq_base64([device dataUsingEncoding:NSUTF8StringEncoding]), @"X-Apple-I-MD-LU",
        @"Setup", @"X-Apple-Client-App-Name", nil]);
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    if (payload) {
        [req setHTTPMethod:@"POST"];
        [req setHTTPBody:aq_encode([NSDictionary dictionaryWithObjectsAndKeys:[NSDictionary dictionary], @"Header", payload, @"Request", nil])];
    }
    NSHTTPURLResponse *response = nil;
    NSData *data = aq_send(owner, req, &response, error);
    if (!data) return nil;
    NSDictionary *result = aq_plist(data);
    if ([response statusCode] != 200 || !result) { *error = aq_error(15, @"Apple device provisioning failed."); return nil; }
    return result;
}
static NSString *aq_adi_provision(AQGSAProtocol *owner, NSString *device, int fd, NSMutableDictionary *record, NSError **error) {
    /* Exactly lookup/start/finish, no retry and no Apple ID or password. */
    NSDictionary *bag = aq_dict([aq_adi_request(owner, @"https://gsa.apple.com/grandslam/GsService2/lookup", nil, device, error) objectForKey:@"urls"]);
    NSString *begin = aq_string([bag objectForKey:@"midStartProvisioning"]), *end = aq_string([bag objectForKey:@"midFinishProvisioning"]);
    if (!aq_adi_url(begin) || !aq_adi_url(end)) { if (!*error) *error = aq_error(15, @"Apple returned an invalid device provisioning lookup."); return nil; }
    NSDictionary *reply = aq_dict([aq_adi_request(owner, begin, [NSDictionary dictionary], device, error) objectForKey:@"Response"]);
    NSData *spim = aq_adi_decode([reply objectForKey:@"spim"]);
    if (!spim) { if (!*error) *error = aq_error(15, @"Apple returned invalid provisioning data."); return nil; }
    void *cpim = NULL; uint32_t length = 0, session = 0;
    int status = AQADI.start((uint64_t)-2, [spim bytes], (uint32_t)[spim length], &cpim, &length, &session);
    BOOL started = !status, finished = NO; NSString *routing = nil;
    @try {
        if (status || !cpim || !length || length > 1024*1024) { *error = aq_error(16, @"Native device provisioning could not start."); return nil; }
        NSString *encoded = aq_base64([NSData dataWithBytes:cpim length:length]);
        AQADI.dispose(cpim); cpim = NULL;
        reply = aq_dict([aq_adi_request(owner, end, [NSDictionary dictionaryWithObject:encoded forKey:@"cpim"], device, error) objectForKey:@"Response"]);
        NSData *ptm = aq_adi_decode([reply objectForKey:@"ptm"]), *tk = aq_adi_decode([reply objectForKey:@"tk"]);
        routing = aq_adi_routing([reply objectForKey:@"X-Apple-I-MD-RINFO"]);
        if (!ptm || !tk || !routing) { if (!*error) *error = aq_error(15, @"Apple returned invalid provisioning data or routing."); return nil; }
        if ([owner isStopped]) { *error = aq_error(NSUserCancelledError, @"Sign-in cancelled."); return nil; }
        /* Persist routing before committing native state, so interruption cannot
         * leave a newly provisioned device with an unknown routing value. */
        [record setObject:routing forKey:@"routing"];
        if (!aq_adi_save(fd, record)) { *error = aq_error(14, @"Could not save Apple's device routing information."); return nil; }
        status = AQADI.finish(session, [ptm bytes], (uint32_t)[ptm length], [tk bytes], (uint32_t)[tk length]);
        if (status) { *error = aq_error(16, @"Native device provisioning could not finish."); return nil; }
        finished = YES;
    } @finally {
        if (cpim) AQADI.dispose(cpim);
        if (started && !finished) AQADI.destroy(session);
    }
    return routing;
}

/* Caller holds the per-user lock and has initialized the native ABI. */
static NSDictionary *aq_adi_headers(AQGSAProtocol *owner, NSString *device, int fd, NSError **error) {
    NSMutableDictionary *record = aq_adi_read(fd);
    NSString *routing = [[record objectForKey:@"device"] isEqual:device] ? aq_adi_routing([record objectForKey:@"routing"]) : nil;
    int state = AQADI.state((uint64_t)-2);
    if (state == -45061) {
        id attempt = [record objectForKey:@"lastAttempt"];
        if ([attempt isKindOfClass:[NSDate class]] && [attempt timeIntervalSinceNow] > -86400) {
            *error = aq_error(17, @"Local device provisioning was already attempted. It can be retried after 24 hours."); return nil;
        }
        [record removeAllObjects]; [record setObject:device forKey:@"device"];
        [record setObject:[NSDate date] forKey:@"lastAttempt"];
        if (!aq_adi_save(fd, record)) { *error = aq_error(14, @"Could not save the device provisioning attempt."); return nil; }
        routing = aq_adi_provision(owner, device, fd, record, error);
        if (!routing) return nil;
    } else if (state) { *error = aq_error(12, @"Native device provisioning state is unavailable."); return nil; }
    if (!routing) { *error = aq_error(18, @"This device is provisioned but its Apple routing record is missing. Existing native state has been preserved."); return nil; }
    void *machine = NULL, *otp = NULL; uint32_t ml = 0, ol = 0;
    int status = AQADI.otp((uint64_t)-2, &machine, &ml, &otp, &ol);
    @try {
        if (status || !machine || !otp || !ml || !ol || ml > 12288 || ol > 12288) { *error = aq_error(12, @"Native device authentication returned no usable OTP."); return nil; }
        return [NSDictionary dictionaryWithObjectsAndKeys:
            aq_base64([NSData dataWithBytes:machine length:ml]), @"X-Apple-MD-M",
            aq_base64([NSData dataWithBytes:otp length:ol]), @"X-Apple-MD", routing, @"X-Apple-I-MD-RINFO", nil];
    } @finally { if (machine) AQADI.dispose(machine); if (otp) AQADI.dispose(otp); }
}

@interface AQNativeAnisetteGenerator : NSObject
+ (NSDictionary *)headersForOwner:(AQGSAProtocol *)owner error:(NSError **)error;
@end
@implementation AQNativeAnisetteGenerator
+ (NSDictionary *)headersForOwner:(AQGSAProtocol *)owner error:(NSError **)error {
    @synchronized(self) {
        if (!aq_adi_load()) { *error = aq_error(10, @"This Apple framework does not expose the required native device authentication routines."); return nil; }
        NSString *device = aq_device_field(aq_device_uuid());
        if (!device) { *error = aq_error(13, @"This Mac has no hardware UUID."); return nil; }
        int fd = aq_adi_lock(error); if (fd < 0) return nil;
        @try { return aq_adi_headers(owner, device, fd, error); }
        @finally { flock(fd, LOCK_UN); close(fd); }
    }
}
@end
