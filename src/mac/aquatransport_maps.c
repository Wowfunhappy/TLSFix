/* Lazy map support. Never load Foundation from a dyld callback or constructor.
 * The callback only replaces an existing Objective-C method with a C trampoline;
 * the separate module loads when that method or a map URL is actually used. */
#include "aquatransport_maps.h"
#include "aquatransport_config.h"
#include "../../deps/fishhook/fishhook.h"
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

static pthread_once_t maps_once = PTHREAD_ONCE_INIT;
static pthread_once_t runtime_once = PTHREAD_ONCE_INIT;
static void (*native_write)(void *, void *, void *);
static void *(*get_class)(const char *);
static void *(*selector)(const char *);
static void *send_message;
static void *(*native_dlopen)(const char *, int);
static int geo_seen;
static pthread_mutex_t hook_lock = PTHREAD_MUTEX_INITIALIZER;

static void resolve_runtime(void) {
    get_class=dlsym(RTLD_DEFAULT,"objc_getClass");
    selector=dlsym(RTLD_DEFAULT,"sel_registerName");
    send_message=dlsym(RTLD_DEFAULT,"objc_msgSend");
}
static int runtime_ready(void) {
    if (!dlsym(RTLD_DEFAULT,"objc_getClass")) return 0;
    pthread_once(&runtime_once,resolve_runtime);
    return get_class && selector && send_message;
}

static int maps_supported(void) {
    struct utsname os;
    return !uname(&os) && atoi(os.release) == 13;
}
static void load_maps(void) {
    Dl_info info; char path[1024];
    if (!dladdr((void *)&load_maps, &info) || !info.dli_fname) return;
    const char *slash = strrchr(info.dli_fname, '/');
    if (!slash || snprintf(path, sizeof path, "%.*s/aquatransport_maps.dylib",
        (int)(slash-info.dli_fname), info.dli_fname) >= sizeof path) return;
    if (!dlopen(path, RTLD_NOW | RTLD_LOCAL))
        tf_log("Maps compatibility module could not be loaded");
}
static void *maps_class(void) {
    if (tf_flag("disable-maps-fixes") || !maps_supported()) return NULL;
    if (!runtime_ready() || !get_class("NSURLConnection")) return NULL;
    pthread_once(&maps_once, load_maps);
    return get_class("AQMapsAdapter");
}
static void maps_write(void *request, void *cmd, void *writer) {
    void *cls = maps_class();
    signed char handled = cls ? ((signed char (*)(void *, void *, void *, void *, void *))send_message)(
        cls, selector("writeDirections:writer:original:"), request, writer, (void *)native_write) : 0;
    if (!handled) native_write(request, cmd, writer);
}
static void install_eta(void) {
    if (native_write || tf_flag("disable-maps-fixes")) return;
    if (!runtime_ready()) return;
    void *(*get_method)(void *, void *) = dlsym(RTLD_DEFAULT, "class_getInstanceMethod");
    void *(*implementation)(void *) = dlsym(RTLD_DEFAULT, "method_getImplementation");
    void (*return_type)(void *, char *, size_t) = dlsym(RTLD_DEFAULT, "method_getReturnType");
    unsigned (*argument_count)(void *) = dlsym(RTLD_DEFAULT, "method_getNumberOfArguments");
    void *(*set_implementation)(void *, void *) = dlsym(RTLD_DEFAULT, "method_setImplementation");
    if (!get_class || !selector || !get_method || !implementation || !return_type || !argument_count || !set_implementation) return;
    void *cls = get_class("GEODirectionsRequest");
    void *method = cls ? get_method(cls, selector("writeTo:")) : NULL;
    char type[8] = {0};
    if (!method || argument_count(method) != 3) return;
    return_type(method, type, sizeof type);
    if (strcmp(type, "v")) return;
    void *original = implementation(method);
    Dl_info owner;
    if (!dladdr(original, &owner) || !owner.dli_fname || !strstr(owner.dli_fname, "/GeoServices.framework/")) return;
    native_write = original;
    set_implementation(method, (void *)&maps_write);
}
static void try_eta(void) {
    pthread_mutex_lock(&hook_lock);
    install_eta();
    pthread_mutex_unlock(&hook_lock);
}
static void maps_image(const struct mach_header *header, intptr_t slide) {
    (void)slide;
    Dl_info image;
    if (!dladdr(header, &image) || !image.dli_fname ||
        !strstr(image.dli_fname, "/GeoServices.framework/")) return;
    __sync_lock_test_and_set(&geo_seen,1);
    try_eta();
}
static void *maps_dlopen(const char *path, int flags) {
    void *image=native_dlopen(path, flags);
    /* On a late load, dyld announces the image before ObjC registers its classes.
     * Retry after dlopen returns, when registration is complete. */
    if (image && __sync_fetch_and_add(&geo_seen,0)) try_eta();
    return image;
}
void tf_maps_install(void) {
    if (maps_supported() && !tf_flag("disable-maps-fixes")) {
        native_dlopen=dlsym(RTLD_DEFAULT,"dlopen");
        if (!native_dlopen) return;
        struct rebinding hook={"dlopen", (void *)&maps_dlopen, NULL};
        rebind_symbols(&hook,1);
        _dyld_register_func_for_add_image(maps_image);
    }
}
char *tf_maps_rewrite_url(const char *url) {
    /* A narrow C prefilter keeps Objective-C out of unrelated URL requests. */
    const char *host;
    if (!strncasecmp(url, "https://", 8)) host = url+8;
    else if (!strncasecmp(url, "http://", 7)) host = url+7;
    else return NULL;
    static const char *hosts[] = { "gspa35-ssl.ls.apple.com", "gspa21.ls.apple.com",
        "gspa19.ls.apple.com", "gspa12.ls.apple.com", "gspa11.ls.apple.com" };
    int matched=0;
    for (unsigned i=0; i<sizeof hosts/sizeof hosts[0]; i++) {
        size_t n=strlen(hosts[i]);
        if (!strncasecmp(host, hosts[i], n) && (!host[n] || strchr("/:?#",host[n]))) { matched=1; break; }
    }
    if (!matched) return NULL;
    void *cls = maps_class();
    if (!cls) return NULL;
    CFStringRef string = CFStringCreateWithCString(NULL, url, kCFStringEncodingUTF8);
    CFURLRef original = string ? CFURLCreateWithString(NULL, string, NULL) : NULL;
    CFURLRef rewritten = original ? ((CFURLRef (*)(void *, void *, CFURLRef))send_message)(
        cls, selector("copyRewrittenURL:"), original) : NULL;
    char *result = NULL;
    if (rewritten) {
        CFStringRef value = CFURLGetString(rewritten);
        CFIndex size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(value), kCFStringEncodingUTF8)+1;
        result = malloc(size);
        if (result && !CFStringGetCString(value, result, size, kCFStringEncodingUTF8)) { free(result); result = NULL; }
        CFRelease(rewritten);
    }
    if (original) CFRelease(original);
    if (string) CFRelease(string);
    return result;
}
