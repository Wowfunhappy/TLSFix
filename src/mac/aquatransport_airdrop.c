/* Early, narrow AirDrop entry point. No Objective-C or IOKit work in a dyld
 * callback/constructor. The native sharingd main calls this CFNetwork function
 * before constructing SharingDaemon; the full adapter loads at that boundary. */
#include "aquatransport_airdrop.h"
#include "aquatransport_airdrop_policy.h"
#include "aquatransport_config.h"
#include "../../deps/fishhook/fishhook.h"
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static void (*native_cache_limit)(int,int);
static pthread_once_t load_once=PTHREAD_ONCE_INIT;
static int adapter_active;
int tf_airdrop_active(void) { return adapter_active; }
static int tap_available(void) { struct stat st; return !lstat("/dev/tap0",&st) && S_ISCHR(st.st_mode); }
static int trusted_file(const char *path) {
    struct stat st; char parent[1024];
    if(!path || path[0]!='/' || strlen(path)>=sizeof(parent) ||
       lstat(path,&st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode&022)) return 0;
    strcpy(parent,path);
    char *slash;
    while((slash=strrchr(parent,'/')) && slash!=parent) {
        *slash=0;
        if(lstat(parent,&st) || !S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode&022)) return 0;
    }
    return 1;
}
#include "aquatransport_airdrop_hardware.h"
static void load_adapter(void) {
    if(tf_flag("disable-airdrop") || !tap_available()) return;
    if(!trusted_file("/usr/share/aquatransport/airdrop/org.aquatransport.airdrop") ||
       !trusted_file("/usr/share/aquatransport/airdrop/org.aquatransport.airdrop.plist") ||
       !trusted_file("/usr/share/aquatransport/airdrop/owl") ||
       !trusted_file("/usr/share/aquatransport/airdrop/ad_ble_wake")) return;
    const struct mach_header *header=_dyld_get_image_header(0);
    if(!header || header->magic!=MH_MAGIC_64) return;
    static const unsigned char supported_uuid[16]={0xc4,0xfa,0x48,0x77,0x6f,0x18,0x37,0x15,0xa5,0xc8,0xde,0xdf,0x90,0x26,0xbd,0xf9};
    const struct load_command *command=(const void *)((const struct mach_header_64 *)header+1); int native_verified=0;
    for(uint32_t i=0;i<header->ncmds;i++,command=(const void *)((const char *)command+command->cmdsize)) {
        if(command->cmd==LC_UUID && command->cmdsize==sizeof(struct uuid_command)) native_verified=!memcmp(((const struct uuid_command *)command)->uuid,supported_uuid,16);
    }
    if(!native_verified) return;
    char interface[32]={0}; if(!hardware_supported(interface,sizeof(interface))) return;
    Dl_info owner; char path[1024];
    if(!dladdr((void *)&load_adapter,&owner) || !owner.dli_fname) return;
    const char *slash=strrchr(owner.dli_fname,'/'); if(!slash) return;
    int length=snprintf(path,sizeof(path),"%.*s/aquatransport_airdrop.dylib",(int)(slash-owner.dli_fname),owner.dli_fname);
    if(length<0 || (size_t)length>=sizeof(path)) return;
    if(!trusted_file(path)) return;
    /* Module checks the complete native API set before installing any hooks. */
    void *module=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if(module) {
        int (*installed)(void)=dlsym(module,"AQAirDropInstalled");
        adapter_active=installed && installed();
    }
    if(!module && tf_debug()) tf_log("AirDrop adapter unavailable: %s",dlerror());
}
static void air_drop_cache_limit(int connection_type,int limit) {
    pthread_once(&load_once,load_adapter);
    native_cache_limit(connection_type,limit);
}
void tf_airdrop_install(void) {
    struct utsname os; char executable[1024]; uint32_t size=sizeof(executable);
    if(uname(&os) || _NSGetExecutablePath(executable,&size) ||
       !aq_airdrop_platform_supported((unsigned)atoi(os.release),sizeof(void *),executable,tap_available()) || tf_flag("disable-airdrop")) return;
    native_cache_limit=dlsym(RTLD_DEFAULT,"_CFNetworkHTTPConnectionCacheSetLimit");
    if(!native_cache_limit) return;
    struct rebinding hook={"_CFNetworkHTTPConnectionCacheSetLimit",(void *)&air_drop_cache_limit,NULL};
    rebind_symbols(&hook,1);
}
