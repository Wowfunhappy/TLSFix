/* Boot coordinator for optional AquaTransport features. Feature jobs are
 * registered only on systems that can use them, judged by durable facts: the
 * OS, configuration flags, installed files and IOKit hardware. Runtime state
 * such as device nodes and the Wi-Fi channel list is checked by the on-demand
 * helpers instead, because it settles after launchd starts this job. */
#import <Foundation/Foundation.h>
#include "aquatransport_airdrop_hardware.h"
#include "aquatransport_config.h"
#include "aquatransport_anisette_service.h"
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <spawn.h>
#include <unistd.h>
#include <launch.h>
#include <errno.h>
#include <dlfcn.h>
#include <xpc/xpc.h>

#define AQ_AIRDROP_JOB "/usr/share/aquatransport/airdrop/org.aquatransport.airdrop.plist"

static BOOL trusted(NSString *path) {
    struct stat st;
    if(lstat(path.fileSystemRepresentation,&st) || !S_ISREG(st.st_mode) || st.st_uid!=0 || (st.st_mode&022)) return NO;
    for(NSString *parent=[path stringByDeletingLastPathComponent];parent.length>1;parent=[parent stringByDeletingLastPathComponent])
        if(lstat(parent.fileSystemRepresentation,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=0 || (st.st_mode&022)) return NO;
    return YES;
}

typedef enum { AQJobUnknown, AQJobMissing, AQJobRegistered } AQJobState;
static AQJobState jobState(const char *label) {
    // A duplicate Mavericks load can replace the socket path before failing.
    // Query launchd itself, including idle socket jobs with no running process.
    launch_data_t request=launch_data_alloc(LAUNCH_DATA_DICTIONARY);
    launch_data_dict_insert(request,launch_data_new_string(label),LAUNCH_KEY_GETJOB);
    launch_data_t response=launch_msg(request);
    launch_data_free(request);
    if(!response) { NSLog(@"AquaTransport bootstrap: cannot query %s",label); return AQJobUnknown; }
    BOOL missing=launch_data_get_type(response)==LAUNCH_DATA_ERRNO && launch_data_get_errno(response)==ESRCH;
    BOOL registered=launch_data_get_type(response)==LAUNCH_DATA_DICTIONARY;
    launch_data_free(response);
    if(!registered && !missing) NSLog(@"AquaTransport bootstrap: unknown job state for %s",label);
    return registered ? AQJobRegistered : missing ? AQJobMissing : AQJobUnknown;
}

static BOOL loadJob(const char *path,const char *label) {
    AQJobState state=jobState(label);
    if(state!=AQJobMissing) return state==AQJobRegistered;
    char *arguments[]={"launchctl","load",(char *)path,NULL};
    char *environment[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C",NULL};
    pid_t child=0;
    int error=posix_spawn(&child,"/bin/launchctl",NULL,NULL,arguments,environment);
    int status=0; pid_t waited=-1;
    if(!error) do { waited=waitpid(child,&status,0); } while(waited<0 && errno==EINTR);
    if(error || waited!=child || !WIFEXITED(status) || WEXITSTATUS(status)) {
        NSLog(@"AquaTransport bootstrap: loading %s failed",label);
        return NO;
    }
    NSLog(@"AquaTransport bootstrap: registered %s",label);
    return YES;
}

static void loadAnisetteIfEligible(void) {
    struct utsname os;
    if(uname(&os) || atoi(os.release)<11 || tf_flag("disable-icloud-gsa") ||
       !trusted(@AQ_ANISETTE_JOB) || !trusted(@AQ_ANISETTE_EXECUTABLE)) return;
    loadJob(AQ_ANISETTE_JOB,"org.aquatransport.anisette");
}

// tuntaposx installs its kext bundle and a LaunchDaemon that loads it; the
// kext creates /dev/tap0 a few seconds into boot, so test the installed bundle.
static BOOL tapDriverInstalled(void) {
    static const char *const bundles[]={"/Library/Extensions/tap.kext","/System/Library/Extensions/tap.kext"};
    struct stat st;
    for(size_t i=0;i<sizeof(bundles)/sizeof(*bundles);i++)
        if(!lstat(bundles[i],&st) && S_ISDIR(st.st_mode)) return YES;
    return NO;
}

// Runs at load and again whenever launchd delivers a Wi-Fi interface or
// Bluetooth controller, including ones that register after this job starts.
// The /dev/tap0 node, channel 149 and Bluetooth power are runtime state that
// sharingd's adapter and the helper's start command check on every request.
static BOOL loadAirDropIfEligible(void) {
    struct utsname os; char interface[32]={0};
    if(uname(&os) || atoi(os.release)!=13 || sizeof(void *)!=8 || tf_flag("disable-modern-airdrop")) return YES;
    if(!trusted(@AQ_AIRDROP_JOB)) {
        NSLog(@"AquaTransport bootstrap: %s is missing or not root-owned",AQ_AIRDROP_JOB);
        return YES;
    }
    // Once registered, the helper owns all live radio checks. Later events
    // must not inspect the hardware during an active session.
    AQJobState state=jobState("org.aquatransport.airdrop");
    if(state!=AQJobMissing) return state==AQJobRegistered;
    if(!tapDriverInstalled()) {
        NSLog(@"AquaTransport bootstrap: AirDrop requires the TAP driver (tap.kext)");
        return NO;
    }
    if(!hardware_supported(interface,sizeof(interface))) {
        NSLog(@"AquaTransport bootstrap: AirDrop requires one Wi-Fi interface and one Bluetooth LE controller");
        return NO;
    }
    return loadJob(AQ_AIRDROP_JOB,"org.aquatransport.airdrop");
}

// Event callbacks and the initial check share the main queue. A short idle
// exit lets XPC deliver/consume queued hardware events before the process ends.
// This timer only exits the process; it never polls hardware or retries work.
static unsigned exitGeneration;
static void finishBootstrapWork(void) {
    unsigned generation=++exitGeneration;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),dispatch_get_main_queue(),^{
        if(generation==exitGeneration) exit(0);
    });
}
static void hardwareAvailable(xpc_object_t event) {
    (void)event;
    @autoreleasepool { loadAirDropIfEligible(); }
    finishBootstrapWork();
}

int main(void) { @autoreleasepool {
    if(geteuid()!=0) return 1;
    // Resolve at runtime to preserve the universal bootstrap's 10.6 support.
    void (*setHandler)(const char *,dispatch_queue_t,xpc_handler_t)=
        dlsym(RTLD_DEFAULT,"xpc_set_event_stream_handler");
    if(setHandler) setHandler("com.apple.iokit.matching",dispatch_get_main_queue(),^(xpc_object_t event) {
        hardwareAvailable(event);
    });
    loadAnisetteIfEligible();
    loadAirDropIfEligible();
    if(setHandler) {
        finishBootstrapWork();
        dispatch_main();
    }
    return 0;
} }
