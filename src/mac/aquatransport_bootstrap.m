/* One-shot boot coordinator for optional AquaTransport features. Keep feature
 * eligibility here so their launchd jobs are not registered unnecessarily. */
#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
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

static BOOL supportsAirDropChannel(CWInterface *wifi) {
    if(!wifi) return NO;
    for(CWChannel *channel in wifi.supportedWLANChannels) if(channel.channelNumber==149) return YES;
    return NO;
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

// One eligibility check per startup or hardware event; no timed retries.
static BOOL loadAirDropIfEligible(void) {
    struct utsname os; char interface[32]={0}; struct stat tap;
    if(uname(&os) || atoi(os.release)!=13 || sizeof(void *)!=8 || tf_flag("disable-modern-airdrop")) return YES;
    if(!trusted(@AQ_AIRDROP_JOB)) return YES;
    // Once registered, the helper owns all live radio checks. Bootstrap retries
    // must not open CoreWLAN or inspect the hardware during an active session.
    AQJobState state=jobState("org.aquatransport.airdrop");
    if(state!=AQJobMissing) return state==AQJobRegistered;
    if(lstat("/dev/tap0",&tap) || !S_ISCHR(tap.st_mode) ||
       !hardware_supported(interface,sizeof(interface))) return NO;
    if(!supportsAirDropChannel([CWInterface interfaceWithName:[NSString stringWithUTF8String:interface]])) return NO;

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
