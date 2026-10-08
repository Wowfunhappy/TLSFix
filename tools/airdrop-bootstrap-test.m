#import <Foundation/Foundation.h>
#include <launch.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
#include <Block.h>

static BOOL tapInstalled,hardwareReady,disabled,registered,noResponse,unsafeJob;
static int loads,queries,hardwareChecks,devChecks,queryError=ESRCH,spawnError,childStatus,interruptWait;
static int darwin=13;
static int fakeHardware(char *name,size_t size) { hardwareChecks++; strlcpy(name,"en1",size); return hardwareReady; }
static int fakeStat(const char *path,struct stat *st) {
    memset(st,0,sizeof(*st));
    // Boot order on the development Mac: the tap kext creates its device node
    // after launchd starts the bootstrap job.
    if(!strncmp(path,"/dev/",5)) { devChecks++; return -1; }
    if(strstr(path,"/tap.kext")) { st->st_mode=S_IFDIR; return tapInstalled ? 0 : -1; }
    if(unsafeJob) return -1;
    st->st_mode=strstr(path,".plist") ? S_IFREG : S_IFDIR;
    return 0;
}
static int fakeUname(struct utsname *os) { memset(os,0,sizeof(*os)); snprintf(os->release,sizeof(os->release),"%d.0.0",darwin); return 0; }
int tf_flag(const char *name) { (void)name; return disabled; }
static launch_data_t fakeLaunch(launch_data_t request) {
    queries++;
    assert(!strcmp(launch_data_get_string(launch_data_dict_lookup(request,LAUNCH_KEY_GETJOB)),"org.aquatransport.airdrop"));
    if(noResponse) return NULL;
    return launch_data_alloc(registered ? LAUNCH_DATA_DICTIONARY : LAUNCH_DATA_ERRNO);
}
static int fakeLaunchErrno(launch_data_t response) { (void)response; return queryError; }
static int fakeSpawn(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *attributes,char *const args[],char *const env[]) {
    (void)actions; (void)attributes; (void)env;
    assert(!strcmp(path,"/bin/launchctl") && !strcmp(args[1],"load"));
    assert(!strcmp(args[2],"/usr/share/aquatransport/airdrop/org.aquatransport.airdrop.plist"));
    loads++; *pid=123; return spawnError;
}
static pid_t fakeWait(pid_t pid,int *status,int options) {
    (void)options;
    if(interruptWait) { interruptWait=0; errno=EINTR; return -1; }
    *status=childStatus; if(!childStatus) registered=YES; return pid;
}
static dispatch_block_t exits[16];
static int scheduledExits,exitCalls;
static void fakeAfter(dispatch_time_t when,dispatch_queue_t queue,dispatch_block_t block) {
    (void)when; (void)queue;
    assert(scheduledExits<16); exits[scheduledExits++]=Block_copy(block);
}
static void fakeExit(int status) { assert(status==0); exitCalls++; }
#define dispatch_after fakeAfter
#define exit fakeExit
#define AQUATRANSPORT_AIRDROP_HARDWARE_H
#define hardware_supported fakeHardware
#define lstat fakeStat
#define uname fakeUname
#define launch_msg fakeLaunch
#define launch_data_get_errno fakeLaunchErrno
#define posix_spawn fakeSpawn
#define waitpid fakeWait
#define main bootstrap_main
#include "../src/mac/aquatransport_bootstrap.m"
#undef main
int main(void) { @autoreleasepool {
    // Unsupported OS, explicit disablement and an untrusted job neither query
    // launchd nor inspect hardware.
    darwin=12; hardwareAvailable(NULL); assert(!queries && !hardwareChecks && !loads);
    darwin=13; disabled=YES; hardwareAvailable(NULL); assert(!queries && !hardwareChecks && !loads);
    disabled=NO; unsafeJob=YES; hardwareAvailable(NULL); assert(!queries && !hardwareChecks && !loads);
    unsafeJob=NO;
    // Without the TAP driver installed the job is never registered, and the
    // IOKit hardware is not inspected.
    tapInstalled=NO; hardwareReady=YES;
    assert(!loadAirDropIfEligible()); hardwareAvailable(NULL);
    assert(!loads && !hardwareChecks);
    // Without one Wi-Fi interface and one Bluetooth LE controller the job is
    // never registered.
    tapInstalled=YES; hardwareReady=NO;
    assert(!loadAirDropIfEligible()); assert(!loads && hardwareChecks==1);
    // A controller that registers after startup arrives as a matching event.
    hardwareReady=YES; interruptWait=1; hardwareAvailable(NULL);
    assert(loads==1 && registered && hardwareChecks==2);
    // Registration never waits for the TAP device node.
    assert(!devChecks);
    // Later events leave the registered helper and its hardware alone.
    for(int i=0;i<10;i++) hardwareAvailable(NULL);
    assert(loads==1 && hardwareChecks==2);
    // Failed queries must never be mistaken for absent jobs.
    registered=NO; queryError=EACCES; assert(!loadAirDropIfEligible()); assert(loads==1);
    noResponse=YES; assert(!loadAirDropIfEligible()); assert(loads==1); noResponse=NO;
    // Failed loads are reported and a later event can still register the job.
    queryError=ESRCH; spawnError=EAGAIN; assert(!loadAirDropIfEligible()); assert(loads==2 && !registered);
    spawnError=0; childStatus=1<<8; assert(!loadAirDropIfEligible()); assert(loads==3 && !registered);
    childStatus=0; hardwareAvailable(NULL); assert(loads==4 && registered);
    assert(!devChecks);
    // Old idle exits cannot end a newer event; the final exit performs no check.
    int queriesBefore=queries;
    for(int i=0;i<scheduledExits-1;i++) exits[i]();
    assert(!exitCalls);
    exits[scheduledExits-1](); assert(exitCalls==1 && queries==queriesBefore);
    for(int i=0;i<scheduledExits;i++) Block_release(exits[i]);
    // The job runs at load and on IOKit arrival of either radio. It has no
    // timers or path watches: launchd opens WatchPaths targets, and the TAP
    // device node is runtime state for the helper.
    NSDictionary *job=[NSDictionary dictionaryWithContentsOfFile:@"src/mac/org.aquatransport.bootstrap.plist"];
    assert([job[@"RunAtLoad"] boolValue]);
    assert(!job[@"StartInterval"] && !job[@"KeepAlive"] && !job[@"WatchPaths"]);
    NSDictionary *events=job[@"LaunchEvents"][@"com.apple.iokit.matching"];
    assert([job[@"LaunchEvents"] count]==1 && events.count==2);
    assert([events[@"WiFiAvailable"][@"IOProviderClass"] isEqual:@"IO80211Interface"]);
    assert([events[@"BluetoothAvailable"][@"IOProviderClass"] isEqual:@"IOBluetoothHCIController"]);
    for(NSDictionary *event in events.allValues) assert([event[@"IOMatchLaunchStream"] boolValue]);
    puts("Bootstrap: unsupported systems, missing TAP driver or radios, late hardware events, registration before the TAP node, registered-job isolation, load failures and idle exit passed.");
} return 0; }
