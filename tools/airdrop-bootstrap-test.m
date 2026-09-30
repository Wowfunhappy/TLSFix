#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
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

static BOOL tapPresent,hardwareReady,channelReady,disabled,registered;
static int loads,queryError=ESRCH,spawnError,childStatus,interruptWait;
static BOOL noResponse;
static int hardwareChecks,channelChecks,queries;
static int darwin=13;
static BOOL unsafeJob;
@interface AQTestChannel : NSObject
- (NSUInteger)channelNumber;
@end
@implementation AQTestChannel
- (NSUInteger)channelNumber { return 149; }
@end
@interface AQTestInterface : NSObject
+ (id)interfaceWithName:(NSString *)name;
- (NSArray *)supportedWLANChannels;
@end
@implementation AQTestInterface
+ (id)interfaceWithName:(NSString *)name { (void)name; return [[[self alloc] init] autorelease]; }
- (NSArray *)supportedWLANChannels { channelChecks++; return channelReady ? @[[[[AQTestChannel alloc] init] autorelease]] : @[]; }
@end
static int fakeHardware(char *name,size_t size) { hardwareChecks++; strlcpy(name,"en1",size); return hardwareReady; }
static int fakeStat(const char *path,struct stat *st) {
    memset(st,0,sizeof(*st));
    if(unsafeJob) return -1;
    if(!strcmp(path,"/dev/tap0")) { st->st_mode=S_IFCHR; return tapPresent ? 0 : -1; }
    st->st_mode=strstr(path,".plist") ? S_IFREG : S_IFDIR;
    return 0;
}
static int fakeUname(struct utsname *os) { memset(os,0,sizeof(*os)); snprintf(os->release,sizeof(os->release),"%d.0.0",darwin); return 0; }
int tf_flag(const char *name) { (void)name; return disabled; }
static launch_data_t fakeLaunch(launch_data_t request) {
    queries++;
    assert(!strcmp(launch_data_get_string(launch_data_dict_lookup(request,LAUNCH_KEY_GETJOB)),"org.aquatransport.airdrop"));
    if(noResponse) return NULL;
    launch_data_t result=launch_data_alloc(registered ? LAUNCH_DATA_DICTIONARY : LAUNCH_DATA_ERRNO);
    return result;
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
#define CWInterface AQTestInterface
#define CWChannel AQTestChannel
#define main bootstrap_main
#include "../src/mac/aquatransport_bootstrap.m"
#undef main
int main(void) { @autoreleasepool {
    // Boot before drivers exist must not prevent a subsequent successful check.
    loadAirDropIfEligible(); assert(loads==0);
    tapPresent=YES; loadAirDropIfEligible(); assert(loads==0);
    hardwareReady=YES; loadAirDropIfEligible(); assert(loads==0);
    channelReady=YES; disabled=YES; loadAirDropIfEligible(); assert(loads==0);
    disabled=NO; interruptWait=1; loadAirDropIfEligible(); assert(loads==1 && registered);
    int hardwareBefore=hardwareChecks,channelsBefore=channelChecks;
    for(int i=0;i<10;i++) loadAirDropIfEligible(); assert(loads==1);
    assert(hardwareChecks==hardwareBefore && channelChecks==channelsBefore);
    // Failed queries must never be mistaken for absent jobs.
    registered=NO; queryError=EACCES; loadAirDropIfEligible(); assert(loads==1);
    noResponse=YES; loadAirDropIfEligible(); assert(loads==1); noResponse=NO;
    queryError=ESRCH; spawnError=EAGAIN; loadAirDropIfEligible(); assert(loads==2 && !registered);
    spawnError=0; childStatus=1<<8; loadAirDropIfEligible(); assert(loads==3 && !registered);
    childStatus=0; loadAirDropIfEligible(); assert(loads==4 && registered);
    NSDictionary *job=[NSDictionary dictionaryWithContentsOfFile:@"src/mac/org.aquatransport.bootstrap.plist"];
    assert([job[@"RunAtLoad"] boolValue] && !job[@"StartInterval"] && !job[@"KeepAlive"]);
    NSDictionary *events=job[@"LaunchEvents"][@"com.apple.iokit.matching"];
    assert(events.count==2);
    assert([events[@"WiFiAvailable"][@"IOProviderClass"] isEqual:@"IO80211Interface"]);
    assert([events[@"BluetoothAvailable"][@"IOProviderClass"] isEqual:@"IOBluetoothHCIController"]);
    for(NSDictionary *event in events.allValues) assert([event[@"IOMatchLaunchStream"] boolValue]);
    // launchd opens WatchPaths; a watch on tap0 reserves it before OWL starts.
    assert([job[@"WatchPaths"] isEqual:@[@"/dev"]]);
    // Unsupported OS and explicit disablement do not query launchd or hardware.
    registered=NO; loads=queries=hardwareChecks=channelChecks=0;
    darwin=12; hardwareAvailable(NULL);
    assert(!queries && !hardwareChecks && !channelChecks && !loads);
    darwin=13; disabled=YES; hardwareAvailable(NULL);
    assert(!queries && !hardwareChecks && !channelChecks && !loads);
    disabled=NO; unsafeJob=YES; hardwareAvailable(NULL);
    assert(!queries && !hardwareChecks && !channelChecks && !loads);
    unsafeJob=NO;
    // Startup without prerequisites does one check and schedules no retries.
    tapPresent=hardwareReady=channelReady=NO;
    loadAirDropIfEligible(); assert(queries==1 && !hardwareChecks && !loads);
    // Arrival events rerun eligibility, regardless of how late they arrive.
    tapPresent=YES; hardwareAvailable(NULL);
    assert(queries==2 && hardwareChecks==1 && !loads);
    hardwareReady=YES; hardwareAvailable(NULL);
    assert(queries==3 && hardwareChecks==2 && channelChecks==1 && !loads);
    channelReady=YES; hardwareAvailable(NULL);
    assert(registered && loads==1);
    queries=hardwareChecks=channelChecks=0;
    hardwareAvailable(NULL);
    assert(queries==1 && !hardwareChecks && !channelChecks && loads==1);
    // Old idle exits cannot end a newer event; the final exit performs no check.
    int queriesBefore=queries;
    for(int i=0;i<scheduledExits-1;i++) exits[i]();
    assert(!exitCalls);
    exits[scheduledExits-1](); assert(exitCalls==1 && queries==queriesBefore);
    for(int i=0;i<scheduledExits;i++) Block_release(exits[i]);
    puts("Bootstrap: startup and hardware events, unsupported systems, late readiness, registered-job isolation and idle exit passed.");
} return 0; }
