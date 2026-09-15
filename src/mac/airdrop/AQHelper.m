#import "AQHelperSupport.h"
#import "AQWiFiLease.h"
#import <CoreWLAN/CoreWLAN.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <spawn.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <launch.h>
#include <mach/mach_time.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include "../aquatransport_airdrop_hardware.h"
static volatile sig_atomic_t stopping;
static void stopSignal(int sig) { (void)sig; stopping=1; }
static pid_t owlPID,blePID; static uid_t owner=(uid_t)-1; static double lease;
static AQWiFiLease *wifiLease;
static double monotonicTime(void) { mach_timebase_info_data_t scale; mach_timebase_info(&scale); return (double)mach_absolute_time()*scale.numer/scale.denom/1e9; }

static BOOL tapReady(void) {
    struct ifaddrs *list=NULL; BOOL ready=NO;
    if(getifaddrs(&list)) return NO;
    for(struct ifaddrs *item=list;item;item=item->ifa_next) {
        if(item->ifa_addr && !strcmp(item->ifa_name,"tap0") &&
           item->ifa_addr->sa_family==AF_INET6 && (item->ifa_flags&IFF_UP) &&
           IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)item->ifa_addr)->sin6_addr)) ready=YES;
    }
    freeifaddrs(list); return ready;
}
static BOOL trusted(NSString *path) {
    struct stat st; if(lstat(path.fileSystemRepresentation,&st) || !S_ISREG(st.st_mode) || st.st_uid!=0 || (st.st_mode&022)) return NO;
    for(NSString *parent=[path stringByDeletingLastPathComponent];parent.length>1;parent=[parent stringByDeletingLastPathComponent]) if(lstat(parent.fileSystemRepresentation,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=0 || (st.st_mode&022)) return NO;
    return YES;
}
static BOOL supportsAirDropChannel(CWInterface *wifi) {
    if(!wifi) return NO;
    for(CWChannel *channel in wifi.supportedWLANChannels) if(channel.channelNumber==149) return YES;
    return NO;
}
static pid_t launch(NSString *name,NSArray *arguments) {
    NSString *path=[@"/usr/share/aquatransport/airdrop" stringByAppendingPathComponent:name];
    AQRequire(trusted(path),@"The installed radio executable is missing or has unsafe permissions.");
    NSMutableArray *args=[NSMutableArray arrayWithObject:path]; [args addObjectsFromArray:arguments];
    char **argv=calloc(args.count+1,sizeof(char *)); for(NSUInteger i=0;i<args.count;i++) argv[i]=strdup([args[i] UTF8String]);
    posix_spawn_file_actions_t actions; posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions,0,"/dev/null",O_RDONLY,0); posix_spawn_file_actions_addopen(&actions,1,"/dev/null",O_WRONLY,0); posix_spawn_file_actions_adddup2(&actions,1,2);
    posix_spawnattr_t attributes; posix_spawnattr_init(&attributes); posix_spawnattr_setflags(&attributes,POSIX_SPAWN_CLOEXEC_DEFAULT);
    char *environment[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C",NULL}; pid_t pid=0;
    int error=posix_spawn(&pid,path.fileSystemRepresentation,&actions,&attributes,argv,environment);
    posix_spawnattr_destroy(&attributes); posix_spawn_file_actions_destroy(&actions);
    for(NSUInteger i=0;i<args.count;i++) free(argv[i]); free(argv); AQRequire(!error && pid>0,@"Could not start the radio process."); return pid;
}
static void reap(pid_t *pid) { if(*pid>0 && waitpid(*pid,NULL,WNOHANG)==*pid) *pid=0; }
static void terminate(pid_t *pid) { if(*pid>0) { kill(*pid,SIGTERM); for(int i=0;i<30;i++) { if(waitpid(*pid,NULL,WNOHANG)==*pid) { *pid=0; return; } usleep(100000); } kill(*pid,SIGKILL); waitpid(*pid,NULL,0); *pid=0; } }
static void radioStop(void) { terminate(&blePID); terminate(&owlPID); [wifiLease restore]; wifiLease=nil; owner=(uid_t)-1; }
int main(void) { @autoreleasepool {
    if(geteuid()!=0) return 1; umask(077); signal(SIGTERM,stopSignal); signal(SIGINT,stopSignal); signal(SIGPIPE,SIG_IGN);
    struct utsname os;
    if(uname(&os) || atoi(os.release)!=13 || sizeof(void *)!=8) return 2;
    launch_data_t request=launch_data_new_string(LAUNCH_KEY_CHECKIN);
    launch_data_t response=launch_msg(request); launch_data_free(request);
    if(!response || launch_data_get_type(response)!=LAUNCH_DATA_DICTIONARY) { if(response) launch_data_free(response); return 3; }
    launch_data_t sockets=launch_data_dict_lookup(response,LAUNCH_JOBKEY_SOCKETS);
    launch_data_t entries=sockets ? launch_data_dict_lookup(sockets,"Listener") : NULL;
    if(!entries || launch_data_get_type(entries)!=LAUNCH_DATA_ARRAY || launch_data_array_get_count(entries)!=1) { launch_data_free(response); return 4; }
    int inherited=launch_data_get_fd(launch_data_array_get_index(entries,0));
    int listener=inherited>=0 ? dup(inherited) : -1;
    launch_data_free(response); if(listener<0) return 5;
    fcntl(listener,F_SETFD,FD_CLOEXEC);
    double last_activity=monotonicTime();
    while(!stopping) { @autoreleasepool {
        uid_t console=(uid_t)-1; gid_t group; CFStringRef user=SCDynamicStoreCopyConsoleUser(NULL,&console,&group); if(user) CFRelease(user);
        reap(&owlPID); reap(&blePID);
        if(owner!=(uid_t)-1 && (monotonicTime()>lease || console!=owner || !owlPID)) radioStop();
        if(!owlPID && monotonicTime()>last_activity+30) break;

        if(owlPID && !blePID) @try { blePID=launch(@"ad_ble_wake",@[@"600"]); } @catch(NSException *e) { radioStop(); }
        fd_set fds; FD_ZERO(&fds); FD_SET(listener,&fds); struct timeval tick={1,0}; if(select(listener+1,&fds,NULL,NULL,&tick)<=0) continue;
        int client=accept(listener,NULL,NULL); if(client<0) continue; fcntl(client,F_SETFD,FD_CLOEXEC);
        last_activity=monotonicTime();
        struct timeval timeout={2,0}; setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)); setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
        NSDictionary *reply=@{@"ok":@NO,@"error":@"Only the logged-in console user may control AirDrop."}; uid_t uid; gid_t gid;
        if(!getpeereid(client,&uid,&gid) && uid==console && uid!=0 && uid!=(uid_t)-1) @try {
            NSMutableData *data=[NSMutableData data]; char c; BOOL complete=NO;
            while(data.length<1024 && read(client,&c,1)==1) { if(c=='\n') { complete=YES; break; } [data appendBytes:&c length:1]; }
            AQRequire(complete,@"Invalid helper request."); id request=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
            AQRequire([request isKindOfClass:[NSDictionary class]] && [request count]==1 && [request[@"command"] isKindOfClass:[NSString class]],@"Invalid helper request."); NSString *command=request[@"command"];
            if([command isEqual:@"start"]) {
                AQRequire(AQHasTAP(),@"The TAP driver is not installed.");
                if(!owlPID) {
                    char interface[32]={0}; AQRequire(hardware_supported(interface,sizeof(interface)),@"AirDrop requires an unambiguous Wi-Fi interface and a connected Bluetooth LE controller."); NSString *interfaceName=[NSString stringWithUTF8String:interface]; CWInterface *wifi=[CWInterface interfaceWithName:interfaceName];
                    AQRequire(wifi!=nil,@"The Wi-Fi interface is unavailable.");
                    AQRequire(supportsAirDropChannel(wifi),@"The Wi-Fi interface does not support AirDrop's configured channel 149.");
                    int (*autoJoin)(NSString *)=dlsym(RTLD_DEFAULT,"CWInterfaceStartAutoJoin");
                    int (^join)(NSString *)=autoJoin ? ^int(NSString *name){ return autoJoin(name); } : nil;
                    wifiLease=[[AQWiFiLease alloc] initWithInterface:(id<AQWiFiInterface>)wifi autoJoin:join];
                    @try {
                        [wifiLease begin];

                        // Retain OWL's normal RSSI admission/grace thresholds.
                        // Disabling them admitted distant masters whose schedule
                        // the nearby iPhone could not follow, removing this Mac.
                        NSMutableArray *radioArguments=[@[@"-i",interfaceName,@"-h",@"tap0",@"-c",@"149",@"-F",@"-Q"] mutableCopy];
                        if(trusted(@"/usr/share/aquatransport/airdrop/radio-diagnostics")) [radioArguments addObject:@"-T"];
                        owlPID=launch(@"owl",radioArguments);
                        owner=uid; blePID=launch(@"ad_ble_wake",@[@"600"]);
                        BOOL ready=NO;
                        for(int i=0;i<50;i++) {
                            usleep(100000); reap(&owlPID); reap(&blePID);
                            if(!owlPID || !blePID) break;
                            if(tapReady()) { ready=YES; break; }
                        }
                        AQRequire(ready,@"The AirDrop radio did not become ready.");
                    } @catch(NSException *e) { radioStop(); @throw; }
                } lease=monotonicTime()+45;
            } else if([command isEqual:@"heartbeat"]) { AQRequire(owner==uid && owlPID>0,@"The radio session has ended."); lease=monotonicTime()+45;
            } else if([command isEqual:@"stop"]) { if(owner==uid) radioStop();
            } else AQRequire([command isEqual:@"status"],@"Unknown helper command.");
            reply=@{@"ok":@YES,@"running":@(owlPID>0),@"tap":@(AQHasTAP())};
        } @catch(NSException *e) { reply=@{@"ok":@NO,@"error":e.reason ?: @"Radio helper error"}; }
        NSMutableData *out=[[NSJSONSerialization dataWithJSONObject:reply options:0 error:NULL] mutableCopy]; [out appendBytes:"\n" length:1]; write(client,out.bytes,out.length); close(client);
    } }
    radioStop(); close(listener); return 0;
} }
