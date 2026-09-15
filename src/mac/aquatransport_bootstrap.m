/* One-shot boot coordinator for optional AquaTransport features. Keep feature
 * eligibility here so their launchd jobs are not registered unnecessarily. */
#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
#include "aquatransport_airdrop_hardware.h"
#include "aquatransport_config.h"
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <spawn.h>
#include <unistd.h>

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

static void loadAirDropIfEligible(void) {
    struct utsname os; char interface[32]={0}; struct stat tap;
    if(uname(&os) || atoi(os.release)!=13 || sizeof(void *)!=8 || tf_flag("disable-airdrop") ||
       lstat("/dev/tap0",&tap) || !S_ISCHR(tap.st_mode) ||
       !hardware_supported(interface,sizeof(interface)) || !trusted(@AQ_AIRDROP_JOB)) return;
    if(!supportsAirDropChannel([CWInterface interfaceWithName:[NSString stringWithUTF8String:interface]])) return;

    char *arguments[]={"launchctl","load",AQ_AIRDROP_JOB,NULL};
    char *environment[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C",NULL};
    pid_t child=0;
    if(!posix_spawn(&child,"/bin/launchctl",NULL,NULL,arguments,environment)) waitpid(child,NULL,0);
}

int main(void) { @autoreleasepool {
    if(geteuid()!=0) return 1;
    loadAirDropIfEligible();
    return 0;
} }
