#include <mach-o/dyld.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    int engine=0;
    for(uint32_t i=0;i<_dyld_image_count();i++) {
        const char *path=_dyld_get_image_name(i);
        if(strstr(path,"aquatransport_engine.dylib")) engine=1;
        if(strstr(path,"aquatransport_airdrop.dylib") || strstr(path,"/SIMBL/")) { fprintf(stderr,"FAIL: unexpected image %s\n",path); return 1; }
    }
    if(!engine) { fputs("FAIL: probe did not exercise AquaTransport\n",stderr); return 1; }
    puts("PASS: AquaTransport active, AirDrop adapter not loaded in unrelated process"); return 0;
}
