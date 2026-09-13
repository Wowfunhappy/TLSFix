/* Ensure the new callbacks do not initialize Foundation in ordinary C programs. */
#include <assert.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void) {
    void *z=dlopen("/usr/lib/libz.dylib",RTLD_NOW|RTLD_LOCAL); assert(z);
    for (uint32_t i=0;i<_dyld_image_count();i++) {
        const char *path=_dyld_get_image_name(i);
        assert(!strstr(path,"/Foundation.framework/") && !strstr(path,"aquatransport_maps.dylib"));
    }
    pid_t child=fork(); assert(child>=0);
    if (!child) _exit(17);
    int status=0; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==17);
    dlclose(z); puts("PASS: map callbacks leave C processes free of Foundation and preserve fork"); return 0;
}
