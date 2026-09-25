// The stub that Security.framework's load command actually names.
//
// Splitting the library in two is not organisational tidiness, it is the whole point: a load
// command is unconditional, so whatever Security names is mapped into every process on the
// system whether that process wants it or not. Some processes cannot tolerate that. A DRM
// module, for instance, inspects its own address space and refuses to run when it finds an
// unexpected 9 MB image there -- and it refuses by wedging, not by saying so. No flag the
// engine reads can help, because by the time engine code runs the mapping already happened.
//
// So the unconditional thing is this file, which is small and does nothing, and the engine
// becomes a dlopen() this file performs only for processes that want it. An excluded process
// maps a few pages of stub and nothing else.
//
// Keep this file tiny and dependency-free. It must not link OpenSSL, and it must not import
// anything newer than the deployment target -- build-macos.sh verifies both.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>

// The rule files (AQ_DISABLED and flags.txt) live in the config subdirectory; the engine does
// not -- it is found beside this file (see aq_engine_path), not under this directory.
#define AQ_DEFAULT_DIR "/usr/share/aquatransport/config"
#define AQ_ENGINE      "aquatransport_engine.dylib"
#define AQ_DISABLED    "disabled.txt"

static const char *aq_dir(void) {
    const char *e = getenv("AQUATRANSPORT_DIR");
    return (e && *e) ? e : AQ_DEFAULT_DIR;
}

// Is `name` on a line of its own in <dir>/<file>? Deliberately a private copy of the same
// one-name-per-line reader the engine has in aquatransport_config.c: pulling that file in
// would drag the engine's headers behind it and this stub has to stay standalone.
static int aq_listed(const char *dir, const char *file, const char *name) {
    if (!name || !*name) return 0;
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, file);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[512];
    int hit = 0;
    while (fgets(buf, sizeof buf, f)) {
        size_t l = strlen(buf);
        while (l && (buf[l-1] == '\n' || buf[l-1] == '\r' || buf[l-1] == ' ' || buf[l-1] == '\t'))
            buf[--l] = 0;
        if (l == 0) continue;
        if (!strcmp(buf, name)) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

// A failed dlopen means no TLS for this process, which looks exactly like the library not
// being installed. Say so when debug is on rather than leaving that to be guessed at.
static void aq_complain(const char *dir, const char *detail) {
    if (!aq_listed(dir, "flags.txt", "debug")) return;
    char path[1024];
    snprintf(path, sizeof path, "/tmp/aquatransport-%u.log", (unsigned)getuid());
    FILE *f = fopen(path, "a");
    if (!f) return;
    fprintf(f, "[%d %s] engine not loaded: %s\n",
            (int)getpid(), getprogname() ? getprogname() : "?", detail ? detail : "?");
    fclose(f);
}

// Where the engine is: beside this file, wherever this file turned out to be. Deliberately not
// AQUATRANSPORT_DIR -- that names the directory of rule files, and a user who points it at a
// directory of their own rules has not said anything about where the code lives. Conflating the
// two would answer that by silently leaving the process without TLS.
static int aq_engine_path(char *out, size_t n) {
    Dl_info info;
    if (!dladdr((const void *)(uintptr_t)&aq_engine_path, &info) || !info.dli_fname) return 0;
    const char *slash = strrchr(info.dli_fname, '/');
    if (!slash) return 0;
    int dirlen = (int)(slash - info.dli_fname);
    return snprintf(out, n, "%.*s/%s", dirlen, info.dli_fname, AQ_ENGINE) < (int)n;
}

__attribute__((constructor))
static void aquatransport_loader_init(void) {
    const char *dir = aq_dir();

    // The excluded case has to leave no trace: no engine, and nothing logged to a file we
    // would have to open in a process that asked us to stay out of it.
    if (aq_listed(dir, AQ_DISABLED, getprogname())) return;

    char path[1024];
    if (!aq_engine_path(path, sizeof path)) { aq_complain(dir, "cannot locate engine"); return; }
    // RTLD_GLOBAL so the engine's one exported symbol, the WKExternalURLRewrite hook, is where a
    // patched WebKit's dlsym(RTLD_DEFAULT, ...) will find it. The engine exports nothing else --
    // the build verifies the OpenSSL namespace stays hidden -- so making it global exposes only
    // that hook and cannot let anything bind to the engine's internals.
    if (!dlopen(path, RTLD_NOW | RTLD_GLOBAL))
        aq_complain(dir, dlerror());
}
