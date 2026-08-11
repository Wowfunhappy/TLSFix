// aqinject -- load the AquaTransport library into an already-running process on
// Mac OS X 10.6-10.9 (i386 + x86_64).
//
// PURPOSE. AquaTransport is a defensive TLS-compatibility shim: it routes these old systems'
// Secure Transport through a modern OpenSSL so that software on 10.6-10.9 can still reach
// today's TLS 1.2/1.3 servers. This tool loads that library into a process the administrator
// already runs on a machine they own, using the process's own dlopen. It edits no system
// configuration and requires no reboot; a faulty library affects only the target process,
// which simply goes unpatched. It reaches running GUI apps as readily as daemons.
//
// It requires root (task_for_pid) and operates only on local processes on the same machine.
// "inject" below is the precise technical term for loading code via the Mach task API; the
// payload is our own single-purpose compatibility library, loaded with the target's own
// dlopen, not arbitrary code.
//
//   sudo aqinject <pid> <dylib>            load into one process
//   sudo aqinject -q <pid> <dylib>         the same, quiet about expected outcomes
//   sudo aqinject --helper <dylib>         serve injection requests on stdin (aqwatch's use)
//
// THE ENGINE IS NOT HERE. It is in aqinject_core.c, which aqwatch links directly: spawning
// this tool per target cost a measured 1.7 ms, and on the gate path the target is frozen for
// every millisecond of it. What remains here are the two jobs that need a separate process.
//
// THE CLI FORM is for debugging: point it at one pid and read what happened. Nothing in the
// shipping package drives it.
//
// THE HELPER FORM is how aqwatch reaches a target of the other architecture. Resolved
// dyld-cache addresses and the pthread_attr_t layout are both architecture-specific, so only a
// same-arch slice can inject a given target; aqwatch is one slice and needs the other. It
// spawns this once, with the binary preference set to the architecture it lacks, and keeps it
// for the life of the daemon -- so a cross-architecture target pays no spawn either.
//
// Requests arrive on stdin, one per line, and answers go to stdout:
//
//   G <pid>\n     inject, gate path (the target is held at a syscall)     -> "<pid> <status>\n"
//   N <pid>\n     inject, ordinary path (wait for dyld, verify afterwards)
//
// <status> is one of the AQ_* outcomes. The dylib path is fixed at startup rather than sent
// per request, so nothing on this channel can name a file to load.
//
//   clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 -o aqinject \
//       tools/aqinject.c tools/aqinject_core.c

#include "aqinject_core.h"

#include <mach-o/dyld.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int serve_helper(const char *dylib) {
    // A dead daemon closes the socket; reads return EOF and this exits. It must not be killed
    // by SIGPIPE first, since a reply may race the daemon's exit.
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    char line[64];
    while (fgets(line, sizeof line, stdin)) {
        aq_opts o; memset(&o, 0, sizeof o);
        o.quiet = 1;
        char mode = 0; int pid = 0;
        if (sscanf(line, "%c %d", &mode, &pid) != 2 || pid <= 1) continue;
        o.gated = (mode == 'G');
        int r = aq_inject_retrying((pid_t)pid, dylib, &o);
        printf("%d %d\n", pid, r);
    }
    return 0;
}

int main(int argc, char **argv) {
    // -q suppresses the outcomes that are expected rather than wrong -- above all a short-lived
    // target exiting part-way through. Real failures print either way, so a caller logging this
    // tool's stderr gets the failures without the churn.
    int helper = 0, ai = 1;
    aq_opts o; memset(&o, 0, sizeof o);
    for (; ai < argc; ai++) {
        if (!strcmp(argv[ai], "--helper"))  helper = 1;
        else if (!strcmp(argv[ai], "-q"))   o.quiet = 1;
        else break;
    }

    if (geteuid() != 0) { fprintf(stderr, "must run as root (task_for_pid)\n"); return AQ_FAILED; }

    if (helper) {
        if (ai != argc - 1) { fprintf(stderr, "usage: %s --helper <dylib>\n", argv[0]); return 2; }
        if (!aq_path_fits(argv[ai])) { fprintf(stderr, "path too long\n"); return 2; }
        return serve_helper(argv[ai]);
    }
    if (argc - ai != 2) {
        fprintf(stderr, "usage: %s [-q] <pid> <dylib>\n"
                        "       %s --helper <dylib>\n", argv[0], argv[0]);
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[ai]);
    const char *path = argv[ai + 1];
    if (!aq_path_fits(path)) { fprintf(stderr, "path too long\n"); return 2; }

    // The sibling slice is this same fat binary, found by its real path rather than by argv[0]
    // -- which may be a bare name resolved through PATH, and posix_spawn does not resolve one.
    char self[4096]; uint32_t sz = sizeof self;
    if (_NSGetExecutablePath(self, &sz) != 0) { fprintf(stderr, "cannot find my own path\n"); return AQ_FAILED; }
    return aq_inject_dispatch(pid, path, &o, self, NULL);
}
