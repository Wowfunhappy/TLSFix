// aqwatch -- load AquaTransport into each process as it launches.
//
// PURPOSE. AquaTransport is a defensive TLS-compatibility shim for Mac OS X 10.6-10.9 (it
// routes Secure Transport through modern OpenSSL so old systems can still reach current TLS
// servers). This daemon extends that fix to processes started after it begins running: it
// watches the kernel's process list for launches and loads the library into each new process
// as it starts. It runs as root on the local machine and loads only our own single-purpose
// library, via aqinject, into cooperating local processes.
//
// It loads the library per-process after launch rather than configuring a system-wide dyld
// insertion, so a faulty library affects at most one process (which simply goes unpatched)
// and can never prevent processes -- including Finder and the login window -- from starting.
//
// HOW. aqwatch polls the kernel's process list (proc_listpids) every POLL_MS and treats any
// pid it has not seen before as a launch. For each one that is not this daemon, one of its own
// children, pid 0/1, or a trust daemon, it runs `aqinject <pid> <dylib>` -- once, with no
// waiting and no conditions. In-flight aqinject children are capped and reaped so an
// app-launch storm cannot fork-bomb the machine.
//
// Injecting unconditionally is what it sounds like: the library goes into every process,
// including ones that will never open a socket. That is deliberate. Nothing can know in
// advance which processes will use TLS -- a process loads Security when it first needs it,
// which may be hours after launch -- so any filter on that would be a guess. The library is
// inert until Secure Transport shows up in the process (see aqinject.c), and it costs a
// measured 1.65ms of launch time and a few dirty pages, so there is nothing to buy by
// guessing.
//
// WHY POLLING RATHER THAN THE AUDIT PIPE. The kernel's BSM audit pipe delivers a record per
// exec, but on 10.9.5 its subject token identifies the new process only for fork+execve. For
// posix_spawn the subject is the process that *called* posix_spawn, the child's pid appears in
// no token at all (AUT_PROCESS and the AUT_ARG pid token are both absent), and the path token
// is the child's executable -- so a posix_spawn record pairs the parent's pid with the child's
// path. Anything driven off it would therefore inject into the parent while believing it was
// the child, and would miss every posix_spawn launch, which on 10.9 is nearly every
// application and XPC service launchd starts.
//
// Polling the process list has neither problem: it sees a process however it was created,
// depends on no privileged record format, and needs no system-wide auditing switched on.
//
//   clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 -o aqwatch tools/aqwatch.c
//   sudo aqwatch /Library/AquaTransport/aquatransport.dylib [/path/to/aqinject]

#include <libproc.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <spawn.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>

extern char **environ;

// Trust daemons the library itself refuses (circular dependency); plus our own tools.
static const char *kNeverLoad[] = {
    "ocspd", "securityd", "securityd_service", "trustd", "aqinject", "aqwatch", 0
};

#define MAX_INFLIGHT   24     // cap concurrent aqinject children
#define POLL_MS       100     // process-list poll interval
#define PID_LIMIT   99999     // OS X caps pids here; the seen-set is a bitmap of this size

static const char *g_dylib;
static char        g_aqinject[1024];
static pid_t       g_self;

// Live aqinject children, 0 in a free slot. Only the main loop touches this array, so the
// in-flight count is exact by construction. A plain counter would not be: incrementing it here
// while a SIGCHLD handler decrements it is a race, every lost decrement is permanent, and the
// count drifts up until it pins the cap and the daemon stops injecting into anything for the
// rest of the boot.
static pid_t g_kids[MAX_INFLIGHT];

// Nothing but interrupting a blocked read; all reaping happens in the main loop.
static void on_sigchld(int sig) { (void)sig; }

static void reap_children(void) {
    for (int i = 0; i < MAX_INFLIGHT; i++) {
        if (!g_kids[i]) continue;
        int st;
        pid_t r = waitpid(g_kids[i], &st, WNOHANG);
        if (r == g_kids[i] || (r < 0 && errno == ECHILD)) g_kids[i] = 0;
    }
}

static int kid_slot(void) {
    for (int i = 0; i < MAX_INFLIGHT; i++) if (!g_kids[i]) return i;
    return -1;
}

static int is_kid(pid_t p) {
    for (int i = 0; i < MAX_INFLIGHT; i++) if (g_kids[i] == p) return 1;
    return 0;
}

// The executable name comes from proc_pidpath, so the deny list is applied to what the process
// actually is. Returns 1 for a blocked name and also for a process that has already exited
// (nothing to load into).
static int name_blocked(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, path, sizeof path) <= 0) return 1;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for (int i = 0; kNeverLoad[i]; i++) if (!strcmp(base, kNeverLoad[i])) return 1;
    return 0;
}

// Fire-and-forget aqinject for one freshly launched pid. aqinject applies the arch dispatch
// and the shared-cache check; we only pre-filter the obvious skips.
static void load_into(pid_t pid) {
    if (pid <= 1) return;

    // Never target ourselves or an injector we spawned. The name check below would catch
    // aqinject by itself, but these are cheaper and, more to the point, they make a
    // self-feeding loop structurally impossible rather than dependent on a name comparison:
    // spawning an injector is itself a process launch, so without them the daemon can feed
    // itself.
    if (pid == g_self) return;
    if (is_kid(pid)) return;

    if (name_blocked(pid)) return;

    // Backpressure during a launch storm, but bounded: time spent here is time not spent
    // polling, and a process missed entirely is worse than one injected into a little late.
    reap_children();
    int slot = kid_slot();
    for (int i = 0; slot < 0 && i < 25; i++) { usleep(20000); reap_children(); slot = kid_slot(); }
    if (slot < 0) return;

    char pidstr[16];
    snprintf(pidstr, sizeof pidstr, "%d", pid);
    char *av[] = { g_aqinject, pidstr, (char *)g_dylib, NULL };

    // aqinject's own diagnostics are per-process noise here; silence them.
    posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t child;
    if (posix_spawn(&child, g_aqinject, &fa, NULL, av, environ) == 0) g_kids[slot] = child;
    posix_spawn_file_actions_destroy(&fa);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <dylib> [aqinject-path]\n", argv[0]); return 2; }
    if (geteuid() != 0) { fprintf(stderr, "must run as root\n"); return 1; }
    g_dylib = argv[1];

    if (argc >= 3) {
        snprintf(g_aqinject, sizeof g_aqinject, "%s", argv[2]);
    } else {
        // Default: aqinject sitting next to the dylib.
        char d[1024]; snprintf(d, sizeof d, "%s", g_dylib);
        snprintf(g_aqinject, sizeof g_aqinject, "%s/aqinject", dirname(d));
    }
    if (access(g_aqinject, X_OK) != 0) { fprintf(stderr, "aqinject not executable at %s\n", g_aqinject); return 1; }
    if (access(g_dylib, R_OK) != 0)    { fprintf(stderr, "dylib not readable at %s\n", g_dylib); return 1; }

    g_self = getpid();
    signal(SIGCHLD, on_sigchld);
    signal(SIGPIPE, SIG_IGN);

    // Seen-set as a bitmap over the pid space: constant-time membership, 12 KB, and a pid
    // that exits clears itself on the next sweep so pid reuse is handled without bookkeeping.
    static unsigned char seen[(PID_LIMIT + 8) / 8];
    static unsigned char cur[(PID_LIMIT + 8) / 8];
#define BIT_SET(m, p)  ((m)[(p) >> 3] |= (unsigned char)(1u << ((p) & 7)))
#define BIT_TEST(m, p) ((m)[(p) >> 3] &  (unsigned char)(1u << ((p) & 7)))

    int cap = 0;
    pid_t *pids = NULL;

    // First sweep only records what is already running. Processes that predate this daemon
    // are the installer's job (`install-macos.sh inject`); treating them as launches here
    // would fire MAX_INFLIGHT injectors at boot for no benefit.
    int first = 1;

    for (;;) {
        int need = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
        if (need <= 0) { usleep(POLL_MS * 1000); continue; }
        // Room to spare: the list can grow between sizing it and reading it.
        need += 64 * (int)sizeof(pid_t);
        if (need > cap) {
            pid_t *np = (pid_t *)realloc(pids, (size_t)need);
            if (!np) { usleep(POLL_MS * 1000); continue; }
            pids = np; cap = need;
        }
        int got = proc_listpids(PROC_ALL_PIDS, 0, pids, cap);
        if (got <= 0) { usleep(POLL_MS * 1000); continue; }
        int n = got / (int)sizeof(pid_t);

        memset(cur, 0, sizeof cur);
        for (int i = 0; i < n; i++) {
            pid_t p = pids[i];
            if (p <= 0 || p > PID_LIMIT) continue;   // proc_listpids pads the tail with zeros
            BIT_SET(cur, p);
            if (first || BIT_TEST(seen, p)) continue;
            load_into(p);
        }
        memcpy(seen, cur, sizeof seen);
        first = 0;

        reap_children();
        usleep(POLL_MS * 1000);
    }
#undef BIT_SET
#undef BIT_TEST
}
