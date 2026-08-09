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
// children, pid 0/1, or a trust daemon, it runs `aqinject <pid> <dylib>`. In-flight aqinject
// children are capped and reaped so an app-launch storm cannot fork-bomb the machine.
//
// ONE INJECTION PER LAUNCH, AND A FAILURE IS REPORTED RATHER THAN WORKED AROUND. aqinject
// waits for the target to be ready and confirms afterwards, by reading the target's dyld image
// list, that the library really arrived; it exits 0 only then. That status is an observation,
// so aqwatch acts on it directly and does not attempt the injection again.
//
// There is deliberately no retry loop and no periodic re-check. Either injection lands, in
// which case repeating it buys nothing, or it does not, in which case the useful response is a
// log line naming the pid and the reason -- not a schedule of further attempts that hides how
// often the first one misses. Every failure aqinject can distinguish reaches
// /var/log/aquatransport.log with its cause attached.
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
//   sudo aqwatch /usr/share/aquatransport/aquatransport.dylib [/path/to/aqinject]

#include <libproc.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <spawn.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
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
#define LOG_PATH   "/var/log/aquatransport.log"
#define LOG_MAX  (1 << 20)    // bound on the log, enforced at startup and while running

#define BITMAP_BYTES   ((PID_LIMIT + 8) / 8)
#define BIT_SET(m, p)  ((m)[(p) >> 3] |= (unsigned char)(1u << ((p) & 7)))
#define BIT_TEST(m, p) ((m)[(p) >> 3] &  (unsigned char)(1u << ((p) & 7)))

static const char *g_dylib;
static char        g_aqinject[1024];
static pid_t       g_self;
static int         g_logfd = -1;

// Live aqinject children and the pid each was launched against, 0 in a free slot. Only the main
// loop touches this array, so the in-flight count is exact by construction. A plain counter
// would not be: incrementing it here while a SIGCHLD handler decrements it is a race, every lost
// decrement is permanent, and the count drifts up until it pins the cap and the daemon stops
// injecting into anything for the rest of the boot.
struct kid { pid_t child; pid_t target; };
static struct kid g_kids[MAX_INFLIGHT];

// Nothing but interrupting a blocked read; all reaping happens in the main loop.
static void on_sigchld(int sig) { (void)sig; }

static void logf_(const char *fmt, ...) {
    if (g_logfd < 0) return;
    char buf[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0) { ssize_t w = write(g_logfd, buf, (size_t)(n < (int)sizeof buf ? n : (int)sizeof buf - 1)); (void)w; }
}

// Reap finished injectors and report the ones that failed. aqinject exits 0 only after reading
// the library back out of the target's dyld image list, so a zero status is a confirmed load
// and needs no comment. Status 2 is "the target exited while we worked", which is the ordinary
// fate of every short-lived process -- each shell command, each helper -- and is not a failure.
//
// Anything else is a process that is still running without the library, which is the one
// outcome worth a line: the injector's own stderr has already gone to the log with the reason,
// and this names the pid alongside it.
static void reap_children(void) {
    for (int i = 0; i < MAX_INFLIGHT; i++) {
        if (!g_kids[i].child) continue;
        int st;
        pid_t r = waitpid(g_kids[i].child, &st, WNOHANG);
        if (r != g_kids[i].child) {
            if (r < 0 && errno == ECHILD) { g_kids[i].child = 0; g_kids[i].target = 0; }
            continue;
        }
        int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        pid_t t = g_kids[i].target;
        g_kids[i].child = 0; g_kids[i].target = 0;
        if (t <= 0 || t > PID_LIMIT) continue;
        if (code == 0 || code == 2) continue;

        char name[PROC_PIDPATHINFO_MAXSIZE];
        const char *base = "?";
        if (proc_pidpath(t, name, sizeof name) > 0) {
            const char *s = strrchr(name, '/');
            base = s ? s + 1 : name;
        }
        logf_("pid %d (%s): NOT PATCHED, injector exited %d\n", (int)t, base, code);
    }
}

static int kid_slot(void) {
    for (int i = 0; i < MAX_INFLIGHT; i++) if (!g_kids[i].child) return i;
    return -1;
}

static int is_kid(pid_t p) {
    for (int i = 0; i < MAX_INFLIGHT; i++) if (g_kids[i].child == p) return 1;
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
    if (slot < 0) {
        // The one path that drops a process without an injector ever running. It gets a line of
        // its own: this pid is not coming back around, so an unreported drop here is a process
        // that goes unpatched for its whole life with nothing to show for it.
        logf_("pid %d: NOT PATCHED, no injector slot free (%d in flight)\n", (int)pid, MAX_INFLIGHT);
        return;
    }

    char pidstr[16];
    snprintf(pidstr, sizeof pidstr, "%d", pid);
    char *av[] = { g_aqinject, "-q", pidstr, (char *)g_dylib, NULL };

    // aqinject reports success on stdout, which is per-process noise, and the reason for a
    // failure on stderr, which is the record of why a process went unpatched -- so stderr goes
    // to the log. -q suppresses the outcomes that are ordinary here rather than wrong: a
    // short-lived target exiting mid-injection is most of what this daemon ever attempts, and
    // logging that flood would bury the failures worth reading.
    posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    if (g_logfd >= 0) posix_spawn_file_actions_adddup2(&fa, g_logfd, STDERR_FILENO);
    else              posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t child;
    if (posix_spawn(&child, g_aqinject, &fa, NULL, av, environ) == 0) {
        g_kids[slot].child = child;
        g_kids[slot].target = pid;
    } else {
        logf_("pid %d: NOT PATCHED, could not spawn injector: %s\n", (int)pid, strerror(errno));
    }
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

    // Root-owned and not world-readable: the failure lines name processes on the machine, and
    // nothing here needs to be legible from a sandbox the way the rule files do. Truncated
    // rather than rotated -- a boot's worth of failures is what is worth keeping, and an
    // unbounded log on a machine this old is its own problem.
    struct stat lst;
    if (stat(LOG_PATH, &lst) == 0 && lst.st_size > LOG_MAX) unlink(LOG_PATH);
    g_logfd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (g_logfd >= 0) fchmod(g_logfd, 0600);

    // Seen-set as a bitmap over the pid space: constant-time membership, 12 KB, and a pid
    // that exits clears itself on the next sweep so pid reuse is handled without bookkeeping.
    static unsigned char seen[BITMAP_BYTES];
    static unsigned char cur[BITMAP_BYTES];

    unsigned long sweep = 0;
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

            // Processes that predate this daemon stay the installer's job (`install-macos.sh
            // inject`): injecting them here would fire an injector at every process on the
            // system during boot, launchd and the login window among them. Recording them in
            // the seen-set is what keeps the sweep below from treating them as launches.
            if (first || BIT_TEST(seen, p)) continue;

            load_into(p);
        }

        memcpy(seen, cur, sizeof seen);
        first = 0;
        sweep++;

        // Keep the log bounded while running. This daemon stays up for the life of the boot,
        // and the one thing guaranteed to write here is a process failing repeatedly, so the
        // bound has to hold without a restart to enforce it.
        if ((sweep % 6000) == 0 && g_logfd >= 0) {          // ~10 minutes
            struct stat ls;
            if (fstat(g_logfd, &ls) == 0 && ls.st_size > LOG_MAX) {
                if (ftruncate(g_logfd, 0) == 0)
                    logf_("log exceeded %d bytes and was truncated\n", LOG_MAX);
            }
        }

        reap_children();
        usleep(POLL_MS * 1000);
    }
}
