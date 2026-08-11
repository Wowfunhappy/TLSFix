// aqwatch -- hold a process at its first network syscall until AquaTransport is loaded.
//
// PURPOSE. AquaTransport is a defensive TLS-compatibility shim for Mac OS X 10.6-10.9: it
// routes Secure Transport through a modern OpenSSL so old systems can still reach current TLS
// servers. This daemon makes that fix arrive in time. It runs as root on the local machine and
// loads only our own single-purpose library, into cooperating local processes.
//
// THE PROBLEM IT SOLVES IS A CORRECTNESS DEFECT, NOT A SLOW ONE. Loading the library into a
// process after that process has started leaves a window, and a process that issues a TLS
// request inside the window uses the system's own Secure Transport -- so the request fails
// against a modern server, or succeeds against a weak one. Either outcome is the bug this
// package exists to fix. Narrowing the window does not close it, and a launch-list poller does
// not even bound it: cross-checked against proc:::exec-success, a 20 ms poller missed nine
// processes outright over one workload -- git, perl, sh, date, env -- which are exactly the
// short-lived, fast-connecting processes that matter.
//
// IN TIME FOR THE HANDSHAKE, NOT FOR THE SETUP, and that distinction is measured rather than
// assumed: CFNetwork creates and configures its SSLContext about 5 ms BEFORE it opens any socket,
// and before the DNS lookup, so the library always arrives after SSLSetIOFuncs on a process's
// first TLS connection. There is no earlier syscall to gate on. The engine answers that from the
// other side -- it takes such a context over at SSLHandshake instead of conceding it to the
// system stack -- so the first request is covered too. See aquatransport_hooks_mac.c.
//
// HOW. The kernel freezes the process instead.
//
//   kernel                          aqwatch (root, LaunchDaemon)
//   ------                          ---------------------------
//   process calls connect()
//     -> probe fires, stop()        [process frozen, synchronously, ~70 ns]
//     -> record buffered
//                                   dtrace_work() drains the record
//                                   thread_suspend(the offending thread)
//                                   kill(pid, SIGCONT)     [clears the BSD stop]
//                                   inject the library if absent      [~2-6 ms]
//                                   thread_resume(the thread)
//   process continues                                      [library present]
//
// The two held states are not the same thing, and the whole design turns on the difference. A
// DTrace stop() is a BSD PROCESS stop, and under one a pthread_create'd thread is never
// scheduled -- so the injector's stage 2, which is a real pthread, never runs and dlopen is
// never called. Converting the process stop into a Mach suspension of the single gated thread
// is what makes injection possible: suspend the thread, SIGCONT the process, inject normally,
// resume. The suspend must precede the SIGCONT, or there is an instant in which the thread is
// runnable and unpatched.
//
// INJECTION HAPPENS ONLY AT A GATE. Nothing is injected at exec, and a process that never
// touches the network never receives the library. Measured on 10.9.5: ~32 processes carrying
// it instead of ~270, and ~19 MB of private memory instead of ~156 MB.
//
// PROCESSES ALREADY RUNNING WHEN THE DAEMON STARTS ARE DELIBERATELY NOT COVERED. One that
// connected before the daemon came up is gated at its next connect, which for a process
// holding a long-lived connection may be a long time. Restarting it -- or rebooting -- covers
// it, and that is the expected remedy. A bulk pass over existing processes would reintroduce
// the whole memory cost this architecture removes, to cover a case a reboot handles.
//
// WHY libdtrace RATHER THAN dtrace(1). The consumer is linked in, so no process named `dtrace`
// appears in the process list and an operator's own interactive DTrace sessions stay
// distinguishable. It costs what dtrace(1) costs, because that footprint is libdtrace's own.
//
// WHY NOT THE AUDIT PIPE, and why not a poller: see the git history and docs/TECHNICAL.md. The
// short version is that the kernel's BSM audit pipe pairs a posix_spawn's PARENT pid with the
// CHILD's path, and that polling cannot see a process that lives for less than one interval.
//
// SAFETY. A stop() that is never released is the one failure this design can cause that a
// poller cannot, so the ways out are layered and none of them has to be perfect on its own: a
// watchdog that releases any hold older than its deadline whatever the injection is doing, an
// on-disk journal replayed at startup, a Mach suspend-count scan, and a blind SIGCONT sweep.
// See aqguard.h. Every exit path from the suspend onwards reaches the release: failing open
// and running unpatched beats leaving a thread held.
//
//   clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 -o aqwatch \
//       tools/aqwatch.c tools/aqguard.c tools/aqinject_core.c -ldtrace
//   sudo aqwatch                       (paths come from the binary's own directory)

#include "aqinject_core.h"
#include "aqguard.h"
#include "../src/aquatransport_deny.h"

#include <dtrace.h>

#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/thread_act.h>
#include <mach/machine.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

#define LOG_PATH   "/var/log/aquatransport.log"
#define LOG_MAX    (1 << 20)

#define MAX_HELD      128     // concurrent holds; also the journal's size
#define RECQ          512     // gate records buffered between the drain and the workers
#define WORKERS         4     // gate workers; an injection is 2-6 ms and must not block a drain
#define MAX_NEVER      64     // gate-never entries an operator may add
#define MAX_INETD      64
#define NAME_MAX_LEN   64

#define DEFAULT_RATE     "50hz"
#define DEFAULT_HOLD_MS  250
#define HEALTHY_SECS     120  // gates armed this long without a forced release == booted fine

// ---- log -------------------------------------------------------------------------------
//
// stderr IS the log: aqinject_core and aqguard both report there, and pointing the descriptor
// at the file rather than threading a handle through everything keeps one account of what
// happened to a process in one place, in order.

static void logf_(const char *fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    fprintf(stderr, "aqwatch: %s", buf);
}

static void log_open(void) {
    // Root-owned and not world-readable: the lines name processes on the machine, and nothing
    // here needs to be legible from a sandbox the way the rule files do. Truncated rather than
    // rotated -- a boot's worth is what is worth keeping.
    struct stat st;
    if (stat(LOG_PATH, &st) == 0 && st.st_size > LOG_MAX) unlink(LOG_PATH);
    int fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    fchmod(fd, 0600);
    dup2(fd, STDERR_FILENO);
    if (fd != STDERR_FILENO) close(fd);
    setvbuf(stderr, NULL, _IONBF, 0);
    // Nothing should reach stdout, but the injector prints there when it is not quiet and a
    // descriptor inherited from launchd is not somewhere to write to by accident.
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); if (devnull != STDOUT_FILENO) close(devnull); }
}

static void log_trim(void) {
    struct stat st;
    if (fstat(STDERR_FILENO, &st) == 0 && st.st_size > LOG_MAX) {
        if (ftruncate(STDERR_FILENO, 0) == 0)
            logf_("log exceeded %d bytes and was truncated\n", LOG_MAX);
    }
}

// ---- paths and configuration -----------------------------------------------------------

static char g_dir[1024];
static char g_dylib[1024];
static char g_aqinject[1024];
static char g_journal[1024];
static char g_stamp[1024];
static char g_flags[1024];
static char g_self_name[NAME_MAX_LEN];
static pid_t g_self;

static struct {
    int  gate_off;
    int  resume_suspended;
    int  test_stall_ms;
    char rate[16];
    int  hold_ms;
    char never[MAX_NEVER][NAME_MAX_LEN];
    int  nnever;
    char inetd[MAX_INETD][NAME_MAX_LEN];
    int  ninetd;
} g_cfg;

// Everything is co-located, so the daemon derives every path from its own location rather than
// being told them. That is also what keeps the LaunchDaemon plist to a single argument.
static int derive_paths(void) {
    char self[1024]; uint32_t sz = sizeof self;
    if (_NSGetExecutablePath(self, &sz) != 0) return 0;
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s", self);
    snprintf(g_self_name, sizeof g_self_name, "%s", basename(tmp));
    snprintf(tmp, sizeof tmp, "%s", self);
    snprintf(g_dir, sizeof g_dir, "%s", dirname(tmp));
    snprintf(g_dylib,    sizeof g_dylib,    "%s/aquatransport.dylib", g_dir);
    snprintf(g_aqinject, sizeof g_aqinject, "%s/aqinject", g_dir);
    snprintf(g_journal,  sizeof g_journal,  "%s/held.journal", g_dir);
    snprintf(g_stamp,    sizeof g_stamp,    "%s/armed.stamp", g_dir);
    snprintf(g_flags,    sizeof g_flags,    "%s/flags.txt", g_dir);
    return 1;
}

// flags.txt is the same file the library reads for its own flags, so an operator has one place
// to configure the package. The gate flags are read once here: the D program is compiled at
// startup, so a changed rate or exclusion means restarting the daemon, and pretending
// otherwise by re-reading the file would be worse than saying so.
static void read_flags(void) {
    snprintf(g_cfg.rate, sizeof g_cfg.rate, "%s", DEFAULT_RATE);
    g_cfg.hold_ms = DEFAULT_HOLD_MS;

    FILE *f = fopen(g_flags, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        size_t l = strlen(line);
        while (l && (line[l-1] == '\n' || line[l-1] == '\r' || line[l-1] == ' ' || line[l-1] == '\t')) line[--l] = 0;
        if (!l) continue;
        if (!strcmp(line, "gate-off")) { g_cfg.gate_off = 1; continue; }
        if (!strcmp(line, "gate-resume-suspended")) { g_cfg.resume_suspended = 1; continue; }
        if (!strncmp(line, "gate-rate=", 10)) {
            snprintf(g_cfg.rate, sizeof g_cfg.rate, "%s", line + 10);
            continue;
        }
        // A deliberate stall between recording the hold and injecting, which is the only way
        // to test a 2-6 ms window without racing it: with this set, the watchdog deadline, the
        // journal replay and the kill-safety cases all become things a script can arrange
        // rather than things it has to catch. Bounded by the watchdog like any other hold.
        if (!strncmp(line, "gate-test-stall-ms=", 19)) {
            int v = atoi(line + 19);
            if (v > 0) g_cfg.test_stall_ms = v;
            continue;
        }
        if (!strncmp(line, "gate-hold-ms=", 13)) {
            int v = atoi(line + 13);
            if (v > 0) g_cfg.hold_ms = v;
            continue;
        }
        if (!strncmp(line, "gate-never=", 11)) {
            if (g_cfg.nnever < MAX_NEVER)
                snprintf(g_cfg.never[g_cfg.nnever++], NAME_MAX_LEN, "%s", line + 11);
            else
                logf_("more than %d gate-never entries; ignoring \"%s\"\n", MAX_NEVER, line + 11);
            continue;
        }
        if (!strncmp(line, "gate-inetd=", 11)) {
            if (g_cfg.ninetd < MAX_INETD)
                snprintf(g_cfg.inetd[g_cfg.ninetd++], NAME_MAX_LEN, "%s", line + 11);
            else
                logf_("more than %d gate-inetd entries; ignoring \"%s\"\n", MAX_INETD, line + 11);
            continue;
        }
        // Anything else is one of the library's own flags, which this daemon does not read.
    }
    fclose(f);
}

// ---- time ------------------------------------------------------------------------------

static uint64_t now_ms(void) {
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info(&tb);
    return (uint64_t)((double)mach_absolute_time() * tb.numer / tb.denom / 1e6);
}

// ---- what the kernel says about one process ---------------------------------------------

struct procstat { uint64_t start; int lp64; };

#ifndef P_LP64
#define P_LP64 0x00000004
#endif
#ifndef SZOMB
#define SZOMB 5
#endif

// The start time is what makes a pid safe to remember. A pid alone is reused, and the library
// does not survive an exec -- so the daemon keys what it knows about a process on the pid, the
// instant the process began, and the instant of its last exec. Two of the three come from
// here; the third rides in on the gate record.
static int proc_stat(pid_t pid, struct procstat *out) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid };
    struct kinfo_proc kp; size_t len = sizeof kp;
    if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0) return 0;
    if (kp.kp_proc.p_stat == SZOMB) return 0;
    out->start = (uint64_t)kp.kp_proc.p_starttime.tv_sec * 1000000ull +
                 (uint64_t)kp.kp_proc.p_starttime.tv_usec;
    out->lp64 = (kp.kp_proc.p_flag & P_LP64) != 0;
    return 1;
}

// ---- the confirmed-patched set -----------------------------------------------------------
//
// Verifying patched-ness by walking a target's dyld image list costs 0.135 ms, which is five
// times what the whole release sequence costs, so what is already known is remembered instead.
//
// The key is (pid, process start, last exec) and all three are load-bearing. The pid alone is
// reused. The start time separates one use of a pid from the next. And the exec stamp -- the
// timestamp DTrace recorded for the process's most recent exec, carried in the gate record --
// separates one program from the next within a single pid, which matters because the library
// does not survive an exec and because xpcproxy re-execs into the real binary for every app
// and XPC service on 10.9.
//
// Nothing has to be invalidated, and no event has to arrive in any particular order: a stale
// entry simply stops matching. An eviction costs one redundant injection, which dlopen makes
// idempotent anyway.

#define PAT_SIZE 1024                            // power of two; ~32 processes are expected

static struct { pid_t pid; uint64_t start, stamp; } g_pat[PAT_SIZE];
static pthread_mutex_t g_pat_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned pat_hash(pid_t pid) { return ((unsigned)pid * 2654435761u) & (PAT_SIZE - 1); }

static int pat_known(pid_t pid, uint64_t start, uint64_t stamp) {
    int hit = 0;
    pthread_mutex_lock(&g_pat_lock);
    for (unsigned i = 0, h = pat_hash(pid); i < 8; i++, h = (h + 1) & (PAT_SIZE - 1)) {
        if (g_pat[h].pid == 0) break;
        if (g_pat[h].pid == pid) {
            hit = (g_pat[h].start == start && g_pat[h].stamp == stamp);
            break;
        }
    }
    pthread_mutex_unlock(&g_pat_lock);
    return hit;
}

static void pat_record(pid_t pid, uint64_t start, uint64_t stamp) {
    pthread_mutex_lock(&g_pat_lock);
    unsigned h = pat_hash(pid), slot = h;
    for (unsigned i = 0; i < 8; i++, h = (h + 1) & (PAT_SIZE - 1)) {
        if (g_pat[h].pid == 0 || g_pat[h].pid == pid) { slot = h; break; }
    }
    g_pat[slot].pid = pid; g_pat[slot].start = start; g_pat[slot].stamp = stamp;
    pthread_mutex_unlock(&g_pat_lock);
}

// ---- one injection per process at a time --------------------------------------------------
//
// The confirmed-patched set only helps AFTER an injection finishes, so it does nothing for
// threads that gate at the same moment: each worker asks "is this process patched", all get
// "no", and all inject. Observed on a live machine: vmnet-natd, a multithreaded daemon, injected
// SIX times from one gate storm. dlopen makes the duplicates harmless to the library, but not to
// the target -- each one is another bare mach thread, another allocation, and another run of the
// dynamic linker inside a process that may be forwarding packets while it happens.
//
// So the process, not the set, is what a worker claims. The first worker to arrive for a pid
// injects; the rest wait and then re-check the set, which by then says yes and costs them a
// signal. Waiting is bounded by the same watchdog as everything else on this path, and progress
// is guaranteed because the holder of a claim is never itself waiting.

#define INFLIGHT_MAX 64

static pid_t           g_inflight[INFLIGHT_MAX];
static pthread_mutex_t g_inflight_lock = PTHREAD_MUTEX_INITIALIZER;

// Claims the right to inject `pid`. Returns 0 if another worker already holds it.
//
// It does NOT wait, and that is the whole point. A worker blocked here is a worker not draining
// the queue, and every record still in the queue is a thread whose stop() has already frozen
// this process. Under a BSD stop the injected stage 2 is never scheduled -- so waiting for an
// injection to finish is waiting for something that cannot finish until the waiter goes back to
// work. Measured directly: eight threads gating at once wedged the target every time.
//
// So a worker that loses the race releases its own thread and moves on. That thread may run
// briefly before the library lands, which is the window per-thread latching exists to close --
// but it is a window on one thread of a process that is being patched right now, against
// deadlocking the whole process, and that is not a close call.
static int inflight_claim(pid_t pid) {
    int got = 0;
    pthread_mutex_lock(&g_inflight_lock);
    int busy = 0, slot = -1;
    for (int i = 0; i < INFLIGHT_MAX; i++) {
        if (g_inflight[i] == pid) { busy = 1; break; }
        if (g_inflight[i] == 0 && slot < 0) slot = i;
    }
    if (!busy && slot >= 0) { g_inflight[slot] = pid; got = 1; }
    else if (!busy)         { got = 1; }   // table full: proceed rather than stall a release
    pthread_mutex_unlock(&g_inflight_lock);
    return got;
}

static void inflight_release(pid_t pid) {
    pthread_mutex_lock(&g_inflight_lock);
    for (int i = 0; i < INFLIGHT_MAX; i++) if (g_inflight[i] == pid) { g_inflight[i] = 0; break; }
    pthread_mutex_unlock(&g_inflight_lock);
}

// ---- the held table and the watchdog -----------------------------------------------------
//
// Pre-allocated at startup, and the release path allocates nothing, so memory pressure cannot
// be the reason a thread stays held.

enum { SLOT_FREE = 0, SLOT_HELD, SLOT_RELEASED };

static struct {
    int          state;
    pid_t        pid;
    uint64_t     tid;
    thread_act_t thread;                         // the worker owns this right for the slot's life
    uint64_t     deadline_ms;
} g_held[MAX_HELD];

static pthread_mutex_t g_held_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long   g_forced;                 // watchdog releases, the signal that this is load-bearing

static int held_claim(pid_t pid, uint64_t tid, thread_act_t th) {
    int slot = -1;
    pthread_mutex_lock(&g_held_lock);
    for (int i = 0; i < MAX_HELD; i++) {
        if (g_held[i].state == SLOT_FREE) {
            g_held[i].state = SLOT_HELD;
            g_held[i].pid = pid; g_held[i].tid = tid; g_held[i].thread = th;
            g_held[i].deadline_ms = now_ms() + (uint64_t)g_cfg.hold_ms;
            slot = i;
            break;
        }
    }
    pthread_mutex_unlock(&g_held_lock);
    return slot;
}

// Give the slot back, resuming the thread unless the watchdog already did.
static void held_done(int slot) {
    pthread_mutex_lock(&g_held_lock);
    if (g_held[slot].state == SLOT_HELD) thread_resume(g_held[slot].thread);
    g_held[slot].state = SLOT_FREE;
    pthread_mutex_unlock(&g_held_lock);
    aqj_clear(slot);
}

// Defined with the queue it drains; the watchdog is simply where it is driven from.
static void queue_expire(void);

// Releases any hold past its deadline regardless of what the injection is doing. 250 ms is
// ample against a 2-6 ms injection, so anything this releases is worth a log line: these three
// counters -- forced releases, sweeps that freed something, and drops -- are what say whether
// the safety net is holding anything up.
static void *watchdog(void *arg) {
    (void)arg;
    for (;;) {
        usleep(10000);
        queue_expire();
        uint64_t now = now_ms();
        pthread_mutex_lock(&g_held_lock);
        for (int i = 0; i < MAX_HELD; i++) {
            if (g_held[i].state != SLOT_HELD || now < g_held[i].deadline_ms) continue;
            thread_resume(g_held[i].thread);
            g_held[i].state = SLOT_RELEASED;
            g_forced++;
            logf_("watchdog released pid %d tid %llu after %d ms\n",
                  (int)g_held[i].pid, (unsigned long long)g_held[i].tid, g_cfg.hold_ms);
        }
        pthread_mutex_unlock(&g_held_lock);
    }
    return NULL;
}

static void release_all_held(void) {
    pthread_mutex_lock(&g_held_lock);
    for (int i = 0; i < MAX_HELD; i++) {
        if (g_held[i].state != SLOT_HELD) continue;
        thread_resume(g_held[i].thread);
        kill(g_held[i].pid, SIGCONT);
        g_held[i].state = SLOT_RELEASED;
    }
    pthread_mutex_unlock(&g_held_lock);
}

// ---- the cross-architecture helpers ------------------------------------------------------
//
// Resolved dyld-cache addresses and the pthread_attr_t layout are both architecture-specific, so
// this daemon's slice can only inject targets of its own kind. For the others it keeps aqinject
// running under the other architecture and hands it pids over a socketpair, so a
// cross-architecture target pays no process spawn either, after the first.
//
// THERE IS ONE CHANNEL PER WORKER, and that is not an optimisation. A helper answers one request
// at a time, so a single shared channel makes every worker queue behind whichever one is using
// it -- and a worker waiting is a worker not draining. Every record still in the queue is a
// process the kernel has already frozen with stop(), so a starved drain does not merely delay
// injections: it leaves unrelated processes stopped with nobody left to continue them. Opening
// Dashboard is enough to trigger it, because its widgets are i386 and arrive in a burst, so
// every one of them needs this path at once.
//
// With as many channels as workers, a free one always exists and no worker ever waits. They are
// spawned on first need: on a machine whose processes are all one architecture, none is ever
// wanted, and idle processes to cover a case that never arrives are not free.

struct helper {
    pthread_mutex_t lock;
    int             fd;
    pid_t           pid;
};
static struct helper g_help[WORKERS];

static void helper_init(void) {
    for (int i = 0; i < WORKERS; i++) {
        pthread_mutex_init(&g_help[i].lock, NULL);
        g_help[i].fd = -1;
        g_help[i].pid = 0;
    }
}

static int helper_is_ours(pid_t pid) {
    for (int i = 0; i < WORKERS; i++) if (g_help[i].pid == pid) return 1;
    return 0;
}

static void helper_close(struct helper *h) {
    if (h->fd >= 0) { close(h->fd); h->fd = -1; }
    if (h->pid > 0) { kill(h->pid, SIGKILL); waitpid(h->pid, NULL, 0); h->pid = 0; }
}

static void helper_close_all(void) {
    for (int i = 0; i < WORKERS; i++) helper_close(&g_help[i]);
}

static int helper_start(struct helper *h) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return 0;
    // A wedged helper must not wedge a worker for longer than the gate can afford. The timeout
    // is well past any real injection.
    struct timeval tv = { 5, 0 };
    setsockopt(sp[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, sp[1], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&fa, sp[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&fa, STDERR_FILENO, STDERR_FILENO);
    posix_spawn_file_actions_addclose(&fa, sp[0]);

    posix_spawnattr_t at; posix_spawnattr_init(&at);
    cpu_type_t pref[1] = { aq_self_lp64() ? CPU_TYPE_X86 : CPU_TYPE_X86_64 };
    size_t oc = 0;
    posix_spawnattr_setbinpref_np(&at, 1, pref, &oc);

    char *av[] = { g_aqinject, (char *)"--helper", g_dylib, NULL };
    pid_t p = 0;
    int r = posix_spawn(&p, g_aqinject, &fa, &at, av, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&at);
    close(sp[1]);
    if (r != 0) { close(sp[0]); errno = r; logf_("cannot start the %s helper: %s\n",
                                                 aq_self_lp64() ? "i386" : "x86_64", strerror(r)); return 0; }
    h->fd = sp[0];
    h->pid = p;
    logf_("started the %s injection helper (pid %d)\n", aq_self_lp64() ? "i386" : "x86_64", (int)p);
    return 1;
}

static int helper_inject(pid_t pid, int gated) {
    // Whichever channel is free. There are as many as there are workers, so the scan always
    // finds one -- and it never blocks, because blocking here is what starves the drain.
    struct helper *h = NULL;
    for (int i = 0; i < WORKERS; i++) {
        if (pthread_mutex_trylock(&g_help[i].lock) == 0) { h = &g_help[i]; break; }
    }
    if (!h) {
        logf_("pid %d: NOT PATCHED, every injection helper is busy\n", (int)pid);
        return AQ_FAILED;
    }

    int status = AQ_FAILED;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (h->fd < 0 && !helper_start(h)) break;

        char req[32];
        int n = snprintf(req, sizeof req, "%c %d\n", gated ? 'G' : 'N', (int)pid);
        if (write(h->fd, req, (size_t)n) != n) { helper_close(h); continue; }

        // One reply line. This channel has a single writer and the helper answers one request
        // at a time, so there is never more than one line in flight on it.
        char reply[64]; size_t got = 0;
        int ok = 0;
        while (got < sizeof reply - 1) {
            ssize_t r = read(h->fd, reply + got, 1);
            if (r != 1) break;
            if (reply[got] == '\n') { ok = 1; break; }
            got++;
        }
        if (!ok) { logf_("an injection helper stopped answering; restarting it\n"); helper_close(h); continue; }
        reply[got] = 0;
        int rpid = 0, rst = AQ_FAILED;
        if (sscanf(reply, "%d %d", &rpid, &rst) == 2 && rpid == (int)pid) status = rst;
        break;
    }
    pthread_mutex_unlock(&h->lock);
    return status;
}

static int inject_target(pid_t pid, int lp64, int gated) {
    if (lp64 == aq_self_lp64()) {
        aq_opts o; memset(&o, 0, sizeof o);
        o.quiet = 1; o.gated = gated;
        return aq_inject_retrying(pid, g_dylib, &o);
    }
    return helper_inject(pid, gated);
}

// ---- the gate ----------------------------------------------------------------------------

static void gate_one(pid_t pid, uint64_t tid, uint64_t stamp, const char *name) {
    // The record names a process the kernel has already frozen, so every path out of here has
    // to end in that process running again -- including the paths that decide not to inject.
    if (pid <= 1 || pid == g_self || helper_is_ours(pid)) { kill(pid, SIGCONT); return; }

    struct procstat ps;
    if (!proc_stat(pid, &ps)) return;            // gone; there is nothing left to release

    // The fast path, and the reason the set exists: a process already carrying the library
    // wants to run, not to be held. Nothing is suspended, so this is one signal.
    if (pat_known(pid, ps.start, stamp)) { kill(pid, SIGCONT); return; }

    task_t task = MACH_PORT_NULL;
    thread_act_t th = MACH_PORT_NULL;
    int slot = -1;

    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
        kill(pid, SIGCONT);
        logf_("pid %d (%s): NOT PATCHED, no task port\n", (int)pid, name);
        return;
    }
    if (!aq_find_thread(task, tid, &th)) {
        kill(pid, SIGCONT);
        mach_port_deallocate(mach_task_self(), task);
        logf_("pid %d (%s): NOT PATCHED, gated thread %llu is gone\n", (int)pid, name, (unsigned long long)tid);
        return;
    }
    // Before the SIGCONT, never after: between the two the thread must never be runnable and
    // unpatched, and that ordering is the only thing enforcing it.
    if (thread_suspend(th) != KERN_SUCCESS) {
        kill(pid, SIGCONT);
        goto out;
    }
    // A hold with no slot has no watchdog behind it, so it is not a hold worth taking.
    if ((slot = held_claim(pid, tid, th)) < 0) {
        thread_resume(th);
        kill(pid, SIGCONT);
        logf_("pid %d (%s): NOT PATCHED, all %d hold slots are in use\n", (int)pid, name, MAX_HELD);
        goto out;
    }
    aqj_set(slot, pid, tid);
    kill(pid, SIGCONT);                          // clears the BSD stop; the thread stays held

    if (g_cfg.test_stall_ms > 0) usleep((useconds_t)g_cfg.test_stall_ms * 1000);

    // One injection per process: a second thread arriving here for the same pid waits, then
    // finds the set already says yes.
    if (!inflight_claim(pid)) {
        // Another worker is injecting this very process. Let this thread go rather than hold a
        // worker -- and the queue -- hostage to it.
        held_done(slot);
        goto out;
    }
    {
        int r = inject_target(pid, ps.lp64, 1);
        inflight_release(pid);
        if (r == AQ_OK) {
            pat_record(pid, ps.start, stamp);
            // One line per process that takes the library, which is the whole account of what
            // this daemon did to the machine: about 32 of them over a session, against ~270
            // processes. It is also what says the fast path is a fast path -- a process gated
            // a second time appears here once.
            logf_("pid %d (%s): patched at gate\n", (int)pid, name);
        } else if (r == AQ_FAILED) {
            logf_("pid %d (%s): NOT PATCHED, injection failed\n", (int)pid, name);
        }
    }
    held_done(slot);

out:
    if (th != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), th);
    mach_port_deallocate(mach_task_self(), task);
}

// The gate-off path: load the library at exec and freeze nothing. It reopens the window this
// daemon exists to close -- the library arrives when it arrives, and a process that connects
// first goes unpatched -- which is the point of an escape hatch and why it is not the default.
static void exec_one(pid_t pid, const char *name) {
    if (pid <= 1 || pid == g_self || helper_is_ours(pid)) return;
    struct procstat ps;
    if (!proc_stat(pid, &ps)) return;
    if (inject_target(pid, ps.lp64, 0) == AQ_OK) logf_("pid %d (%s): patched at exec\n", (int)pid, name);
}

// ---- the record queue ----------------------------------------------------------------------
//
// The drain must never wait on an injection. libdtrace formats records into a FILE*, a reader
// thread parses them off the other end of a pipe, and the workers do the gate -- so a 6 ms
// injection cannot stall the consumer and turn a held process into a dropped record.

struct rec { char kind; pid_t pid; uint64_t tid, stamp; char name[32]; uint64_t queued_ms; };

static struct rec g_q[RECQ];
static int g_qhead, g_qtail, g_qclosed;
static pthread_mutex_t g_qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_qcond = PTHREAD_COND_INITIALIZER;

// A RECORD WAITING IN THE QUEUE IS A FROZEN PROCESS THAT NOTHING ELSE BOUNDS.
//
// The watchdog below covers holds -- threads this daemon suspended and recorded. A record still
// in the queue has none of that: stop() froze its process in the kernel, and until a worker
// reaches it there is no slot, no journal entry and no deadline. So if the workers ever stop
// draining, unrelated processes stay stopped indefinitely, and the machine grinds rather than
// merely going unpatched.
//
// Workers have been starved twice by things that looked local: waiting for another worker's
// injection, and queueing behind a single shared cross-architecture helper. Both are fixed, but
// the failure they produced is far too severe to leave resting on having found every cause. This
// puts the same deadline on queue residency that the watchdog puts on a hold: past it, the
// process is let go unpatched, which is the outcome this design prefers everywhere else.
static void queue_expire(void) {
    uint64_t now = now_ms();
    for (;;) {
        pid_t victim = 0;
        pthread_mutex_lock(&g_qlock);
        if (g_qhead != g_qtail && now - g_q[g_qtail].queued_ms > (uint64_t)g_cfg.hold_ms) {
            if (g_q[g_qtail].kind == 'G') victim = g_q[g_qtail].pid;
            g_qtail = (g_qtail + 1) % RECQ;
        }
        pthread_mutex_unlock(&g_qlock);
        if (!victim) break;
        kill(victim, SIGCONT);
        logf_("pid %d: NOT PATCHED, waited more than %d ms for a worker; released unpatched\n",
              (int)victim, g_cfg.hold_ms);
    }
}

static void q_push(const struct rec *r) {
    pthread_mutex_lock(&g_qlock);
    int next = (g_qhead + 1) % RECQ;
    if (next == g_qtail) {                       // full: let the process go rather than lose it
        pthread_mutex_unlock(&g_qlock);
        if (r->kind == 'G') {
            kill(r->pid, SIGCONT);
            logf_("pid %d: NOT PATCHED, the gate queue is full\n", (int)r->pid);
        }
        return;
    }
    g_q[g_qhead] = *r;
    g_q[g_qhead].queued_ms = now_ms();
    g_qhead = next;
    pthread_cond_signal(&g_qcond);
    pthread_mutex_unlock(&g_qlock);
}

static void *worker(void *arg) {
    (void)arg;
    for (;;) {
        struct rec r;
        pthread_mutex_lock(&g_qlock);
        while (g_qhead == g_qtail && !g_qclosed) pthread_cond_wait(&g_qcond, &g_qlock);
        if (g_qhead == g_qtail) { pthread_mutex_unlock(&g_qlock); return NULL; }
        r = g_q[g_qtail];
        g_qtail = (g_qtail + 1) % RECQ;
        pthread_mutex_unlock(&g_qlock);

        if (r.kind == 'G') gate_one(r.pid, r.tid, r.stamp, r.name);
        else               exec_one(r.pid, r.name);
    }
}

static void *reader(void *arg) {
    FILE *rd = (FILE *)arg;
    char line[512];
    while (fgets(line, sizeof line, rd)) {
        struct rec r; memset(&r, 0, sizeof r);
        int pid = 0; unsigned long long tid = 0, stamp = 0;
        if (sscanf(line, "G %d %llu %llu %31s", &pid, &tid, &stamp, r.name) == 4) {
            r.kind = 'G'; r.pid = (pid_t)pid; r.tid = tid; r.stamp = stamp;
        } else if (sscanf(line, "X %d %31s", &pid, r.name) == 2) {
            r.kind = 'X'; r.pid = (pid_t)pid;
        } else {
            continue;                            // D's own diagnostics, if any ever appear
        }
        q_push(&r);
    }
    pthread_mutex_lock(&g_qlock);
    g_qclosed = 1;
    pthread_cond_broadcast(&g_qcond);
    pthread_mutex_unlock(&g_qlock);
    return NULL;
}

// ---- running a helper program and reading what it said -------------------------------------

static int run_capture(char *const av[], char *buf, size_t n) {
    int pfd[2];
    if (pipe(pfd) != 0) return 0;
    posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pfd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addclose(&fa, pfd[0]);
    pid_t p = 0;
    int r = posix_spawn(&p, av[0], &fa, NULL, av, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(pfd[1]);
    if (r != 0) { close(pfd[0]); return 0; }
    size_t got = 0;
    while (got < n - 1) {
        ssize_t k = read(pfd[0], buf + got, n - 1 - got);
        if (k <= 0) break;
        got += (size_t)k;
    }
    buf[got] = 0;
    close(pfd[0]);
    int st = 0; waitpid(p, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static int chew(const dtrace_probedata_t *d, void *a) { (void)d; (void)a; return DTRACE_CONSUME_THIS; }
static int chewrec(const dtrace_probedata_t *d, const dtrace_recdesc_t *r, void *a) {
    (void)d; (void)a;
    return r == NULL ? DTRACE_CONSUME_NEXT : DTRACE_CONSUME_THIS;
}

// ---- how far the kernel truncates execname -------------------------------------------------
//
// This is measured, not assumed, and the whole exclusion list depends on getting it right.
//
// execname is NOT the 16-character MAXCOMLEN truncation that shows up elsewhere: on 10.9.5 it
// is 15, so a process named securityd_service reports securityd_servi. A D predicate written
// as `execname == "securityd_servic"` -- the 16 characters a careful reading of the other
// truncation suggests -- compiles, runs, and matches nothing, and the daemon it was written to
// skip gets frozen and injected instead. The failure is silent: no error appears anywhere.
//
// So the length is established by asking DTrace directly, once, before the gates arm: exec a
// copy of a harmless binary under a deliberately over-long name and read back what execname
// says it was called. If that cannot be established, the exclusion list cannot be trusted, and
// the daemon comes up with the gates disabled rather than arming a predicate that may be dead.

#define CALIB_NAME "aqcalibrate0123456789abcdefghijklmnopqrs"   /* 40 characters */

static int copy_file(const char *from, const char *to, mode_t mode) {
    int in = open(from, O_RDONLY);
    if (in < 0) return 0;
    int out = open(to, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) { close(in); return 0; }
    char buf[65536]; ssize_t k; int ok = 1;
    while ((k = read(in, buf, sizeof buf)) > 0) if (write(out, buf, (size_t)k) != k) { ok = 0; break; }
    if (k < 0) ok = 0;
    close(in); close(out);
    if (ok) chmod(to, mode);
    return ok;
}

static int measure_execname_limit(void) {
    char dir[] = "/var/tmp/aqcalib.XXXXXX";
    if (!mkdtemp(dir)) { logf_("calibration: no temp directory: %s\n", strerror(errno)); return 0; }

    char prog[1024], out[1024], progtext[512];
    snprintf(prog, sizeof prog, "%s/%s", dir, CALIB_NAME);
    snprintf(out,  sizeof out,  "%s/out", dir);

    int limit = 0;
    dtrace_hdl_t *dtp = NULL;
    FILE *fp = NULL, *sink = NULL;

    if (!copy_file("/usr/bin/true", prog, 0755)) { logf_("calibration: cannot stage %s\n", prog); goto done; }

    snprintf(progtext, sizeof progtext,
             "proc:::exec-success /ppid == %d/ { printf(\"N %%s\\n\", execname); }\n", (int)g_self);
    {
        char dpath[1024];
        snprintf(dpath, sizeof dpath, "%s/d", dir);
        FILE *w = fopen(dpath, "w");
        if (!w) goto done;
        fputs(progtext, w);
        fclose(w);
        fp = fopen(dpath, "r");
        if (!fp) goto done;
    }

    int err;
    if ((dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
        logf_("calibration: dtrace_open: %s\n", dtrace_errmsg(NULL, err));
        goto done;
    }
    dtrace_setopt(dtp, "bufsize", "64k");
    dtrace_setopt(dtp, "switchrate", "100hz");
    {
        dtrace_prog_t *pgp = dtrace_program_fcompile(dtp, fp, DTRACE_C_PSPEC, 0, NULL);
        if (!pgp) { logf_("calibration: compile: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp))); goto done; }
        dtrace_proginfo_t info; memset(&info, 0, sizeof info);
        if (dtrace_program_exec(dtp, pgp, &info) == -1) { logf_("calibration: enable failed\n"); goto done; }
    }
    if (dtrace_go(dtp) == -1) { logf_("calibration: go: %s\n", dtrace_errmsg(dtp, dtrace_errno(dtp))); goto done; }

    {
        char *av[] = { prog, NULL };
        pid_t p = 0;
        if (posix_spawn(&p, prog, NULL, NULL, av, environ) != 0) { logf_("calibration: cannot run %s\n", prog); goto done; }
        waitpid(p, NULL, 0);
    }

    sink = fopen(out, "w+");
    if (!sink) goto done;
    for (int i = 0; i < 100 && limit == 0; i++) {
        dtrace_sleep(dtp);
        if (dtrace_work(dtp, sink, chew, chewrec, NULL) == DTRACE_WORKSTATUS_ERROR) break;
        fflush(sink);
        rewind(sink);
        char line[256];
        while (fgets(line, sizeof line, sink)) {
            char name[128];
            if (sscanf(line, "N %127s", name) == 1) { limit = (int)strlen(name); break; }
        }
        fseek(sink, 0, SEEK_END);
    }

done:
    if (sink) fclose(sink);
    if (dtp) { dtrace_stop(dtp); dtrace_close(dtp); }
    if (fp) fclose(fp);
    unlink(prog);
    { char p[1024]; snprintf(p, sizeof p, "%s/d", dir); unlink(p); }
    unlink(out);
    rmdir(dir);
    return limit;
}

// ---- launchd's inetd jobs ------------------------------------------------------------------
//
// A job with inetdCompatibility is handed an already-connected socket by launchd and calls
// neither connect nor accept, so neither gate can see it. 10.9 ships 18 such plists -- ssh,
// telnet, ftp, tftp, finger, cups-lpd, eppc and the rest -- and on a stock machine none of them
// is loaded, in which case the clause that would cover them is not emitted at all.
//
// The scan is a raw substring test first, which is both cheap and correct for XML and binary
// plists alike, and only then a plutil conversion of the handful that survive it.

static int name_in(char names[][NAME_MAX_LEN], int n, const char *name) {
    for (int i = 0; i < n; i++) if (!strcmp(names[i], name)) return 1;
    return 0;
}

static int file_contains(const char *path, const char *needle) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    static char buf[262144];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    return strstr(buf, needle) != NULL;
}

// The value of the first <string> after <key>NAME</key>. Enough for Label and Program; for
// ProgramArguments it lands on the first argument, which is the executable.
static int xml_value(const char *xml, const char *key, char *out, size_t n) {
    char pat[128];
    snprintf(pat, sizeof pat, "<key>%s</key>", key);
    const char *k = strstr(xml, pat);
    if (!k) return 0;
    const char *s = strstr(k, "<string>");
    if (!s) return 0;
    s += 8;
    const char *e = strstr(s, "</string>");
    if (!e || (size_t)(e - s) >= n) return 0;
    memcpy(out, s, (size_t)(e - s));
    out[e - s] = 0;
    return 1;
}

static int scan_inetd_jobs(char names[][NAME_MAX_LEN], int max, int found) {
    static char loaded[262144];
    { char *av[] = { (char *)"/bin/launchctl", (char *)"list", NULL };
      if (!run_capture(av, loaded, sizeof loaded)) loaded[0] = 0; }

    static const char *dirs[] = { "/System/Library/LaunchDaemons", "/Library/LaunchDaemons", NULL };
    for (int d = 0; dirs[d]; d++) {
        DIR *dp = opendir(dirs[d]);
        if (!dp) continue;
        struct dirent *de;
        while ((de = readdir(dp)) != NULL && found < max) {
            size_t l = strlen(de->d_name);
            if (l < 7 || strcmp(de->d_name + l - 6, ".plist")) continue;
            char path[1024];
            snprintf(path, sizeof path, "%s/%s", dirs[d], de->d_name);
            if (!file_contains(path, "inetdCompatibility")) continue;

            static char xml[262144];
            char *av[] = { (char *)"/usr/bin/plutil", (char *)"-convert", (char *)"xml1",
                           (char *)"-o", (char *)"-", path, NULL };
            if (!run_capture(av, xml, sizeof xml)) {
                logf_("cannot read %s; its inetd gate is not armed\n", path);
                continue;
            }
            char label[256], prog[1024];
            if (!xml_value(xml, "Label", label, sizeof label)) continue;
            if (!loaded[0] || !strstr(loaded, label)) continue;      // not loaded: nothing to gate
            if (!xml_value(xml, "Program", prog, sizeof prog) &&
                !xml_value(xml, "ProgramArguments", prog, sizeof prog)) continue;
            char tmp[1024]; snprintf(tmp, sizeof tmp, "%s", prog);
            const char *base = basename(tmp);
            if (name_in(names, found, base)) continue;
            snprintf(names[found++], NAME_MAX_LEN, "%s", base);
            logf_("inetd job %s (%s) will be gated on its inherited socket\n", label, base);
        }
        closedir(dp);
    }
    return found;
}

// ---- the D program -------------------------------------------------------------------------

// Truncate to what the kernel will actually report, so nothing anywhere has to count
// characters and an operator writes full names everywhere.
static void trunc_name(const char *in, int limit, char *out, size_t n) {
    snprintf(out, n, "%s", in);
    if (limit > 0 && (int)strlen(out) > limit) out[limit] = 0;
}

static void emit_denied(FILE *f, int limit, char used[][NAME_MAX_LEN], int *nused) {
    // The names the package never touches, and why, are in aquatransport_deny.h. Two kinds:
    // the trust daemons, which would route the library's own trust evaluation through the
    // process that implements it, and processes whose freezing costs far more than gating them
    // could ever gain -- launchd above all, which a "pid > 1" test does NOT cover, because the
    // per-user launchd that starts every service in a login session has an ordinary pid.
    const char *extra[3];
    int nx = 0;
    extra[nx++] = g_self_name;                   // this daemon has nobody to release it
    extra[nx++] = "aqinject";                    // nor does its own injection helper
    extra[nx] = NULL;

    for (int i = 0; kAquaNeverTouch[i]; i++) {
        char t[NAME_MAX_LEN];
        trunc_name(kAquaNeverTouch[i], limit, t, sizeof t);
        if (name_in(used, *nused, t)) continue;
        snprintf(used[(*nused)++], NAME_MAX_LEN, "%s", t);
        fprintf(f, "\tdenied[\"%s\"] = 1;\n", t);
    }
    for (int i = 0; i < nx; i++) {
        char t[NAME_MAX_LEN];
        trunc_name(extra[i], limit, t, sizeof t);
        if (name_in(used, *nused, t)) continue;
        snprintf(used[(*nused)++], NAME_MAX_LEN, "%s", t);
        fprintf(f, "\tdenied[\"%s\"] = 1;\n", t);
    }
    for (int i = 0; i < g_cfg.nnever; i++) {
        char t[NAME_MAX_LEN];
        trunc_name(g_cfg.never[i], limit, t, sizeof t);
        if (name_in(used, *nused, t)) {
            logf_("gate-never=%s truncates to \"%s\", which is already excluded\n", g_cfg.never[i], t);
            continue;
        }
        snprintf(used[(*nused)++], NAME_MAX_LEN, "%s", t);
        fprintf(f, "\tdenied[\"%s\"] = 1;\n", t);
    }
}

// Writes the program and returns how many clauses it has, which is what the enable is checked
// against afterwards.
static int write_program(const char *path, int limit,
                         char inetd[][NAME_MAX_LEN], int ninetd) {
    FILE *f = fopen(path, "w");
    if (!f) return 0;

    char used[MAX_NEVER + 16][NAME_MAX_LEN];
    int nused = 0;
    int clauses = 0;

    fprintf(f, "/* generated by aqwatch; execname truncates to %d characters here */\n", limit);
    fprintf(f, "BEGIN\n{\n");
    emit_denied(f, limit, used, &nused);
    for (int i = 0; i < ninetd; i++) {
        char t[NAME_MAX_LEN];
        trunc_name(inetd[i], limit, t, sizeof t);
        fprintf(f, "\tinetd[\"%s\"] = 1;\n", t);
    }
    fprintf(f, "}\n\n");
    clauses++;

    if (g_cfg.gate_off) {
        // The escape hatch: arm nothing, freeze nothing, and fall back to loading the library
        // at exec -- which restores the window this daemon exists to close, and says so.
        fprintf(f,
            "proc:::exec-success\n"
            "/pid > 1 && !denied[execname]/\n"
            "{ printf(\"X %%d %%s\\n\", pid, execname); }\n");
        clauses++;
        fclose(f);
        return clauses;
    }

    // The library does not survive an exec, so neither may the latch. The exec timestamp is
    // also what lets the daemon tell one program from the next within a single pid, which
    // matters because xpcproxy re-execs into the real binary for every app and XPC service on
    // 10.9. Both associative arrays are cleared on thread and process exit; without that they
    // grow for the life of the boot.
    fprintf(f,
        "proc:::exec-success { latched[tid] = 0; execstamp[pid] = timestamp; }\n"
        "proc:::lwp-exit     { latched[tid] = 0; }\n"
        "proc:::exit         { latched[tid] = 0; execstamp[pid] = 0; }\n\n");
    clauses += 3;

    // Outbound, and it takes THREE syscalls to cover, not one.
    //
    // connect_nocancel is the same trap write_nocancel is: a blocking call made from a thread
    // that is a cancellation point goes through the _nocancel variant, and a predicate on the
    // plain name silently never fires for it.
    //
    // connectx is the one that matters most, and it is not an edge case. On 10.9 CFNetwork does
    // not call connect() for a TCP connection at all -- it calls connectx(), so gating connect
    // alone misses every CFNetwork client, which is nearly every application this package
    // exists for. Measured directly: a CFNetwork request to an https host produces
    // connect_nocancel for a unix socket, connect for an AF_SYSTEM control socket, and the real
    // TCP connection only as connectx.
    //
    // Its 10.9 signature puts the SOURCE address in arg1 -- normally null -- and the
    // DESTINATION in arg3, which is why it cannot share the address argument with the others.
    //
    // sockaddr on OS X: byte 0 is sa_len, byte 1 is sa_family. AF_INET is 2 and AF_INET6 is 30;
    // everything else -- unix and AF_SYSTEM sockets above all -- is not our business.
    //
    // this->fam is cleared before the copyin rather than relied upon to start at zero: a
    // clause-local carries whatever the last firing left in it, and a connectx with no
    // destination would otherwise inherit a previous connection's family and be gated on it.
    fprintf(f,
        "syscall::connect:entry, syscall::connect_nocancel:entry\n"
        "{ this->sa = arg1; this->fam = 0; }\n\n"
        "syscall::connectx:entry\n"
        "{ this->sa = arg3; this->fam = 0; }\n\n"
        "syscall::connect:entry, syscall::connect_nocancel:entry, syscall::connectx:entry\n"
        "/this->sa != 0/\n"
        "{ this->p = (uint8_t *)copyin(this->sa, 2); this->fam = this->p[1]; }\n\n"
        "syscall::connect:entry, syscall::connect_nocancel:entry, syscall::connectx:entry\n"
        "/(this->fam == 2 || this->fam == 30) && pid > 1 && latched[tid] == 0 && !denied[execname]/\n"
        "{ latched[tid] = 1; stop();\n"
        "  printf(\"G %%d %%llu %%llu %%s\\n\", pid, (unsigned long long)tid,\n"
        "         (unsigned long long)execstamp[pid], execname); }\n\n");
    clauses += 4;

    // Inbound, on RETURN so the descriptor exists and the thread is held before it can be
    // used. At entry there is no connection yet and the thread would sit in the gate while the
    // process was merely idle waiting for one.
    fprintf(f,
        "syscall::accept*:return\n"
        "/arg0 >= 0 && pid > 1 && latched[tid] == 0 && !denied[execname]/\n"
        "{ latched[tid] = 1; stop();\n"
        "  printf(\"G %%d %%llu %%llu %%s\\n\", pid, (unsigned long long)tid,\n"
        "         (unsigned long long)execstamp[pid], execname); }\n\n");
    clauses++;

    // Inherited connected socket, inetd style: the process calls neither connect nor accept, so
    // its first touch of the network is a read or a write. Emitted only for jobs that are
    // actually loaded, because this is the one clause on a hot syscall. stdio flushes through
    // write_nocancel rather than write, so the wildcard is not optional -- a predicate on
    // `write` alone silently never fires.
    if (ninetd > 0) {
        fprintf(f,
            "syscall::read*:entry, syscall::write*:entry\n"
            "/inetd[execname] && pid > 1 && latched[tid] == 0 && !denied[execname]/\n"
            "{ latched[tid] = 1; stop();\n"
            "  printf(\"G %%d %%llu %%llu %%s\\n\", pid, (unsigned long long)tid,\n"
            "         (unsigned long long)execstamp[pid], execname); }\n\n");
        clauses++;
    }

    fclose(f);
    return clauses;
}

// ---- the consumer ------------------------------------------------------------------------

static dtrace_hdl_t *g_dtp;
static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_dropped;
static unsigned long g_drops, g_sweeps;

static void on_sig(int s) { (void)s; g_stop = 1; }

static int on_err(const dtrace_errdata_t *e, void *a) {
    (void)a;
    logf_("D error: %s\n", e->dteda_msg ? e->dteda_msg : "?");
    return DTRACE_HANDLE_OK;
}

// A drop is a gate record that was never delivered, which by definition means a process may be
// frozen with nobody holding its pid. Nothing distinguishes such a process from a running one,
// so the answer is the blind sweep -- run from the main loop rather than from here, since this
// runs inside the drain.
static int on_drop(const dtrace_dropdata_t *d, void *a) {
    (void)a;
    logf_("DROP: %s\n", d->dtdda_msg ? d->dtdda_msg : "?");
    g_dropped = 1;
    return DTRACE_HANDLE_OK;
}

// ---- health ------------------------------------------------------------------------------

// The stamp exists so a gate-induced hang can happen at most once. It is written when the
// gates arm and removed once the machine has plainly finished booting with them armed; a
// start that finds a PREVIOUS boot's stamp still in place comes up gate-disabled.
static void *healthy_after_a_while(void *arg) {
    (void)arg;
    sleep(HEALTHY_SECS);
    if (g_forced == 0) {
        aq_stamp_clear(g_stamp);
        logf_("gates have been armed for %d s with no forced release; cleared the arm stamp\n",
              HEALTHY_SECS);
    } else {
        logf_("%lu forced release(s) in the first %d s; leaving the arm stamp in place, so the "
              "next start comes up gate-disabled\n", g_forced, HEALTHY_SECS);
    }
    return NULL;
}

// ---- main --------------------------------------------------------------------------------

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    if (geteuid() != 0) { fprintf(stderr, "must run as root\n"); return 1; }
    if (!derive_paths()) { fprintf(stderr, "cannot find my own path\n"); return 1; }

    log_open();
    helper_init();
    g_self = getpid();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    if (access(g_dylib, R_OK) != 0)    { logf_("no dylib at %s\n", g_dylib); return 1; }
    if (access(g_aqinject, X_OK) != 0) { logf_("no aqinject at %s\n", g_aqinject); return 1; }

    read_flags();

    // RECOVERY FIRST, ALWAYS. Whatever brought this daemon up -- boot, a launchd restart after
    // a crash, an operator reloading it -- the machine may be carrying holds that only this
    // process can clear, and none of them can be found once the gates are armed and busy.
    uint64_t boot = aq_boot_id();
    int replayed = aqj_open(g_journal, boot, MAX_HELD);
    if (replayed < 0) logf_("cannot open %s; the journal layer is not available\n", g_journal);
    else if (replayed > 0) logf_("journal replay released %d hold(s)\n", replayed);

    {
        // The scan acts only when the journal could not: with the journal healthy, every hold
        // it could have found has already been released by name, and what is left is other
        // software's business. See aqguard.h.
        int resume = g_cfg.resume_suspended || replayed < 0;
        int seen = 0;
        int resumed = aq_resume_suspended_threads(g_self, "aquatransport.dylib", resume, &seen);
        if (seen > 0)
            logf_("suspend-count scan: %d suspended thread(s) found, %d released\n", seen, resumed);
    }

    {
        int skipped = 0;
        int sent = aq_sigcont_sweep(&skipped);
        logf_("startup sweep: SIGCONT to %d processes, %d genuinely stopped left alone\n", sent, skipped);
    }

    // The previous boot armed the gates and never got far enough to say it was healthy. Come
    // up disabled and say why, so the machine demotes itself instead of hanging again.
    {
        uint64_t stamped = 0;
        if (aq_stamp_read(g_stamp, &stamped) && stamped != boot) {
            logf_("the previous boot armed the gates and never reported healthy; coming up "
                  "GATE-DISABLED. Remove %s to arm them again.\n", g_stamp);
            g_cfg.gate_off = 1;
        }
    }

    // The exclusion list is the boot-hang protection, and it is worth nothing if the names in
    // it cannot match. If the truncation length cannot be established, do not arm.
    int limit = 0;
    if (!g_cfg.gate_off) {
        limit = measure_execname_limit();
        if (limit <= 0) {
            logf_("could not establish how far execname truncates; the exclusion list cannot be "
                  "trusted, so the gates stay disarmed\n");
            g_cfg.gate_off = 1;
        } else if (limit >= (int)strlen(CALIB_NAME)) {
            logf_("execname is not truncated on this system (%d characters survived)\n", limit);
        } else {
            logf_("execname truncates to %d characters here\n", limit);
        }
    }

    char inetd[MAX_INETD][NAME_MAX_LEN];
    int ninetd = 0;
    if (!g_cfg.gate_off) {
        // Configured names first, then what launchd is actually running. An operator with a
        // service that is handed a connected socket by something other than launchd has no
        // other way to say so, and neither has a test.
        for (int i = 0; i < g_cfg.ninetd && ninetd < MAX_INETD; i++)
            snprintf(inetd[ninetd++], NAME_MAX_LEN, "%s", g_cfg.inetd[i]);
        ninetd = scan_inetd_jobs(inetd, MAX_INETD, ninetd);
    }

    char dpath[1024];
    snprintf(dpath, sizeof dpath, "%s/gate.d", g_dir);
    int clauses = write_program(dpath, limit, inetd, ninetd);
    if (clauses <= 0) { logf_("cannot write %s\n", dpath); return 1; }

    int err;
    if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
        logf_("dtrace_open: %s\n", dtrace_errmsg(NULL, err));
        return 1;
    }
    dtrace_setopt(g_dtp, "bufsize", "256k");
    dtrace_setopt(g_dtp, "switchrate", g_cfg.rate);
    if (!g_cfg.gate_off) dtrace_setopt(g_dtp, "destructive", 0);   // stop() needs it

    {
        // A multi-clause program is what dtrace(1) compiles for -s, not for -n.
        // dtrace_program_strcompile() with a probespec takes ONE clause, enables it, reports a
        // plausible probe count and no error, and silently drops the rest -- so this uses
        // fcompile, and checks the enable against the clause count rather than against zero.
        //
        // DTRACE_C_ZDEFS permits a probe description that matches nothing, which connectx is on
        // any kernel older than 10.9. Without it the whole program fails to compile there and
        // the daemon cannot arm at all. The clause-count check below is what keeps that from
        // becoming a licence for a probe name to be quietly wrong: every gate clause names the
        // plain syscall alongside its variants, so each still has to match something.
        FILE *fp = fopen(dpath, "r");
        if (!fp) { logf_("cannot read %s\n", dpath); return 1; }
        dtrace_prog_t *pgp = dtrace_program_fcompile(g_dtp, fp, DTRACE_C_PSPEC | DTRACE_C_ZDEFS, 0, NULL);
        fclose(fp);
        if (!pgp) { logf_("compile: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))); return 1; }
        dtrace_proginfo_t info; memset(&info, 0, sizeof info);
        if (dtrace_program_exec(g_dtp, pgp, &info) == -1) {
            logf_("enable: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
            return 1;
        }
        if (info.dpi_matches < clauses) {
            logf_("only %d probes matched for %d clauses; the program was not fully enabled\n",
                  info.dpi_matches, clauses);
            return 1;
        }
        logf_("%d clauses, %d probes, switchrate %s, hold %d ms%s\n",
              clauses, info.dpi_matches, g_cfg.rate, g_cfg.hold_ms,
              g_cfg.gate_off ? ", GATES OFF (injecting at exec)" : "");
    }
    dtrace_handle_err(g_dtp, on_err, NULL);
    dtrace_handle_drop(g_dtp, on_drop, NULL);

    // libdtrace formats printf() records into a FILE* backed by a real descriptor. A pipe back
    // into this same process keeps everything here. dtrace_handle_buffered() looks like the
    // tidier route and does deliver the text, but its pid and tid values were wrong in testing
    // -- one pid/tid pair repeated across three different processes while execname varied
    // correctly -- and funopen() is not a way round it either: libdtrace writes nothing at all
    // to a funopen-backed FILE*. The descriptor has to be real, and it has to be line
    // buffered, or gate records sit in stdio while the processes that generated them stay
    // frozen.
    int pfd[2];
    if (pipe(pfd) != 0) { logf_("pipe: %s\n", strerror(errno)); return 1; }
    FILE *sink = fdopen(pfd[1], "w");
    FILE *src  = fdopen(pfd[0], "r");
    if (!sink || !src) { logf_("fdopen: %s\n", strerror(errno)); return 1; }
    setvbuf(sink, NULL, _IOLBF, 0);

    pthread_t rt, wt[WORKERS], dog, health;
    pthread_create(&rt, NULL, reader, src);
    for (int i = 0; i < WORKERS; i++) pthread_create(&wt[i], NULL, worker, NULL);
    if (!g_cfg.gate_off) pthread_create(&dog, NULL, watchdog, NULL);

    if (dtrace_go(g_dtp) == -1) {
        logf_("go: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
        return 1;
    }
    if (!g_cfg.gate_off) {
        aq_stamp_write(g_stamp, boot);
        pthread_create(&health, NULL, healthy_after_a_while, NULL);
    }
    logf_("armed\n");

    uint64_t last_trim = now_ms(), last_sweep = 0;
    while (!g_stop) {
        dtrace_sleep(g_dtp);
        if (dtrace_work(g_dtp, sink, chew, chewrec, NULL) == DTRACE_WORKSTATUS_ERROR) {
            logf_("consumer error: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
            break;
        }
        if (g_dropped) {
            g_dropped = 0;
            uint64_t t = now_ms();
            if (t - last_sweep > 1000) {          // the sweep is 0.45 ms, but not every tick
                last_sweep = t;
                int skipped = 0, sent = aq_sigcont_sweep(&skipped);
                g_drops++; g_sweeps++;
                logf_("sweep after a drop: SIGCONT to %d processes, %d left alone\n", sent, skipped);
            }
        }
        if (now_ms() - last_trim > 600000) { last_trim = now_ms(); log_trim(); }
    }

    // Going away is itself a reason to release: launchd unloading this daemon must not leave a
    // thread held behind it.
    logf_("stopping; %lu forced release(s), %lu drop(s), %lu sweep(s)\n", g_forced, g_drops, g_sweeps);
    dtrace_stop(g_dtp);
    release_all_held();
    aq_sigcont_sweep(NULL);
    aq_stamp_clear(g_stamp);
    helper_close_all();
    return 0;
}
