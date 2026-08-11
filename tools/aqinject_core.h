// The injection engine, shared by the aqinject CLI and the aqwatch daemon.
//
// It loads the AquaTransport compatibility library into a process the administrator already
// runs on a machine they own, using the target's own dlopen. See aqinject_core.c for the
// mechanism and aqinject.c for what the tool around it is for.
//
// aqwatch links this directly rather than spawning aqinject per target: the spawn alone
// measured 1.7 ms, which is a third of the budget for a whole gated injection, and the gated
// target is frozen for every millisecond of it.

#ifndef AQINJECT_CORE_H
#define AQINJECT_CORE_H

#include <mach/mach.h>
#include <sys/types.h>

// Outcomes. Every caller distinguishes these four, because the right response differs: a
// target that merely exited is the ordinary end of most injections and is not worth a log
// line, while a live target without the library is the one outcome that is.
#define AQ_OK      0    // the library is confirmed present in the target
#define AQ_FAILED  1    // the target is alive and does not have it; the reason went to stderr
#define AQ_GONE    2    // the target exited on the way there; nothing to report
#define AQ_RACED   3    // an exec replaced the address space we wrote into; retry is worthwhile

typedef struct {
    // Suppress the outcomes that are expected rather than wrong -- above all a short-lived
    // target exiting part-way through. Real failures print either way.
    int quiet;

    // The target is held at a gated syscall (aqwatch's gate path). Three things follow, each
    // of which removes work that only exists to handle a target that might be mid-exec:
    //
    //   * no wait for dyld startup. A process sitting in connect(), accept() or read() passed
    //     that point long ago, so the readiness test becomes a single assertion.
    //   * no closing image-list check. That check catches a dlopen into an address space an
    //     exec is about to replace; the gated thread is suspended, so no exec can race it.
    //   * the done flag is polled at 100 us rather than 100 ms, because the target is frozen
    //     for the whole wait and the poll interval is most of the latency.
    int gated;
} aq_opts;

// One attempt against a same-architecture target.
int aq_inject(pid_t pid, const char *dylib, const aq_opts *o);

// The same, retrying the one failure worth retrying: the target raced us through an exec and
// is still alive. Each attempt re-acquires the task port, so the retry works against the
// post-exec address space.
int aq_inject_retrying(pid_t pid, const char *dylib, const aq_opts *o);

// The same, spawning `sibling` (a fat binary, normally the caller's own path) under the
// target's architecture when the target is not ours. Resolved dyld-cache addresses and the
// pthread_attr_t layout are both architecture-specific, so a slice injects only its own kind.
// `sibling_argv0_flag` is passed to the spawned copy ahead of the pid, or NULL for none.
int aq_inject_dispatch(pid_t pid, const char *dylib, const aq_opts *o,
                       const char *sibling, const char *sibling_flag);

// Is the process 64-bit? Returns 0 if it is gone, in which case *lp64 is untouched.
int aq_proc_lp64(pid_t pid, int *lp64);

// Is this build's own slice 64-bit? Callers compare it against aq_proc_lp64 to decide whether
// a target needs the other slice.
int aq_self_lp64(void);

// Still able to receive a library. A zombie answers kill(pid, 0) exactly as a running process
// does but has already torn down its task, so this reads p_stat instead.
int aq_alive(pid_t pid);

// Is an image whose path contains `needle` loaded in the target? 1 yes, 0 no, -1 unreadable.
// Costs 0.135 ms, which is why the daemon remembers the answer rather than asking twice.
int aq_task_has_image(task_t task, const char *needle);

// The longest dylib path the payload page has room for, so a caller can refuse a path it
// cannot deliver rather than truncating one.
int aq_path_fits(const char *path);

#endif
