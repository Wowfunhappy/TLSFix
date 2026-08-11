// The layered recovery for aqwatch's connection gate. See aqguard.h for what each layer is
// for and why there is more than one.

#include "aqguard.h"
#include "aqinject_core.h"

#include <mach/mach_time.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef SSTOP
#define SSTOP 4
#endif
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

uint64_t aq_boot_id(void) {
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    struct timeval tv; size_t len = sizeof tv;
    if (sysctl(mib, 2, &tv, &len, NULL, 0) != 0 || len == 0) return 0;
    return (uint64_t)tv.tv_sec * 1000000ull + (uint64_t)tv.tv_usec;
}

int aq_find_thread(task_t task, uint64_t tid, thread_act_t *out) {
    thread_act_array_t list = NULL; mach_msg_type_number_t n = 0;
    if (task_threads(task, &list, &n) != KERN_SUCCESS) return 0;
    int found = 0;
    for (unsigned i = 0; i < n; i++) {
        if (!found) {
            thread_identifier_info_data_t ii;
            mach_msg_type_number_t c = THREAD_IDENTIFIER_INFO_COUNT;
            if (thread_info(list[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&ii, &c) == KERN_SUCCESS &&
                ii.thread_id == tid) {
                *out = list[i];
                found = 1;
                continue;                       // keep this one's port right; drop the rest
            }
        }
        mach_port_deallocate(mach_task_self(), list[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof(thread_act_t));
    return found;
}

// ---- held journal ----------------------------------------------------------------------
//
// Fixed-width records at fixed offsets, so recording a hold is one pwrite at a computed offset
// and clearing it is another. Nothing is allocated, nothing is rewritten wholesale, and the
// file never has to be parsed while the daemon is running.
//
// There is no fsync. What this protects against is the daemon dying, not the machine losing
// power: a write that has reached the buffer cache survives the process by definition, and an
// fsync per gate would cost more than the injection it is guarding.

#define J_REC   64                              // bytes per record, header included
#define J_MAGIC "AQJ1"

static int      g_jfd = -1;
static int      g_jslots = 0;

// Record 0 is the header; slot i lives at record i + 1.
static void j_write(off_t record, const char *text) {
    if (g_jfd < 0) return;
    char buf[J_REC];
    memset(buf, ' ', sizeof buf);
    size_t n = strlen(text);
    if (n > sizeof buf - 1) n = sizeof buf - 1;
    memcpy(buf, text, n);
    buf[sizeof buf - 1] = '\n';
    ssize_t w = pwrite(g_jfd, buf, sizeof buf, record * J_REC);
    (void)w;
}

void aqj_set(int slot, pid_t pid, uint64_t tid) {
    if (slot < 0 || slot >= g_jslots) return;
    char rec[J_REC];
    snprintf(rec, sizeof rec, "H %d %llu", (int)pid, (unsigned long long)tid);
    j_write(slot + 1, rec);
}

void aqj_clear(int slot) {
    if (slot < 0 || slot >= g_jslots) return;
    j_write(slot + 1, ".");
}

// Release one hold left by a previous run: resume the thread if it is still suspended, and
// clear the kernel stop in case the daemon died before it got that far. Both are safe to
// repeat -- a thread_resume on an unsuspended thread fails harmlessly, and SIGCONT is a no-op
// on a running process -- which is what lets one replay cover every point the daemon could
// have died at.
static void release_recorded(pid_t pid, uint64_t tid) {
    task_t task;
    if (task_for_pid(mach_task_self(), pid, &task) == KERN_SUCCESS) {
        thread_act_t th = MACH_PORT_NULL;
        if (aq_find_thread(task, tid, &th)) {
            thread_resume(th);
            mach_port_deallocate(mach_task_self(), th);
        }
        mach_port_deallocate(mach_task_self(), task);
    }
    kill(pid, SIGCONT);
}

static int replay(uint64_t boot) {
    char hdr[J_REC + 1];
    if (pread(g_jfd, hdr, J_REC, 0) != J_REC) return 0;
    hdr[J_REC] = 0;
    unsigned long long had = 0;
    if (sscanf(hdr, J_MAGIC " %llu", &had) != 1) return 0;
    if (had != boot) {
        fprintf(stderr, "aqwatch: held journal is from an earlier boot; discarding it unread\n");
        return 0;
    }
    int released = 0;
    for (int i = 0; i < g_jslots; i++) {
        char rec[J_REC + 1];
        if (pread(g_jfd, rec, J_REC, (off_t)(i + 1) * J_REC) != J_REC) break;
        rec[J_REC] = 0;
        int pid = 0; unsigned long long tid = 0;
        if (sscanf(rec, "H %d %llu", &pid, &tid) != 2 || pid <= 1) continue;
        fprintf(stderr, "aqwatch: journal replay releases pid %d tid %llu\n", pid, tid);
        release_recorded((pid_t)pid, (uint64_t)tid);
        released++;
    }
    return released;
}

int aqj_open(const char *path, uint64_t boot, int slots) {
    g_jslots = slots;
    // 0600: it lists pids, nothing sandboxed reads it, and it needs no world visibility.
    g_jfd = open(path, O_RDWR | O_CREAT, 0600);
    if (g_jfd < 0) { g_jslots = 0; return -1; }
    fchmod(g_jfd, 0600);

    int released = replay(boot);

    char hdr[J_REC];
    snprintf(hdr, sizeof hdr, J_MAGIC " %llu", (unsigned long long)boot);
    j_write(0, hdr);
    for (int i = 0; i < slots; i++) aqj_clear(i);
    if (ftruncate(g_jfd, (off_t)(slots + 1) * J_REC) != 0) { /* size is advisory */ }
    return released;
}

// ---- untargeted recovery ---------------------------------------------------------------

// One snapshot of the process table. Both sweeps want it and neither can afford to fail for
// want of memory, so the caller-visible failure is "returns 0 having done nothing".
static struct kinfo_proc *proc_snapshot(int *count) {
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t len = 0;
    if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0 || len == 0) return NULL;
    len += 64 * sizeof(struct kinfo_proc);       // the list can grow between sizing and reading
    struct kinfo_proc *p = (struct kinfo_proc *)malloc(len);
    if (!p) return NULL;
    if (sysctl(mib, 3, p, &len, NULL, 0) != 0) { free(p); return NULL; }
    *count = (int)(len / sizeof *p);
    return p;
}

int aq_resume_suspended_threads(pid_t self, const char *needle, int resume, int *found) {
    int n = 0;
    struct kinfo_proc *procs = proc_snapshot(&n);
    if (found) *found = 0;
    if (!procs) return 0;

    int resumed = 0;
    for (int i = 0; i < n; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid <= 1 || pid == self) continue;
        if (procs[i].kp_proc.p_flag & P_TRACED) continue;

        task_t task;
        if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) continue;
        thread_act_array_t list = NULL; mach_msg_type_number_t tn = 0;
        if (task_threads(task, &list, &tn) == KERN_SUCCESS) {
            // Asked at most once per process, and only for one that has a suspended thread at
            // all -- which on a healthy machine is two or three processes in three hundred.
            int ours = -1;
            for (unsigned t = 0; t < tn; t++) {
                thread_basic_info_data_t bi;
                mach_msg_type_number_t c = THREAD_BASIC_INFO_COUNT;
                if (thread_info(list[t], THREAD_BASIC_INFO, (thread_info_t)&bi, &c) != KERN_SUCCESS ||
                    bi.suspend_count <= 0) {
                    mach_port_deallocate(mach_task_self(), list[t]);
                    continue;
                }
                if (found) (*found)++;
                if (ours < 0) ours = resume && (!needle || aq_task_has_image(task, needle) == 1);
                if (ours) {
                    fprintf(stderr, "aqwatch: suspend-count scan releases pid %d (count %d)\n",
                            (int)pid, bi.suspend_count);
                    for (int k = 0; k < bi.suspend_count; k++) thread_resume(list[t]);
                    resumed++;
                } else {
                    fprintf(stderr, "aqwatch: pid %d has a suspended thread (count %d); "
                                    "leaving it alone\n", (int)pid, bi.suspend_count);
                }
                mach_port_deallocate(mach_task_self(), list[t]);
            }
            vm_deallocate(mach_task_self(), (vm_address_t)list, tn * sizeof(thread_act_t));
        }
        mach_port_deallocate(mach_task_self(), task);
    }
    free(procs);
    return resumed;
}

int aq_sigcont_sweep(int *skipped) {
    int n = 0, sent = 0, skip = 0;
    struct kinfo_proc *procs = proc_snapshot(&n);
    if (!procs) { if (skipped) *skipped = 0; return 0; }

    for (int i = 0; i < n; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid <= 1) continue;                             // never signal launchd
        if (procs[i].kp_proc.p_stat == SSTOP) { skip++; continue; }   // a real Ctrl-Z job
        kill(pid, SIGCONT);
        sent++;
    }
    free(procs);
    if (skipped) *skipped = skip;
    return sent;
}

// ---- armed stamp -----------------------------------------------------------------------

int aq_stamp_read(const char *path, uint64_t *boot) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long long v = 0;
    int got = fscanf(f, "%llu", &v) == 1;
    fclose(f);
    if (got && boot) *boot = (uint64_t)v;
    return got;
}

void aq_stamp_write(const char *path, uint64_t boot) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    char buf[32];
    int n = snprintf(buf, sizeof buf, "%llu\n", (unsigned long long)boot);
    ssize_t w = write(fd, buf, (size_t)n); (void)w;
    close(fd);
}

void aq_stamp_clear(const char *path) { unlink(path); }
