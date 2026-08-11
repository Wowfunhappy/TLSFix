// The layered recovery for aqwatch's connection gate.
//
// The gate freezes a process at the moment it first touches the network and releases it once
// the library is loaded. A freeze that is never released is the one failure this design can
// cause, so the ways out are layered: no single one has to be perfect.
//
//   held journal          the targeted path. Every hold is on disk before the process is let
//                         out of its kernel stop and gone from disk after the thread resumes,
//                         so a daemon that dies mid-hold leaves an exact record of what to
//                         release. Stamped with the boot session, because after a reboot those
//                         pids belong to other processes.
//   suspend-count scan    the untargeted path for Mach holds. A thread_suspend outlives the
//                         suspender, but thread_basic_info.suspend_count makes it visible to
//                         any privileged process, so a lost or stale journal is still
//                         recoverable by inspection. What it may ACT on is narrow: see below.
//   blind SIGCONT sweep   the untargeted path for kernel stops, which are NOT visible: a
//                         process frozen by a DTrace stop() whose record was never drained
//                         reports p_stat == SRUN and is indistinguishable from a running one.
//                         Nothing can find it, so the sweep does not try to -- it signals
//                         everything that is not genuinely SIGSTOPped, which is a no-op on a
//                         running process and leaves a real Ctrl-Z'd job alone.
//   armed stamp           the last resort. If the gates armed on the previous boot and the
//                         system never got far enough to say it was healthy, the next start
//                         comes up with the gates disabled, so a gate-induced hang can happen
//                         at most once and then the machine demotes itself.
//
// Everything here reports to stderr, which the daemon points at its log.

#ifndef AQGUARD_H
#define AQGUARD_H

#include <mach/mach.h>
#include <stdint.h>
#include <sys/types.h>

// Fixed for the life of a boot and different across reboots, from kern.boottime. It is what
// separates a journal worth replaying from one whose pids now name other processes.
uint64_t aq_boot_id(void);

// The Mach thread whose thread_id is `tid` -- which is what D reports as `tid`, verified by
// direct comparison. Returns 0 and leaves *out untouched if the task has no such thread.
int aq_find_thread(task_t task, uint64_t tid, thread_act_t *out);

// ---- held journal ----------------------------------------------------------------------
//
// Opens (creating if needed) the journal at `path` with room for `slots` holds. If the file
// already carries the current boot's id, whatever it lists is released first -- that is the
// previous run of this daemon dying mid-hold. A journal from an earlier boot is discarded
// unread: replaying it would thread_resume threads that are not ours, unbalancing a suspend
// someone else owns.
//
// Returns the number of holds released, or -1 if the journal could not be opened, in which
// case the other layers are all that is left and the daemon says so.
int aqj_open(const char *path, uint64_t boot, int slots);

// Record and forget one hold. Called with the slot index the caller is using for it, before
// the process is let out of its kernel stop and after the thread is resumed respectively.
// Neither call allocates, and neither fails in a way the caller can act on: a journal that
// cannot be written is a recovery layer that is gone, not a hold that should be abandoned.
void aqj_set(int slot, pid_t pid, uint64_t tid);
void aqj_clear(int slot);

// ---- untargeted recovery ---------------------------------------------------------------

// Report every thread on the system with a non-zero Mach suspend count, and resume the ones
// this package can account for. Returns the number resumed; *found, when given, receives the
// number seen.
//
// A SUSPENDED THREAD IS NOT NECESSARILY OURS, and measurement is what settled this. On an
// untouched 10.9.5 machine, coresymbolicationd and xpcd each park a thread with thread_suspend
// as a matter of course. Resuming those would set another program's thread running at a moment
// it deliberately chose to stop it -- at every boot, on every machine, to recover from
// something that has not happened. That is a worse trade than the hold it would clear: a
// process with a suspended thread still dies to SIGTERM and to SIGKILL, so a wedged
// application behaves like any other beachball and the user's normal escape hatch is intact.
//
// So this layer REPORTS always and ACTS only when it is the layer that is needed. Every
// suspended thread is logged whatever happens -- that they are visible at all is the property
// §7.3 rests on, since a BSD stop leaves nothing to find, and it is what makes a wedged
// machine diagnosable. Resuming is separate, and `resume` is what the daemon passes when the
// targeted layer cannot do its job:
//
//   journal available   the exact record of every hold is on disk and was already replayed,
//                       so there is nothing here for this layer to find. Report only.
//   journal unavailable there is no record of what was held, so a best-effort release is
//                       better than none, and it is confined to processes carrying `needle`:
//                       a hold left behind after a successful injection is one of ours, and a
//                       process that never took the library was never one we suspended.
//   operator asked      the gate-resume-suspended flag, for someone looking at a machine they
//                       believe is wedged and deciding for themselves.
//
// Even confined that way it is best effort, not proof: a process we patched can also park its
// own threads -- xpcd is both, on this machine -- and nothing distinguishes the two. That is
// precisely why it is not the primary and why it does not run when the primary is healthy.
//
// Processes under a debugger are skipped outright: their suspended threads belong to the
// debugger, and nothing here can tell those from ours.
int aq_resume_suspended_threads(pid_t self, const char *needle, int resume, int *found);

// SIGCONT every process that is not genuinely stopped, which releases an orphaned DTrace
// stop() whose pid nothing could have known. Returns the number signalled; *skipped, when
// given, receives the count of genuinely stopped jobs left alone.
int aq_sigcont_sweep(int *skipped);

// ---- armed stamp -----------------------------------------------------------------------

// 1 if the stamp exists, with *boot set to the boot session that wrote it. A stamp carrying
// the current boot's id is this daemon's own, left by a restart within the same boot; one
// carrying an older id is a previous boot that armed the gates and never reported healthy.
int  aq_stamp_read(const char *path, uint64_t *boot);
void aq_stamp_write(const char *path, uint64_t boot);
void aq_stamp_clear(const char *path);

#endif
