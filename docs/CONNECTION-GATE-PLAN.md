(Note: The below was written by Claude.)

# AquaTransport Connection Gate — Implementation Plan

Target: Mac OS X 10.6 – 10.9, `x86_64` + `i386`. All measurements below are from 10.9.5
(build 13F1911) unless noted.

## Status

AquaTransport is a prototype. It is installed on one machine — the 10.9.5 system every
measurement here comes from — and has never been released. Nothing depends on it. This means
there is **No migration, and no compatibility surface.** The polling loader in `tools/aqwatch.c`
is deleted outright rather than kept behind a switch. Paths, flag names and the LaunchDaemon
label can change freely; install and uninstall can be rewritten.

## 1. The problem

`aqwatch` polls `proc_listpids` every 100 ms and runs `aqinject` against each pid it has not
seen. Measured launch-to-patched latency on that path:

| | min | median | max |
|---|---|---|---|
| current polling loader | 18.6 ms | ~120 ms | 144 ms |

A process that issues a TLS request inside that window uses Mavericks' own Secure Transport:
the request fails against a modern server, or succeeds against a weak one. Either outcome is
the bug this package exists to fix, so the window is a correctness defect, not a performance
one.

Polling also misses processes outright. Cross-checking a 20 ms poller against
`proc:::exec-success` over the same workload, DTrace saw nine processes — `git`, `perl`, `sh`,
`date`, `env` — that the poller never observed at all. At the shipping 100 ms interval it is
worse. `git` and `curl` fetching over HTTPS are exactly the short-lived, fast-connecting
processes this affects.

Reducing latency narrows the window but cannot close it. This plan closes it: a process is
frozen by the kernel at the moment it first touches the network, and is not released until the
library is loaded.

## 2. Architecture

One daemon, `aqwatch`, at the current path and LaunchDaemon label
(`org.aquatransport.watch`). It links `libdtrace` directly, so no process named `dtrace`
appears in the process list and the operator's own interactive DTrace sessions stay
distinguishable.

The name stays because it still describes the job — the daemon exists to see that processes
carry the library — and because a second name for the same role in the same package buys
nothing. There is no installed base to migrate (see *Status* above), so this is a readability
choice, not a compatibility one.

```
  kernel                          aqwatch (root, LaunchDaemon)
  ------                          ---------------------------
  process calls connect()
    -> probe fires, stop()        [process frozen, synchronously, ~70 ns]
    -> record buffered
                                  dtrace_work() drains record  (switchrate, default 50 Hz)
                                  thread_suspend(offending thread)
                                  kill(pid, SIGCONT)           [clears the BSD stop]
                                  inject library if absent     [~2-6 ms]
                                  thread_resume(thread)
  process continues                                            [library present]
```

Injection happens **only** at a gate. Nothing is injected at exec. A process that never
touches the network never receives the library.

**Processes already running when the daemon starts are deliberately not covered.** One that
connected before the daemon came up is gated at its next `connect`, which for a process holding
a long-lived connection may be a long time. Restarting it — or rebooting — covers it, and that
is the expected remedy. The alternative, a bulk pass over existing processes at install time,
is the `aqinject --all` mode this plan **deletes**: it reintroduces the whole memory cost the
gate architecture removes, to cover a case a reboot handles. `install-macos.sh inject` goes
with it.

| | processes carrying the library | private memory |
|---|---|---|
| current (inject at every exec) | ~270 | ~156 MB |
| this plan (inject at first network use) | ~32 | **~19 MB** |

Measured cost of the library in a target: **~600 KB of private, dirty memory per process**
(`vm_stat` active+wired delta across 10 processes: 6036 KB / 10 = 603 KB). `__TEXT` is shared
and contributes almost nothing after the first process; `__DATA` is 680 KB and goes private as
soon as the constructor writes to it.

## 3. Platform facts the design depends on

These are non-obvious, were established by measurement, and will be rediscovered painfully if
changed without evidence.

### 3.1 Probe selection

**`proc:::exec-success` is the only exec probe that reports the new process.** It fires from
`__mac_execve` for fork+exec and from `dtrace_thread_bootstrap` for `posix_spawn` — the latter
in the new process's own thread as it bootstraps into user space, before dyld runs. `pid`,
`execname` and `ppid` are all the child's.

Rejected alternatives, each for a concrete reason:

- `proc:::exec` — on the `posix_spawn` path reports the **parent's** pid with the child's path.
- `syscall::exec*:return` — a successful `execve` never returns; `posix_spawn` returns in the
  parent.
- `syscall::fork:return` — fires in the parent, and a `fork` without `exec` needs no injection:
  the child inherits the patched address space, verified directly.
- The BSM audit pipe — same parent/child confusion as `proc:::exec`, documented in
  `tools/aqwatch.c`.

**One pid can produce several `exec-success` events.** Re-exec chains observed: `env`→`true`,
`python`→`Python`, `perl`→`perl5.16`, and above all **`xpcproxy`→the real binary**, which is
how every app and XPC service launches on 10.9. The library does not survive an exec, so any
per-pid or per-tid state must be cleared on every `exec-success`.

**stdio flushes through `write_nocancel`, not `write`.** Any probe on the write path must use
`syscall::write*:entry`. A predicate on `write` alone silently never fires.

### 3.2 `stop()` semantics

A DTrace `stop()` is a **BSD process stop**, and it has two properties that together dictate
the whole design.

**It freezes before dyld runs, so it cannot be used at `exec-success`.** A process stopped
there never initialises libSystem, and the injector waits for `libSystemInitialized` forever:

```
aqinject <pid> ... ->  pid 56554: never finished dyld startup
```

**Under a BSD stop, `pthread_create`'d threads are never scheduled.** The injector's stage 1
is a raw mach thread from `thread_create_running` and runs fine; stage 2 is a real pthread and
does not. `dlopen` is therefore never called. Sampling a process in this state shows it
exactly:

```
Thread_2980000  ???  (in <unknown binary>) [0x100035424]        <- stage 1, spinning, fine
Thread_2980001  thread_start (in libsystem_pthread.dylib) + 0   <- stage 2: created, never run
```

**The fix is to downgrade the process stop to a thread suspension** before injecting:
`thread_suspend` the offending thread, `SIGCONT` the process to clear the BSD stop, inject
normally, then `thread_resume`. Ordering matters — suspend *before* `SIGCONT`, so there is no
instant in which the thread is runnable and unpatched.

D's `tid` equals the Mach `thread_id` from `thread_info(THREAD_IDENTIFIER_INFO)`, verified by
direct comparison, so the thread is found with a `task_threads` scan.

### 3.3 Held-state discoverability

The two held states behave very differently when the daemon dies. This drives the recovery
design in §7.

| | BSD stop (DTrace `stop()`) | Mach `thread_suspend` |
|---|---|---|
| lifetime in this design | ~20 µs, transient | the injection window, 2–6 ms |
| `ps` shows | `R+` / `S+` — normal | `S+` — normal |
| `p_stat` | `SRUN` — indistinguishable | `SRUN` |
| `thread_basic_info.suspend_count` | 0 — invisible | **> 0 — discoverable** |
| survives daemon death | **yes, forever** | **yes, forever** |
| another process can undo it | yes (`SIGCONT`) | yes (`thread_resume`) |
| findable with no journal | **no** | yes |
| `SIGKILL` / `SIGTERM` still reap it | yes | yes |

Two consequences:

1. **Force quit always works.** A process with a suspended thread dies to `SIGKILL` *and* to
   plain `SIGTERM`. The user's normal escape hatch is intact; a wedged app behaves like any
   other beachball.
2. **A BSD stop whose record is never read is unrecoverable by inspection.** If the daemon dies
   before draining the record, the pid was never known to user space and no state distinguishes
   the frozen process from a running one. §7.4 is the answer.

### 3.4 Costs

Probe overhead with an enabled probe and a false predicate: **+0.05–0.08 µs per syscall**.
Idle system-wide `read`/`write` rate: 541/s. Observed inet `connect` rate: 243 in ~30 s across
8 processes, of which only **9 distinct `(pid,tid)` pairs** would ever latch — Transmission
alone accounted for 223 connects on one thread.

Consumer CPU is linear in `switchrate` and goes to nothing at the bottom (gates only, 30 s
samples):

| switchrate | CPU | CPU-time / 30 s | release delay on a gated connection |
|---|---|---|---|
| 1 Hz | 0.0% | 0.00 s | up to 1 s |
| 10 Hz | 0.0% | 0.02 s | ~20–75 ms |
| **50 Hz** | **0.3%** | **0.08 s** | **~20 ms** |
| 100 Hz | 0.6% | 0.18 s | ~9 ms |
| 250 Hz | 1.2% | 0.44 s | ~4 ms |

Because the process is frozen for the whole delay, `switchrate` buys latency, not safety.

## 4. Component 1 — the trace consumer

### 4.1 The D program

```d
/* 1. outbound. sockaddr on OS X: byte 0 = sa_len, byte 1 = sa_family.
      AF_INET = 2, AF_INET6 = 30. */
syscall::connect:entry
{ this->p = (uint8_t *)copyin(arg1, 2); this->fam = this->p[1]; }

syscall::connect:entry
/(this->fam == 2 || this->fam == 30) && latched[tid] == 0 && !denied[execname]/
{ latched[tid] = 1; stop(); printf("G %d %d %s\n", pid, tid, execname); }

/* 2. inbound. On RETURN, so the fd exists and the thread is held before it can be used.
      At entry there is no connection and the thread would sit in the gate while idle. */
syscall::accept*:return
/arg0 >= 0 && latched[tid] == 0 && !denied[execname]/
{ latched[tid] = 1; stop(); printf("G %d %d %s\n", pid, tid, execname); }

/* 3. inherited connected socket (inetd-style). Emitted only when §4.3 finds a loaded job. */
syscall::read*:entry, syscall::write*:entry
/inetd[execname] && latched[tid] == 0/
{ latched[tid] = 1; stop(); printf("G %d %d %s\n", pid, tid, execname); }

/* The library does not survive an exec, so the latch must not either. */
proc:::exec-success { latched[tid] = 0; }

/* Bound the associative arrays: without these they grow for the life of the boot. */
proc:::lwp-exit { latched[tid] = 0; }
proc:::exit     { latched[tid] = 0; }
```

`denied[]` and `inetd[]` are populated in a generated `BEGIN` block (§4.3).

Latching on `tid` rather than `pid` closes the window where a second thread connects while the
first is still being rescued. Measured cost of that choice: **9 latches instead of 8** over the
sample workload. Every latch after the first on a given process takes the fast release path.

### 4.2 libdtrace

`/usr/lib/libdtrace.dylib` and `/usr/include/dtrace.h` ship on 10.9; `DTRACE_VERSION` is 3.
Verified working end to end at 0.4% CPU / 7.8 MB RSS at 50 Hz — the same cost as `dtrace(1)`,
because that footprint is libdtrace's own.

```c
dtrace_hdl_t *dtp = dtrace_open(DTRACE_VERSION, 0, &err);
dtrace_setopt(dtp, "bufsize", "256k");
dtrace_setopt(dtp, "switchrate", "50hz");
dtrace_setopt(dtp, "destructive", 0);       /* required for stop() */
dtrace_setopt(dtp, "quiet", 0);

/* A multi-clause program is what dtrace(1) compiles for -s, not -n.
   dtrace_program_strcompile() with a probespec takes ONE clause, enables it, reports a
   plausible probe count and NO error, and silently drops the rest. Use fcompile. */
FILE *fp = /* temp file holding the program text */;
dtrace_prog_t *pgp = dtrace_program_fcompile(dtp, fp, DTRACE_C_PSPEC, 0, NULL);

dtrace_proginfo_t info;
dtrace_program_exec(dtp, pgp, &info);       /* info.dpi_matches must be non-zero */
dtrace_handle_err(dtp, on_err, NULL);
dtrace_handle_drop(dtp, on_drop, NULL);     /* see §7.4 -- a drop is a lost gate record */
dtrace_go(dtp);

while (!stopping) {
    dtrace_sleep(dtp);
    if (dtrace_work(dtp, sink, chew, chewrec, NULL) == DTRACE_WORKSTATUS_ERROR) break;
}
```

`sink` is a `FILE *` over the write end of a `pipe()`; a reader thread parses
`G <pid> <tid> <execname>` off the read end and drives the gate. Everything stays in one
process. Do not run the injection on the reader thread if it would block the drain — see §5.

Three traps, each of which presents as a silently working consumer:

1. **`strcompile` truncation.** `dtrace_program_strcompile()` with a probespec compiles **one
   clause** the way `dtrace -n` does, enables it, reports a plausible probe count and no error,
   and drops the rest. Use `dtrace_program_fcompile()` — the `dtrace -s` path — and assert
   `info.dpi_matches` equals the expected count.
2. **`dtrace_handle_buffered()` yields wrong field values.** It does deliver each `printf()` as
   text in `dtbda_buffered`, but in testing the `pid` and `tid` fields were wrong — one pid/tid
   pair repeated across three different processes while `execname` varied correctly. The
   `dtrace_work()` `FILE *` path formats the same records correctly. Avoid the buffered handler
   until someone establishes why; the failure is silent and produces plausible-looking output.
3. **Output buffering.** The `FILE *` must be line-buffered or explicitly flushed, or gate
   records sit in stdio while the processes that generated them stay frozen.

`funopen()` is not a workaround for trap 2: libdtrace writes nothing to a `funopen`-backed
`FILE *`, though records are confirmed to arrive at the callbacks. Use a real descriptor.

### 4.3 Generated `BEGIN` block

At startup, before compiling, `aqwatch` builds a `BEGIN` clause:

- `denied[]` — the exclusion list from §7.5. **These are never latched, never frozen, never
  injected.**
- `inetd[]` — see below.

**`execname` truncates to 15 characters.** Measured directly: a process named
`securityd_service` reports `execname` as `securityd_servi` (15), and `diskarbitrationd`
reports `diskarbitration` (15). This is *not* the 16-character `MAXCOMLEN` truncation that
`tools/aqinject.c` documents for `kinfo_proc.kp_proc.p_comm` — that is a different code path
and its prefix matching is correct there.

The consequence is a silent failure: a D predicate written as
`execname == "securityd_servic"` (16 characters, the value a careful reading of `aqinject.c`
suggests) **never matches**, and `securityd_service` gets gated.

The trust cycle itself would still be avoided — the library self-gates inside the target
(§7.5.1), so it installs no hooks there regardless. What the bug actually costs is a
critical daemon frozen and injected for no benefit: a 2–6 ms hold on the security daemon in
the normal case, and one more process exposed to the orphan risk in §7.7. Not a deadlock, but
not something to discover in production either — and it fails with no error anywhere.

So: **do not hand-write truncated names.** Seed `denied[]` and `inetd[]` from full names
truncated programmatically when the `BEGIN` block is generated, and add a startup assertion
that every configured name survives a round trip. pid 1 is excluded separately in the daemon,
by pid, since `execname` is not a safe key for it.
- `inetd[]` — executables of launchd jobs that use `inetdCompatibility`, which are handed an
  already-connected socket and call neither `connect` nor `accept`. 10.9 ships 18 such plists
  (`ssh`, `telnet`, `ftp`, `tftp`, `finger`, `cups-lpd`, `eppc`, …). **Emit clause 3 only for
  jobs that are actually loaded** — on a stock machine that is typically none, and the clause
  is then omitted entirely at zero cost. Even when enabled it is cheap: 541 read/writes per
  second at ~0.07 µs is ~0.004% CPU.

## 5. Component 2 — the gate

On each `G <pid> <tid> <execname>` record, on a worker thread (never the libdtrace callback):

```
 1. reject pid <= 1
 2. task_for_pid(pid)                          0.003 ms
 3. task_threads + thread_info scan for tid     0.012 ms
 4. thread_suspend(match)                       0.007 ms   <- must precede the SIGCONT
 5. journal (pid, tid, deadline) to disk        §7.2
 6. kill(pid, SIGCONT)                          clears the BSD stop
 7. if pid not in the confirmed-patched set:
        inject (§6)                             ~2-6 ms
        on success, add pid to the set
 8. thread_resume(match)                        0.003 ms
 9. clear the journal entry
```

Steps 2–4 and 8 total **0.026 ms**. Verifying patched-ness by walking the target's dyld image
list costs a further 0.135 ms, so keep a confirmed-patched pid set in the daemon and use the
image walk only to seed or re-check it. The set must be cleared for a pid on `exec-success`
and on `exit`.

**Every exit path from step 4 onward must reach step 8.** Injection failure, target death, an
allocation failure, an unexpected `kern_return_t` — all release the thread and let the process
run unpatched. Failing open is correct; a wedged process is worse than an unpatched one.

Verified behaviour of the held syscalls, all with the library confirmed present on release:

| gate | result after release |
|---|---|
| `connect` | `connect returned 0 errno=0`, no `EINTR` |
| `accept` | `accept returned 4 errno=0`, peer payload intact |
| `read` (inetd) | `read returned 17 errno=0`, full payload delivered |

## 6. Component 3 — the injector

`tools/aqinject.c` is the starting point. **Keep the two-stage design** — bare mach thread sets
a TSD via `thread_fast_set_cthread_self`, calls `pthread_create`, and stage 2 on the real
pthread calls `dlopen`. Calling `dlopen` directly from the bare mach thread is not safe. The
two-stage design requires that the target not be under a BSD stop (§3.2), which §5 step 6
guarantees: the `SIGCONT` clears the stop before injection begins.

Changes, in descending order of value:

0. **Delete `--all` and `inject_all()`** (§2), which takes `is_denied()` and `aqinject.c`'s
   `kDeny[]` with it. What remains of `aqinject` is the cross-architecture helper, plus its
   single-pid CLI form, which is worth keeping for debugging.
1. **Move injection into `aqwatch`.** The current `posix_spawn` of `aqinject` per target costs
   **1.7 ms** measured. Keep a pre-warmed `i386` helper process, fed target pids over a
   socketpair, for cross-architecture targets, so those do not pay a spawn either.
2. **Poll the stage-2 done flag at 100 µs.** The shipping value is 100 ms; a 1 ms variant
   brought a cold injection against a ready target from ~126 ms to ~18 ms of wall time.
3. **Skip the closing `target_has_image` verification on the gate path.** It exists to catch a
   `dlopen` that succeeded into an address space an exec was about to replace. The gated thread
   is suspended, so no exec can race it. Saves 0.135 ms.
4. **Drop `wait_for_exec` on the gate path.** A process at `connect`, `accept` or `read` has
   long since finished dyld startup. Keep the check as a cheap assertion, not a wait loop.
5. Retain `verify_shared_cache` and the architecture dispatch unchanged.

Target: **2–6 ms** for a cold injection, against 3.3–8.2 ms measured today including the spawn.
The floor is `dlopen` of the 3.8 MB library plus its constructor, and it belongs to the payload,
not the injector. `RTLD_LAZY` in place of `RTLD_NOW` was tested and is **not** a demonstrated
win (medians 4.0 vs 7.0 ms, but both distributions are bimodal at ~3.5 and ~8 ms and the
variance swamps the difference at n=5). Revisit only with a proper sample.

## 7. Safety and recovery

A `stop()` that is never released is the one failure this design can cause that the current
one cannot. The mitigations are layered so that no single one has to be perfect.

### 7.1 Bounded hold (watchdog)

A dedicated thread releases any held `(pid, tid)` older than a deadline — 250 ms is ample
against a 2–6 ms injection — regardless of what the injection is doing. Its state table is
**pre-allocated at startup** and its release path must not allocate, so that memory pressure
cannot prevent a release.

### 7.2 Journal

Held `(pid, tid, deadline)` triples are written to a file before the `SIGCONT` and cleared
after the resume. On startup `aqwatch` replays it and releases anything listed. This is the
targeted path; it must never be the only one.

### 7.3 Suspend-count scan

A Mach `thread_suspend` outlives the suspender — verified: a tool that suspended a thread and
exited left the target frozen indefinitely — but is discoverable via
`thread_basic_info.suspend_count > 0` and undoable by any privileged process. On startup, scan
and resume. This covers a lost or stale journal.

### 7.4 Blind `SIGCONT` sweep

The worst case is a BSD stop whose record was never drained: the pid was never known to user
space, and §3.3 shows no field distinguishes that process from a running one. The sweep is
therefore blind, and safe because a real `SIGSTOP` *is* distinguishable:

```
for each process:
    if pid <= 1: skip
    if p_stat == SSTOP: skip      /* a genuine Ctrl-Z job -- leave it alone */
    kill(pid, SIGCONT)            /* a no-op on a running process */
```

Measured: **271 processes, `SIGCONT` to 268, 1 genuinely stopped skipped, 0.45 ms** — and it
released an orphan whose pid nothing could have known while leaving a real Ctrl-Z'd job
untouched (still `T+`).

Run it at startup, and whenever `dtrace_handle_drop` reports a drop, since a dropped gate
record is by definition a process frozen with nobody holding its pid.

### 7.5 Deterministic exclusion list

Boot-hang exposure is handled by **never latching a set of named processes**, not by deferring
when the gates arm. There is no time floor and no "wait until the system looks up" check: both
are timing-dependent, and a race is exactly what must not sit underneath a mechanism that can
freeze a process. A name comparison in a D predicate is deterministic, inspectable and
testable.

The gates are therefore armed as soon as the daemon starts. A daemon that fails to start at all
remains safe by construction: no probe is enabled, so nothing can freeze.

**Exclusion criteria.** A process is excluded if it's a circular dependency — injecting it would
route the library's own trust evaluation through the process that implements trust evaluation.
It may also make sense to exclude processes like WindowServer that could potentially break boot
and should never be making network requests in the first place.

### 7.5.1 The deny lists that already exist

The codebase carries the same four trust-daemon names in three places, matched three different
ways. A developer needs to know all of them, because this plan's D predicate is a fourth.

| where | contents | matched against | fate |
|---|---|---|---|
| `src/mac/aquatransport_hooks_mac.c` `kDeny[]` | `ocspd`, `securityd`, `securityd_service`, `trustd` | `getprogname()`, exact | **keep** |
| `tools/aqinject.c` `kDeny[]` | the same four | `kinfo_proc.kp_proc.p_comm`, **prefix** (16 chars) | **delete** |
| `tools/aqwatch.c` `kNeverLoad[]` | the same four **plus `aqinject` and `aqwatch`** | `proc_pidpath` basename, exact | replaced by the D predicate |

`aqinject.c`'s copy is reachable only from `is_denied()`, which is called only from
`inject_all()` — the `--all` mode this plan deletes (§2). Removing that mode removes the list
with it, leaving two: the library's own gate, and the D predicate.

`aqwatch`'s two extra entries prevent a self-feeding loop: spawning an injector is itself a
process launch, so without them the daemon feeds itself. Under this plan the poller is gone and
launches no longer trigger anything, but the daemon must still never gate **itself** — it would
freeze on its own network activity with nobody left to release it.

**The library self-gates, and that is the real backstop.** `process_eligible()` in
`aquatransport_hooks_mac.c` runs inside the target: loaded into a trust daemon, the library
installs no hooks at all. The injection-side lists are defence in depth, not the sole
protection against the trust cycle.

There is also `tf_name_listed()` in `src/mac/aquatransport_config.c` — a user-editable rewriter
deny list, declared in the header and implemented, with **no callers anywhere in the tree**.
Either wire it up or delete it; a deny mechanism that silently does nothing is worse than not
having one. `docs/TECHNICAL.md` states the rewriter has "No process gating", which matches the
code, while the summary table says "apps only (see gating)". Reconcile the two.

These should all be consolidated into a single source of truth.

### 7.6 Previous-boot breadcrumb

Write a flag when the gates arm; clear it once the system is demonstrably healthy. If `aqwatch`
starts and finds last boot's flag still set, come up **gate-disabled** and log why. A
gate-induced hang can then happen at most once, after which the machine self-demotes.

### 7.7 Residual risk

After all of the above: the daemon must die within the few milliseconds between latching a
process and releasing it, *and* the restart sweep must fail, *and* the process must be one whose
freezing matters and which §7.5 does not exclude. Low, not zero. The machine remains recoverable
by booting single-user (⌘-S), which does not load LaunchDaemons, and removing the plist.

**This residual is accepted, and `stop()` is the decided mechanism.** The fail-open alternative
— `chill()`, which spins in-kernel for a bounded interval so a dead daemon lets the process
proceed unpatched — is **rejected**: it turns the guarantee back into a probability, which is
the defect this plan exists to remove. Do not reintroduce it as a "safer default."

## 8. On-disk layout and configuration

### 8.1 Layout

Everything lives in **one directory**, plus one plist. `/Library/AquaTransport` is removed.

```
/usr/share/aquatransport/                       0755 root:wheel
    aquatransport.dylib                         0644   dlopen'd by targets, from their sandbox
    aqwatch                                     0755   the daemon (links libdtrace)
    aqinject                                    0755   cross-arch helper only; no --all mode
    redirects.txt                               0644   user-editable
    headers.txt                                 0644   user-editable
    flags.txt                                   0644   user-editable (§8.2)
    held.journal                                0600   runtime, §7.2
    armed.stamp                                 0600   runtime, §7.6

/Library/LaunchDaemons/
    org.aquatransport.watch.plist               0644
```

**Why one directory is safe.** The split existed because `/usr/share` is one of the few paths
`system.sb` lets a sandboxed process read, while the tools needed no such visibility. Moving
the tools in grants nothing: the directory stays `root:wheel 0755`, so it is not user-writable,
and `aqinject` requires `task_for_pid` — a non-root caller fails regardless of where the binary
sits. Nothing about the sandbox grant depends on the directory holding only data.

**What must not change.** The dylib and the three rule files stay `0644`. `system.sb`'s grant
carries a `(file-mode #o0004)` requirement, so a stricter mode leaves them readable to root
alone and every rule silently inert. The two runtime files are `0600` — they list pids, nothing
sandboxed reads them, and they need no world visibility.

**The two runtime files have opposite lifetimes, and one directory has to serve both.**
`held.journal` must be ignored after a reboot: its pids belong to other processes by then, and
replaying it would `thread_resume` threads that are not ours, unbalancing a suspend someone
else owns. `armed.stamp` must *survive* a reboot — detecting that the previous boot armed the
gates and never got healthy is its whole purpose.

Resolve this with a **boot session id** rather than by placing the files in directories with
different clearing behaviour. `sysctl kern.boottime` returns a value that is fixed for the life
of a boot and changes across reboots (verified: repeated reads return the identical
`sec.usec`). Stamp it into the journal header; on startup, replay the journal only when its
recorded id matches the current one, and otherwise discard it unread. That is explicit and
testable, and it does not depend on whether 10.9 clears `/var/run` at boot.

**The plist carries one argument.** With everything co-located, the daemon derives the dylib
and helper paths from its own location via `_NSGetExecutablePath`, so `ProgramArguments` is
just `/usr/share/aquatransport/aqwatch`. `RunAtLoad` and `KeepAlive` stay true; `KeepAlive` is
what drives the restart-and-recover path in §7.

**Uninstall** becomes `launchctl unload`, remove the plist, `rm -rf /usr/share/aquatransport`.
Removing the dylib does not unload it from processes that already have it — that remains true
and should stay in the uninstall notes.

**Log** stays at `/var/log/aquatransport.log`, root-owned, `0600`, size-bounded as now.

`/Library/AquaTransport` is referenced 16 times across `install-macos.sh`, `build-macos.sh`,
`packaging/Scripts/postinstall`, `packaging/uninstall.sh` and `docs/TECHNICAL.md`. The build
stages to `build/stage/usr/share/aquatransport/` only; `build/stage/Library/` goes away.

### 8.2 Flags

`/usr/share/aquatransport/flags.txt`, alongside the existing flags:

| flag | effect |
|---|---|
| `gate-off` | arm nothing; inject at `exec-success` only. Escape hatch. |
| `gate-rate=<n>hz` | consumer switchrate, default `50hz` (§3.4) |
| `gate-hold-ms=<n>` | watchdog deadline, default 250 |
| `gate-never=<name>` | add an executable to the §7.5 exclusion list |

`gate-never` takes **full** executable names. The daemon truncates them to 15
characters itself when generating the `BEGIN` block (§4.3); an operator must never have to
count characters, and a name that does not survive the round trip is a startup error rather
than a silently dead predicate.

The log stays at `/var/log/aquatransport.log`, root-owned, `0600`, size-bounded as now. Log
every release that the watchdog forced, every sweep that released anything, and every drop
reported by libdtrace — those three are the signals that the safety net is load-bearing.

## 9. Performance targets

Regressions against these should block merge.

| | target | source |
|---|---|---|
| daemon CPU, idle, 50 Hz | ≤ 0.5% of one core | 0.3–0.4% measured |
| daemon RSS | ≤ 9 MB | 7.8 MB measured |
| probe overhead per syscall | ≤ 0.1 µs | 0.05–0.08 µs measured |
| gate release, already patched | ≤ 0.1 ms | 0.026 ms measured |
| gate rescue, cold inject | ≤ 8 ms | 3.3–8.2 ms today, target 2–6 |
| private memory per patched process | ~600 KB | 603 KB measured |
| processes carrying the library | networking only | ~32 of ~270 |

## 10. Test plan

Extend `tools/selftest.sh`. Each of these has been reproduced by hand and should be automated.

**Gate correctness.** A test binary that prints its patched state immediately before and after
the gated syscall. It must print `patched=0` before and `patched=1` after, with the syscall
returning success and no `EINTR`:

- outbound: `connect` to a local listener
- inbound: `accept` from a local peer, verifying the peer's payload survives
- inetd: a launcher that accepts, then `posix_spawn`s a child with the connected socket as fd 0

**Fast path.** Second and subsequent gated threads in an already-patched process must take the
release path and not re-inject.

**exec invalidation.** A process that connects, is patched, then execs, must be re-gated and
re-patched on its next connection. Exercise `xpcproxy`-style chains explicitly.

**fork inheritance.** A patched process that forks without exec must have a patched child.

**Recovery, one test per layer.**
- watchdog: stall the injector artificially; assert release within `gate-hold-ms`
- journal: SIGKILL the daemon mid-hold; assert release on restart
- suspend-count scan: suspend a thread out of band, delete the journal, assert release
- blind sweep: `stop()` a process, kill the consumer before it drains, assert release on
  restart, and assert a Ctrl-Z'd job is still stopped afterwards

**Kill safety.** A process held at each gate must die to `SIGTERM` and to `SIGKILL`.

**Exclusion list (§7.5).** Two separate assertions, because the failure mode is silent:

1. **Assert the truncation round trip.** For every configured name, assert the generated
   `BEGIN` entry matches what DTrace actually reports as `execname` for a process of that name.
   A 16-character entry for `securityd_service` compiles, runs and matches nothing, freezing
   and injecting the daemon it was written to skip. Most of the list is never observed to
   connect (§7.5), so this assertion — not a skip test — is what proves those entries are live.
2. For any listed process that *can* be made to connect, assert it is never latched.
3. Assert the daemon never gates itself. It has nobody to release it.
4. Stand up a process named `WindowServer` or `loginwindow` in a scratch directory, make it
   connect, and assert it is skipped. This exercises the predicate itself without waiting on a
   process that may never reach a gate in normal operation.

**Soak.** Boot, log in, drive a browser and a few CLI tools for an hour. Assert: zero forced
watchdog releases, zero drops, zero processes left with `suspend_count > 0`.

## 11. Known gaps

Both are narrower than the gap the gate closes, and both should be documented rather than
papered over.

**Descriptor passing over a unix socket (`SCM_RIGHTS`).** A process handed an
already-connected socket at runtime rather than at spawn is caught by none of the three gates.
`syscall::recvmsg:return`, latched once per thread, is the natural fourth gate;
`recvmsg` is cold enough that its cost should resemble `connect` rather than `read`. Measure
before adding, and only after finding a case where it matters on 10.9 — unlike the inetd case,
which ships with 18 concrete plists, this one is speculative.

**UDP / DTLS.** An unconnected UDP socket uses `sendto`/`recvfrom` with no `connect`. Gating
`sendto` would be expensive and DTLS is close to nonexistent on this platform.

## 12. Verify before shipping

1. **libdtrace on 10.6.** Everything in §4.2 is verified on 10.9.5 only. DTrace ships from 10.5
   on, but `DTRACE_VERSION 3` and this API shape are unconfirmed on Snow Leopard, and it is a
   private interface. Test early — it gates the whole "no process named dtrace" property. The
   fallback is a **renamed copy** of `/usr/sbin/dtrace` spawned as a helper, which does display
   under the new name; a symlink does not work.
2. **`stop()` semantics on 10.6 – 10.8.** §3.2 and §3.3 are 10.9.5 findings. The BSD-stop
   behaviour and the discoverability table must be re-confirmed per OS version, since the whole
   recovery design rests on them.
3. **Gate stall end to end at 25–100 Hz.** The release-delay column in §3.4 is derived from
   record-delivery latency, not from a full stall-to-release cycle at those rates.
4. **`connect:return` as an alternative to `connect:entry`.** TLS bytes cannot flow either way,
   since that needs user space to run, but gating on return would let the TCP handshake —
   often 10–50 ms of round trip — absorb the notification delay instead of adding to it. It
   would not help non-blocking connects, which return immediately. Untested; measure before
   adopting.
5. **CPU under sustained load.** The 0.3–0.4% figure is idle. The switch timer is fixed-rate so
   it should hold, but confirm it does not degrade when competing with real work.
6. **`execname` truncation length per OS version.** The 15-character result in §4.3 is measured
   on 10.9.5. Re-measure on 10.6 – 10.8 rather than assuming, and keep the startup round-trip
   assertion so a change in this value fails loudly instead of quietly disarming the exclusion
   list.

Items 1, 2 and 6 all concern **10.6 – 10.8**, and all three are ship blockers. A first working
version can be built and iterated on 10.9.5, since that is the machine every measurement here
comes from — but that is sequencing, not scope, and none of them may be skipped for release.
Item 1 in particular can invalidate a design choice rather than merely need a port: if
`libdtrace` is unusable on 10.6 the consumer falls back to a renamed helper binary, which is
worth discovering early.

---

# Appendix A — Reference prototypes

**These are throwaway prototypes, not a starting skeleton.** Each one exists to prove a single
claim in the body of this plan actually holds on real hardware, and each was run on 10.9.5 to
produce the numbers quoted above. They cut every corner that a daemon cannot: no error
recovery, no cleanup on failure paths, fixed-size buffers, no architecture dispatch, root
assumed, return values ignored.

Treat them as executable evidence for the measurements, and as a way to reproduce those
measurements before trusting them. **Discard or rewrite any of it freely** — if the
implementation disagrees with a prototype here, the implementation is probably right. What
should survive scrutiny is the *measurements*, and those can be re-taken with these tools.

Build everything with:

```sh
clang -arch x86_64 -mmacosx-version-min=10.6 -o <name> <name>.c [-ldtrace]
```

`-ldtrace` is needed only for A.1. Everything that touches another process needs root.

## A.1 `aqtrace.c` — the trace consumer

Proves §4.2: the probes can be enabled and drained from inside our own process, with no
process named `dtrace`, at the cost quoted in §3.4. Verified output:

```
GATE pid=37557 tid=2923706 exec=vmnet-natd
GATE pid=28552 tid=2578253 exec=Transmission
GATE pid=73224 tid=3092113 exec=curl
GATE pid=73228 tid=3092130 exec=git-remote-http
```

This prototype omits `stop()` so it can be run without anything to release held threads. Adding
`stop()` to the two gate clauses is what makes it a gate; do that only alongside A.2 and the
recovery paths in §7.

```c
// The trace consumer, inside our own process: no dtrace(1), so an operator's own interactive
// dtrace sessions stay distinguishable in the process list.
#include <dtrace.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

static dtrace_hdl_t *g_dtp;
static volatile sig_atomic_t g_stop;
static void on_sig(int s) { (void)s; g_stop = 1; }

static int on_err(const dtrace_errdata_t *e, void *a) {
    (void)a; fprintf(stderr, "  D error: %s\n", e->dteda_msg ? e->dteda_msg : "?");
    return DTRACE_HANDLE_OK;
}
// A drop is a gate record that was never delivered, which means a process may be frozen with
// nobody holding its pid. The daemon answers this with the sweep in A.3.
static int on_drop(const dtrace_dropdata_t *d, void *a) {
    (void)a; fprintf(stderr, "  DROP: %s\n", d->dtdda_msg ? d->dtdda_msg : "?");
    return DTRACE_HANDLE_OK;
}

// libdtrace formats printf() records into a FILE* backed by a real descriptor. A pipe back
// into this same process keeps everything in-process. dtrace_handle_buffered() looks like the
// tidier route and delivers the text, but its pid/tid values were wrong in testing -- see the
// traps in section 4.2.
static void *reader(void *arg) {
    FILE *rd = (FILE *)arg;
    char line[256];
    while (fgets(line, sizeof line, rd)) {
        int p, t; char name[64];
        if (sscanf(line, "G %d %d %63s", &p, &t, name) == 3)
            printf("GATE pid=%d tid=%d exec=%s\n", p, t, name);  // real daemon: run the gate
    }
    return NULL;
}

static int chew(const dtrace_probedata_t *d, void *a) { (void)d; (void)a; return DTRACE_CONSUME_THIS; }
static int chewrec(const dtrace_probedata_t *d, const dtrace_recdesc_t *r, void *a) {
    (void)d; (void)a;
    return r == NULL ? DTRACE_CONSUME_NEXT : DTRACE_CONSUME_THIS;
}

static const char *kProg =
"syscall::connect:entry\n"
"{ this->p = (uint8_t *)copyin(arg1, 2); this->fam = this->p[1]; }\n"
"syscall::connect:entry\n"
"/(this->fam == 2 || this->fam == 30) && latched[tid] == 0/\n"
"{ latched[tid] = 1; printf(\"G %d %d %s\\n\", pid, tid, execname); }\n"
"syscall::accept*:return\n"
"/arg0 >= 0 && latched[tid] == 0/\n"
"{ latched[tid] = 1; printf(\"G %d %d %s\\n\", pid, tid, execname); }\n"
"proc:::exec-success { latched[tid] = 0; }\n"
"proc:::lwp-exit { latched[tid] = 0; }\n";

int main(int argc, char **argv) {
    const char *rate = argc > 1 ? argv[1] : "50hz";
    setvbuf(stdout, NULL, _IOLBF, 0);

    int pfd[2];
    if (pipe(pfd)) { perror("pipe"); return 1; }
    FILE *sink = fdopen(pfd[1], "w");
    setvbuf(sink, NULL, _IOLBF, 0);
    pthread_t rt;
    pthread_create(&rt, NULL, reader, fdopen(pfd[0], "r"));

    int err;
    if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
        fprintf(stderr, "dtrace_open: %s\n", dtrace_errmsg(NULL, err)); return 1;
    }
    dtrace_setopt(g_dtp, "bufsize", "256k");
    dtrace_setopt(g_dtp, "switchrate", rate);
    // A gate build also needs: dtrace_setopt(g_dtp, "destructive", 0);

    // A multi-clause program is what dtrace(1) compiles for -s, not -n: strcompile with a
    // probespec takes one clause and silently ignores the rest.
    char dpath[] = "/tmp/aqtrace-XXXXXX";
    int dfd = mkstemp(dpath);
    if (dfd < 0) { perror("mkstemp"); return 1; }
    if (write(dfd, kProg, strlen(kProg)) < 0) { perror("write"); return 1; }
    lseek(dfd, 0, SEEK_SET);
    FILE *dfp = fdopen(dfd, "r");
    dtrace_prog_t *pgp = dtrace_program_fcompile(g_dtp, dfp, DTRACE_C_PSPEC, 0, NULL);
    fclose(dfp);
    unlink(dpath);
    if (pgp == NULL) {
        fprintf(stderr, "compile: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))); return 1;
    }

    dtrace_proginfo_t info;
    memset(&info, 0, sizeof info);
    if (dtrace_program_exec(g_dtp, pgp, &info) == -1) {
        fprintf(stderr, "exec: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))); return 1;
    }
    dtrace_handle_err(g_dtp, on_err, NULL);
    dtrace_handle_drop(g_dtp, on_drop, NULL);
    if (dtrace_go(g_dtp) == -1) {
        fprintf(stderr, "go: %s\n", dtrace_errmsg(g_dtp, dtrace_errno(g_dtp))); return 1;
    }
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    // dpi_matches is the check against silent strcompile truncation.
    fprintf(stderr, "aqtrace: %s, probes matched=%d\n", rate, info.dpi_matches);

    while (!g_stop) {
        dtrace_sleep(g_dtp);
        if (dtrace_work(g_dtp, sink, chew, chewrec, NULL) == DTRACE_WORKSTATUS_ERROR) break;
    }
    dtrace_stop(g_dtp);
    dtrace_close(g_dtp);
    return 0;
}
```

## A.2 `gatehold.c` — the gate sequence

Proves §3.2 and §5: a DTrace `stop()` can be converted into a Mach suspension of one thread,
the target can then be injected normally, and the held syscall completes correctly on release.

Driven by hand against a pid/tid printed by a `stop()`-bearing D script. Verified against all
three gates, in each case on a process that had reached the syscall unpatched:

```
about to connect   patched=0
  injector exit=0 after 7.3 ms
  thread_resume ok -- released after 7.4 ms held
connect returned 0 errno=0 (ok)   patched=1
```

```c
// Hold one thread at its gated syscall while the library is loaded, then let it go.
//
// A DTrace stop() is a BSD process stop, under which pthread_create'd threads are never
// scheduled -- so the injector's stage 2 never runs and dlopen is never called. The fix is to
// convert that process-wide stop into a Mach suspension of the single gated thread: suspend
// the thread, SIGCONT the process so injection can proceed normally, inject, then resume.
// The suspend must precede the SIGCONT, or the thread is briefly runnable and unpatched.
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;

static double ms(uint64_t a, uint64_t b) {
    static mach_timebase_info_data_t t;
    if (!t.denom) mach_timebase_info(&t);
    return (double)(b - a) * t.numer / t.denom / 1e6;
}

int main(int argc, char **argv) {          // pid tid dylib injector
    pid_t pid = atoi(argv[1]);
    uint64_t want = strtoull(argv[2], NULL, 10);   // D's tid == Mach thread_id

    task_t task;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) { perror("task_for_pid"); return 1; }
    thread_act_array_t list; mach_msg_type_number_t n;
    if (task_threads(task, &list, &n) != KERN_SUCCESS) { fprintf(stderr, "task_threads\n"); return 1; }

    thread_act_t match = MACH_PORT_NULL;
    for (unsigned i = 0; i < n; i++) {
        thread_identifier_info_data_t ii; mach_msg_type_number_t c = THREAD_IDENTIFIER_INFO_COUNT;
        if (thread_info(list[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&ii, &c) != KERN_SUCCESS) continue;
        if (ii.thread_id == want) match = list[i];
    }
    if (!match) { fprintf(stderr, "no thread matched tid %llu\n", (unsigned long long)want); return 1; }

    uint64_t t0 = mach_absolute_time();
    if (thread_suspend(match) != KERN_SUCCESS) { fprintf(stderr, "thread_suspend failed\n"); return 1; }
    kill(pid, SIGCONT);                       // clears the BSD stop; the thread stays held

    char *av[] = { argv[4], (char *)"-q", argv[1], argv[3], NULL };
    pid_t c;
    if (posix_spawn(&c, argv[4], NULL, NULL, av, environ)) { perror("spawn"); thread_resume(match); return 1; }
    int st; waitpid(c, &st, 0);
    printf("  injector exit=%d after %.1f ms\n", WEXITSTATUS(st), ms(t0, mach_absolute_time()));

    // In the daemon this belongs on every exit path, not just this one: failing open and
    // running unpatched beats leaving a thread held.
    thread_resume(match);
    printf("  thread_resume ok -- released after %.1f ms held\n", ms(t0, mach_absolute_time()));
    return 0;
}
```

## A.3 `sweep.c` — blind recovery sweep

Proves §7.4: an orphaned BSD stop whose pid was never delivered to user space can still be
released, without disturbing a genuine Ctrl-Z'd job. Measured `271 processes: SIGCONT to 268,
skipped 1 genuinely stopped -- 0.45 ms`, releasing an orphan while a real stopped job stayed
`T+`.

```c
// Startup recovery sweep: release any process frozen by an orphaned DTrace stop().
//
// Such a process reports p_stat == SRUN and is otherwise indistinguishable from a running one,
// so the sweep is blind: SIGCONT everything that is not genuinely SIGSTOPped. SIGCONT is a
// no-op on a running process, and a real stopped job (Ctrl-Z) reports SSTOP and is skipped.
#include <sys/sysctl.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#ifndef SSTOP
#define SSTOP 4
#endif

int main(int argc, char **argv) {
    int dry = argc > 1 && !strcmp(argv[1], "-n");
    mach_timebase_info_data_t tb; mach_timebase_info(&tb);
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t len = 0;
    if (sysctl(mib, 3, NULL, &len, NULL, 0)) { perror("sysctl"); return 1; }
    struct kinfo_proc *p = malloc(len);
    if (sysctl(mib, 3, p, &len, NULL, 0)) { perror("sysctl"); return 1; }

    int n = len / sizeof *p, sent = 0, skipped = 0;
    uint64_t t0 = mach_absolute_time();
    for (int i = 0; i < n; i++) {
        pid_t pid = p[i].kp_proc.p_pid;
        if (pid <= 1) continue;                                      // never signal launchd
        if (p[i].kp_proc.p_stat == SSTOP) { skipped++; continue; }    // a real Ctrl-Z job
        if (!dry) kill(pid, SIGCONT);
        sent++;
    }
    printf("  %d processes: SIGCONT to %d, skipped %d genuinely stopped -- %.2f ms\n",
           n, sent, skipped,
           (double)(mach_absolute_time() - t0) * tb.numer / tb.denom / 1e6);
    return 0;
}
```

## A.4 `scanheld.c` — suspend-count scan

Proves §7.3: a Mach hold left by a dead daemon is discoverable even though `ps` shows the
process as normal. Output while a thread is held: `suspend_count=1  <== HELD`, with `ps`
reporting `S+`.

```c
// Report any thread with a non-zero Mach suspend count -- what a hold left behind by a dead
// daemon looks like. ps shows such a process as ordinary, so this is the only way to find one
// without a journal.
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    pid_t pid = atoi(argv[1]);
    task_t task;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) { perror("task_for_pid"); return 1; }
    thread_act_array_t list; mach_msg_type_number_t n;
    if (task_threads(task, &list, &n) != KERN_SUCCESS) return 1;
    for (unsigned i = 0; i < n; i++) {
        thread_basic_info_data_t bi; mach_msg_type_number_t c = THREAD_BASIC_INFO_COUNT;
        if (thread_info(list[i], THREAD_BASIC_INFO, (thread_info_t)&bi, &c) != KERN_SUCCESS) continue;
        printf("  thread %u: suspend_count=%d run_state=%d%s\n", i, bi.suspend_count, bi.run_state,
               bi.suspend_count > 0 ? "   <== HELD" : "");
    }
    return 0;
}
```

## A.5 `pstat.c` and `thrctl.c` — state inspection and out-of-band hold

`pstat.c` produces the §3.3 discoverability table: a DTrace-stopped process reports
`p_stat=2 (SRUN)`, a real `SIGSTOP` reports `p_stat=4 (SSTOP)`. That difference is what makes
A.3 safe.

```c
// Is a held process discoverable via the kernel's proc state?
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, atoi(argv[1]) };
    struct kinfo_proc kp; size_t len = sizeof kp;
    if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0) { printf("gone\n"); return 1; }
    const char *names[] = { "?", "SIDL", "SRUN", "SSLEEP", "SSTOP", "SZOMB" };
    int s = kp.kp_proc.p_stat;
    printf("  p_stat=%d (%s)  p_flag=0x%x\n", s, (s >= 0 && s <= 5) ? names[s] : "?", kp.kp_proc.p_flag);
    return 0;
}
```

`thrctl.c` suspends or resumes a thread by index and exits immediately, which models a daemon
dying while holding a thread. It establishes that the hold outlives the suspender and that any
privileged process can undo it — the two facts §7.3 rests on.

```c
// Suspend or resume a thread of another process, by index. Exits immediately afterwards, so
// "suspend" models a daemon that dies while holding a thread.
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {          // pid suspend|resume [index]
    pid_t pid = atoi(argv[1]); int idx = argc > 3 ? atoi(argv[3]) : 0;
    task_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "task_for_pid: %s\n", mach_error_string(kr)); return 1; }
    thread_act_array_t list; mach_msg_type_number_t n;
    if ((kr = task_threads(task, &list, &n)) != KERN_SUCCESS) { fprintf(stderr, "task_threads\n"); return 1; }
    if (idx >= (int)n) { fprintf(stderr, "only %u threads\n", n); return 1; }
    kr = strcmp(argv[2], "suspend") == 0 ? thread_suspend(list[idx]) : thread_resume(list[idx]);
    printf("%s thread %d of %u: %s\n", argv[2], idx, n, mach_error_string(kr));
    return kr != KERN_SUCCESS;
}
```

## A.6 Gate test programs

Each prints its own patched state immediately before and after the gated syscall, which is the
assertion the §10 tests automate: `patched=0` before, `patched=1` after, syscall successful,
no `EINTR`, payload intact.

Shared helper, used by all three:

```c
#include <mach-o/dyld.h>
#include <string.h>
static int patched(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *p = _dyld_get_image_name(i);
        if (p && strstr(p, "aquatransport.dylib")) return 1;
    }
    return 0;
}
```

**`connclient.c`** — outbound gate. Needs a listener (`nc -l <port>`).

```c
int main(int argc, char **argv) {
    int port = atoi(argv[1]);
    printf("about to connect   patched=%d\n", patched()); fflush(stdout);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_len = sizeof a; a.sin_family = AF_INET; a.sin_port = htons(port);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    errno = 0;
    int r = connect(s, (struct sockaddr *)&a, sizeof a);
    printf("connect returned %d errno=%d (%s)   patched=%d\n",
           r, errno, r ? strerror(errno) : "ok", patched());
    return 0;
}
```

**`acceptserver.c`** — inbound gate. Drive with `echo HELLO | nc 127.0.0.1 <port>`; the read
after `accept` is what proves the connection survived the hold.

```c
int main(int argc, char **argv) {
    int port = atoi(argv[1]);
    int ls = socket(AF_INET, SOCK_STREAM, 0); int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_len = sizeof a; a.sin_family = AF_INET; a.sin_port = htons(port);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(ls, (struct sockaddr *)&a, sizeof a)) { perror("bind"); return 1; }
    listen(ls, 8);
    printf("about to accept    patched=%d\n", patched()); fflush(stdout);
    errno = 0;
    int fd = accept(ls, NULL, NULL);
    printf("accept returned %d errno=%d (%s)   patched=%d\n",
           fd, errno, fd < 0 ? strerror(errno) : "ok", patched());
    if (fd >= 0) {
        char b[64]; int n = read(fd, b, sizeof b - 1);
        if (n > 0) { b[n] = 0; printf("read %d bytes from peer: %.*s", n, n, b); }
    }
    return 0;
}
```

**`inetdchild.c`** and **`inetdlauncher.c`** — inherited-socket gate. The launcher stands in for
launchd's inetd mode: it accepts a connection and spawns the child with that already-connected
socket as fd 0, so the child calls neither `connect` nor `accept`.

```c
/* inetdchild.c -- fd 0 is already a connected socket. */
int main(void) {
    printf("about to read fd0   patched=%d\n", patched()); fflush(stdout);
    char b[64]; errno = 0;
    int n = read(0, b, sizeof b - 1);
    printf("read returned %d errno=%d (%s)   patched=%d\n",
           n, errno, n < 0 ? strerror(errno) : "ok", patched());
    if (n > 0) { b[n] = 0; printf("payload: %.*s", n, b); }
    return 0;
}

/* inetdlauncher.c -- accepts, then hands the connected socket to the child as fd 0. */
int main(int argc, char **argv) {
    int port = atoi(argv[1]);
    int ls = socket(AF_INET, SOCK_STREAM, 0); int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_len = sizeof a; a.sin_family = AF_INET; a.sin_port = htons(port);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    bind(ls, (struct sockaddr *)&a, sizeof a); listen(ls, 8);
    int fd = accept(ls, NULL, NULL);
    posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fd, 0);
    char *av[] = { (char *)"./inetdchild", NULL };
    pid_t p; posix_spawn(&p, "./inetdchild", &fa, NULL, av, environ);
    int st; waitpid(p, &st, 0);
    return 0;
}
```

## A.7 `heartbeat.c` — recovery-test subject

A process whose progress is externally visible, so "frozen" and "released" are observable
without instrumenting it. Used for every test in §7 and for the kill-safety tests.

```c
#include <stdio.h>
#include <unistd.h>
int main(void) { for (int i = 0; ; i++) { printf("beat %d\n", i); fflush(stdout); usleep(300000); } }
```

## A.8 `waitpatch.c` — launch-to-patched latency harness

Produces the §1 and §3.4 latency figures. The parent stamps `mach_absolute_time()` immediately
before spawning; the child polls its own dyld image list and reports how long the library took
to arrive, along with how long it took to reach `main`.

```c
#include <mach/mach_time.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
extern char **environ;

static double ms_since(uint64_t t0) {
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info(&tb);
    return (double)(mach_absolute_time() - t0) * tb.numer / tb.denom / 1e6;
}
static int patched(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *p = _dyld_get_image_name(i);
        if (p && strstr(p, "aquatransport.dylib")) return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "--child")) {
        uint64_t t0 = strtoull(argv[2], NULL, 10);
        double first_main = ms_since(t0);
        for (int i = 0; i < 20000; i++) {              // 20s ceiling at 1ms granularity
            if (patched()) { printf("%.1f %.1f\n", first_main, ms_since(t0)); return 0; }
            usleep(1000);
        }
        printf("%.1f TIMEOUT\n", first_main);
        return 1;
    }
    int reps = argc >= 2 ? atoi(argv[1]) : 5;
    char self[4096]; uint32_t sz = sizeof self; _NSGetExecutablePath(self, &sz);
    for (int r = 0; r < reps; r++) {
        char stamp[32];
        snprintf(stamp, sizeof stamp, "%llu", (unsigned long long)mach_absolute_time());
        char *av[] = { self, (char *)"--child", stamp, NULL };
        pid_t p;
        if (posix_spawn(&p, self, NULL, NULL, av, environ)) { perror("spawn"); return 1; }
        int st; waitpid(p, &st, 0);
        sleep(1);
    }
    return 0;
}
```

## A.9 Measurement D scripts

Not part of the daemon; these produce numbers quoted in §3.

**Time from exec to first outbound connection** (§3.4, and the basis for dropping any
inject-at-exec pre-warm):

```d
#pragma D option quiet
#pragma D option switchrate=100hz
proc:::exec-success { start[pid] = timestamp; }
syscall::connect:entry
{ this->p = (uint8_t *)copyin(arg1, 2); this->fam = this->p[1]; }
syscall::connect:entry
/(this->fam == 2 || this->fam == 30) && start[pid] != 0 && seen[pid] == 0/
{
    seen[pid] = 1;
    printf("%-24s %8d ms after exec\n", execname, (timestamp - start[pid]) / 1000000);
}
proc:::exit { start[pid] = 0; seen[pid] = 0; }
```

**Which exec probe reports the new process** (§3.1). Run it and launch something via both a
shell (`fork`+`execve`) and `posix_spawn`:

```d
#pragma D option quiet
proc:::exec-success { printf("EXEC-SUCCESS %s pid=%d exec=%s ppid=%d\n", probefunc, pid, execname, ppid); }
proc:::exec         { printf("EXEC         %s pid=%d exec=%s arg0=%s\n", probefunc, pid, execname, stringof(arg0)); }
```

**System-wide read/write rate**, for pricing the inetd gate (§4.3):

```d
syscall::read*:entry, syscall::write*:entry { @c = count(); }
tick-10s { printa("  %@d read/write syscalls in 10s\n", @c); exit(0); }
```
