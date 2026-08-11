(Note: The below was written by Claude.)

# AquaTransport for Mac OS X 10.6 – 10.9

Modern TLS for Snow Leopard through Mavericks, by replacing the crypto behind Secure
Transport rather than proxying traffic. Ported from the iOS tweak; the engine
(`src/aquatransport_engine.c`) is shared, the hook layer and URL rewriter are new.

Two independent subsystems in one package:

| Subsystem | What it does | Where it runs |
|---|---|---|
| TLS engine | Routes Secure Transport through OpenSSL: TLS 1.0–1.3, modern ciphers, OS-delegated trust | every process carrying the library |
| URL rewriter | Applies `redirects.txt` and `headers.txt` at the request layer | the same processes; each rule carries its own scope line |

Neither is gated on what the process is. The rewriter's *rules* are scoped — every block begins
with a scope line naming the apps it applies to, or `*` — but the hooks themselves go into every
process the library reaches. See *How the rewriter works* below.

Which processes the library reaches is a separate question, and the answer is: the ones that use
the network, held at the moment they first do. See *The connection gate*.

Verified on 10.9.5 (51/51 per-process tests, 39/39 gate tests), and on 10.6.8 for the engine
(`NSURLSession` is 10.9+ and is skipped there), both `x86_64` and `i386`.

## Build

```
./build-macos.sh          # OpenSSL + dylib + the daemon and injector
./tools/selftest.sh       # per-process tests, installs nothing
sudo ./tools/gatetest.sh  # the connection gate, end to end; needs root
```

The two suites cannot share a process. `selftest.sh` asserts that *stock* Secure Transport fails
`api.twitter.com`, which a running gate would turn into a pass by loading the library into the
probe before it connected — so it refuses to run while `aqwatch` is up, and the gate is tested
separately.

Everything is vendored: `deps/openssl-3.5.7.tar.gz` (checksum matches upstream). No network
needed to build.

The build enforces three invariants, each guarding a failure that is silent at link time:

1. **Both slices present.** The library needs an `i386` and an `x86_64` slice so aqinject can
   load it into targets of either architecture; the build refuses without both.
2. **Zero exported symbols.** Loaded into another process by any mechanism, the library must
   export nothing: a naive link exports 9252 symbols, the whole `SSL_*`/`EVP_*` namespace
   among them, which would interpose those names in the host.
3. **No post-10.6 libc imports.** `getentropy` is 10.12+; `strndup`, `strnlen`, `getline`,
   `getdelim` are 10.7+. They bind *lazily*, so the dylib loads fine and then kills the
   process on first use. OpenSSL is configured `--with-rand-seed=devrandom` to keep seeding
   off `getentropy`; the check below is what catches any other such import.

## Install

```
sudo ./install-macos.sh stage      # copy files into place, start nothing
sudo ./install-macos.sh watch      # + the connection-gate daemon, at boot and now
sudo ./install-macos.sh uninstall  # stop the daemon, then remove the files
```

Everything lives in one directory, plus one plist:

| path | contents |
| --- | --- |
| `/usr/share/aquatransport/` | `aquatransport.dylib`, `aqwatch`, `aqinject`, `flags.txt`, `headers.txt`, `redirects.txt`, and two runtime files (`held.journal`, `armed.stamp`) |
| `/Library/LaunchDaemons/org.aquatransport.watch.plist` | starts the daemon at boot |

The directory is `/usr/share` because of who reads what. A target `dlopen`s the dylib and reads
the rule files itself, so those reads happen under the *target's* sandbox, and
`/System/Library/Sandbox/Profiles/system.sb` — imported by every sandboxed process — grants
`file-read*` only for world-readable files under `/System`, `/usr/lib`, `/usr/share`,
`/private/var/db/dyld` and `/Library/Filesystems/NetFSPlugins`:

```scheme
(allow file-read*
       (require-all (file-mode #o0004)
                    (require-any ... (subpath "/usr/share") ...)))
```

A `deny default` daemon — WebKit's `webpushd` is one — reads nothing outside that set, and a
`dlopen` it cannot satisfy leaves it running unpatched with a kernel log line as the only
trace:

```
Sandbox: webpushd(715) deny file-read-data /usr/share/aquatransport/aquatransport.dylib
```

The `(file-mode #o0004)` clause is why the installers set 0644 on these files and 0755 on the
directory: a stricter mode is readable to root alone, and every sandboxed target goes
unpatched.

Not every sandboxed process is this restricted. `application.sb`, which backs the app sandbox,
carries a blanket `(allow file-read* (subpath "/Library"))`, and WebKit's `WebProcess` and
`NetworkProcess` profiles reach the dylib as well. `/usr/share` is what the whole range of
them share.

**The tools sit in the same directory, and gain nothing from it.** They need no sandbox
visibility — root runs them from outside any sandbox — but the directory stays `root:wheel`
`0755`, so it is not user-writable, and injecting requires `task_for_pid`, which a non-root
caller fails wherever the binary sits. Co-locating them is what lets `aqwatch` derive every
path from its own location, which is why the plist carries a single argument.

The two runtime files are `0600`: they list pids, nothing sandboxed reads them, and they need
no world visibility. They also have opposite lifetimes — `held.journal` must be ignored after a
reboot, because its pids belong to other processes by then, while `armed.stamp` must survive
one. Both carry a **boot session id** from `sysctl kern.boottime`, which is fixed for the life
of a boot and changes across reboots, so each is read only when its id says it is still meant
to apply. That is explicit and testable, and it does not depend on whether 10.9 clears any
particular directory at boot.

The library is loaded into a process by the injection engine in `tools/aqinject_core.c` —
`task_for_pid` plus a hand-built `mach_inject` — using the target's own `dlopen`. It edits no
system launch configuration, so a faulty library is confined to the process it is loaded into
and can never keep the machine or another process from starting.

- **`stage`** puts the files in place and starts nothing.
- **`watch`** installs `aqwatch` (`tools/aqwatch.c`) as a LaunchDaemon, started at each boot.
  It holds each process at its first use of the network and loads the library before letting it
  go. See *The connection gate* below.

### Loading into a running process

The engine loads the compatibility library into a cooperating process the administrator
already runs on a machine they own; the payload is loaded by the target's own `dlopen`.
`pthread_create_from_mach_thread` does not exist before 10.7, so its effect is rebuilt by
hand — every step below is validated on 10.6.8, i386 and x86_64:

1. `task_for_pid` for the target task port (root only).
2. Allocate in the target a payload page (context + a detached `pthread_attr_t` + the path +
   two shellcode blobs), a bootstrap stack, and a TSD page.
3. `thread_create_running` a **bare** mach thread. A bare mach thread has no thread-local
   storage, and almost all libc — `errno`, `malloc`, dyld — faults without it. So stage 1
   first sets the `%gs` base with the `thread_fast_set_cthread_self` machdep trap (call #3:
   x86_64 `syscall` `rax=0x03000003`; i386 `int $0x82` `eax=3`), pointing it at a
   self-referential TSD page. That is the minimum to make one further libc call safe.
4. That one call is `pthread_create(&tid, detached_attr, stage2, &ctx)`. The kernel builds a
   real pthread — its stack and struct come from the kernel, not `malloc` — so stage 2 runs
   with complete TLS.
5. Stage 2 calls `dlopen(path, RTLD_NOW|RTLD_GLOBAL)`; our constructor installs the hooks via
   fishhook, then records the handle and a done flag the injector polls.

Two facts make it reliable. **The dyld shared cache is at the same fixed address in every
process of a given arch on 10.6–10.9**, so `dlopen`/`pthread_create` resolved in the injector
are valid in the target; it is verified byte-for-byte before use, and refused on mismatch.
**Each fat slice loads only same-arch targets** and spawns the matching slice for a target of
the other arch, so resolved addresses and the `pthread_attr_t` layout are always arch-correct.

**No safety gate.** Injection is unconditional: `aqinject` does not require the target to have
loaded `Security.framework`, and nothing waits for a framework to appear.

That is safe because the library links CoreFoundation and Security *lazily* (`-lazy_framework`,
see `build-macos.sh`), so loading it into a process pulls in neither — no framework initializer
runs, and `CFInitialize`, which traps when first run late on a secondary thread, is never
reached. Its hooks are rebound by name, which requires nothing to be loaded, and fishhook
rebinds the call sites if and when Secure Transport arrives. The library therefore sits inert
in a process that never does TLS and starts working the moment one does. The trigger is an
event, not a timeout.

A gate on `Security.framework` would have to predict *when* a process loads it, which is
unanswerable: a process loads Security when it first needs TLS, and for Safari's shared WebKit
networking service that is when the user first navigates — arbitrarily long after launch. A
freshly launched `com.apple.WebKit.Networking` on 10.9.5 still has no `Security.framework`
1500 ms in. No timeout is long enough, because there is no deadline to be right about.

Lazy linking forbids *data* references to those frameworks — the linker rejects them outright
("illegal data reference to `_kCFTypeArrayCallBacks` in lazy loaded dylib"). There are exactly
two in this code, both avoided: `kCFTypeArrayCallBacks` is looked up by name, and the constant
CFString behind `CFSTR("Host")` (a reference to `___CFConstantStringClassReference`) is built
at runtime. A new one fails the build rather than silently restoring eager loading.

Verified on 10.9.5, x86_64, by `tools/latecheck.c`: loaded into a process with **no
CoreFoundation and no Security**, both stay absent; CFNetwork is then brought in afterwards and
a request to `api.twitter.com` returns HTTP 404 — which stock Secure Transport on 10.9 cannot
do (-9824). The same holds when the injection comes from `aqwatch` rather than the process
itself, for both `fork`+`execve` and `posix_spawn` launches.

## The connection gate

Loading a library into a process that has already started leaves a window, and a process that
issues a TLS request inside that window uses the system's own Secure Transport — so the request
fails against a modern server, or succeeds against a weak one. **Either outcome is the bug this
package exists to fix, so the window is a correctness defect, not a performance one.**

Narrowing it does not close it, and a launch-list poller cannot even bound it. Cross-checked
against `proc:::exec-success` over one workload, a 20 ms poller never observed nine processes at
all — `git`, `perl`, `sh`, `date`, `env` — because they lived for less than one interval. `git`
and `curl` fetching over HTTPS are exactly the short-lived, fast-connecting processes this
affects.

So the kernel freezes the process instead:

```
kernel                          aqwatch (root, LaunchDaemon)
------                          ---------------------------
process calls connect()
  -> probe fires, stop()        [process frozen, synchronously]
  -> record buffered
                                dtrace_work() drains the record
                                thread_suspend(the offending thread)
                                kill(pid, SIGCONT)     [clears the BSD stop]
                                inject the library if absent
                                thread_resume(the thread)
process continues                                      [library present]
```

Three probes, and each has a reason to be where it is:

| gate | probe | why there |
|---|---|---|
| outbound | `syscall::connect:entry` | `AF_INET`/`AF_INET6` only, read from the `sockaddr`'s `sa_family` byte |
| inbound | `syscall::accept*:return` | on **return**, so the descriptor exists — at entry the thread would sit in the gate while the process was merely idle waiting |
| inherited socket | `syscall::read*:entry`, `write*:entry` | inetd-style jobs call neither `connect` nor `accept`; emitted only for executables that need it |

The wildcards are not optional. stdio flushes through `write_nocancel` rather than `write`, so a
predicate on `write` alone silently never fires, and `accept*` covers `accept_nocancel` too.

**Injection happens only at a gate.** Nothing is injected at exec, and a process that never
touches the network never receives the library — about **32 processes of ~270** rather than all
of them, at a measured ~600 KB of private dirty memory each.

**Processes already running when the daemon starts are deliberately not covered.** One that
connected before the daemon came up is gated at its *next* connection, which for a process
holding a long-lived one may be a long time. Restarting it, or rebooting, is the remedy. A bulk
pass over existing processes would reintroduce the whole memory cost this architecture removes,
to cover a case a reboot handles.

### Why the process stop has to become a thread suspension

A DTrace `stop()` is a **BSD process stop**, and it has two properties that together dictate the
whole design.

It freezes the process **before dyld runs**, so it cannot be used at exec: a process stopped
there never initialises libSystem, and the injector waits for `libSystemInitialized` forever.

And **under a BSD stop, `pthread_create`'d threads are never scheduled.** The injector's stage 1
is a raw mach thread and runs fine; stage 2 is a real pthread and does not, so `dlopen` is never
called. Sampling a process in that state shows it exactly — stage 1 spinning at its `jmp`, stage
2 created and never run.

The fix is to downgrade the process stop to a thread suspension before injecting: `thread_suspend`
the offending thread, `SIGCONT` the process to clear the BSD stop, inject normally, then
`thread_resume`. **Ordering matters** — suspend *before* the `SIGCONT`, so there is no instant in
which the thread is runnable and unpatched. D's `tid` equals the Mach `thread_id` from
`thread_info(THREAD_IDENTIFIER_INFO)`, which is how the thread is found.

### What the daemon remembers, and why it cannot go stale

Verifying patched-ness by walking a target's dyld image list costs 0.135 ms, so the daemon keeps
a set of processes it has already patched. The key is **(pid, process start time, last exec
timestamp)**, and all three are load-bearing:

- a pid alone is reused;
- the start time separates one use of a pid from the next;
- the exec timestamp separates one *program* from the next within a single pid — which matters
  because the library does not survive an exec, and because `xpcproxy` re-execs into the real
  binary for every application and XPC service on 10.9.

The exec timestamp rides in on the gate record itself, recorded by D at `proc:::exec-success`.
That is what makes the set safe without any invalidation protocol: nothing has to be told that a
process exec'd, and no event has to arrive in any particular order — a stale entry simply stops
matching. An eviction costs one redundant injection, which `dlopen` makes idempotent anyway.

A process already in the set takes the fast path: one `SIGCONT` and nothing else. It is not
suspended at all, because a process that already carries the library wants to run.

### Taking over a context configured before the library arrived

The gate is in time for the handshake but **not** for the setup, and the difference is not
academic. Measured with the pid provider on a fresh CFNetwork client, same process:

```
16506  SSLCreateContext
16506  SSLSetIOFuncs        <- where the engine normally attaches
16506  SSLSetConnection
16510  socket / connect / connect_nocancel
16511  connectx             <- where the gate fires
16592  SSLHandshake
```

CFNetwork builds and configures its `SSLContext` **before it opens any socket at all** — about
5 ms before, and before even the DNS lookup. So on the first TLS connection of a CFNetwork
process the library is loaded between `SSLSetIOFuncs` and `SSLHandshake`: the context is fully
configured and our setter for it never ran. Left alone, that connection falls through to the
system's Secure Transport, which is precisely the old-TLS exposure this package exists to
remove — and for a short-lived process it would be every request it ever makes.

So the engine takes such a context over at `SSLHandshake` instead. Everything the setters would
have recorded has a public getter except the two I/O callbacks:

| state | recovered from | why it matters |
|---|---|---|
| connection | `SSLGetConnection` | the transport, and the per-context layout check |
| peer name | `SSLGetPeerDomainNameLength` + `SSLGetPeerDomainName` | **SNI, and what the certificate is verified against** |
| peer id | `SSLGetPeerID` | session cache key |
| break-on-server-auth | `SSLGetSessionOption` | whether the app verifies the chain itself |
| read/write callbacks | no getter — see below | |

**"No shadow" is the wrong thing to test for.** CFNetwork sets the I/O funcs up front but sets
the peer name and peer id *later*, after the gate has released the process and the hooks are
installed — so those later setters create a shadow with no callbacks in it. What decides whether
a context needs taking over is whether the callbacks are there, not whether a shadow exists.
Testing the wrong one leaves the connection silently on the system stack.

**The callbacks are found by discovery, not by a written-down offset.** There is no
`SSLGetIOFuncs`, so the layout is derived at runtime in each process: build a throwaway context,
set sentinel callbacks through the real `SSLSetIOFuncs`, and find where they landed, with
`malloc_size` bounding the search to the context's own allocation. It comes out as
`{16, 24, 32}` on x86_64 and `{8, 12, 16}` on i386 — but nothing depends on those numbers, and a
future layout simply produces different ones.

Three checks keep a wrong layout from being a crash rather than a decline:

1. The calibration has to succeed **twice**, on two independently created contexts, or no
   takeover is attempted at all.
2. Every context is checked individually before it is trusted: the connection read through the
   public `SSLGetConnection` must equal the word at the calibrated offset. A layout that does not
   apply to this context is caught there, before anything is called.
3. The recovered pointers must be non-null and resolve through `dladdr` to a loaded image.

Any check failing leaves the shadow incomplete, and the existing guard hands the connection to
the system stack — which is what would have happened anyway. **Nothing gets worse on failure.**

A context whose peer name cannot be read is refused outright rather than taken over: without it
there is no SNI and no name to verify against, and a takeover that skipped verification would be
far worse than not taking over at all. `tools/gatetest.sh` asserts that directly — a fresh
process's first request to `expired`, `wrong.host` and `untrusted-root` `badssl.com` must still
be rejected, alongside the assertion that its first request to `api.twitter.com` succeeds and is
carried at TLS 1.3.

**The one piece that cannot be read is a client certificate.** `SSLSetCertificate` refuses a
sentinel array (`-50`), so its slot cannot be calibrated the way the callbacks are, and there is
no getter. A context that had an identity set before the library arrived is therefore taken over
without it, and if the server demands a client certificate that first connection fails. It is
confined to a process's very first TLS connection presenting a client certificate — and
CFNetwork normally sets an identity only in response to a server's request, which is a later
connection, by which time the hooks are installed and the identity is captured properly.

### Recovery

A `stop()` that is never released is the one failure this design can cause that a poller cannot.
The mitigations are layered so that no single one has to be perfect (`tools/aqguard.c`):

| layer | covers |
|---|---|
| **watchdog** | releases any hold older than `gate-hold-ms` (default 250) regardless of what the injection is doing. Its table is pre-allocated and its release path allocates nothing, so memory pressure cannot prevent a release. |
| **journal** | every hold is written to `held.journal` before the process leaves its kernel stop and cleared after the thread resumes, so a daemon that dies mid-hold leaves an exact record. Replayed at startup, and only when its boot session id matches. |
| **suspend-count scan** | a Mach hold outlives its suspender but is visible as `thread_basic_info.suspend_count > 0`. Reported always; acted on only when the journal could not do its job. |
| **blind `SIGCONT` sweep** | a kernel stop whose record was never drained is *not* visible — such a process reports `p_stat == SRUN`, indistinguishable from a running one. So the sweep does not try to find it: it signals everything that is not genuinely `SIGSTOP`ped, which is a no-op on a running process. Measured at 0.45 ms over 271 processes. |
| **armed stamp** | if the previous boot armed the gates and never reported healthy, the next start comes up gate-disabled. A gate-induced hang can happen at most once. |

**Every exit path from the suspend onwards reaches the release.** Injection failure, target
death, an unexpected `kern_return_t` — all release the thread and let the process run unpatched.
Failing open is correct: a wedged process is worse than an unpatched one.

**Force quit always works.** A process with a suspended thread dies to `SIGKILL` *and* to plain
`SIGTERM`, so a wedged application behaves like any other beachball and the user's normal escape
hatch is intact. `tools/gatetest.sh` asserts this directly.

The one deliberately narrowed layer is the suspend-count scan. Measured on an untouched 10.9.5
machine, `coresymbolicationd` and `xpcd` each park a thread with `thread_suspend` as a matter of
course — so resuming every suspended thread on the system would set another program's thread
running at a moment it deliberately chose to stop it, at every boot, to recover from something
that has not happened. It therefore reports always and resumes only when the journal was
unavailable, or when `gate-resume-suspended` asks it to.

### The exclusion list

Boot-hang exposure is handled by **never latching a set of named processes**, not by deferring
when the gates arm. There is no time floor and no "wait until the system looks up" check: both
are timing-dependent, and a race is exactly what must not sit underneath a mechanism that can
freeze a process. A name comparison in a D predicate is deterministic, inspectable and testable.
The gates are armed as soon as the daemon starts, and a daemon that fails to start at all is
safe by construction — no probe is enabled, so nothing can freeze.

**`execname` truncates to 15 characters**, and this is where the list can silently die. A process
named `securityd_service` reports `execname` as `securityd_servi`. This is *not* the 16-character
`MAXCOMLEN` truncation that applies to `kinfo_proc.kp_proc.p_comm` — it is a different code path,
and a predicate written as `execname == "securityd_servic"` compiles, runs, and **matches
nothing**, freezing and injecting the daemon it was written to skip, with no error anywhere.

So no name is ever written out pre-truncated. The daemon **measures** the limit at startup — it
execs a copy of a harmless binary under a deliberately over-long name and reads back what DTrace
says `execname` was — and truncates the configured full names itself when generating the `BEGIN`
block. If the limit cannot be established, the exclusion list cannot be trusted, so the daemon
comes up **gate-disabled** rather than arming a predicate that may be dead. That also means the
15 above is re-derived per machine and per OS version rather than assumed.

`pid > 1` is in every predicate, so launchd is never frozen; the daemon and its own injection
helper are in the deny list, because they would have nobody to release them.

### The log

`/var/log/aquatransport.log`, root-owned, `0600`, bounded and truncated in place while running.
It carries one line per process that takes the library — about 32 over a session — plus the
three signals that say whether the safety net is load-bearing: **every release the watchdog
forced, every sweep that released anything, and every drop reported by libdtrace**. A drop is by
definition a process frozen with nobody holding its pid, so it also triggers a sweep.

That log is only worth reading if it is quiet when nothing is wrong, so the outcomes that are
expected rather than wrong stay out of it. A target that exits part-way through is the ordinary
end of many injections, and it is distinguished from a fault at each point it can happen: no task
port, no dyld startup, a failed `mach_vm_write`, a failed `thread_create_running`. A process that
is merely quitting answers `kill(pid, 0)` exactly as a running one does, so the liveness test
reads `p_stat` and treats a zombie as gone, and a failed `task_for_pid` is retried briefly before
being believed.

### Cost

Measured on 10.9.5, x86_64, against an installed daemon at the default 50 Hz:

| | target | measured |
|---|---|---|
| daemon CPU, idle | ≤ 0.5% of one core | **0.2%** (0.06 s over 30 s) |
| daemon RSS | ≤ 9 MB | **5.1 MB** |
| find the thread + suspend | ≤ 0.1 ms | **0–1 ms** |
| injection, cold | ≤ 8 ms | **1–10 ms**, median ~3 |
| probe overhead per syscall, false predicate | ≤ 0.1 µs | 0.05–0.08 µs |
| private memory per patched process | ~600 KB | 603 KB |

**The stall a gated `connect` sees is dominated by one thing: waiting for DTrace's next buffer
switch.** The daemon's own work is small and nearly constant; the wait for the record is neither.

Decomposed inside the daemon, with the probe's own `timestamp` carried in the gate record and
the D clock calibrated against `mach_absolute_time` in the same run (the two run ~300 ppm apart,
so a calibration from minutes earlier is worthless), at 50 Hz:

| stage | cost |
|---|---|
| probe fires → record drained | **2.1–13.1 ms** |
| drained → picked up by a worker | 0.01–0.42 ms |
| suspend + inject + resume | 1.7–2.3 ms |
| **total, and the connect duration the process measures** | **3.9–15.1 ms** |

A record becomes visible only at the next switch of the principal buffer, and a `connect` arrives
at a uniformly random phase within that interval — so the wait is uniform over one period, and
the whole stall tracks `switchrate` linearly. Measured end to end from inside the connecting
process, 15 samples per rate, daemon settled:

| `gate-rate` | switch period | median | range |
|---|---|---|---|
| 10 Hz | 100 ms | 66 ms | 16–101 ms |
| 25 Hz | 40 ms | 25 ms | 6–43 ms |
| **50 Hz** (default) | **20 ms** | **17 ms** | **6–31 ms** |
| 100 Hz | 10 ms | 9 ms | 5–15 ms |
| 250 Hz | 4 ms | 5 ms | 2–30 ms |

Median ≈ half a period plus ~2 ms of work, worst case ≈ one period plus the same, which is what
the mechanism predicts. So `gate-rate` is a direct latency/CPU dial: at the default the first
connection of a process waits ~17 ms and the daemon costs 0.2% of a core; 100 Hz roughly halves
the wait and roughly doubles the CPU.

**Measure this with the daemon settled.** Taken in the first seconds after it starts, these
numbers are two to four times worse and appear not to scale with the rate at all — the daemon is
gating the launch storm that `launchctl load` itself produced, and the queue is what is being
measured rather than the mechanism.

It is a **one-off cost per process**, paid on its first network syscall and never again: every
later connection in that process takes the fast path. And because the process is frozen for the
whole delay, `switchrate` buys latency, not safety.

### Why libdtrace rather than dtrace(1)

The consumer is linked in, so no process named `dtrace` appears in the process list and an
operator's own interactive DTrace sessions stay distinguishable. It costs what `dtrace(1)` costs,
because that footprint is libdtrace's own.

Three traps, each of which presents as a silently working consumer:

1. **`dtrace_program_strcompile()` truncates.** With a probespec it compiles **one clause** the
   way `dtrace -n` does, enables it, reports a plausible probe count and no error, and drops the
   rest. The daemon uses `dtrace_program_fcompile()` — the `dtrace -s` path — and refuses to arm
   unless `dpi_matches` is at least the number of clauses it generated.
2. **`dtrace_handle_buffered()` yields wrong field values.** It does deliver each `printf()` as
   text, but in testing the `pid` and `tid` fields were wrong — one pid/tid pair repeated across
   three different processes while `execname` varied correctly. The `dtrace_work()` `FILE *` path
   formats the same records correctly.
3. **Output buffering.** The `FILE *` must be line-buffered, or gate records sit in stdio while
   the processes that generated them stay frozen.

`funopen()` is not a workaround for the second: libdtrace writes nothing to a `funopen`-backed
`FILE *`, though records do arrive at the callbacks. The descriptor has to be real, so the daemon
uses a `pipe()` back into itself, with a reader thread parsing records off the other end and a
small pool of workers running the gate — an injection must never stall the drain, because a
stalled drain becomes a dropped record, and a dropped record is a frozen process nobody knows
about.

### Why not the audit pipe

The kernel's BSM audit pipe delivers a record per exec, but on 10.9.5 its subject token
identifies the new process only for `fork`+`execve`. For `posix_spawn` the subject is the process
that *called* `posix_spawn`, the child's pid appears in no token at all (`AUT_PROCESS` and the
`AUT_ARG` pid token are both absent), and the path token is the *child's* executable — so a
`posix_spawn` record pairs the parent's pid with the child's path. Anything driven off it would
inject into the parent while believing it was the child, and would miss every `posix_spawn`
launch, which on 10.9 is nearly every application and XPC service launchd starts.

`proc:::exec-success` has neither problem, and it is the only exec probe that reports the *new*
process: `proc:::exec` reports the **parent's** pid with the child's path on the `posix_spawn`
path, a successful `execve` never returns, and `syscall::fork:return` fires in the parent — where
a `fork` without `exec` needs no injection anyway, because the child inherits the patched address
space.

### Injecting before libSystem is initialized

This is what the gate removes, and it is worth recording because the ordinary injection path
still has to handle it — `gate-off` uses that path, and so does the `aqinject` CLI.

The injector must not touch a target that is still exec'ing, and the condition it waits for has
to be the right one. dyld publishes `infoArray` *as it loads*, so `infoArrayCount` goes positive
early — while dyld is still working, and **before libSystem's initializer has run**. Measured on
10.9.5, a `com.apple.WebKit.Networking` launch spends **14–51 ms** with an image list published
(225 images) and `libSystemInitialized` still false.

Injecting there asks a process whose pthread subsystem is not yet initialized to run
`pthread_create` off a bare mach thread with a hand-built TSD. It fails, and it fails
invisibly: stage 1 gets a non-zero return, stage 2 never runs, no `dlopen` is ever attempted,
and the injector sits out its entire wait and reports a timeout. Sampling a target caught in
this state shows exactly that — the stage-1 bootstrap thread spinning at its `jmp`, no stage-2
thread in existence, and the library unmapped, in a process that is otherwise completely idle.

The condition the payload actually depends on is the one dyld already exposes, so the injector
waits for `dyld_all_image_infos.libSystemInitialized` rather than for a non-empty image list.

**On the gate path that wait becomes a single assertion.** A process sitting in `connect`,
`accept` or `read` finished dyld startup long ago, so a negative answer there is not a target to
wait for — it is something unaccounted for, and the useful response is to say so and let the
process run. The gate path also skips the closing image-list check, which exists to catch a
`dlopen` into an address space an exec is about to replace: the gated thread is suspended, so no
exec can race it, and the check costs 0.135 ms of a hold on a frozen process.

The done flag is polled at **100 µs** on both paths rather than 100 ms, because the target is
frozen for the whole wait; that alone takes a cold injection against a ready target from ~126 ms
to ~18 ms of wall time.

"Timed out" and "dlopen returned NULL" are symptoms rather than causes, so the injector reports
the cause underneath each:

- Stage 1 stores `pthread_create`'s return value in the payload (sentinel-initialised, so
  success is distinguishable from "not reached"), and the injector reports it as an errno.
- Stage 2 calls `dlerror()` when `dlopen` returns NULL and stores the string pointer; the
  injector reads the message out of the target and prints it.

**Nothing waits for `Security.framework`, at any point.** The library sits inert in a process
that never does TLS and starts working the moment one does, so there is no framework to gate on —
which is what lets the gate be about the *network* rather than about what the process has loaded.

### Reaching a target of the other architecture

Resolved dyld-cache addresses and the `pthread_attr_t` layout are both architecture-specific, so
a slice can only inject targets of its own kind. `aqwatch` is one slice, so for the others it
keeps a single `aqinject --helper` running under the other architecture and hands it pids over a
socketpair — one process spawn per boot rather than one per target, which matters because a
`posix_spawn` per injection measured **1.7 ms**, a third of the budget for a whole gated
injection, with the target frozen for every millisecond of it.

It is started on first need rather than at startup: on a machine whose processes are all one
architecture it is never wanted, and the socket carries a pid and a mode, never a path, so
nothing on that channel can name a file to load.

### Flags

`flags.txt` in `/usr/share/aquatransport/` holds one flag per line. The library reads its own
at runtime, on every mtime change:

```
disabled-mtls      # hand client-certificate connections back to the system stack
debug              # log handshakes to the system log, tagged AquaTransport
allow-legacy-tls   # negotiate TLS 1.0/1.1 and the legacy suites, and let a refused
                   # connection be retried on the system stack
```

### What the engine will negotiate, and the one flag that changes it

The package exists so that an old machine gets modern TLS, so the default is modern TLS and
nothing else:

| | default | with `allow-legacy-tls` |
|---|---|---|
| protocol | TLS 1.2, TLS 1.3 | TLS 1.0 – 1.3 |
| cipher suites (≤1.2) | `HIGH:!aNULL:!eNULL:!EXPORT:!3DES:!RC4:!MD5:!PSK:!SRP` | `ALL` |
| security level | 1 — a floor under key sizes, notably DH ≥ 1024 bits | 0 — no floor at all |

Measured against `badssl.com` with the defaults: `tls-v1-0` and `tls-v1-1` refused, `tls-v1-2`
accepted; `3des`, `rc4`, `null` and `dh512` refused; `dh1024` accepted, which is where security
level 1 puts the line. Every ordinary host is unaffected.

**Security level is what puts a floor under key sizes**, and it is the reason level 0 is not the
default any more. A cipher list says which suites may be negotiated; it says nothing about the
size of the Diffie-Hellman group the server picks. At level 0 there is no minimum, so an engine
advertising TLS 1.3 could still be talked into a 512-bit group — the Logjam case. Level 1 sets
that floor at 1024 bits.

`allow-legacy-tls` is read **per connection**, so editing `flags.txt` applies to the next
handshake rather than the next reboot, and it is set on the `SSL` rather than the `SSL_CTX` so
turning it off again needs no restart either. It exists for a server the defaults will not talk
to — an appliance or an intranet host still on TLS 1.0 — and it gives up exactly what the
defaults buy.

**The same flag also decides whether a refusal is final**, because that is the same question
asked from the other end. By default it is: CFNetwork retries a failed handshake, and answering
that retry with the system stack would let a server this engine just rejected be accepted a
moment later, so the weakest stack on the machine would get the last word on every security
decision this one makes. That is not theoretical — it is what made Qualys' client test report
this machine as Logjam-vulnerable while simultaneously reporting TLS 1.3: the engine refused the
512-bit-DH probe, and Secure Transport completed it on the retry.

Splitting the two into separate flags was a mistake worth naming, because the combination that
looks most cautious is the one that is not: refusing to negotiate an obsolete protocol while
still permitting the system stack to negotiate it on the retry reaches the server anyway, on
worse terms, and reports nothing. So there is one flag. Either an obsolete server is worth
reaching or it is not.

The fallback half is only observable when the caller retries **on the same `SSLContext`**.
CFNetwork does that on some paths and not others, so a single synchronous request shows no
difference either way; the debug log names which behaviour is in force on every refusal.

and the daemon reads these **once, at startup** — the D program is compiled when it arms, so a
changed rate or exclusion means `launchctl unload` and `load`, and pretending otherwise by
re-reading the file would be worse than saying so:

| flag | effect |
|---|---|
| `gate-off` | arm nothing; load the library at exec instead. The escape hatch — it reopens the window the gate closes, which is why it is not the default. |
| `gate-rate=<n>hz` | how often gate records are collected (default `50hz`) |
| `gate-hold-ms=<n>` | watchdog deadline for one hold (default 250) |
| `gate-never=<name>` | never gate a process with this executable name |
| `gate-inetd=<name>` | this executable is handed an already-connected socket |
| `gate-resume-suspended` | let the suspend-count scan resume every suspended thread it finds, not only the ones it can attribute |
| `gate-test-stall-ms=<n>` | stall the injection deliberately. Only `tools/gatetest.sh` sets it: a 2–6 ms window cannot be raced reliably, so the watchdog, journal and kill-safety cases arrange it instead. |

`gate-never` and `gate-inetd` take **full** executable names. The daemon truncates them to what
`execname` actually reports when it generates the `BEGIN` block; an operator must never have to
count characters.

`tf_flag()` (`aquatransport_config.c`) reports whether a name is a line in `flags.txt`;
`selftest.sh` exercises the mechanism through `debug`. To stop the engine entirely, uninstall
it — the library stays loaded in processes that already have it, so removing the file is not a
way to turn it off.

`install-macos.sh` updates the dylib with `rename(2)`, never an in-place write, so a load in
progress never sees a partially written file.

## How the hooks are installed

Both subsystems rebind symbol pointers by name with fishhook (`deps/fishhook/`).

Rebinding rewrites call sites rather than function bodies, so the "function too small,
clobbers adjacent memory" failure that makes `SSLClose` unsafe under body-patching schemes
cannot occur. The property that carries the injector work is this: **rebinding does not
require the library to be present at process launch.** A library that arrives late — via
`dlopen`, or loaded into a process that is already running — installs these hooks just as
well. That is what makes `aqinject`/`aqwatch` possible.

Measured on 10.6.8 and 10.9.5, `i386` and `x86_64`: a `dlopen`ed image successfully rebinds
CFNetwork's calls into Secure Transport *after* those symbols have already been bound and
used. Both frameworks live in the dyld shared cache, and the cache does not prevent it.

Two consequences for anyone editing `src/mac/aquatransport_hooks_mac.c`:

- **Never call a hooked function by name from that file.** fishhook rebinds the symbol in
  every loaded image including our own, so `SSLHandshake(c)` lands back in the replacement
  and recurses until the process dies. Call through the `o_SSLHandshake` pointer. For the
  same reason, `dlsym(RTLD_NEXT, ...)` resolves back to the replacement and must not be used.
- **The `o_*` originals come from `dlsym(RTLD_DEFAULT)`, not from fishhook's `replaced`
  output.** fishhook reports whatever value was in the symbol slot, and for a lazy symbol
  that has never been called that value is dyld's stub helper rather than the function.
  `dlsym` resolves through the symbol table and is correct whether or not the symbol has
  ever been bound.

`install_ssl_hooks()` decides per process whether to install anything, so a process on the
trust-daemon deny list carries no hooks at all. The per-hook `tf_on()` gate still runs on
every call: `tf_reentrant()` is dynamic and cannot be decided at install time.

## Rules

Blocks separated by blank lines, each beginning with a **scope** line: `*` for every
process, or a comma-separated list of app bundle names. Commas rather than spaces because
executable names contain them (`QuickTime Player`); space around a comma is trimmed. A
trailing `.app` is optional, and the executable name is matched as well as the bundle name.
URLs are always matched as a **prefix**, so the tail and any query string survive. `*` is
the only wildcard (`?` is literal) and works the same in both files. It matches any run of
characters **except `/`**, which is what makes `https://*.wikipedia.org/` cover
`en.wikipedia.org` and `en.m.wikipedia.org` while never spanning a path separator — an
unrestricted star would let `https://*.apple.com/` match
`https://tracker.example/?u=https://cdn.apple.com/x`. Changes are picked up on mtime
change, no restart. Working examples are in `examples/`.

There is no comment syntax. Every non-blank line is part of a rule, so a `#` line is read
as rule content like any other.

`redirects.txt` — scope, from, to. `from` is a prefix, so the tail and query survive; what
a `*` consumed is dropped rather than carried into the replacement:

```
HelpViewer
https://help.apple.com/Library/Documentation/Resources/Flamingo/6/flamingo.js
https://mavericksforever.com/resources/flamingo.js

Pages, Numbers, Keynote
https://configuration.apple.com/configurations/internetservices/iworkapps/RemoteDefaults.plist
https://mavericksforever.com/resources/RemoteDefaults.plist

*
https://api.twitter.com/
https://twb.preloading.dev/
```

`headers.txt` — scope, URL pattern, then headers to set:

```
Dictionary
https://*.wikipedia.org/w/api.php?action=
User-Agent: Something Else
```

Scope matches the process that **issues** the request, which is not always the app you have
in mind. WebKit1 apps load in-process, so `Dictionary`, `HelpViewer`, the iWork apps and
`Twitter` all work. A **WebKit2 app hands its loads to the shared
`com.apple.WebKit.Networking` service**, so a rule scoped to `Safari` will never match —
use `*` for those, or scope nothing and accept system-wide application.

A block too short to hold a scope line is ignored.

Rewriting happens at the request layer, not in the TLS stream, because the interesting
rules change the destination host — and by the time `SSLWrite` runs, CFNetwork has already
resolved DNS and handshaked with the *original* host. At the request layer CFNetwork does
DNS, SNI and certificate validation against the rewritten host, and `http://` rules and
`http`→`https` upgrades work too.

### How the rewriter works, and why it is pure C

**The hooks are installed in every process the library reaches; the scoping is in the rules.**
Nothing about a process decides whether the rewriter is active in it — it is compiled into the
dylib and rebinds CFNetwork functions at runtime, in whatever process has them. What decides
whether a *rule* fires is that rule's own scope line. There is no second, process-level deny
mechanism anywhere in the rewriter, and the reason is the next few paragraphs: no property of a
process is a safe thing to gate on here.

It is pure C, not an Objective-C `NSURLProtocol` bundle, because loading Foundation and the
ObjC runtime into a process that then forks without exec is fatal to the child:

- **`sshd`** — confirmed. libdispatch aborts in the privilege-separation child
  (`BUG in libdispatch`, SIGILL on `com.apple.libdispatch-manager`); every ssh connection
  died. Reproduced on an alternate port, fixed by not loading the bundle, broken again by
  loading it.
- **`loginwindow`** — implicated in a login-keychain unlock failure.

No property-based gate works: "a Foundation symbol is resolvable" is true inside `sshd`, and
"the main executable links Foundation directly" excludes Safari and WebProcess (they reach it
through WebKit) while including `loginwindow`. Excluding processes by name only hides the
fragility — the next thing to break is something nobody thought to list.

Foundation's own URL loading sits on CFNetwork's C API (Foundation imports 69 of those
symbols on 10.9, 53 on 10.6.8), so working there covers `NSURLConnection`, `NSURLSession`
and raw CFNetwork clients while touching no Objective-C, no libdispatch and no Foundation.

**Rebinding rather than interposing.** A `__DATA,__interpose` section only takes effect on
images bound after the interposing library is registered, and dyld registers it only for
libraries inserted at launch. Measured on 10.9.5: the same dylib interposing `getppid`
returns 4242 under `DYLD_INSERT_LIBRARIES`, and changes nothing when `dlopen`ed into a
running process. That rules out static interposing for `aqinject`.

Interposing is also address-based — a tuple names a definition, not a name — so a hook
cannot be installed before the target library is loaded and its symbols are addressable.
Rebinding by name needs nothing loaded, which is what lets the library sit inert in a
process that never does TLS. Processes without CFNetwork have nothing to rebind.

`dyld_dynamic_interpose` would sidestep the first point but not the second, and does not
exist before 10.10: on 10.9.5 it is absent from `libdyld.dylib`, from dyld's
`_dyld_func_lookup` table, and from `dlsym(RTLD_DEFAULT, ...)`.

The hook points come from experiment, not from headers, because these are private API:

| Path | Entry point | Request arg |
|---|---|---|
| synchronous | `CFURLConnectionSendSynchronousRequest` | arg 0 |
| asynchronous | `CFURLConnectionCreateWithProperties` | arg 1 |

The argument positions are the ones found by recording pointers returned from the
request-creating functions and testing the funnel arguments for pointer **equality** — no
guessed pointer is ever dereferenced, so a wrong guess could not crash. Hooks declare six
pointer parameters against real arities of four: passing more arguments than the callee
reads is harmless on both x86_64 and i386, while declaring fewer would make it read
uninitialised registers.

### The one list that remains, and why

`ocspd`, `securityd`, `securityd_service`, `trustd`. That is not "things that happen to break" —
it is a circular dependency: our verify path calls `SecTrustEvaluate`, which those processes
*implement*. A re-entrancy guard (`tf_guard_enter`/`tf_reentrant`, pthread-specific rather than
`__thread` for 10.6) handles the same-thread case; these four are where the cycle crosses a
process boundary.

**One list, in `src/aquatransport_deny.h`, read by both subsystems that need it** — the
library's own gate in `aquatransport_hooks_mac.c`, which matches `getprogname()` exactly, and
`aqwatch`, which turns the same names into a D predicate against `execname`. They must match
differently (the kernel truncates `execname`, `getprogname()` is not truncated), which is why
the header carries **full** names and each consumer derives its own form. A name written out
pre-truncated in one place and not the other is precisely the silent failure the header exists
to prevent.

**The library's gate is the real backstop.** `process_eligible()` runs *inside* the target: loaded
into a trust daemon by any means, the library installs no hooks at all. The daemon's predicate is
defence in depth — what it actually buys is not freezing and injecting a critical daemon for no
benefit.

Processes an operator wants kept away from the *gate* for their own reasons are a different
mechanism with a different meaning: `gate-never=<name>` in `flags.txt`.

Anything else misbehaving under injection is a bug in the engine to fix, not a name to add.

## The I/O contract

`SSLRead` and `SSLWrite` are replaced, so what they *answer* is part of the interface, not an
implementation detail. CFNetwork's socket streams are written against Secure Transport's
answers exactly, and a plausible-looking substitute is not good enough: a status that differs
from what the stock stack returns in the same state fails the whole stream rather than
degrading.

The failure has a shape worth recognising, because it hides from ordinary use. A request whose
body fits in the socket send buffer never blocks, so it never reaches the interesting states at
all — every GET, and every small POST, behaves identically under any of these answers. Only a
body large enough to fill the send buffer gets there, which puts the boundary between a 10 KB
upload and a 200 KB one, and makes "browsing works" say nothing about whether the contract is
right.

So the contract is measured rather than reasoned about. `tools/writecontract.c` and
`tools/readcontract.c` drive Secure Transport with I/O callbacks of their own that they can
starve on demand, putting the transport in each state that matters and recording what comes
back. Run against the stock stack they produce the reference answers below; run against the
engine they must produce the same ones. `selftest.sh` runs both ways and diffs, so the
assertion is "matches Secure Transport" rather than numbers someone once wrote down.

### Writing

| state | status | `*processed` |
|---|---|---|
| data offered, transport blocks | `errSSLWouldBlock` | **= `dataLength`** |
| zero length, still blocked | `errSSLWouldBlock` | 0 |
| zero length, transport free | `noErr` | 0, queue drained |
| data offered, queue still full | `errSSLWouldBlock` | **0**, data refused |

The first row carries the rest. A blocked write takes the caller's **whole buffer** into the
context's own queue and says so, which makes `errSSLWouldBlock` mean *"I am holding it, come
back"* rather than *"I did nothing"*. Reporting no progress on data the caller has not been
relieved of is the one answer it cannot act on.

Three consequences follow, and each is load-bearing:

- **The retry is zero-length.** The caller advances by `*processed`, and `*processed` was the
  whole buffer, so there is nothing left to re-present. Its next call is a pure flush — which
  is why a zero length must never reach `SSL_write`, whose zero-length return reads as an
  error and would abort a connection that is merely being flushed.
- **Refusing new data while the queue is full is the backpressure**, and it is what bounds the
  queue at one call's worth. Nothing more is accepted until it drains, so no amount of upload
  becomes an in-memory copy of the body.
- **The retry needs `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`.** The queue is our copy, so a
  resumed `SSL_write` presents the same bytes at a different address; the mode permits exactly
  that, and the length only ever grows, which is the part no mode relaxes.

`bio_bwrite` asks the caller's write callback **at most once per entry**, matching
`sslIoWrite`, which makes exactly one `ioCtx.write` call and returns what it says. OpenSSL's
record layer would otherwise loop against a transport that has already reported would-block.
The latch clears on each entry — a write, a read, or a handshake — since that is the point at
which the caller has decided the socket is worth trying again.

Nothing here waits on the socket. The caller comes back on its own, exactly as it does with the
stock stack, so a large upload costs the connections sharing its run loop nothing.

### Reading

| state | status | `*processed` |
|---|---|---|
| anything transferred | `noErr` | what was transferred, short or not |
| nothing available | `errSSLWouldBlock` | 0 |
| zero length asked | `noErr` | 0, transport not touched |

The status reports **progress, not fullness**. A short read is `noErr`, and the bytes left over
are not lost to the caller: they are held here and `SSLGetBufferedReadSize` reports them. Those
two halves are one mechanism — a short `noErr` is only safe because that hook answers
truthfully, and the hook is only worth answering because short reads are normal. `SSL_pending`
alone would under-report it, since bytes pulled off the socket but not yet decrypted are
invisible to it; `SSL_has_pending` covers both kinds, which is what the question is asking.

One record per call is what comes back, which is both what the stock stack returns and what
`SSL_read` yields. Filling the caller's buffer from further records would be legal, since the
status says progress rather than fullness, but it would answer differently from the stack being
replaced and buy nothing: the bytes it delivered early are reported by `SSLGetBufferedReadSize`
and collected by the next call, which the caller makes either way.

An end of stream or an error reached *after* some bytes is not allowed to swallow them: the
data is handed over with `noErr` and the condition surfaces on the next call, once there is
nothing left to deliver first.

### The one thing that does not match, and why it cannot

Every status and every `*processed` above matches the stock stack. What does not is how many
times the transport is asked, in one case: reading a response, the engine calls the read
callback four times where the stock stack calls it twice.

That is not the read path. It is **TLS 1.3**. The stock stack cannot negotiate it and lands on
1.2, where session tickets arrive inside the handshake; the engine negotiates 1.3, where the
server sends `NewSessionTicket` as post-handshake records that are read on the application
path. Two tickets, arriving inline, are the extra reads — visible in the debug log as two
`session cached` lines during the first read.

Capping the engine at `TLS1_2_VERSION` collapses the count to 2, matching stock exactly, which
is what says the read logic is not responsible. Removing the difference means giving up TLS
1.3, which is the reason this engine exists. So `selftest.sh` compares the statuses and
`*processed` and drops the callback counts — and the byte totals with them, which differ by
record overhead for the same reason.

### Sizes

`dataLength` is a `size_t` on both entry points and Secure Transport documents no limit on it,
fragmenting into records internally. `SSL_read` and `SSL_write` take an `int`. So a caller's
buffer is transferred in runs of `IO_RUN_MAX` rather than handed over whole, and any length
works. CFNetwork never exposes this — it chunks at 32 KB whatever the body size — so only a
direct Secure Transport caller reaches it, which mail clients and other socket-level code are.
`tools/bigbufprobe.c` covers both directions: a megabyte through one `SSLWrite`, and an
`SSLRead` buffer whose length does not fit in an `int`.

## What a trust evaluation costs

`SecTrustEvaluate` is the single most expensive thing on a connection. Where a chain's issuer
CRL is already cached, a profile puts it in `mulg`, `modg_via_recip`, `grammarSquare`,
`gshiftright` — Security.framework's CryptKit "giants" bignum routines, verifying the chain's
signatures in software. That part is local arithmetic, not a bloated trust store (211 roots)
and not IPC (`securityd` and `ocspd` sit at 0% CPU while it runs), and it reproduces in a
clean process with no library loaded. Where the issuer CRL is *not* cached, a synchronous
download dominates instead, and the profile moves to `tpFetchCrlFromNet`.

Two things drive it. One is signature verification, which varies by chain: measured by
`tools/trustbench.c`, an RSA-2048 chain (`www.gnu.org`) evaluates in 20 ms where an ECDSA one
(`github.com`) takes 486 ms. The other is revocation checking, covered in the next section,
which adds a fixed overhead to every evaluation and a large one-off cost per issuer. The
multi-second stalls come from revocation rather than from the signature algorithm, so they
happen on RSA hosts as readily as ECDSA ones.

**Nothing about it is cached, anywhere.** `trustbench` re-evaluates the same `SecTrustRef` a
second time and it costs the same as the first (461 ms vs 464 ms on Wikipedia's chain); a
fresh object over identical certificates costs the same again. There is no warm-up to exploit
and no result to reuse, so the only saving available is not asking twice — which is what
*Trust evaluation, once per connection* and *The verified-chain cache* below do.

Whatever remains is a floor, not something this engine can optimise away. The OpenSSL linked
into this library does the same arithmetic roughly two orders of magnitude faster, but
CFNetwork evaluates the `SecTrustRef` handed back to it, so a real `SecTrustEvaluate` has to
happen somewhere.

## Revocation checking

Trust evaluation on 10.9 checks revocation by "best attempt", through Security's legacy CSSM
path. The engine leaves it there: it builds each `SecTrustRef` with the SSL policy alone and
sets no revocation policy of its own.

That is a deliberate choice, because naming an explicit revocation policy turns the check off.
`tools/crltest/` demonstrates it with a private CA, two leaves — one of them revoked — and a
CRL published at the leaf's distribution point on localhost. Nothing is installed: the CA is
made an anchor with `SecTrustSetAnchorCertificates` for one `SecTrustRef` in one process, so
no keychain and no system trust store is involved.

| certificate | policy | verdict |
|---|---|---|
| good | SSL policy alone | ACCEPTED |
| **revoked** | **SSL policy alone** | **REJECTED**, and the CRL is fetched |
| revoked | explicit `CRL` | ACCEPTED |
| revoked | explicit `OCSP\|CRL` | ACCEPTED |
| revoked | explicit `OCSP` | ACCEPTED |

Reproduces 3/3 each way. CRL checking on this platform works: the legacy path fetches the CRL
and rejects the revoked certificate, while every explicit revocation policy — including one
naming `kSecRevocationCRLMethod` — skips the fetch and accepts it. There is no combination
that keeps the check and avoids the cost.

The cost is real, and it is the largest remaining one on a connection. Staying on the legacy
path is about 1.7x slower per evaluation whether or not any revocation data exists:
`github.com`'s issuer publishes no CRL distribution point at all, so no CRL work is possible
there, and it still costs 540 ms against 320 ms under any explicit policy. On top of that, a
CRL that is not yet cached is fetched synchronously inside `SecTrustEvaluate`, on whichever
thread asked — a DigiCert chain costs **911 ms against 32 ms**, the whole difference being one
download. A machine in ordinary use accumulates **81 MB across 66 issuers in `/var/db/crls`,
one file of 46 MB with 987,186 entries**. A CRL already cached is cheap to consult (Amazon and
GoDaddy chains evaluate in 7–8 ms), so the download is a per-issuer cost rather than a
per-evaluation one.

Where the asking thread is a browser's shared networking process main thread, one uncached CRL
stalls every connection that process has at once. That is a property of the caller, not of the
engine; see *Where the evaluation happens* below.

### What revocation does not cover

Revocation status is undetermined for a growing share of the web, and this is upstream of the
OS rather than a property of the engine. **Let's Encrypt and Google Trust Services no longer
publish OCSP**: their leaves carry a CA Issuers URI and no responder URI. The only
channel left for those certificates is the CRL in their distribution point, and 10.9 does not
fetch it — zero packets to the distribution point, and nothing from those issuers anywhere in
`/var/db/crls`.

`tools/revcheck.c` shows the consequence on `revoked.badssl.com`, a genuinely revoked,
unexpired Let's Encrypt certificate: every policy 10.9 offers accepts it, including
`kSecRevocationRequirePositiveResponse`, whose whole purpose is to turn "could not determine"
into a rejection. Its CRL is current, 37 KB, lists the serial, and downloads in 55 ms; it is
simply never requested.

The two halves line up: every issuer whose CRL 10.9 fetches also publishes OCSP, and every
issuer that has dropped OCSP is one whose CRL it does not fetch. So revocation is checked for
traditional CAs and unchecked for the modern ones, and no configuration available at this
layer changes that.

## Trust evaluation, once per connection

CFNetwork calls `SSLCopyPeerTrust` on *every request*, not once per connection, and a fresh
`SecTrustRef` built from freshly created `SecCertificateRef`s costs a full evaluation each
time — the system's own caching never sees the same object twice. So the `SecTrustRef` has to
be kept off the per-request path. This is the cost that matters most in practice: a browser
loads dozens of small subresources over a handful of pooled connections, so nearly all of its
requests are warm ones.

The peer chain cannot change within a connection, so neither can the trust decision.
`sh_build_trust` builds the `SecTrustRef` once and caches it on the `Shadow` for the life of
the connection, with each caller still getting its own reference (`SSLCopyPeerTrust` has copy
semantics). The cache is dropped whenever the `SSL` object is re-initialised — late SNI, or
`SSLSetCertificate` — because that means a new handshake and a new chain.

### The object is handed back unevaluated

`sh_build_trust` returns the `SecTrustRef` without evaluating it. Exactly one evaluation of a
chain then happens per connection: `verify_chain`'s on the plain path, or CFNetwork's own on
the app-verified path, which is the one CFNetwork takes on nearly every connection.

Evaluating here as well would be pure duplicated cost on the connection's critical path —
hundreds of milliseconds for a chain whose issuer CRL is cached, and most of a second for one
whose is not:

- **The result would not be the security decision.** That belongs to `verify_chain` or to
  CFNetwork's evaluation of the object; a result computed here is read by nothing.
- **It could not be reused for CFNetwork's evaluation either.** CFNetwork calls
  `SecTrustSetKeychains` on the object immediately before evaluating it, which invalidates any
  result already recorded on it.
- **Nothing needs the object pre-settled.** `tools/trustbench.c` calls
  `SecTrustCopyExceptions` and `SecTrustGetCertificateCount` on a trust that has never been
  evaluated: both succeed, because Security evaluates on demand underneath them.

Measured on 10.9.5, x86_64, 12 parallel requests across 12 cold hosts (`tools/concprobe.m`),
against the same engine evaluating in `sh_build_trust` as well, three runs each:

| | first round, all connections cold |
|---|---|
| Two evaluations per connection | 7.50 s / 7.59 s / 7.33 s |
| **One evaluation per connection** | **3.89 s / 3.90 s / 4.18 s** |

and on 10 pooled warm requests over one connection (`tools/poolprobe.m`), where the single
remaining evaluation is CFNetwork's own and the engine is at parity with the stock stack:

| | wall | CPU |
|---|---|---|
| Native Secure Transport | 0.97 / 1.08 / 0.92 s | 0.51 s |
| **AquaTransport** | **1.00 / 1.19 / 0.90 s** | **0.49 s** |

### Where the evaluation happens

The one remaining evaluation runs wherever the caller asks for it, and for a browser that
placement dominates everything else. WebKit forwards each server-trust challenge to the UI
process; encoding the `NSURLProtectionSpace` for that IPC archives the `SecTrustRef`, and
archiving one evaluates it:

```
WKNetworkSessionDelegate URLSession:task:didReceiveChallenge:
  -> NetworkLoad::didReceiveChallenge
    -> AuthenticationManager::didReceiveAuthenticationChallenge
      -> IPC encode of NSURLProtectionSpace
        -> SerializableArchive::add(CFString, __SecTrust*)
          -> SecTrustEvaluate
```

That path runs on the shared networking process's **main thread**, so every connection's
evaluation serialises behind every other one, and an uncached CRL fetch inside one of them
stalls the whole browser. Sampling `com.apple.WebKit.Networking` during a cold page load puts
874 samples there. Nothing in this engine can move it; the placement belongs to the caller.

## The verified-chain cache

One evaluation per connection is what the stock stack costs too. What is avoidable beyond that
is re-verifying a chain this process has *already* verified: a browser opens several
connections to one host at once, and every one of them runs `verify_chain` over an identical
chain.

`aquatransport_engine.c` keeps a 32-entry cache keyed on the peer name and a SHA-256 over the
chain's DER, with a 10-minute TTL. `verify_chain` consults it before calling
`SecTrustEvaluate` and fills it after a success. Measured on `en.wikipedia.org`, six
connections in one process: the first `verify_chain` costs 481 ms and the rest are free.

Two properties keep it from becoming a way round a rejection:

- **Only successes are cached.** A chain that fails evaluation is never recorded, so it is
  re-examined at full price on every connection. Nothing an attacker presents can be answered
  from this cache.
- **The key covers everything the decision depends on** — the peer name the handshake is
  bound to, and every certificate the server sent, in order. A different chain, or the same
  chain for a different host, misses.

The TTL bounds how long a newly-expired or newly-revoked certificate could ride a cached
success, which is the same order of exposure a resumed TLS session already carries.
`selftest.sh` asserts the security property directly: `expired` and `untrusted-root`
`badssl.com` must be rejected on all four of four connections in one process, and a valid host
immediately followed by `wrong.host.badssl.com` must not carry its success across.

**Once per connection is what Secure Transport itself does**, measured rather than assumed.
Native CPU, same host:

| | user CPU |
|---|---|
| 1 connection × 6 requests | 0.595 s |
| 1 connection × 12 requests | 0.644 s |
| 6 connections × 1 request | 2.164 s |

Doubling the *requests* on one connection costs nothing; going from one *connection* to six
costs +1.57 s, about 314 ms each. The stock stack evaluates once per connection, and the engine
matches it: one `SecTrustEvaluate` per connection, CFNetwork's own. The verified-chain cache
above goes one step further within a process, for repeats of a chain already verified there.

Only `poolprobe` can see the per-request half of this. Every other harness here forces a new
connection per request (`multiprobe` sends `Connection: close`, and `CFReadStream` does not
pool at all), which buries a per-request evaluation under handshake and network time.
`selftest.sh` asserts the evaluation count rather than timing it, so a regression shows up as a
count rather than as noise.

## Session resumption

Secure Transport keeps a session cache, so the engine keeps one too. Without it every
connection pays a full handshake where the stock stack resumes — an extra round trip against a
TLS 1.2 server, plus the certificate chain and its signature checks, on every connection. A
browser opens a lot of connections to the same host, so this dominates everything else in the
engine.

`aquatransport_engine.c` keeps a 32-entry LRU cache of `SSL_SESSION`s, filled from
`new_session_cb` and offered by `ossl_init` through `SSL_set_session`. OpenSSL checks the
session's own validity and falls back to a full handshake if it has expired or the server
declines it, so nothing here reasons about lifetime.

The key is the caller's `SSLSetPeerID` blob, recorded by the hook of the same name — which is
what Secure Transport keys its own cache on: "data, opaque to this library, which is sufficient
to uniquely identify the peer of the current session. An example would be IP address and port"
(`SecureTransport.h`). CFNetwork passes `{<address>:<port>}<hostname>`.

A hostname on its own is not a safe key, because it does not separate two servers reached at
the same name on different ports. `https://www.ssllabs.com/` and the 512-bit-DH server at
`https://www.ssllabs.com:10445/` are one such pair: keyed on the name, the first server's
session was offered to the second, which risks resuming onto a configuration that connection
never validated. The peer id separates them, and the debug log shows the second connection as
a `session MISS`.

A connection whose caller set no peer id is neither cached nor resumed. The same header calls
`SSLSetPeerID` "mandatory if this session is to be resumable", so this matches stock, and with
nothing identifying the endpoint there is no key that can be trusted to name it.

Measured on 10.9.5, x86_64, 40 sequential connections to `www.cloudflare.com` each forced onto
a fresh connection (`tools/multiprobe.c`):

| | mean per connection |
|---|---|
| Native Secure Transport | 429 ms |
| **AquaTransport** | **129 ms** |

The first connection to a host costs ~450 ms; every one after it lands at ~82 ms. Bulk
throughput is unaffected (20 MB download: 2007 ms vs 2175 ms native), which is what says the
per-call read/write path is not worth optimising — resumption is where the time is.

Two things the cache deliberately does not do:

- **Connections carrying a client certificate are never cached or resumed.** The key does not
  include the identity, so a resumed session could otherwise carry an identity the caller did
  not choose for this connection. mTLS connections are rare and a full handshake for them
  costs nothing anyone will notice.
- **It does not weaken validation.** Resumption skips the certificate message, so
  `verify_chain` does not run on a resumed connection — correct, and what every TLS client
  does, since a session only enters the cache after a handshake that already verified. The
  app-verified path is unaffected too: the chain lives on in the `SSL_SESSION`, so
  `SSLCopyPeerTrust` hands CFNetwork the same certificates to evaluate on a resumed
  connection as on a fresh one. `selftest.sh` asserts this directly — three connections to
  `wrong.host.badssl.com` and `expired.badssl.com` in one process, with a warm cache, must
  all be rejected.

`flags.txt`, `redirects.txt` and `headers.txt` are still re-read when their mtime changes, but
that check is throttled to once a second. Unthrottled it costs a `stat()` for each rule file on
every HTTP request and a full open/read of `flags.txt` on every connection presenting a client
certificate; a second is far below the granularity at which anyone edits these files.

## Platform notes

**Trust is the OS's job.** OpenSSL does the crypto; `SecTrustEvaluate` or CFNetwork makes
the decision, against the live system trust store. 10.6.8 validates modern chains
correctly once modern roots are installed, so no OpenSSL-side verifier is needed. A stock
10.6 has no modern roots — install them first or everything looks broken.

In practice CFNetwork sets `kSSLSessionOptionBreakOnServerAuth` on nearly every
connection, so the app-verified path (`sh_build_trust` → CFNetwork evaluates) is the
common one, not an edge case for pinning apps.

**mTLS.** `SecKeyRawSign` and `SecKeyDecrypt` exist on both 10.6 and 10.9 (exported but
absent from the OS X headers, so declared in `aquatransport.h`), so the private key never
leaves the keychain. RSA identities only; anything else falls back to the system stack
(`capture_identity`).

Both RSA padding modes are supported, and both are needed. OpenSSL picks the
`CertificateVerify` algorithm from what the server offers without consulting what our
`RSA_METHOD` can do, and `rsa_pss_rsae_*` precedes `rsa_pkcs1_*` in the modern defaults;
TLS 1.3 permits nothing but PSS. A PKCS#1-only signer would fail against most current
servers and every 1.3 one. `SSL_set1_client_sigalgs_list` could force PKCS#1 instead — the
iOS original does exactly that — but it gives up TLS 1.3 client certificates altogether.

So `rsa_seckey_priv_enc` handles `RSA_NO_PADDING` as well, where OpenSSL has already built
the PSS block and wants only `m^d mod n` over it. That raw operation is `SecKeyDecrypt` with
`kSecPaddingNone` — an RSA private decrypt without padding is the same modular exponentiation
as a raw sign — which takes exactly one block.

`SecKeyRawSign` cannot serve here: **its `kSecPaddingNone` is not a raw operation on OS X.**
It still applies PKCS#1 v1.5 padding, so a full-block input comes back
`errSecInputLengthError` (on 10.9.5, inputs up to blocksize−11 are accepted and anything
larger fails). "None" there means no DigestInfo, not no padding.

`tools/pssprobe.c` measures all of this on a live machine: it builds the same public-only
RSA with the same custom method, signs through EVP the way OpenSSL's CertificateVerify does,
and verifies against the plain public key. On 10.9.5 both padding modes verify, and 4000 PSS
signatures produced no failures. The short-block guard in that function (right-align and
zero-fill) is defensive: 10.9 always returns a full block, and it does not fire across those
4000. It is there because a raw result carries a leading zero byte about 1 time in 256, and
OpenSSL uses the returned length verbatim as the signature length, so a CSP that trimmed to
the minimal-length integer would produce an intermittently malformed signature.

One caveat this cannot test with a generated key: keychain ACLs distinguish *sign* from
*decrypt* authorisation. An identity whose ACL grants signing but not decryption would fail
the PSS path, and possibly prompt. Ordinary `.p12` imports grant both.

No version cap on client-certificate connections. `tls_prepare_client_certificate()` is
version agnostic in OpenSSL — it calls `client_cert_cb` for TLS 1.3 as well, and honours the
same `-1` → `SSL_X509_LOOKUP` suspend, so the pre-approval pause survives at every version.
`tools/mtlsprobe.c` drives it end to end against a local `s_server` requiring a client
certificate; verified at TLS 1.0, 1.2 and 1.3, with the server confirming the client
certificate each time. `disabled-mtls` is the escape hatch.

**OpenSSL 3.5.** The current LTS, supported to 2030-04. The engine's floor is TLS 1.0: a
legacy server that stock Secure Transport can reach must stay reachable through the engine,
since anything less is worse than not installing at all. Two settings carry that.

Security level 0 permits the legacy suites but does not offer them, so
`SSL_CTX_set_cipher_list(gCtx, "ALL")` is what puts them in the ClientHello — without it a
TLS 1.0 server fails on cipher overlap rather than version. And the i386 slice needs
`-DBROKEN_CLANG_ATOMICS`: this era's clang cannot emit the 8-byte atomic in
`threads_pthread.c` ("cannot compile this atomic library call yet"), and that macro is
OpenSSL's own escape hatch, selecting the mutex-backed paths instead.

## Testing on old systems

```
tools/probe-10.6.sh     # no compiler needed on the target
tools/symprobe.c        # runtime dlsym checks -- a stock 10.6 has lipo but no nm/otool
tools/urlprobe.m        # NSURLConnection; 10.6's curl is OpenSSL 0.9.8 and never
                        # touches Secure Transport, so curl proves nothing there
tools/httpsprobe.c      # CFNetwork directly
tools/pssprobe.c        # drives the mtls signing callback against a transient keychain key
                        # and verifies the result; needs the built OpenSSL, see its header
tools/multiprobe.c      # N connections in one process, so cross-connection state (the session
                        # cache) can be tested at all; single-shot probes cannot reach it
tools/trustbench.c      # what one SecTrustEvaluate costs for a given host's real chain, whether
                        # a second one is any cheaper (it is not), and whether an unevaluated
                        # SecTrustRef still answers -- the three facts the trust path rests on
tools/concprobe.m       # a page load's shape: N hosts requested in PARALLEL, so the per-connection
                        # trust cost stacks up instead of hiding behind one request's network time
tools/revprobe.c        # what revocation checking costs an evaluation, per policy, and whether
                        # the system CRL cache grows as a result
tools/revcheck.c        # every revocation policy 10.9 offers, against one host, with the verdict
                        # for each -- including require-positive-response
tools/crlonly.c         # one policy per process, so a cold CRL is not warmed by an earlier run;
                        # revprobe/revcheck cannot isolate that
tools/crltest/          # a private CA, a revoked leaf and a CRL on localhost: does revocation
                        # actually reject? Installs nothing -- the CA is an anchor for one
                        # SecTrustRef via SecTrustSetAnchorCertificates, no keychain touched
tools/poolprobe.m       # N POOLED requests over a reused connection -- the warm path a browser
                        # actually spends its time on, which every other probe here hides
                        # behind handshake and network time
tools/latecheck.c       # loads the dylib into a process with no CoreFoundation/Security, then
                        # brings CFNetwork in afterwards: the no-gate property, end to end
tools/tlsprobe-loop.c   # long-lived cooperating harness: requests api.twitter.com every 2s,
                        # so you can load the library into it with aqinject and watch the
                        # same live process go from FAIL to HTTP 404 without restarting
tools/writecontract.c   # what SSLWrite answers when the transport will not take everything, by
tools/readcontract.c    # starving an IO callback of its own; run against the stock stack these
                        # print the reference answers, and against the engine they must match.
                        # Nothing else here reaches those states: a request small enough to fit
                        # in the socket send buffer never blocks
tools/uploadprobe.c     # a POST big enough to fill that buffer, in-memory body or streamed from
                        # a file, blocking reads or run-loop scheduled -- CFNetwork drives writes
                        # differently in each, and reports peak RSS so a write path that grew
                        # with the body would show
tools/bigbufprobe.c     # the sizes a direct Secure Transport caller may pass and CFNetwork never
                        # does: a megabyte through one SSLWrite, and an SSLRead buffer whose
                        # length does not fit in an int
tools/gatetest/         # the gate's own subjects. Each prints its patched state immediately
                        # before and after the syscall it is meant to be held at, which is the
                        # assertion tools/gatetest.sh automates: patched=0 before, patched=1
                        # after, the syscall successful, no EINTR, payload intact
```

To demonstrate late loading end-to-end on the disposable test VM:

```
# into one already-running process
./tlsprobe-loop &                       # prints FAIL err=-9836 every 2s
sudo ./aqinject $! aquatransport.dylib  # same pid starts printing HTTP 404

# and through the gate, with nothing done by hand
sudo ./install-macos.sh watch
./tlsprobe-loop                         # a NEW process: HTTP 404 on its FIRST request
```

The difference between those two is the whole point. Under the gate the first line is already
`HTTP 404`: the process was frozen at its `connect` and the library was in place before the
handshake could start.

## Coverage

Only apps that use Secure Transport are affected. Apps bundling their own TLS (Chromium
and Electron, Go, current bundled OpenSSL) are unreachable — but they also ship modern TLS
already, so they are not broken. The real gap is software linking the system's OpenSSL
0.9.8, notably Python 2.7's `ssl` module: broken *and* unreachable by this design.

Within that, coverage is "processes that use the network, from their first use of it". A
process that never opens a socket never receives the library, and one that was already running
when the daemon started is covered at its next connection — for something holding a long-lived
one, that may be a long time, and restarting it or rebooting is the remedy.

Re-loading is idempotent — `dlopen` of an already-loaded image returns the existing handle
without re-running the constructor — so a redundant injection, which an eviction from the
confirmed-patched set can cause, costs time and nothing else.

### Known gaps

Both are narrower than the gap the gate closes, and both are documented rather than papered
over.

**Descriptor passing over a unix socket (`SCM_RIGHTS`).** A process handed an already-connected
socket at runtime rather than at spawn is caught by none of the three gates.
`syscall::recvmsg:return`, latched once per thread, is the natural fourth; `recvmsg` is cold
enough that its cost should resemble `connect` rather than `read`. Unlike the inetd case, which
ships with 18 concrete plists, this one is speculative — worth measuring before adding, and only
after finding a case where it matters on 10.9.

**UDP / DTLS.** An unconnected UDP socket uses `sendto`/`recvfrom` with no `connect`. Gating
`sendto` would be expensive and DTLS is close to nonexistent on this platform.
