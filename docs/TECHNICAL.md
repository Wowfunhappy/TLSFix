(Note: The below was written by Claude.)

# AquaTransport for Mac OS X 10.6 – 10.9

Modern TLS for Snow Leopard through Mavericks, by replacing the crypto behind Secure
Transport rather than proxying traffic. Ported from the iOS tweak; the engine
(`src/aquatransport_engine.c`) is shared, the hook layer and URL rewriter are new.

Two independent subsystems in one package:

| Subsystem | What it does | Where it runs |
|---|---|---|
| TLS engine | Routes Secure Transport through OpenSSL: TLS 1.0–1.3, modern ciphers, OS-delegated trust | every process |
| URL rewriter | Applies `redirects.txt` and `headers.txt` at the request layer | apps only (see gating) |

Verified on 10.9.5 (51/51 local tests) and 10.6.8 (`NSURLSession` is 10.9+ and is
skipped there), both `x86_64` and `i386`.

## Build

```
./build-macos.sh          # OpenSSL + dylib + loader tools (aqinject, aqwatch)
./tools/selftest.sh       # per-process tests, installs nothing
```

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
sudo ./install-macos.sh stage      # copy files into place, load nothing
sudo ./install-macos.sh inject     # + load into every eligible running process now
sudo ./install-macos.sh watch      # + a daemon that loads into each process as it launches
sudo ./install-macos.sh uninstall  # remove the daemon, then the files
```

The install spans two directories:

| path | contents |
| --- | --- |
| `/usr/share/aquatransport/` | `aquatransport.dylib`, `flags.txt`, `headers.txt`, `redirects.txt` |
| `/Library/AquaTransport/` | `aqinject`, `aqwatch`, `uninstall.sh` |

The split follows from who reads what. A target `dlopen`s the dylib and reads the rule files
itself, so those reads happen under the *target's* sandbox, and
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
unpatched. `aqinject` and `aqwatch` face none of this — root runs them from outside any
sandbox — so they live in `/Library/AquaTransport`.

Not every sandboxed process is this restricted. `application.sb`, which backs the app sandbox,
carries a blanket `(allow file-read* (subpath "/Library"))`, and WebKit's `WebProcess` and
`NetworkProcess` profiles reach the dylib as well. `/usr/share` is what the whole range of
them share.

The library is loaded into a process by `aqinject` (`tools/aqinject.c`) — `task_for_pid`
plus a hand-built `mach_inject` — using the target's own `dlopen`. It edits no system launch
configuration, so a faulty library is confined to the process it is loaded into and can never
keep the machine or another process from starting.

- **`inject`** loads the library into every eligible process running at the time. It reaches
  GUI apps and daemons alike, and covers what is running when it runs.
- **`watch`** installs `aqwatch` (`tools/aqwatch.c`) as a LaunchDaemon (started at each boot).
  It loads the library into each process as the process launches, so it also covers processes
  started later, with the same per-process confinement as `inject`. This is the recommended
  path to full coverage; run `inject` once alongside it for the current session. See *A
  launch-time watcher* below.

### Loading into a running process (aqinject)

`aqinject` loads the compatibility library into a cooperating process the administrator
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

Injection is therefore unconditional: `--all` walks every process, skipping only pid 0/1 and
the trust-daemon deny list. Verified on 10.6.8 under the older gated build: `--all` loaded into
31 live processes (Dock, Finder, SystemUIServer, coreservicesd among them) with zero crashes.

`inject`/`aqinject --all` cover processes running when they run. To cover processes started
later, `watch` runs the launch-time watcher described next.

### A launch-time watcher (aqwatch)

`aqwatch` loads the library into each process as it launches, giving coverage of
later-started processes with the same per-process confinement `aqinject` has. It polls the
kernel's process list (`proc_listpids`) every 100 ms and treats any pid it has not seen
before as a launch, keeping the seen-set as a bitmap over the pid space so a pid that exits
clears itself on the next sweep. For each new process that is not the daemon itself, one of
its own children, pid 0/1, or a trust daemon, `aqwatch` runs
`aqinject <pid> <dylib>`. In-flight `aqinject`
children are capped and reaped so an app-launch storm cannot fork-bomb the machine. The
deny list is applied to `proc_pidpath` of the pid, so it matches what the process actually
is rather than anything the daemon was told.

**One injection per launch, and a failure is reported rather than worked around.** `aqinject`
waits for the target to be ready and then confirms, by reading the target's own dyld image
list, that the library actually arrived; it exits 0 only then. `aqwatch` acts on that status
and does not try again.

There is deliberately no retry loop and no periodic re-check. Either the injection lands, in
which case repeating it buys nothing, or it does not, in which case the useful response is a
log line naming the pid and the reason — not a schedule of further attempts that would hide
how often the first one misses. Anything that leaves a live process without the library,
including the one path where no injector runs at all (`MAX_INFLIGHT` exhausted), writes a
`NOT PATCHED` line to `/var/log/aquatransport.log` (0600, bounded and truncated in place while
running).

That log is only worth reading if it is quiet when nothing is wrong, so the outcomes that are
expected rather than wrong are classified as such and stay out of it. A target that exits
part-way through is the ordinary end of most injections — every shell command is one — and it
is distinguished from a fault at each point it can happen: no task port, no dyld startup, a
failed `mach_vm_write`, a failed `thread_create_running`. A process that is merely quitting
answers `kill(pid, 0)` exactly as a running one does, so the liveness test reads `p_stat` and
treats a zombie as gone, and a failed `task_for_pid` is retried briefly before being believed.
Measured over ~480 short-lived process launches plus eight forced relaunches of Safari's
networking service: **zero bytes logged**.

### Injecting before libSystem is initialized

`aqinject` waits for the target to finish exec'ing before touching it, and the condition it
waits for has to be the right one. dyld publishes `infoArray` *as it loads*, so
`infoArrayCount` goes positive early — while dyld is still working, and **before libSystem's
initializer has run**. Measured on 10.9.5, a `com.apple.WebKit.Networking` launch spends
**14–51 ms** with an image list published (225 images) and `libSystemInitialized` still false.
`aqwatch` fires the moment a pid appears in the process list, so it lands inside that window.

Injecting there asks a process whose pthread subsystem is not yet initialized to run
`pthread_create` off a bare mach thread with a hand-built TSD. It fails, and it fails
invisibly: stage 1 gets a non-zero return, stage 2 never runs, no `dlopen` is ever attempted,
and the injector sits out its entire wait and reports a timeout. Sampling a target caught in
this state shows exactly that — the stage-1 bootstrap thread spinning at its `jmp`, no stage-2
thread in existence, and the library unmapped, in a process that is otherwise completely idle.

The condition the payload actually depends on is the one dyld already exposes, so
`wait_for_exec` waits for `dyld_all_image_infos.libSystemInitialized` rather than for a
non-empty image list. Measured over eight forced relaunches of Safari's networking process
under the watcher, it is patched in **1–2 s every time**.

"Timed out" and "dlopen returned NULL" are symptoms rather than causes, so the injector reports
the cause underneath each:

- Stage 1 stores `pthread_create`'s return value in the payload (sentinel-initialised, so
  success is distinguishable from "not reached"), and the injector reports it as an errno.
- Stage 2 calls `dlerror()` when `dlopen` returns NULL and stores the string pointer; the
  injector reads the message out of the target and prints it.

Injecting unconditionally means the library goes into every process, including ones that will
never open a socket. That is deliberate: nothing can know in advance which processes will use
TLS, so any filter on that is a guess, and the guess is what left Safari's networking service
permanently unpatched. Measured cost of not guessing, on 10.9.5: **1.65 ms** added to a process
launch (60 launches, 131 ms → 230 ms) and **0.33 ms** per launch to a shell spawning processes
back to back (200 launches, 254 ms → 320 ms, the injection being asynchronous).

The watcher runs from `/Library/LaunchDaemons/org.aquatransport.watch.plist` with
`RunAtLoad`/`KeepAlive`, so it starts at boot and is restarted if it exits. It needs no
system auditing and no auditd.

**Why not the audit pipe.** The kernel's BSM audit pipe delivers a record per exec, but on
10.9.5 its subject token identifies the new process only for `fork`+`execve`. For
`posix_spawn` the subject is the process that *called* `posix_spawn`, the child's pid appears
in no token at all (`AUT_PROCESS` and the `AUT_ARG` pid token are both absent), and the path
token is the *child's* executable — so a `posix_spawn` record pairs the parent's pid with the
child's path.

Anything driven off it therefore injects into the parent while believing it is the child, and
misses every `posix_spawn` launch — which on 10.9 is nearly every application and XPC service
launchd starts. It also cannot see its own injector spawns for what they are, so a daemon that
spawns `aqinject` reads the resulting record as naming itself.

Polling the process list has neither problem: it sees a process however it was created, and
depends on no privileged record format.

Verified on 10.9.5, x86_64: a freshly launched process is loaded into within about 500 ms,
whether it was started by `fork`+`execve` or by `posix_spawn`; at idle the daemon holds no
injectors. Verified on 10.6.8, i386 and x86_64: a freshly launched process goes from
`FAIL err=-9836` on its first request to `HTTP 404`, with no manual step. Across a reboot the
LaunchDaemon starts the watcher early (observed as an init-time pid) and newly launched
processes are loaded into the same way.

There is an inherent window: a process that completes a TLS handshake within the first ~100 ms
of starting can do so before the watcher loads the library into it. This is fundamental to
loading a library into a process after it has already started, and it is the price of never
touching the process's launch. The window is bounded by the poll interval alone; nothing about
it depends on when the process gets round to loading `Security.framework`.

### Flags

`flags.txt` in `/usr/share/aquatransport/` holds one flag name per line, read at runtime by
every loaded copy of the library. Two flags are recognised:

```
disabled-mtls   # hand client-certificate connections back to the system stack
debug           # log handshakes to /tmp/aquatransport-<uid>.log
```

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

No process gating. Nothing is special-cased. The rewriter is compiled into the dylib and
works by rebinding two CFNetwork functions at runtime.

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

`ocspd`, `securityd`, `securityd_service`, `trustd` are excluded from the engine. That is
not "things that happen to break" — it is a circular dependency: our verify path calls
`SecTrustEvaluate`, which those processes *implement*. A re-entrancy guard
(`tf_guard_enter`/`tf_reentrant`, pthread-specific rather than `__thread` for 10.6)
handles the same-thread case; these four are where the cycle crosses a process boundary.

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
```

To demonstrate late loading end-to-end on the disposable test VM:

```
# into one already-running process
./tlsprobe-loop &                       # prints FAIL err=-9836 every 2s
sudo ./aqinject $! aquatransport.dylib  # same pid starts printing HTTP 404

# into processes as they launch
sudo ./aqwatch aquatransport.dylib ./aqinject &   # watcher
./tlsprobe-loop                                   # a NEW process: FAIL, then HTTP 404, unaided
```

## Coverage

Only apps that use Secure Transport are affected. Apps bundling their own TLS (Chromium
and Electron, Go, current bundled OpenSSL) are unreachable — but they also ship modern TLS
already, so they are not broken. The real gap is software linking the system's OpenSSL
0.9.8, notably Python 2.7's `ssl` module: broken *and* unreachable by this design.

Re-loading is idempotent — `dlopen` of an already-loaded image returns the existing handle
without re-running the constructor — so `aqinject --all` and the `aqwatch` per-launch load
compose safely: running `inject` once to cover the current session and `watch` for everything
launched afterward leaves no process loaded into twice in any harmful way.
