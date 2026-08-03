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

Verified on 10.9.5 (37/37 local tests) and 10.6.8 (`NSURLSession` is 10.9+ and is
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
sudo ./install-macos.sh stage      # copy to /Library/AquaTransport, load nothing
sudo ./install-macos.sh inject     # + load into every eligible running process now
sudo ./install-macos.sh watch      # + a daemon that loads into each process as it launches
sudo ./install-macos.sh uninstall  # remove the daemon, then the files
```

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
`aqinject <pid> <dylib>` — once, with no waiting and no conditions. In-flight `aqinject`
children are capped and reaped so an app-launch storm cannot fork-bomb the machine. The
deny list is applied to `proc_pidpath` of the pid, so it matches what the process actually
is rather than anything the daemon was told.

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

`flags.txt` in `/Library/AquaTransport/` holds one flag name per line, read at runtime by
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

**Rebinding rather than interposing** is forced by the install name differing across the
range — `/System/Library/Frameworks/CFNetwork.framework/...` on 10.9 versus
`/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CFNetwork.framework/...`
on 10.6. Interposing needs the symbol at link time, and a dylib linked against either path
fails to load at all on the other OS. fishhook rebinds by *name*, so nothing is linked and
processes without CFNetwork have nothing to rebind.

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

## What a trust evaluation costs

`SecTrustEvaluate` costs about **335 ms** on 10.9-era hardware, and a profile says exactly
where it goes: `mulg`, `modg_via_recip`, `grammarSquare`, `gshiftright` — Security.framework's
CryptKit "giants" bignum routines, verifying the chain's signatures in software. It is not
revocation fetching (disabling network fetch changes nothing: 331 ms vs 340 ms), not a bloated
trust store (211 roots), and not IPC (`securityd` and `ocspd` sit at 0% CPU while it runs). It
is 335 ms of local arithmetic, and it reproduces in a clean process with no library loaded, on
a leaf-only chain as readily as a full one.

It is a floor, not something this engine can optimise away. The OpenSSL linked into this
library does the same arithmetic roughly two orders of magnitude faster, but CFNetwork
evaluates the `SecTrustRef` handed back to it, so a real `SecTrustEvaluate` has to happen
somewhere. What can be avoided is doing it more than once per connection, which is what the
next section covers.

## Trust evaluation, once per connection

`SecTrustEvaluate` costs about **335 ms** on 10.9-era hardware, and CFNetwork calls
`SSLCopyPeerTrust` on *every request*, not once per connection. A fresh `SecTrustRef` built
from freshly created `SecCertificateRef`s costs a full evaluation each time, because the
system's own caching never sees the same object twice — so the evaluation has to be kept off
the per-request path. This is the cost that matters most in practice: a browser loads dozens of
small subresources over a handful of pooled connections, so nearly all of its requests are warm
ones.

The peer chain cannot change within a connection, so neither can the trust decision.
`sh_build_trust` evaluates once and caches the result on the `Shadow` for the life of the
connection, with each caller still getting its own reference (`SSLCopyPeerTrust` has copy
semantics). The cache is dropped whenever the `SSL` object is re-initialised — late SNI, or
`SSLSetCertificate` — because that means a new handshake and a new chain.

**Once per connection is what Secure Transport itself does**, measured rather than assumed.
Native CPU, same host:

| | user CPU |
|---|---|
| 1 connection × 6 requests | 0.595 s |
| 1 connection × 12 requests | 0.644 s |
| 6 connections × 1 request | 2.164 s |

Doubling the *requests* on one connection costs nothing; going from one *connection* to six
costs +1.57 s, about 314 ms each. The stock stack evaluates once per connection and does not
carry the result between connections, and this matches it exactly. Caching across connections
would beat it, but only by holding a security decision past the connection boundary that
produced it, which is a policy the platform does not have.

Measured on 10.9.5, x86_64, 10 pooled `NSURLConnection` requests (`tools/poolprobe.m`):

| | wall | CPU | per warm request |
|---|---|---|---|
| Native Secure Transport | 1.58 s | 0.76 s | ~85 ms |
| **AquaTransport** | **1.85 s** | **1.16 s** | **~80 ms** |

Only `poolprobe` can see this. Every other harness here forces a new connection per request
(`multiprobe` sends `Connection: close`, and `CFReadStream` does not pool at all), which buries
a per-request evaluation under handshake and network time. `selftest.sh` asserts the evaluation
count rather than timing it, so a regression shows up as a count rather than as noise.

## Session resumption

Secure Transport keeps a session cache, so the engine keeps one too. Without it every
connection pays a full handshake where the stock stack resumes — an extra round trip against a
TLS 1.2 server, plus the certificate chain and its signature checks, on every connection. A
browser opens a lot of connections to the same host, so this dominates everything else in the
engine.

`aquatransport_engine.c` keeps a 32-entry LRU cache of `SSL_SESSION`s keyed on the peer name,
filled from `new_session_cb` and offered by `ossl_init` through `SSL_set_session`. The key is
the name the handshake is bound to (`SSL_set1_host`), which is the only thing a session may
be reused for. OpenSSL checks the session's own validity and falls back to a full handshake
if it has expired or the server declines it, so nothing here reasons about lifetime.

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
tools/poolprobe.m       # N POOLED requests over a reused connection -- the warm path a browser
                        # actually spends its time on, which every other probe here hides
                        # behind handshake and network time
tools/latecheck.c       # loads the dylib into a process with no CoreFoundation/Security, then
                        # brings CFNetwork in afterwards: the no-gate property, end to end
tools/tlsprobe-loop.c   # long-lived cooperating harness: requests api.twitter.com every 2s,
                        # so you can load the library into it with aqinject and watch the
                        # same live process go from FAIL to HTTP 404 without restarting
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
