# AquaTransport for Mac OS X 10.6 – 10.9

Modern TLS for Snow Leopard through Mavericks, by replacing the crypto behind Secure
Transport rather than proxying traffic. Ported from the iOS tweak; the engine
(`src/aquatransport_engine.c`) is shared, the hook layer and URL rewriter are new.

Two independent subsystems in one package:

| Subsystem | What it does | Where it runs |
|---|---|---|
| TLS engine | Routes Secure Transport through LibreSSL: TLS 1.0–1.3, modern ciphers, OS-delegated trust | every process |
| URL rewriter | Applies `redirects.txt` and `headers.txt` at the request layer | apps only (see gating) |

Verified on 10.9.5 (22/22 local tests) and 10.6.8 (17/17), both `x86_64` and `i386`.

## Build

```
./build-macos.sh          # LibreSSL + dylib + rewrite bundle
./tools/selftest.sh       # per-process tests, installs nothing
```

Everything is vendored: `deps/libressl-4.3.2.tar.gz` (checksum matches upstream) and
`deps/ppcstub/aquatransport-ppc.dylib`. No network needed to build.

The build enforces three invariants, each of which corresponds to a way the thing broke
during development:

1. **All slices present.** dyld treats a missing slice in an inserted library as fatal, so
   an `x86_64`-only build kills every 32-bit process — and every PowerPC process under
   Rosetta.
2. **Zero exported symbols.** A naive link exports 3987, including `arc4random`,
   `getentropy` and the whole `SSL_*`/`EVP_*` namespace, into every process on the system.
3. **No post-10.6 libc imports.** `strndup`, `strnlen`, `getline`, `getdelim` are 10.7+.
   They bind *lazily*, so the dylib loads fine and then kills the process on first use.
   LibreSSL's configure probes the SDK rather than the deployment target, so its own
   compat versions must be forced on (`ac_cv_func_strndup=no`, etc.).

## Install

```
sudo ./install-macos.sh stage      # copy to /Library/AquaTransport, inject nothing
sudo ./install-macos.sh boot       # + /etc/launchd.conf, takes effect next reboot
sudo ./install-macos.sh uninstall  # clear injection, then remove files
```

`boot` is the only mode that reliably covers GUI apps. Runtime `launchctl setenv`
(the `session` mode) **cannot** reach them on 10.6: apps inherit the environment their
launcher captured, and Dock/Finder predate any runtime change. Restarting the Dock does
not help. `/etc/launchd.conf` works because everything descends from a launchd that had
the variable from boot.

Note also that there are two launchd contexts. `sudo launchctl setenv` sets the **system**
one, which injects into daemons — the opposite of what "session" suggests. The installer
now sets both explicitly.

### Disabling

**Never disable by deleting the dylib.** With the variable set, a missing file means
nothing on the machine launches. Use the sentinels:

```
sudo touch /Library/AquaTransport/disabled           # everything
sudo touch /Library/AquaTransport/disabled-tls       # TLS engine only
sudo touch /Library/AquaTransport/disabled-rewrite   # rewriter only
sudo touch /Library/AquaTransport/disabled-mtls      # client certs -> system stack
sudo touch /Library/AquaTransport/debug              # log handshakes to /tmp/aquatransport-<uid>.log
```

Updates must use `rename(2)`, never an in-place write — `cp` leaves a window where a
truncated dylib is visible, which bricks every launch. `install-macos.sh` does this.

**Recovery** if a machine will not boot: single-user mode (Cmd-S), `mount -uw /`, delete
`/etc/launchd.conf`, reboot.

## Rules

Blocks separated by blank lines, each beginning with a **scope** line: `*` for every
process, or a space-separated list of app bundle names. A trailing `.app` is optional, and
the executable name is matched as well as the bundle name. `*` is the only wildcard in URL
patterns (`?` is literal). Changes are picked up on mtime change, no restart. Working
examples are in `examples/`.

```
# redirects.txt — scope, from, to. "from" is a prefix, so the tail and query survive.
HelpViewer
https://help.apple.com/Library/Documentation/Resources/Flamingo/6/flamingo.js
https://mavericksforever.com/resources/flamingo.js

Pages Numbers Keynote
https://configuration.apple.com/configurations/internetservices/iworkapps/RemoteDefaults.plist
https://mavericksforever.com/resources/RemoteDefaults.plist

*
https://api.twitter.com/
https://twb.preloading.dev/
```

```
# headers.txt — scope, URL pattern, then headers to set
Dictionary
https://*.wikipedia.org/w/api.php?action=
User-Agent: Something Else
```

Scope matches the process that **issues** the request, which is not always the app you have
in mind. WebKit1 apps load in-process, so `Dictionary`, `HelpViewer`, the iWork apps and
`Twitter` all work. A **WebKit2 app hands its loads to the shared
`com.apple.WebKit.Networking` service**, so a rule scoped to `Safari` will never match —
use `*` for those, or scope nothing and accept system-wide application.

This format is *not* AquaProxy's: rule blocks gained the leading scope line. AquaProxy's
files would parse as zero usable rules, so the installer no longer seeds from them. Turn on
the `debug` flag and ignored blocks are reported by name.

Rewriting happens at the request layer, not in the TLS stream, because the interesting
rules change the destination host — and by the time `SSLWrite` runs, CFNetwork has already
resolved DNS and handshaked with the *original* host. At the request layer CFNetwork does
DNS, SNI and certificate validation against the rewritten host, and `http://` rules and
`http`→`https` upgrades work too.

### How the rewriter works, and why it is pure C

No process gating. Nothing is special-cased. The rewriter is compiled into the dylib and
works by rebinding two CFNetwork functions at runtime.

It was originally an Objective-C `NSURLProtocol` bundle `dlopen`'d per process, and that
was abandoned because injecting Foundation and the ObjC runtime before `main()` is fatal
to anything that forks without exec:

- **`sshd`** — confirmed. libdispatch aborts in the privilege-separation child
  (`BUG in libdispatch`, SIGILL on `com.apple.libdispatch-manager`); every ssh connection
  died. Reproduced on an alternate port, fixed by not loading the bundle, broken again by
  loading it.
- **`loginwindow`** — implicated in a login-keychain unlock failure.

Two property-based gates were tried and both were wrong in *both* directions. "A
Foundation symbol is resolvable" is true inside `sshd`. "The main executable links
Foundation directly" excludes Safari and WebProcess (they reach it through WebKit) while
including `loginwindow`. Excluding processes by name only hid the fragility — the next
thing to break would have been something nobody thought to list.

Foundation's own URL loading sits on CFNetwork's C API (Foundation imports 69 of those
symbols on 10.9, 53 on 10.6.8), so working there covers `NSURLConnection`, `NSURLSession`
and raw CFNetwork clients while touching no Objective-C, no libdispatch and no Foundation.

**Rebinding rather than interposing** is forced by the install name differing across the
range — `/System/Library/Frameworks/CFNetwork.framework/...` on 10.9 versus
`/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CFNetwork.framework/...`
on 10.6. Interposing needs the symbol at link time, and a dylib linked against either path
fails to load on the other, which is fatal to every process. fishhook rebinds by *name*,
so nothing is linked and processes without CFNetwork have nothing to rebind.

The hook points were found by experiment, not from headers, because these are private API:

| Path | Entry point | Request arg |
|---|---|---|
| synchronous | `CFURLConnectionSendSynchronousRequest` | arg 0 |
| asynchronous | `CFURLConnectionCreateWithProperties` | arg 1 |

The argument positions were identified by recording pointers returned from the
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

## Platform notes

**Trust is the OS's job.** LibreSSL does the crypto; `SecTrustEvaluate` or CFNetwork makes
the decision, against the live system trust store. 10.6.8 validates modern chains
correctly once modern roots are installed, so no OpenSSL-side verifier is needed. A stock
10.6 has no modern roots — install them first or everything looks broken.

In practice CFNetwork sets `kSSLSessionOptionBreakOnServerAuth` on nearly every
connection, so the app-verified path (`sh_build_trust` → CFNetwork evaluates) is the
common one, not an edge case for pinning apps.

**PowerPC.** On 10.6 with Rosetta, injection reaches the translated environment and a
missing slice is fatal:

```
arch -ppc /usr/bin/true                       -> exit 0
+ i386/x86_64-only insertion                  -> exit 133
+ 3-slice insertion (with the stub)           -> exit 0
```

`deps/ppcstub/aquatransport-ppc.dylib` is a vendored no-op that exists purely so dyld has
something to load. PPC apps keep the stock stack; a real PPC engine would mean LibreSSL
built big-endian running under translation, which is not worth it. Rebuild only via
`tools/build-ppcstub.sh` on 10.6 with Xcode 3.2.6 — the last Xcode with ppc codegen.

**mTLS.** `SecKeyRawSign` exists on both 10.6 and 10.9 (exported but absent from the OS X
headers, so declared in `aquatransport.h`), so the private key never leaves the keychain. Capped
at TLS 1.2: LibreSSL has no sigalgs-list API, so a server insisting on RSA-PSS will fail —
use `disabled-mtls` if that bites. Untested against a real client-certificate server.

**LibreSSL, not OpenSSL.** 1.1.1 is EOL. LibreSSL keeps the 1.1-era API this engine is
written against and is still maintained. Two gaps needed work: no `SSL_set_cert_cb` (use
`SSL_CTX_set_client_cert_cb`, whose `-1` return gives the same
`SSL_ERROR_WANT_X509_LOOKUP` suspend the pinning path needs, and which frees both
out-params so the callback must hand over owned references) and no sigalgs API at all.

## Testing on old systems

```
tools/probe-10.6.sh     # no compiler needed on the target
tools/symprobe.c        # runtime dlsym checks -- a stock 10.6 has lipo but no nm/otool
tools/urlprobe.m        # NSURLConnection; 10.6's curl is OpenSSL 0.9.8 and never
                        # touches Secure Transport, so curl proves nothing there
tools/httpsprobe.c      # CFNetwork directly
```

## Coverage

Only apps that use Secure Transport are affected. Apps bundling their own TLS (Chromium
and Electron, Go, current bundled OpenSSL) are unreachable — but they also ship modern TLS
already, so they are not broken. The real gap is software linking the system's OpenSSL
0.9.8, notably Python 2.7's `ssl` module: broken *and* unreachable by this design.
