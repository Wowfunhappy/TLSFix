// The processes this package never touches, in one place.
//
// Two different reasons to be on this list, and they are worth keeping distinct because the
// arguments for adding to them are different.
//
// THE TRUST DAEMONS are a circular dependency. Our verify path calls SecTrustEvaluate, which
// these processes implement, so routing their own traffic through that check would make trust
// evaluation depend on trust evaluation. Nothing else belongs here on that argument: if some
// other process misbehaves under injection, that is a bug in the engine to fix, not a name to
// add.
//
// THE CRITICAL PROCESSES are on the list because of what the connection gate does rather than
// what the library does. The gate freezes a process at its first network syscall, and for these
// the cost of being frozen -- or of carrying an extra library at all -- is out of proportion to
// anything gained:
//
//   launchd        every launchd, not only pid 1. The per-user launchd has an ordinary pid, so
//                  a "pid > 1" test in the probe does not cover it, and it is the process that
//                  starts every service and XPC job in a login session.
//   WindowServer   the session's display server; disrupting it disrupts everything visible.
//   loginwindow    owns the login session itself.
//
// None of the three has any business making the kind of TLS request this package exists to fix,
// so excluding them costs nothing real. Operators can extend this at runtime with
// `gate-never=<name>` in flags.txt, which is the same mechanism with a per-machine scope.
//
// FULL NAMES ONLY. Two subsystems read this list and they match it differently:
//
//   src/mac/aquatransport_hooks_mac.c   getprogname(), exact -- the library's own gate, which
//                                       runs inside the target and holds however it arrived
//   tools/aqwatch.c                     a D predicate on execname, which the kernel truncates
//                                       (15 characters on 10.9.5, measured at startup) -- the
//                                       daemon truncates these names itself
//
// A name written out pre-truncated would compile, run, and match nothing.

#ifndef AQUATRANSPORT_DENY_H
#define AQUATRANSPORT_DENY_H

static const char *const kAquaNeverTouch[] = {
    // circular dependency
    "ocspd", "securityd", "securityd_service", "trustd",
    // too costly to freeze or to carry the library
    "launchd", "WindowServer", "loginwindow",
    0
};

#endif
