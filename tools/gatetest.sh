#!/bin/bash
# System-level tests for the connection gate. Needs root, because the thing being tested is a
# root daemon that freezes processes.
#
#   ./build-macos.sh && sudo ./tools/gatetest.sh
#
# It stands up its own aqwatch in build/gatetest/stage and never touches /usr/share, so an
# installed AquaTransport is neither used nor disturbed -- but /var/log/aquatransport.log is a
# fixed path, so the existing one is moved aside and put back at the end.
#
# This is deliberately not part of tools/selftest.sh. That suite runs each case with
# DYLD_INSERT_LIBRARIES on one command, installs nothing, and refuses to run at all while a
# watcher is loaded -- because a daemon that patches every process would turn its "stock Secure
# Transport must fail" cases into passes. The two cannot share a process, so they do not share
# a script.
#
# Each gate case asserts the same pair: patched=0 immediately before the gated syscall and
# patched=1 immediately after, with the syscall returning normally and any payload intact. A
# subject that reports patched=1 beforehand proves nothing, so that fails too.

DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$DIR/build/stage/usr/share/aquatransport"
OUT="$DIR/build/gatetest"
STAGE="$OUT/stage"
LOG=/var/log/aquatransport.log
LOGSAVE=/var/log/aquatransport.log.gatetest-save
pass=0; fail=0

[ "$(id -u)" = 0 ] || { echo "must run as root (the daemon needs task_for_pid): sudo $0"; exit 1; }
[ -f "$SRC/aquatransport.dylib" ] || { echo "no build -- run ./build-macos.sh first"; exit 1; }
[ -f "$SRC/aqwatch" ] || { echo "no aqwatch in $SRC -- run ./build-macos.sh first"; exit 1; }

if ps ax -o command= 2>/dev/null | grep -q '[/]usr/share/aquatransport/aqwatch'; then
    echo "an installed aqwatch is running; it would gate these subjects before this one could."
    echo "stop it first:  sudo launchctl unload /Library/LaunchDaemons/org.aquatransport.watch.plist"
    exit 1
fi

check() { # check <name> <expected-ERE> <actual>
  if echo "$3" | grep -qE "$2"; then printf "  ok    %s\n" "$1"; pass=$((pass+1));
  else printf "  FAIL  %-52s got: %s\n" "$1" "$(echo "$3" | tr '\n' '|')"; fail=$((fail+1)); fi
}
checkno() { # the opposite: <name> <must-NOT-match-ERE> <actual>
  if echo "$3" | grep -qE "$2"; then printf "  FAIL  %-52s got: %s\n" "$1" "$(echo "$3" | tr '\n' '|')"; fail=$((fail+1));
  else printf "  ok    %s\n" "$1"; pass=$((pass+1)); fi
}

# ---- build the subjects ----------------------------------------------------------------
mkdir -p "$OUT" "$STAGE"
for t in connclient acceptserver inetdchild inetdlauncher twogates manygates forkchild execchain \
         heartbeat listener thrctl; do
  [ -x "$OUT/$t" ] && [ "$OUT/$t" -nt "$DIR/tools/gatetest/$t.c" ] && continue
  clang -arch x86_64 -mmacosx-version-min=10.6 -Wall -Wno-unused-function \
        -o "$OUT/$t" "$DIR/tools/gatetest/$t.c" || exit 1
done
# The CFNetwork subject needs the frameworks, and is the one that exercises connectx.
if [ ! -x "$OUT/cfclient" ] || [ ! "$OUT/cfclient" -nt "$DIR/tools/gatetest/cfclient.c" ]; then
  clang -arch x86_64 -mmacosx-version-min=10.6 -Wall -Wno-unused-function \
        -framework CoreFoundation -framework CFNetwork \
        -o "$OUT/cfclient" "$DIR/tools/gatetest/cfclient.c" || exit 1
fi
cp -f "$SRC/aquatransport.dylib" "$SRC/aqwatch" "$SRC/aqinject" "$STAGE/"

# ---- daemon control --------------------------------------------------------------------
# Assigns to PORT rather than echoing it: a command substitution runs in a subshell, so an
# increment there would be discarded and every case would reuse one port.
PORT=12900
next_port() { PORT=$((PORT+1)); }

stop_daemon() { pkill -f "$STAGE/aqwatch" 2>/dev/null; sleep 1; }

# start_daemon [flag ...] -- each argument is a line of flags.txt.
start_daemon() {
  stop_daemon
  : > "$STAGE/flags.txt"
  for f in "$@"; do echo "$f" >> "$STAGE/flags.txt"; done
  : > "$LOG"
  "$STAGE/aqwatch" &
  # Wait for the arm line rather than sleeping a guessed interval: startup does a process
  # sweep, an execname calibration and a launchd scan before it arms.
  for _ in $(seq 1 100); do grep -q 'aqwatch: armed' "$LOG" 2>/dev/null && return 0; sleep 0.2; done
  echo "  daemon never armed; log follows:"; sed 's/^/      /' "$LOG"; return 1
}

listener_on() { "$OUT/listener" "$1" >/dev/null 2>&1 & sleep 1; }

[ -f "$LOG" ] && mv -f "$LOG" "$LOGSAVE"
cleanup() {
  stop_daemon
  pkill -f "$OUT/listener" 2>/dev/null
  pkill -f "$OUT/heartbeat" 2>/dev/null
  [ -f "$LOGSAVE" ] && mv -f "$LOGSAVE" "$LOG"
  rm -rf "$OUT/deny"
  # Everything here was created by root inside the user's own build tree, which would leave
  # them unable to clean or rebuild it.
  [ -n "$SUDO_USER" ] && chown -R "$SUDO_USER" "$OUT" 2>/dev/null
  return 0
}
trap cleanup EXIT

echo "== the three gates =="
start_daemon || exit 1
next_port; p=$PORT; listener_on $p
out=$("$OUT/connclient" $p 2>&1)
check "outbound: held at connect, released patched" \
      "before  patched=0" "$out"
check "outbound: connect returned 0, no EINTR" "connect=0 errno=0 \(ok\) patched=1" "$out"

# The case that matters most, and the one a hand-written connect() cannot stand in for. On 10.9
# CFNetwork reaches the network with connectx(), not connect(), so this is what says the gate
# covers the software the package is actually for.
next_port; p=$PORT; listener_on $p
out=$("$OUT/cfclient" $p 2>&1)
check "CFNetwork: arrives unpatched"        "before  patched=0" "$out"
check "CFNetwork: held at connectx, released patched" \
      "after   cfnetwork request done patched=1" "$out"

next_port; p=$PORT
"$OUT/acceptserver" $p > "$OUT/acc.txt" 2>&1 &
sleep 1; printf 'HELLOPEER\n' | nc 127.0.0.1 $p >/dev/null 2>&1; sleep 2
out=$(cat "$OUT/acc.txt")
check "inbound: held at accept, released patched" "accept=[0-9]+ errno=0 \(ok\) patched=1" "$out"
check "inbound: the peer's payload survived the hold" "payload HELLOPEER" "$out"

# The inetd clause only covers executables the daemon was told about, so the subject is named
# in flags.txt exactly as a non-launchd inetd-style service would have to be.
start_daemon "gate-inetd=inetdchild" || exit 1
next_port; p=$PORT
( cd "$OUT" && ./inetdlauncher $p ./inetdchild > "$OUT/inetd.txt" 2>&1 & )
sleep 1; printf 'INHERITED\n' | nc 127.0.0.1 $p >/dev/null 2>&1; sleep 3
out=$(cat "$OUT/inetd.txt")
check "inetd: held at read on an inherited socket" "read=[0-9]+ errno=0 \(ok\) patched=1" "$out"
check "inetd: the payload survived the hold" "payload INHERITED" "$out"

echo "== fast path =="
start_daemon || exit 1
next_port; p=$PORT; listener_on $p
out=$("$OUT/twogates" $p 2>&1)
check "first thread arrives unpatched"  "one before  patched=0" "$out"
check "second thread is already patched" "two before  patched=1" "$out"
n=$(grep -c 'twogates.*patched at gate' "$LOG")
check "the process was injected exactly once" "^1$" "$n"

# Threads that gate at the SAME instant all arrive before any injection has finished, so the
# confirmed-patched set cannot help them -- only a claim on the process can. Without one, every
# racing thread starts its own injection into a process that may be doing real work.
next_port; p=$PORT; listener_on $p
out=$("$OUT/manygates" $p 2>&1)
check "8 racing threads all end up patched" "8 threads raced the gate patched=1" "$out"
n=$(grep -c 'manygates.*patched at gate' "$LOG")
check "and the process was injected exactly once" "^1$" "$n"

echo "== exec and fork =="
start_daemon || exit 1
next_port; p=$PORT; listener_on $p
out=$( cd "$OUT" && ./execchain $p ./connclient 2>&1 )
check "patched before the exec"                "first   after   patched=1" "$out"
check "re-gated and re-patched after the exec" "connect=0 errno=0 \(ok\) patched=1" "$out"
check "the post-exec program arrived unpatched" "^before  patched=0$" "$out"

out=$("$OUT/forkchild" $p 2>&1)
check "a fork without exec inherits the library" "child   inherited patched=1" "$out"
n=$(grep -c 'forkchild.*patched at gate' "$LOG")
check "and the child needed no injection of its own" "^1$" "$n"

echo "== recovery =="
# The watchdog must release whatever the injection is doing, so the injection is made to take
# far longer than the deadline. Failing open is the designed outcome: the process runs, and it
# runs unpatched.
start_daemon "gate-test-stall-ms=1500" "gate-hold-ms=300" || exit 1
next_port; p=$PORT; listener_on $p
t0=$(date +%s)
out=$("$OUT/connclient" $p 2>&1)
t1=$(date +%s)
check "watchdog: released at the deadline"       "watchdog released pid .* after 300 ms" "$(cat $LOG)"
check "watchdog: the syscall still completed"    "connect=0 errno=0 \(ok\)" "$out"
check "watchdog: it failed open, unpatched"      "connect=0 errno=0 \(ok\) patched=0" "$out"
check "watchdog: and it did not wait out the stall" "^[0-2]$" "$((t1-t0))"

# Journal: kill the daemon while it is holding, and assert the restart releases what it left.
start_daemon "gate-test-stall-ms=4000" "gate-hold-ms=60000" || exit 1
next_port; p=$PORT; listener_on $p
"$OUT/heartbeat" $p > "$OUT/hb.txt" 2>&1 &
sleep 1
pkill -9 -f "$STAGE/aqwatch"; sleep 3
check "journal: the process is frozen with the daemon gone" "^0$" "$(wc -l < "$OUT/hb.txt" | tr -d ' ')"
check "journal: the hold is on disk"      "^H [0-9]+ [0-9]+" "$(grep -a '^H ' "$STAGE/held.journal")"
: > "$LOG"; "$STAGE/aqwatch" & sleep 6
check "journal: replayed on restart"      "journal replay released [1-9]" "$(cat $LOG)"
beats=$(wc -l < "$OUT/hb.txt" | tr -d ' ')
check "journal: and the process is running again" "^[1-9]" "$beats"
pkill -f "$OUT/heartbeat"

# Suspend-count scan. A hold left by something that died without writing a journal is
# invisible to every targeted mechanism, but a non-zero Mach suspend count still finds it.
# The daemon only acts on that when the journal could not do the job, or when asked -- see
# aqguard.h -- so the test asks.
start_daemon || exit 1
next_port; p=$PORT; listener_on $p
"$OUT/heartbeat" $p > "$OUT/hb2.txt" 2>&1 & HB=$!
sleep 3                                   # let it get gated and patched
"$OUT/thrctl" $HB suspend 0 >/dev/null 2>&1
sleep 2
before=$(wc -l < "$OUT/hb2.txt" | tr -d ' ')
sleep 2
check "suspend scan: the out-of-band hold froze it" "^$before$" "$(wc -l < "$OUT/hb2.txt" | tr -d ' ')"
start_daemon "gate-resume-suspended" || exit 1
sleep 2
check "suspend scan: found and released on restart" "suspend-count scan: [1-9]" "$(cat $LOG)"
check "suspend scan: and the process is running again" "^[1-9]" \
      "$(( $(wc -l < "$OUT/hb2.txt" | tr -d ' ') - before ))"
pkill -f "$OUT/heartbeat"

# Blind sweep. A DTrace stop() whose record was never drained leaves a process that reports
# p_stat == SRUN and is indistinguishable from a running one, so nothing can name it. A real
# SIGSTOPped job IS distinguishable, which is what makes signalling everything else safe.
stop_daemon
next_port; p=$PORT; listener_on $p
"$OUT/heartbeat" > "$OUT/cz.txt" 2>&1 & CZ=$!
sleep 1; kill -STOP $CZ; sleep 1
dtrace -w -q -n 'syscall::connect:entry /execname == "heartbeat"/ { stop(); exit(0); }' >/dev/null 2>&1 &
sleep 3
"$OUT/heartbeat" $p > "$OUT/orph.txt" 2>&1 &
sleep 3
check "sweep: an orphaned stop freezes the process" "^0$" "$(wc -l < "$OUT/orph.txt" | tr -d ' ')"
start_daemon || exit 1
check "sweep: the startup sweep released it" "^[1-9]" "$(wc -l < "$OUT/orph.txt" | tr -d ' ')"
check "sweep: a genuinely stopped job was left alone" \
      "startup sweep: SIGCONT to [0-9]+ processes, [1-9][0-9]* genuinely stopped left alone" "$(cat $LOG)"
kill -CONT $CZ 2>/dev/null; kill -9 $CZ 2>/dev/null
pkill -f "$OUT/heartbeat"

echo "== kill safety =="
# A held process must remain reapable. The user's normal escape hatch has to survive this
# design, or a wedged application would be one nothing could clear.
for sig in TERM KILL; do
  start_daemon "gate-test-stall-ms=8000" "gate-hold-ms=60000" || exit 1
  next_port; p=$PORT; listener_on $p
  "$OUT/heartbeat" $p > "$OUT/k.txt" 2>&1 & K=$!
  sleep 2
  kill -$sig $K 2>/dev/null
  sleep 2
  kill -0 $K 2>/dev/null && alive=yes || alive=no
  check "a process held at a gate dies to SIG$sig" "^no$" "$alive"
  wait $K 2>/dev/null
done

echo "== the exclusion list =="
start_daemon "gate-never=AquaNeverGateMe" || exit 1
LIMIT=$(sed -n 's/.*execname truncates to \([0-9]*\) characters.*/\1/p' "$LOG" | head -1)
check "the truncation length was measured, not assumed" "^1[0-9]$" "$LIMIT"
# The assertion the whole list rests on: what went into the predicate is what DTrace will
# actually report. A 16-character entry for securityd_service matches nothing at all, and
# freezes the daemon it was written to skip.
want=$(printf 'securityd_service' | cut -c1-"$LIMIT")
check "securityd_service was truncated to what execname reports" \
      "denied\[\"$want\"\] = 1;" "$(cat "$STAGE/gate.d")"
check "the daemon excludes itself"     'denied\["aqwatch"\] = 1;'  "$(cat "$STAGE/gate.d")"
check "and its injection helper"       'denied\["aqinject"\] = 1;' "$(cat "$STAGE/gate.d")"
# launchd is the one a "pid > 1" test does NOT cover: the per-user launchd that starts every
# service in a login session has an ordinary pid, and freezing or injecting it is not worth
# whatever gating it could gain.
for n in launchd WindowServer loginwindow; do
  check "the built-in list excludes $n" "denied\[\"$n\"\] = 1;" "$(cat "$STAGE/gate.d")"
done

# A live subject for the predicate, since most of the list is never observed to connect. A copy
# named WindowServer must reach the network untouched.
mkdir -p "$OUT/deny"
cp "$OUT/connclient" "$OUT/deny/AquaNeverGateMe"
next_port; p=$PORT; listener_on $p
out=$("$OUT/deny/AquaNeverGateMe" $p 2>&1)
check "a gate-never process is never gated" "connect=0 errno=0 \(ok\) patched=0" "$out"
checkno "and never appears in the log"      "AquaNeverGateMe" "$(cat $LOG)"
checkno "the daemon never gated itself"    "\(aqwatch\)|\(aqinject\)" "$(cat $LOG)"

echo "== a real TLS request, first time, through the gate =="
# The case the whole gate exists for, and the one a loopback listener cannot stand in for.
# CFNetwork configures its SSLContext BEFORE it opens a socket, so on a process's first TLS
# connection our setters never ran -- the engine has to take the context over at the handshake
# instead. Needs network; api.twitter.com is the target because stock Secure Transport on 10.9
# cannot negotiate with it at all, which makes "did the engine actually carry this request"
# unambiguous rather than a matter of inspecting a cipher.
PROBE="$DIR/build/httpsprobe"
[ -x "$PROBE" ] || clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
    -framework CoreFoundation -framework CFNetwork -o "$PROBE" "$DIR/tools/httpsprobe.c"
if "$PROBE" https://www.cloudflare.com/ >/dev/null 2>&1 || true; then :; fi
start_daemon || exit 1
out=$("$PROBE" https://api.twitter.com/ 2>&1 | tail -1)
check "a fresh process's FIRST HTTPS request is carried by the engine" "^404" "$out"

# And the property that must survive taking a context over: the peer name has to be recovered,
# or there is no SNI and nothing to verify the certificate against. A rejection here is the
# assertion -- an adopted context that skipped verification would return 200.
for h in expired wrong.host untrusted-root; do
  out=$("$PROBE" "https://$h.badssl.com/" 2>&1 | tail -1)
  checkno "adopted context still rejects $h.badssl.com" "^200" "$out"
done

echo "== gate-off =="
# The escape hatch: nothing is frozen, and the library is loaded at exec instead -- which
# reopens the window the gate closes, and is why it is not the default.
start_daemon "gate-off" || exit 1
check "comes up with the gates disarmed" "GATES OFF" "$(cat $LOG)"
next_port; p=$PORT; listener_on $p
sleep 1
"$OUT/heartbeat" > "$OUT/go.txt" 2>&1 &
sleep 3
check "and still loads the library at exec" "patched at exec" "$(cat $LOG)"
pkill -f "$OUT/heartbeat"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
