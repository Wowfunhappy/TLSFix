#!/bin/bash
# Installs AquaTransport on Mac OS X 10.6 - 10.9.
#
#   sudo ./install-macos.sh stage      copy files into place, start nothing
#   sudo ./install-macos.sh watch      + the connection-gate daemon, at boot and now
#   sudo ./install-macos.sh uninstall  stop the daemon, then remove the files
#
# WHAT THE DAEMON DOES. aqwatch asks the kernel to freeze a process at the moment it first
# touches the network -- connect, accept, or a read on a socket it was handed -- and does not
# let it go until AquaTransport is loaded into it. Everything that process does on the network
# from then on is covered, without waiting for a poller to notice it started.
#
# CFNetwork builds its TLS context BEFORE it opens a socket, so on an app's first HTTPS request
# the library arrives after that request has been set up but before it is sent. The engine takes
# such a connection over at the handshake rather than conceding it, so the first request is
# covered too -- see "Taking over a context configured before the library arrived" in
# docs/TECHNICAL.md.
#
# It edits no system launch configuration and sets nothing in launchd's global environment, so
# a faulty library is confined to the one process it was loaded into and can never keep the
# machine, or any other process, from starting.
#
# Only processes that actually use the network are touched -- roughly 32 of ~270 on a normal
# session -- so a process that never opens a socket never receives the library.
#
# PROCESSES ALREADY RUNNING when the daemon starts are not covered until their next connection.
# One holding a long-lived connection may not reach a gate for a long time; restarting it, or
# rebooting, is the remedy.
#
# The dylib is installed root-owned and not group/world writable: it loads into root daemons, so
# a user-writable path would be a privilege escalation. Updates use rename(2), never an in-place
# write, so a partially written dylib is never visible to a load in progress.
#
# /usr/share/aquatransport/flags.txt holds one flag per line. The library reads:
#     debug                  log handshakes to the system log, tagged AquaTransport
#     disabled-mtls          hand client-certificate connections back to the system stack
#     allow-legacy-tls       negotiate TLS 1.0/1.1 and the legacy cipher suites, and let a
#                            refused connection be retried on the system stack
# and the daemon reads, at startup:
#     gate-off               arm nothing; load the library at exec instead. The escape hatch.
#     gate-rate=<n>hz        how often gate records are collected (default 50hz)
#     gate-hold-ms=<n>       watchdog deadline for one hold (default 250)
#     gate-never=<name>      never gate a process with this executable name
#     gate-inetd=<name>      this executable is handed an already-connected socket

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

# One directory. The dylib and the rule files have to live under /usr/share because a target
# dlopens the dylib and reads the rules itself, under its OWN sandbox, and /usr/share is one of
# the few paths system.sb lets a sandboxed process read. The tools cost nothing by joining
# them: the directory stays root:wheel 0755, so it is not user-writable, and aqinject requires
# task_for_pid, which a non-root caller fails wherever the binary sits.
SRC="$DIR/build/stage/usr/share/aquatransport"
LIBDIR="/usr/share/aquatransport"
DYLIB="$LIBDIR/aquatransport.dylib"
PLIST_LABEL="org.aquatransport.watch"
PLIST="/Library/LaunchDaemons/$PLIST_LABEL.plist"
MODE="${1:-}"

need_root() { [ "$(id -u)" = "0" ] || { echo "must run as root (use sudo)"; exit 1; }; }

verify_build() {
  [ -f "$SRC/aquatransport.dylib" ] || { echo "no build found at $SRC -- run ./build-macos.sh first"; exit 1; }
  have=$(lipo -info "$SRC/aquatransport.dylib" | sed 's/.*://')
  for a in x86_64 i386; do
    echo "$have" | grep -qw "$a" || {
      echo "REFUSING TO INSTALL: dylib is missing the $a slice."
      echo "It could not be loaded into $a processes."; exit 1; }
  done
  n=$(nm -arch x86_64 -g "$SRC/aquatransport.dylib" 2>/dev/null | grep -cE " (T|D|B|S) _" || true)
  [ "$n" = "0" ] || { echo "REFUSING TO INSTALL: dylib exports $n symbols"; exit 1; }
  echo "  verified: both slices present, no exported symbols"
}

# Install one file atomically: write alongside with its final owner and mode, then rename over,
# so a load in progress never sees a partial or wrong-permissioned file.
stage_file() { # src dst mode
  [ -f "$1" ] || { echo "missing $1 -- run ./build-macos.sh first"; exit 1; }
  cp "$1" "$2.new"; chown root:wheel "$2.new"; chmod "$3" "$2.new"; mv -f "$2.new" "$2"
}

do_stage() {
  verify_build
  # 0755 and root-owned: a sandboxed target has to traverse this directory to reach the dylib,
  # and a user-writable path holding a library that loads into root daemons would be a
  # privilege escalation.
  mkdir -p "$LIBDIR"; chown root:wheel "$LIBDIR"; chmod 0755 "$LIBDIR"

  stage_file "$SRC/aquatransport.dylib" "$DYLIB"            0644
  stage_file "$SRC/aqwatch"             "$LIBDIR/aqwatch"   0755
  stage_file "$SRC/aqinject"            "$LIBDIR/aqinject"  0755

  # Seed config files on a fresh install without clobbering existing edits. 0644 is what makes
  # them legible from a sandbox: system.sb's grant carries a (file-mode #o0004) requirement,
  # so a stricter mode leaves them readable to root alone and every rule silently inert.
  for f in headers.txt redirects.txt flags.txt; do
    [ -f "$LIBDIR/$f" ] && continue
    if [ -f "$DIR/examples/$f" ]; then cp "$DIR/examples/$f" "$LIBDIR/$f"; else : > "$LIBDIR/$f"; fi
    chown root:wheel "$LIBDIR/$f"; chmod 0644 "$LIBDIR/$f"
  done

  echo "  installed to $LIBDIR (nothing running yet)"
  echo "  test on one process first:  DYLD_INSERT_LIBRARIES=$DYLIB curl -v https://api.twitter.com"
}

do_watch() {
  # Everything is co-located, so aqwatch derives the dylib and helper paths from its own
  # location and the plist carries a single argument. RunAtLoad starts it at every boot;
  # KeepAlive restarts it if it exits, which is also what drives the recovery on restart.
  cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$PLIST_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$LIBDIR/aqwatch</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
PLIST_EOF
  chown root:wheel "$PLIST"; chmod 0644 "$PLIST"
  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load "$PLIST"
  echo "  aqwatch installed and running ($PLIST)."
  echo "  It holds each process at its first network use until the library is loaded,"
  echo "  and starts again at every boot. Processes already running are covered at their"
  echo "  next connection; restart one, or reboot, to cover it now."
  echo "  Log: /var/log/aquatransport.log"
}

do_uninstall() {
  # Stop the daemon first, so nothing gates a process while the files are going away.
  if [ -f "$PLIST" ]; then
    launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    echo "  removed the daemon ($PLIST)"
  fi
  # KeepAlive means launchd may have a copy running that outlives the unload. It releases every
  # hold it owns on the way out; the sweep below is for a copy that did not get the chance.
  pkill -f "$LIBDIR/aqwatch" 2>/dev/null || true
  sleep 1

  rm -rf "$LIBDIR"
  echo "  removed $LIBDIR"

  # Deleting the dylib does not unload it. A process that already loaded it keeps running with
  # it, because a mapped image survives the file being unlinked; nothing new picks it up once
  # the daemon and the file are gone. Restarting a process is what frees it of the library, and
  # a reboot clears every one.
  echo "  uninstalled. Processes already running keep the library until they restart."
}

case "$MODE" in
  stage)     need_root; do_stage ;;
  watch)     need_root; do_stage; do_watch ;;
  uninstall) need_root; do_uninstall ;;
  *) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
