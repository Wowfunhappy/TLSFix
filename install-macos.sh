#!/bin/bash
# Installs AquaTransport on Mac OS X 10.6 - 10.9.
#
#   sudo ./install-macos.sh stage      copy files into place, load nothing
#   sudo ./install-macos.sh inject     load into every eligible process running right now
#   sudo ./install-macos.sh watch      install a daemon that loads into each process as it starts
#   sudo ./install-macos.sh uninstall  remove the daemon, then the files
#
# The dylib is loaded into a target process with aqinject (task_for_pid + a hand-built
# mach_inject), using the target's own dlopen. It edits no system launch configuration, so a
# faulty dylib is confined to the process it is loaded into -- it can never keep the machine or
# any other process from starting.
#
#   inject  Loads the dylib into each eligible process running at the time. Covers what is
#           running now; reaches GUI apps and daemons alike.
#   watch   Runs aqwatch from a LaunchDaemon (starting at each boot), which loads the dylib
#           into each process as the process launches. Covers processes started later too.
#           Recommended for full coverage; run `inject` once alongside it for the current session.
#
# The dylib is installed root-owned and not group/world writable: it loads into root daemons,
# so a user-writable path would be a privilege escalation. Updates use rename(2), never an
# in-place write, so a partially written dylib is never visible to a load in progress.
#
# /usr/share/aquatransport/flags.txt holds one flag name per line, read at runtime by every
# loaded copy:
#     debug           log handshakes to /tmp/aquatransport-<uid>.log
#     disabled-mtls   hand client-certificate connections back to the system stack

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

# The dylib and the rule files live under /usr/share, which is one of the few directories
# system.sb lets a sandboxed process read; a target dlopens the dylib and reads the rule files
# itself, under its own sandbox. aqinject and aqwatch live in /Library/AquaTransport, where
# root runs them from outside any sandbox.
SRC="$DIR/build/stage/usr/share/aquatransport"
SRCTOOL="$DIR/build/stage/Library/AquaTransport"
LIBDIR="/usr/share/aquatransport"
DEST="/Library/AquaTransport"
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
      echo "aqinject could not load into $a processes."; exit 1; }
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
  # Both directories are 0755 and root-owned: a sandboxed target has to traverse $LIBDIR to
  # reach the dylib, and a user-writable path holding a library that loads into root daemons
  # would be a privilege escalation.
  mkdir -p "$LIBDIR"; chown root:wheel "$LIBDIR"; chmod 0755 "$LIBDIR"
  mkdir -p "$DEST";   chown root:wheel "$DEST";   chmod 0755 "$DEST"

  stage_file "$SRC/aquatransport.dylib" "$DYLIB"         0644
  stage_file "$SRCTOOL/aqinject"        "$DEST/aqinject" 0755
  stage_file "$SRCTOOL/aqwatch"         "$DEST/aqwatch"  0755

  # Seed config files on a fresh install without clobbering existing edits. 0644 is what makes
  # them legible from a sandbox: system.sb's grant carries a (file-mode #o0004) requirement,
  # so a stricter mode leaves them readable to root alone and every rule silently inert.
  for f in headers.txt redirects.txt flags.txt; do
    [ -f "$LIBDIR/$f" ] && continue
    if [ -f "$DIR/examples/$f" ]; then cp "$DIR/examples/$f" "$LIBDIR/$f"; else : > "$LIBDIR/$f"; fi
    chown root:wheel "$LIBDIR/$f"; chmod 0644 "$LIBDIR/$f"
  done

  echo "  installed to $LIBDIR and $DEST (nothing loaded yet)"
  echo "  test on one process first:  DYLD_INSERT_LIBRARIES=$DYLIB curl -v https://api.twitter.com"
}

do_inject() {
  echo "  loading into all eligible running processes..."
  "$DEST/aqinject" --all "$DYLIB"
  echo "  done. To cover processes started later, use 'watch'."
}

do_watch() {
  # aqwatch polls the process list, so nothing here enables system auditing or loads auditd.

  # Install and start the LaunchDaemon. RunAtLoad + the plist in /Library/LaunchDaemons start
  # aqwatch at every boot; KeepAlive restarts it if it exits.
  cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$PLIST_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$DEST/aqwatch</string>
    <string>$DYLIB</string>
    <string>$DEST/aqinject</string>
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
  echo "  It loads AquaTransport into each process as it starts, and restarts at every boot."
  echo "  Processes already running are not covered by the watcher alone -- run 'inject' once"
  echo "  to cover the current session."
}

do_uninstall() {
  # Stop and remove the watcher daemon first, so nothing loads the dylib again while the
  # files are going away.
  if [ -f "$PLIST" ]; then
    launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    echo "  removed watcher daemon ($PLIST)"
  fi
  # KeepAlive means launchd may have a copy running that outlives the unload.
  pkill -f "$DEST/aqwatch" 2>/dev/null || true

  rm -rf "$DEST" "$LIBDIR"
  echo "  removed $DEST and $LIBDIR"

  # Deleting the dylib does not unload it. A process that already loaded it keeps running
  # with it, because a mapped image survives the file being unlinked; nothing new picks it up
  # once the watcher and the file are gone. Restarting a process is what frees it of the
  # library, and a reboot clears every one.
  echo "  uninstalled. Processes already running keep the library until they restart."
}

case "$MODE" in
  stage)     need_root; do_stage ;;
  inject)    need_root; do_stage; do_inject ;;
  watch)     need_root; do_stage; do_watch ;;
  uninstall) need_root; do_uninstall ;;
  *) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
