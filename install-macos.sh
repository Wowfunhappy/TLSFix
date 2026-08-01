#!/bin/bash
# Installs AquaTransport system-wide on Mac OS X 10.6 - 10.9.
#
#   sudo ./install-macos.sh stage      copy files into /Library/AquaTransport, inject nothing
#   sudo ./install-macos.sh session    also inject into the current login session
#   sudo ./install-macos.sh boot       also inject at boot via /etc/launchd.conf
#   sudo ./install-macos.sh uninstall  remove injection, then the files
#
# READ THIS FIRST
#
# The `boot` step puts DYLD_INSERT_LIBRARIES into launchd's environment, which every
# process on the system inherits. dyld treats a failed insertion as FATAL: if the dylib
# is missing, unreadable, or lacks the running process's architecture, that process dies
# at launch with SIGTRAP. With the variable set in /etc/launchd.conf that means nothing
# boots -- including Terminal and Finder.
#
# Consequences, all enforced below:
#   * both i386 and x86_64 slices must be present
#   * files are installed BEFORE the variable is set, and on uninstall the variable is
#     cleared BEFORE the files are removed
#   * updates use rename(2), never an in-place write, so no truncated file is ever visible
#   * root-owned and not group/world writable: this dylib loads into root daemons, so a
#     user-writable path would be a privilege escalation
#
# TO DISABLE WITHOUT REBOOTING, DO NOT DELETE THE DYLIB. Touch the kill switch instead:
#     sudo touch /Library/AquaTransport/disabled
# Deleting the dylib while the variable is set is exactly what makes a machine unbootable.
#
# RECOVERY, if a machine will not boot after `boot`:
#   Boot single-user (Cmd-S), then:
#     /sbin/mount -uw /
#     rm /etc/launchd.conf        (or delete just the setenv line)
#     reboot
#   Or boot from another volume and delete /etc/launchd.conf on the affected disk.

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/.build/stage/Library/AquaTransport"
DEST="/Library/AquaTransport"
DYLIB="$DEST/aquatransport.dylib"
CONF="/etc/launchd.conf"
MODE="${1:-}"

need_root() { [ "$(id -u)" = "0" ] || { echo "must run as root (use sudo)"; exit 1; }; }

verify_build() {
  [ -f "$SRC/aquatransport.dylib" ] || { echo "no build found at $SRC -- run ./build-macos.sh first"; exit 1; }
  have=$(lipo -info "$SRC/aquatransport.dylib" | sed 's/.*://')
  for a in x86_64 i386; do
    echo "$have" | grep -qw "$a" || {
      echo "REFUSING TO INSTALL: dylib is missing the $a slice."
      echo "Every $a process on this machine would die at launch."; exit 1; }
  done
  n=$(nm -arch x86_64 -g "$SRC/aquatransport.dylib" 2>/dev/null | grep -cE " (T|D|B|S) _" || true)
  [ "$n" = "0" ] || { echo "REFUSING TO INSTALL: dylib exports $n symbols"; exit 1; }
  echo "  verified: both slices present, no exported symbols"
}

do_stage() {
  verify_build
  mkdir -p "$DEST"
  # Atomic replace: write alongside, then rename over. A partially written dylib at this
  # path would brick every process launch.
  cp "$SRC/aquatransport.dylib" "$DEST/.aquatransport.dylib.new"
  chown root:wheel "$DEST/.aquatransport.dylib.new"
  chmod 0644 "$DEST/.aquatransport.dylib.new"
  mv -f "$DEST/.aquatransport.dylib.new" "$DYLIB"

  rm -rf "$DEST/.rewrite.bundle.new"
  cp -R "$SRC/rewrite.bundle" "$DEST/.rewrite.bundle.new"
  rm -rf "$DEST/rewrite.bundle"
  mv -f "$DEST/.rewrite.bundle.new" "$DEST/rewrite.bundle"

  # Preserve existing rule files; seed from examples/ on a fresh install.
  #
  # Deliberately NOT seeded from /Library/AquaProxy any more: rule blocks now begin with a
  # scope line ("*" or a list of app bundle names), so AquaProxy's files would parse as
  # zero usable rules. Enable the debug flag to see ignored blocks reported.
  for f in headers.txt redirects.txt; do
    if [ ! -f "$DEST/$f" ]; then
      if [ -f "$DIR/examples/$f" ]; then cp "$DIR/examples/$f" "$DEST/$f"
      else : > "$DEST/$f"; fi
    fi
  done
  for f in headers.txt redirects.txt; do
    if [ -f "/Library/AquaProxy/$f" ] && ! grep -qE '^\*$|^[A-Za-z]' "$DEST/$f" 2>/dev/null; then
      echo "  note: $DEST/$f has no scope lines -- see examples/$f for the format"
    fi
  done

  chown -R root:wheel "$DEST"
  chmod 0755 "$DEST"
  find "$DEST" -type f -exec chmod 0644 {} +
  chmod 0755 "$DEST/rewrite.bundle/Contents/MacOS/rewrite"
  echo "  installed to $DEST (nothing injected yet)"
  echo
  echo "  test it on one process before going system-wide:"
  echo "    DYLD_INSERT_LIBRARIES=$DYLIB curl -v https://api.twitter.com"
}

do_session() {
  [ -f "$DYLIB" ] || { echo "run 'stage' first"; exit 1; }

  # There are two launchd contexts and they do not share environment. Running
  # `sudo launchctl setenv` only touches the system one, which injects into DAEMONS --
  # the opposite of what "session" implies, and how this script once killed every sshd.
  launchctl setenv DYLD_INSERT_LIBRARIES "$DYLIB"
  echo "  system context set (daemons launched from now on)"

  # The Aqua login session runs its own per-user launchd that does not inherit the above.
  # Reach it by entering the bootstrap of a process already inside that session.
  gui=$(ps -axo pid,comm | awk '/\/Dock$|\/Finder$/{print $1; exit}')
  if [ -n "$gui" ]; then
    if launchctl bsexec "$gui" launchctl setenv DYLD_INSERT_LIBRARIES "$DYLIB" 2>/dev/null; then
      echo "  Aqua session context set via pid $gui (GUI apps launched from now on)"
    else
      echo "  WARNING: could not reach the Aqua session; GUI apps will NOT be injected"
    fi
  else
    echo "  no GUI session found; only the system context was set"
  fi

  echo "  Already-running processes are unaffected."
  echo "  Undo: sudo launchctl unsetenv DYLD_INSERT_LIBRARIES"
  echo "        sudo launchctl bsexec <gui-pid> launchctl unsetenv DYLD_INSERT_LIBRARIES"
}

do_boot() {
  [ -f "$DYLIB" ] || { echo "run 'stage' first"; exit 1; }
  verify_build
  echo
  echo "  About to add DYLD_INSERT_LIBRARIES to $CONF."
  echo "  Every process on this machine will load $DYLIB at launch."
  echo "  If that file is ever missing or corrupt, THE MACHINE WILL NOT BOOT."
  echo "  Recovery is single-user mode (Cmd-S) and deleting $CONF."
  echo
  # AQUATRANSPORT_ASSUME_YES=1 skips the prompt for scripted installs (VMs, test rigs). Do not
  # use it on a machine you cannot reach the console of: recovery from a bad install
  # requires single-user mode.
  if [ "${AQUATRANSPORT_ASSUME_YES:-}" = "1" ]; then
    echo "  AQUATRANSPORT_ASSUME_YES=1 -- proceeding without confirmation"
  else
    printf "  Type EXACTLY 'i understand' to proceed: "
    read -r ack
    [ "$ack" = "i understand" ] || { echo "  aborted"; exit 1; }
  fi

  touch "$CONF"
  grep -v "^setenv DYLD_INSERT_LIBRARIES" "$CONF" > "$CONF.tf.new" 2>/dev/null || true
  echo "setenv DYLD_INSERT_LIBRARIES $DYLIB" >> "$CONF.tf.new"
  chown root:wheel "$CONF.tf.new"; chmod 0644 "$CONF.tf.new"
  mv -f "$CONF.tf.new" "$CONF"
  echo "  written. Takes effect on next boot."
}

do_uninstall() {
  # Order matters: stop injecting before the file can disappear.
  launchctl unsetenv DYLD_INSERT_LIBRARIES 2>/dev/null || true
  gui=$(ps -axo pid,comm | awk '/\/Dock$|\/Finder$/{print $1; exit}')
  [ -n "$gui" ] && launchctl bsexec "$gui" launchctl unsetenv DYLD_INSERT_LIBRARIES 2>/dev/null || true
  if [ -f "$CONF" ]; then
    grep -v "^setenv DYLD_INSERT_LIBRARIES" "$CONF" > "$CONF.tf.new" 2>/dev/null || true
    if [ -s "$CONF.tf.new" ]; then mv -f "$CONF.tf.new" "$CONF"; else rm -f "$CONF.tf.new" "$CONF"; fi
    echo "  removed injection from $CONF"
  fi
  echo "  injection cleared. Rule files kept."
  echo
  echo "  Reboot now, THEN remove the files:"
  echo "    sudo rm -rf $DEST"
  echo "  Removing them before rebooting would break every process still inheriting the variable."
}

case "$MODE" in
  stage)     need_root; do_stage ;;
  session)   need_root; do_stage; do_session ;;
  boot)      need_root; do_stage; do_boot ;;
  uninstall) need_root; do_uninstall ;;
  *) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
