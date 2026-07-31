#!/bin/bash
# Installs TLSFix system-wide on Mac OS X 10.6 - 10.9.
#
#   sudo ./install-macos.sh stage      copy files into /Library/TLSFix, inject nothing
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
#     sudo touch /Library/TLSFix/disabled
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
SRC="$DIR/.build/stage/Library/TLSFix"
DEST="/Library/TLSFix"
DYLIB="$DEST/tlsfix.dylib"
CONF="/etc/launchd.conf"
MODE="${1:-}"

need_root() { [ "$(id -u)" = "0" ] || { echo "must run as root (use sudo)"; exit 1; }; }

verify_build() {
  [ -f "$SRC/tlsfix.dylib" ] || { echo "no build found at $SRC -- run ./build-macos.sh first"; exit 1; }
  have=$(lipo -info "$SRC/tlsfix.dylib" | sed 's/.*://')
  for a in x86_64 i386; do
    echo "$have" | grep -qw "$a" || {
      echo "REFUSING TO INSTALL: dylib is missing the $a slice."
      echo "Every $a process on this machine would die at launch."; exit 1; }
  done
  n=$(nm -arch x86_64 -g "$SRC/tlsfix.dylib" 2>/dev/null | grep -cE " (T|D|B|S) _" || true)
  [ "$n" = "0" ] || { echo "REFUSING TO INSTALL: dylib exports $n symbols"; exit 1; }
  echo "  verified: both slices present, no exported symbols"
}

do_stage() {
  verify_build
  mkdir -p "$DEST"
  # Atomic replace: write alongside, then rename over. A partially written dylib at this
  # path would brick every process launch.
  cp "$SRC/tlsfix.dylib" "$DEST/.tlsfix.dylib.new"
  chown root:wheel "$DEST/.tlsfix.dylib.new"
  chmod 0644 "$DEST/.tlsfix.dylib.new"
  mv -f "$DEST/.tlsfix.dylib.new" "$DYLIB"

  rm -rf "$DEST/.rewrite.bundle.new"
  cp -R "$SRC/rewrite.bundle" "$DEST/.rewrite.bundle.new"
  rm -rf "$DEST/rewrite.bundle"
  mv -f "$DEST/.rewrite.bundle.new" "$DEST/rewrite.bundle"

  # Preserve existing rule files; seed from AquaProxy's if this is a fresh install.
  for f in headers.txt redirects.txt; do
    if [ ! -f "$DEST/$f" ]; then
      if [ -f "/Library/AquaProxy/$f" ]; then cp "/Library/AquaProxy/$f" "$DEST/$f"
      else : > "$DEST/$f"; fi
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
  launchctl setenv DYLD_INSERT_LIBRARIES "$DYLIB"
  echo "  injected into the current login session."
  echo "  Applies to processes launched from now on; already-running apps are unaffected."
  echo "  Undo with: sudo launchctl unsetenv DYLD_INSERT_LIBRARIES"
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
  printf "  Type EXACTLY 'i understand' to proceed: "
  read -r ack
  [ "$ack" = "i understand" ] || { echo "  aborted"; exit 1; }

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
