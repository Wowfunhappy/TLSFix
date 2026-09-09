#!/bin/bash
# Installs AquaTransport on Mac OS X 10.6 - 10.9.
#
#   sudo ./install-macos.sh install
#   sudo ./install-macos.sh uninstall
#
# Security.framework is given a weak load command naming the library, so every process that
# loads Security loads it too, at launch, before it can complete a handshake. Security is what
# exports SSLHandshake and the rest, so those are exactly the processes that could use Secure
# Transport. Nothing is injected and no daemon runs.
#
# The flip side is that a library which crashes in its constructor takes down everything that
# loads Security, loginwindow included. If that happens, boot from another volume or into
# single-user mode (Cmd-S, then `mount -uw /`) and put the original back:
#
#   ln -f /System/Library/Frameworks/Security.framework/Versions/A/Security.original \
#         /System/Library/Frameworks/Security.framework/Versions/A/Security

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/build/stage/usr/share/aquatransport"
DEFAULTS="$DIR/packaging/Default Configuration"
LIBDIR=/usr/share/aquatransport
CONFDIR="$LIBDIR/config"
DYLIB="$LIBDIR/aquatransport.dylib"
ENGINE="$LIBDIR/aquatransport_engine.dylib"
SEC="${AQ_SECURITY_PATH:-/System/Library/Frameworks/Security.framework/Versions/A/Security}"
BACKUP="$SEC.original"
INSERT="${AQ_INSERT_DYLIB:-/usr/local/bin/insert_dylib}"

case "${1:-}" in install|uninstall) ;; *) sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;; esac
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

case "$1" in
install)
  updating=0
  if [ -e "$BACKUP" ]; then
    # Updating the payload needs no further framework patch. Refuse an inconsistent
    # backup/patch pair before changing anything, retaining the recovery original.
    LC_ALL=C grep -q -a -F "$DYLIB" "$SEC" ||
      { echo "Security backup exists but the AquaTransport load command is missing"; exit 1; }
    updating=1
  fi
  # Require the complete payload before replacing any library. Package installations
  # can supply it in LIBDIR instead of the build stage.
  for lib in aquatransport_gsa.dylib aquatransport_engine.dylib aquatransport.dylib; do
    [ -f "$SRC/$lib" ] || [ -f "$LIBDIR/$lib" ] ||
      { echo "missing $lib -- run ./build-macos.sh first"; exit 1; }
  done

  # A package install has already put the library in place; a build in this tree supersedes it,
  # by rename rather than in-place write, so a load in progress never sees a partial file.
  # Dependencies go first. Only the loader is named by a load command, so a window in which
  # the loader is present and the engine is not is a window of processes without TLS.
  mkdir -p "$LIBDIR" "$CONFDIR"
  for lib in aquatransport_gsa.dylib aquatransport_engine.dylib aquatransport.dylib; do
    if [ -f "$SRC/$lib" ]; then
      cp "$SRC/$lib" "$LIBDIR/$lib.new"
      chown root:wheel "$LIBDIR/$lib.new"; chmod 0644 "$LIBDIR/$lib.new"
      mv -f "$LIBDIR/$lib.new" "$LIBDIR/$lib"
    fi
  done
  [ -f "$DYLIB" ] || { echo "no library at $DYLIB -- run ./build-macos.sh first"; exit 1; }
  [ -f "$ENGINE" ] || { echo "no engine at $ENGINE -- run ./build-macos.sh first"; exit 1; }
  # Seed each rule file from the shipped default when it is not already present, so a reinstall
  # keeps a user's edits. flags.txt has no default and starts empty.
  for f in headers.txt redirects.txt disabled.txt; do
    [ -f "$CONFDIR/$f" ] || cp "$DEFAULTS/$f" "$CONFDIR/$f"
  done
  [ -f "$CONFDIR/flags.txt" ] || : > "$CONFDIR/flags.txt"

  # Everything stays world-readable: system.sb grants file-read* under /usr/share only for
  # world-readable files, and because the load command is weak, a sandboxed process that cannot
  # read the library is left unpatched in silence rather than failing. The library directory is
  # root:wheel because the library loads into root daemons.
  chown root:wheel "$LIBDIR" "$DYLIB" "$ENGINE"
  chmod 0755 "$LIBDIR"; chmod 0644 "$DYLIB" "$ENGINE"
  if [ -f "$LIBDIR/aquatransport_gsa.dylib" ]; then
    chown root:wheel "$LIBDIR/aquatransport_gsa.dylib"
    chmod 0644 "$LIBDIR/aquatransport_gsa.dylib"
  fi

  # insert_dylib and the installer scripts are run as programs, not read as data, so they keep the
  # execute bit. Still world-readable, which is all the /usr/share grant asks for.
  for t in insert_dylib aquatransport.sh uninstall.sh; do
    [ -e "$LIBDIR/$t" ] && { chown root:wheel "$LIBDIR/$t"; chmod 0755 "$LIBDIR/$t"; }
  done

  # The rule files sit in their own group-writable directory so an admin can edit them in a GUI
  # editor -- whose save replaces the file, needing write on the directory -- without write to the
  # directory that holds the dylibs. root:admin 0775 on the directory and 0664 on the files, still
  # world-readable for the sandbox; the subpath grant reaches this depth under /usr/share.
  chown root:admin "$CONFDIR"; chmod 0775 "$CONFDIR"
  chown root:admin "$CONFDIR"/*; chmod 0664 "$CONFDIR"/*

  if [ "$updating" = 1 ]; then
    echo "Updated. Quit and reopen affected applications, including System Preferences for iCloud."
    exit 0
  fi

  # --strip-codesig: editing the file invalidates Security's signature, and an invalid signature
  # is far worse than none. The kernel validates the pages of a signed library as a signed
  # process maps them and kills the process when they do not match, so every signed application
  # stops launching while unsigned command-line binaries carry on. Nothing is left to validate.
  "$INSERT" --weak --all-yes --strip-codesig "$DYLIB" "$SEC" "$SEC.new" > /dev/null
  chown root:wheel "$SEC.new"; chmod 0755 "$SEC.new"

  # Linked from the original before the rename replaces it, and after the patch has succeeded, so
  # a failed patch leaves nothing behind.
  ln "$SEC" "$BACKUP"
  mv -f "$SEC.new" "$SEC" # rename, so no launch ever sees a half-written framework

  echo "Installed. Restart your computer."
  ;;

uninstall)
  [ -e "$BACKUP" ] || { echo "not installed"; exit 1; }
  ln "$BACKUP" "$SEC.restore"; mv -f "$SEC.restore" "$SEC"; rm -f "$BACKUP"
  rm -rf "$LIBDIR"
  echo "Uninstalled. Restart your computer."
  ;;
esac
