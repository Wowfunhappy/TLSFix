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
#   ln -f /System/Library/Frameworks/Security.framework/Versions/A/Security.aquatransport-original \
#         /System/Library/Frameworks/Security.framework/Versions/A/Security

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/build/stage/usr/share/aquatransport"
LIBDIR=/usr/share/aquatransport
DYLIB="$LIBDIR/aquatransport.dylib"
SEC="${AQ_SECURITY_PATH:-/System/Library/Frameworks/Security.framework/Versions/A/Security}"
BACKUP="$SEC.aquatransport-original"
INSERT="${AQ_INSERT_DYLIB:-/usr/local/bin/insert_dylib}"

case "${1:-}" in install|uninstall) ;; *) sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;; esac
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

case "$1" in
install)
  [ -e "$BACKUP" ] && { echo "already installed"; exit 1; }

  # A package install has already put the library in place; a build in this tree supersedes it,
  # by rename rather than in-place write, so a load in progress never sees a partial file.
  mkdir -p "$LIBDIR"
  [ -f "$SRC/aquatransport.dylib" ] &&
    { cp "$SRC/aquatransport.dylib" "$DYLIB.new"; mv -f "$DYLIB.new" "$DYLIB"; }
  [ -f "$DYLIB" ] || { echo "no library at $DYLIB -- run ./build-macos.sh first"; exit 1; }
  for f in flags.txt headers.txt redirects.txt; do [ -f "$LIBDIR/$f" ] || : > "$LIBDIR/$f"; done

  # 0755 on the directory and 0644 on the files is what system.sb requires: it grants
  # file-read* under /usr/share only for world-readable files, and because the load command is
  # weak, a sandboxed process that cannot read the library is left unpatched in silence rather
  # than failing. root:wheel because the library loads into root daemons.
  chown root:wheel "$LIBDIR" "$LIBDIR"/*
  chmod 0755 "$LIBDIR"; chmod 0644 "$LIBDIR"/*

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
  rm -rf "$LIBDIR" /Library/AquaTransport
  echo "Uninstalled. Restart your computer."
  ;;
esac
