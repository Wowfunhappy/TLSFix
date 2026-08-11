#!/bin/bash
# AquaTransport uninstaller. Installed to /usr/share/aquatransport/uninstall.sh
#
# Removes the connection-gate daemon, then the files. Because the library is loaded per-process
# and nothing is written to launchd's global environment, this needs no reboot: once the daemon
# is gone nothing gates or loads anything, and the files can be removed immediately. Processes
# that already loaded the library keep running with it until they exit -- a loaded library keeps
# working even after the file backing it is deleted.

set -e
LIBDIR=/usr/share/aquatransport
PLIST_LABEL=org.aquatransport.watch
PLIST="/Library/LaunchDaemons/$PLIST_LABEL.plist"

[ "$(id -u)" = "0" ] || { echo "run with sudo: sudo $0"; exit 1; }
say() { echo "AquaTransport: $*"; }

# ---- stop the daemon -----------------------------------------------------------------
# It releases every process it is holding on the way out. The pkill is for a copy KeepAlive
# started that outlived the unload; a daemon killed outright still leaves nothing wedged,
# because anything it was holding is in its journal and no daemon remains to re-freeze
# anything. A reboot clears the last of it either way.
if [ -f "$PLIST" ]; then
  launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  say "removed the daemon ($PLIST)"
else
  say "no daemon installed"
fi
pkill -f "$LIBDIR/aqwatch" 2>/dev/null || true
sleep 1

# ---- remove the files, keeping the user's rules --------------------------------------
if [ -d "$LIBDIR" ]; then
  if [ -f "$LIBDIR/redirects.txt" ] || [ -f "$LIBDIR/headers.txt" ]; then
    BACKUP="/Library/AquaTransport-rules-backup"
    mkdir -p "$BACKUP"
    for f in redirects.txt headers.txt flags.txt; do
      [ -f "$LIBDIR/$f" ] && cp "$LIBDIR/$f" "$BACKUP/$f"
    done
    say "copied your rule files to $BACKUP"
  fi
  rm -rf "$LIBDIR"
  say "removed $LIBDIR"
else
  say "$LIBDIR is already gone"
fi

say "uninstalled. Processes already running keep the library until they restart."
exit 0
