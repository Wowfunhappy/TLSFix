#!/bin/bash
# AquaTransport uninstaller. Installed to /Library/AquaTransport/uninstall.sh
#
# Removes the watcher daemon, then the files. Because the library is loaded per-process and
# nothing is written to launchd's global environment, this needs no reboot: once the daemon is
# gone nothing new loads the library, and the files can be removed immediately. Processes that
# already loaded it keep running with it until they exit -- a loaded library keeps working even
# after the file backing it is deleted.

set -e
DEST=/Library/AquaTransport
PLIST_LABEL=org.aquatransport.watch
PLIST="/Library/LaunchDaemons/$PLIST_LABEL.plist"

[ "$(id -u)" = "0" ] || { echo "run with sudo: sudo $0"; exit 1; }
say() { echo "AquaTransport: $*"; }

# ---- stop and remove the watcher -----------------------------------------------------
if [ -f "$PLIST" ]; then
  launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  say "removed watcher daemon ($PLIST)"
else
  say "no watcher daemon installed"
fi

# ---- remove the files, keeping the user's rules --------------------------------------
if [ -d "$DEST" ]; then
  if [ -f "$DEST/redirects.txt" ] || [ -f "$DEST/headers.txt" ]; then
    BACKUP="/Library/AquaTransport-rules-backup"
    mkdir -p "$BACKUP"
    for f in redirects.txt headers.txt; do
      [ -f "$DEST/$f" ] && cp "$DEST/$f" "$BACKUP/$f"
    done
    say "copied your rule files to $BACKUP"
  fi
  rm -rf "$DEST"
  say "removed $DEST"
else
  say "$DEST is already gone"
fi
say "uninstalled."
exit 0
