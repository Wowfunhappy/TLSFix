#!/bin/bash
# AquaTransport uninstaller. Installed to /Library/AquaTransport/uninstall.sh
#
# Restores Security.framework from the hard link kept beside it, which puts the original inode
# and mtime back at that path and so returns every process to the shared cache copy, then
# removes the installed files. aquatransport.sh does the work, so removing by package and
# removing by hand take the same path.
#
# No reboot is needed for the machine to be back to stock, but processes already running keep
# the library until they restart: a mapped image outlives both the file and the load command
# that named it. A reboot clears every one.

set -e
DEST="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" = "0" ] || { echo "run with sudo: sudo $0"; exit 1; }
[ -x "$DEST/aquatransport.sh" ] || {
  echo "AquaTransport: $DEST/aquatransport.sh missing; cannot uninstall automatically."
  echo "Restore Security.framework by hand with:"
  echo "  ln -f /System/Library/Frameworks/Security.framework/Versions/A/Security.aquatransport-original \\"
  echo "        /System/Library/Frameworks/Security.framework/Versions/A/Security"
  exit 1; }

exec "$DEST/aquatransport.sh" uninstall
