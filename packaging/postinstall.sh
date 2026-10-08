#!/bin/bash

set -e
SECURITY_BIN="/System/Library/Frameworks/Security.framework/Versions/A/Security"

# Feature jobs live under /usr/share and are registered by the existing boot
# coordinator. Refresh Anisette on upgrade without starting its generator.
ANIS_LIB=/usr/share/aquatransport
ANIS_JOB="$ANIS_LIB/org.aquatransport.anisette.plist"
BOOT_JOB=/Library/LaunchDaemons/org.aquatransport.bootstrap.plist
launchctl unload "$ANIS_JOB" >/dev/null 2>&1 || true
# Refresh the socket job before bootstrap loads it again. Mavericks launchctl
# can replace a socket path while rejecting a duplicate load, leaving the old
# registered listener unreachable (ECONNREFUSED).
launchctl unload "$ANIS_LIB/airdrop/org.aquatransport.airdrop.plist" >/dev/null 2>&1 || true
# Migrate the development version that used a per-user LaunchAgent.
OLD_AGENT=/Library/LaunchAgents/org.aquatransport.anisette.plist
if [ -f "$OLD_AGENT" ]; then
    anis_user=$(stat -f %Su /dev/console)
    if [ "$anis_user" != root ] && [ "$anis_user" != loginwindow ] && [ -n "$anis_user" ]; then
        sudo -u "$anis_user" launchctl unload "$OLD_AGENT" >/dev/null 2>&1 || true
    fi
    rm -f "$OLD_AGENT"
    killall aquatransport-anisette >/dev/null 2>&1 || true
    # Remove only the obsolete sockets, leaving any unrelated files alone.
    for anis_socket in "$ANIS_LIB"/run/anisette-*.sock; do
        [ ! -S "$anis_socket" ] || rm -f "$anis_socket"
    done
    rmdir "$ANIS_LIB/run" >/dev/null 2>&1 || true
fi

if [[ ! -e "$SECURITY_BIN.original" ]]
then
# Write the load command into a copy of Security.
./insert_dylib --weak --all-yes --strip-codesig "/usr/share/aquatransport/aquatransport.dylib" "$SECURITY_BIN" "$SECURITY_BIN.new"
chown root:wheel "$SECURITY_BIN.new"
chmod 0755 "$SECURITY_BIN.new"

# Save the original (hard link), then swap atomically.
ln "$SECURITY_BIN" "$SECURITY_BIN.original"
mv -f "$SECURITY_BIN.new" "$SECURITY_BIN"

update_dyld_shared_cache
fi

# Register optional feature jobs exactly as at boot (Anisette starts at Lion).
if [ -f "$BOOT_JOB" ]; then
    launchctl unload "$BOOT_JOB" >/dev/null 2>&1 || true
    launchctl load "$BOOT_JOB"
fi
