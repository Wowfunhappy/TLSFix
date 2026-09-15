#!/bin/bash

set -e
SECURITY_BIN="/System/Library/Frameworks/Security.framework/Versions/A/Security"

if [[ -e "$SECURITY_BIN.original" ]]
then
	# Already installed
	exit 0
fi

# Write the load command into a copy of Security.
./insert_dylib --weak --all-yes --strip-codesig "/usr/share/aquatransport/aquatransport.dylib" "$SECURITY_BIN" "$SECURITY_BIN.new"
chown root:wheel "$SECURITY_BIN.new"
chmod 0755 "$SECURITY_BIN.new"

# Save the original (hard link), then swap atomically.
ln "$SECURITY_BIN" "$SECURITY_BIN.original"
mv -f "$SECURITY_BIN.new" "$SECURITY_BIN"

update_dyld_shared_cache
