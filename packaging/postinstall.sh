#!/bin/bash
set -e

DEST="/usr/share/aquatransport"
JOB=/Library/LaunchDaemons/org.aquatransport.airdrop.plist
HELPER=/Library/PrivilegedHelperTools/org.aquatransport.airdrop
launchctl unload "$JOB" || true
if [ "$(uname -r | cut -d. -f1)" = 13 ] && [ "$(sysctl -n hw.optional.x86_64)" = 1 ]; then
  install -d -o root -g wheel -m 755 /Library/PrivilegedHelperTools
  install -o root -g wheel -m 755 "$DEST/airdrop/radio-helper" "$HELPER.new"
  mv -f "$HELPER.new" "$HELPER"
  install -o root -g wheel -m 644 "$DEST/airdrop/org.aquatransport.airdrop.plist" "$JOB"
  launchctl load "$JOB"
else
  rm -f "$JOB" "$HELPER"
fi
SECURITY_BIN="${AQ_SECURITY_PATH:-/System/Library/Frameworks/Security.framework/Versions/A/Security}"

if [[ -e "$SECURITY_BIN.original" ]]
then
	# Already installed
	exit 0
fi

# Write the load command into a copy of Security.
"${AQ_INSERT_DYLIB:-./insert_dylib}" --weak --all-yes --strip-codesig "$DEST/aquatransport.dylib" "$SECURITY_BIN" "$SECURITY_BIN.new"
chown root:wheel "$SECURITY_BIN.new"
chmod 0755 "$SECURITY_BIN.new"

# Save the original (hard link), then swap atomically.
ln "$SECURITY_BIN" "$SECURITY_BIN.original"
mv -f "$SECURITY_BIN.new" "$SECURITY_BIN"

update_dyld_shared_cache
