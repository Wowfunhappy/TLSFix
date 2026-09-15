#!/bin/bash

clear
printf "You are about to remove AquaTransport from your computer. Your computer will restart automatically once the process is complete. Continue? (yes/no) "
read -r confirmation
if [ "$confirmation" != "y" ] && [ "$confirmation" != "yes" ]
then
	echo "Exiting. No changes have been made."
	exit 1
fi

echo "Please type in your password and press return. No characters will appear as you type."
sudo true || exit 1

sudo launchctl unload /usr/share/aquatransport/airdrop/org.aquatransport.airdrop.plist
sudo launchctl unload /Library/LaunchDaemons/org.aquatransport.bootstrap.plist
sudo rm -f /Library/LaunchDaemons/org.aquatransport.bootstrap.plist

SECURITY_BIN="/System/Library/Frameworks/Security.framework/Versions/A/Security"
sudo mv -f "$SECURITY_BIN.original" "$SECURITY_BIN"
sudo rm -rf "/usr/share/aquatransport"

sudo pkgutil --forget Wowfunhappy.AquaTransport

# Tap Kext
sudo launchctl unload /Library/LaunchDaemons/net.sf.tuntaposx.tap.plist
sudo rm -f /Library/LaunchDaemons/net.sf.tuntaposx.tap.plist
sudo rm -f /Library/Extensions/tap.kext
sudo pkgutil --forget net.sf.tuntaposx.tap

sudo update_dyld_shared_cache
sudo shutdown -r now
