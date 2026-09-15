#!/bin/bash
# Run after tools/build-airdrop.sh. Uses offline valid frames, never a radio.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
OBJ="$DIR/build/airdrop/owl"
clang -Wall -Wextra -I "$DIR/deps/owl/src" -I "$DIR/deps/owl/daemon" \
 -I "$DIR/deps/owl/radiotap" -I "$DIR/build/airdrop/libev-4.33" \
 "$DIR/tools/airdrop-service-session-test.c" "$OBJ"/src/*.o "$OBJ"/radiotap/*.o \
 "$OBJ"/daemon/core.o "$OBJ"/daemon/io.o "$OBJ"/daemon/netutils.o "$OBJ"/daemon/corewlan.o \
 -lpcap "$DIR/build/airdrop/libev-4.33/.libs/libev.a" \
 -framework Foundation -framework CoreWLAN -framework SystemConfiguration \
 -o "$DIR/build/airdrop-service-session-test"
"$DIR/build/airdrop-service-session-test"
