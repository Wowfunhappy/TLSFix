#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
OWL="$DIR/deps/owl/src"
mkdir -p "$DIR/build"
clang -Wall -Wextra -I "$OWL" "$DIR/tools/airdrop-multicast-test.c" \
  "$OWL/schedule.c" "$OWL/sync.c" "$OWL/channel.c" "$OWL/log.c" \
  -o "$DIR/build/airdrop-multicast-test"
"$DIR/build/airdrop-multicast-test"
