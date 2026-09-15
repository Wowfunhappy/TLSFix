#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
for part in publication stream-events outgoing-offer discovery-cache; do
 clang -mmacosx-version-min=10.9 -fobjc-arc -fblocks -Wall -Wextra -Wno-unused-parameter \
 "$DIR/tools/airdrop-$part-test.m" -framework Foundation -framework CFNetwork -o "$DIR/build/airdrop-$part-test"
 "$DIR/build/airdrop-$part-test"
done
