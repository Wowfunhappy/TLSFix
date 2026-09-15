#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
clang -mmacosx-version-min=10.9 -fobjc-arc -fblocks -Wall -Wextra -Wno-unused-parameter \
 "$DIR/tools/airdrop-transfer-lease-test.m" -framework Foundation -o "$DIR/build/airdrop-transfer-lease-test"
"$DIR/build/airdrop-transfer-lease-test"
