#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$DIR/build"
clang -Wall -Wextra -I "$DIR/deps/owl/src" "$DIR/tools/airdrop-clock-delay-test.c" \
 "$DIR/deps/owl/src/sync.c" -o "$DIR/build/airdrop-clock-delay-test"
"$DIR/build/airdrop-clock-delay-test"
