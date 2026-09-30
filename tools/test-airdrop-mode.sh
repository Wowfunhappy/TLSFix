#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
clang -fobjc-arc -fblocks -mmacosx-version-min=10.9 "$DIR/tools/airdrop-mode-test.m" -framework Foundation -o "$DIR/build/airdrop-mode-test"
"$DIR/build/airdrop-mode-test"
