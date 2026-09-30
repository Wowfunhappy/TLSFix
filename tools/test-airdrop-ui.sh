#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$DIR/build"
clang -fobjc-arc -fblocks -mmacosx-version-min=10.9 "$DIR/tools/airdrop-ui-test.m" \
  -framework AppKit -framework IOBluetooth -framework CoreWLAN -o "$DIR/build/airdrop-ui-test"
"$DIR/build/airdrop-ui-test" "$DIR/src/mac/airdrop/AirDropUI.bundle"
