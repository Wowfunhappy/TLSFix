#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
mkdir -p build
clang -mmacosx-version-min=10.9 -fblocks -Wall -Wextra tools/airdrop-bootstrap-test.m -framework Foundation -framework CoreWLAN -o build/airdrop-bootstrap-test
build/airdrop-bootstrap-test
