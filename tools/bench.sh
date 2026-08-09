#!/bin/bash
# Measures the cost of injecting aquatransport.dylib. Four separate costs, because they affect very
# different things:
#
#   1. process launch  -- paid by EVERY process on the system, including ones that never make
#                         a network connection. This is the one that matters for a global install.
#   2. memory          -- resident size added per process.
#   3. handshake       -- OpenSSL doing a handshake vs Secure Transport doing one.
#   4. rewriting       -- per-request rule matching, including the rules-file stat().
#
# Run from the repo root after ./build-macos.sh. Installs nothing.

DIR="$(cd "$(dirname "$0")/.." && pwd)"
T="$DIR/build/stage/usr/share/aquatransport"
D="$T/aquatransport.dylib"
N="${N:-40}"
export AQUATRANSPORT_DIR="$T"
rm -f "$T/debug"          # logging off: writing a line per handshake would dominate

[ -f "$D" ] || { echo "no build -- run ./build-macos.sh"; exit 1; }
TIMEFORMAT='%3R'

ms() { awk -v t="$1" -v n="$2" 'BEGIN{printf "%.1f", (t*1000)/n}'; }

bench() { # bench <label> <iterations> <command...>
  local label="$1" n="$2"; shift 2
  local base inj b i d
  base=$( { time ( for i in $(seq "$n"); do "$@" >/dev/null 2>&1; done ) ; } 2>&1 )
  inj=$(  { time ( for i in $(seq "$n"); do DYLD_INSERT_LIBRARIES="$D" "$@" >/dev/null 2>&1; done ) ; } 2>&1 )
  b=$(ms "$base" "$n"); i=$(ms "$inj" "$n")
  d=$(awk -v a="$b" -v c="$i" 'BEGIN{printf "%+.1f", c-a}')
  printf "  %-36s %7s ms -> %7s ms  (%s ms each)\n" "$label" "$b" "$i" "$d"
}

echo "=== 1. process launch overhead (n=$N) ==="
bench "/usr/bin/true (links nothing)"     "$N" /usr/bin/true
bench "/bin/echo"                         "$N" /bin/echo hi
bench "sw_vers (CoreFoundation)"          "$N" /usr/bin/sw_vers
bench "urlprobe (Foundation, no request)" "$N" "$DIR/build/urlprobe"

echo
echo "=== 2. resident memory added ==="
sz() { # sz <label> [env]
  if [ -n "$2" ]; then DYLD_INSERT_LIBRARIES="$D" /bin/sh -c 'sleep 3' & else /bin/sh -c 'sleep 3' & fi
  local p=$!; sleep 1
  local r=$(ps -o rss= -p $p 2>/dev/null | tr -d ' ')
  kill $p 2>/dev/null; wait $p 2>/dev/null
  echo "${r:-0}"
}
a=$(sz plain); b=$(sz injected x)
printf "  %-36s %7s KB -> %7s KB  (+%s KB)\n" "/bin/sh RSS" "$a" "$b" "$((b - a))"
echo "  (dylib text is file-backed and shared between processes; only dirty pages cost per-process)"

echo
echo "=== 3. handshake + fetch, n=10 (includes network variance) ==="
bench "httpsprobe www.cloudflare.com" 10 "$DIR/build/httpsprobe" https://www.cloudflare.com/

echo
echo "=== 4. rewriting cost: one non-matching rule vs no rules file, n=10 ==="
[ -f "$T/redirects.txt" ] && cp "$T/redirects.txt" "$T/redirects.txt.bak"
[ -f "$T/headers.txt" ]   && cp "$T/headers.txt"   "$T/headers.txt.bak"
cat > "$T/redirects.txt" <<'EOF'
https://nonmatching.invalid/x
https://example.com/y
EOF
rm -f "$T/headers.txt"
w=$( { time ( for i in $(seq 10); do DYLD_INSERT_LIBRARIES="$D" "$DIR/build/urlprobe" https://www.cloudflare.com/ >/dev/null 2>&1; done ) ; } 2>&1 )
rm -f "$T/redirects.txt"
o=$( { time ( for i in $(seq 10); do DYLD_INSERT_LIBRARIES="$D" "$DIR/build/urlprobe" https://www.cloudflare.com/ >/dev/null 2>&1; done ) ; } 2>&1 )
[ -f "$T/redirects.txt.bak" ] && mv -f "$T/redirects.txt.bak" "$T/redirects.txt"
[ -f "$T/headers.txt.bak" ]   && mv -f "$T/headers.txt.bak"   "$T/headers.txt"
printf "  %-36s %7s ms -> %7s ms\n" "no rules file / one rule" "$(ms "$o" 10)" "$(ms "$w" 10)"
echo "  (the rewriter stats both rule files per request so edits apply without a restart)"
