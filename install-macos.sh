#!/bin/bash
# Installs AquaTransport on Mac OS X 10.6 - 10.9 by adding a load command to
# Security.framework, so the library loads in every process that loads Security.
#
#   ./install-macos.sh check           report whether the load command fits, change nothing
#   sudo ./install-macos.sh stage      copy files into place, patch nothing
#   sudo ./install-macos.sh install    stage, then patch Security.framework
#   sudo ./install-macos.sh patch      patch Security.framework, assuming the files are in place
#   sudo ./install-macos.sh status     report what is installed and whether it loads
#   sudo ./install-macos.sh uninstall  restore Security.framework, then remove the files
#
# The installer package ships this script to /Library/AquaTransport and runs `patch` from its
# postinstall, so a package install and a command-line install take the same path through the
# same checks, including the rollback when a freshly started process does not load the library.
#
# Only the architectures the dylib itself has are patched. On 10.6 Security also carries a ppc
# slice for Rosetta, which is left untouched: a ppc process could not load an x86-only dylib.
#
# Nothing is loaded into a process from outside and no daemon runs: the library is a dependency
# of Security.framework, so every process that loads Security loads it too, at launch, before it
# can complete a handshake. Security is the framework that exports SSLHandshake and the rest, so
# the processes that load it are exactly the processes that could use Secure Transport -- there
# is no narrower place to put this that does not miss some of them.
#
# The risk to weigh is the blast radius: a library that crashes in its constructor takes down
# everything that loads Security, loginwindow and Finder included. The load command is weak, so
# a library that is *missing* is skipped silently and every process still starts; that covers
# deletion, not a crash. Try this in a VM before a machine you need.
#
# RECOVERY, if a patched Security stops the machine from booting. The original file is kept as
# a hard link beside it, so restoring it needs no copy and no build. Boot from another volume
# or into single-user mode (Cmd-S, then `mount -uw /`) and run:
#
#   ln -f /System/Library/Frameworks/Security.framework/Versions/A/Security.aquatransport-original \
#         /System/Library/Frameworks/Security.framework/Versions/A/Security
#
# MECHANISM. Security.framework lives in the dyld shared cache, and dyld uses the cached copy
# only while the file on disk still matches the inode and mtime the cache recorded. Patching
# the file breaks that match, so every process loads Security from disk instead: +0.8 ms per
# launch on 10.9.5 for a process linking little else, more for one where many loaded images
# import Security. That is also why the original is preserved as a hard link rather
# than a copy: a hard link keeps the original inode and mtime, so restoring it puts Security back
# on the shared cache exactly as it was.
# A restored copy would have a fresh inode, leaving every process loading Security from disk
# forever after an uninstall.
#
# The load command carries compatibility version 0. dyld refuses a dependency whose
# compatibility version is lower than the one demanded, and a weak dependency it refuses is
# mapped but never initialised -- the dylib appears in DYLD_PRINT_LIBRARIES and does nothing.
# insert_dylib writes 0, which is why this script uses it rather than editing the header here.
#
# /usr/share/aquatransport/flags.txt holds one flag name per line, read at runtime by every
# loaded copy:
#     debug           log handshakes to /tmp/aquatransport-<uid>.log
#     disabled-mtls   hand client-certificate connections back to the system stack

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

# The dylib and the rule files live under /usr/share, which is one of the few directories
# system.sb lets a sandboxed process read. That grant covers both reads a patched process makes
# for itself: dyld mapping the library at launch, and the library reading the rule files. A weak
# load command the sandbox denies is skipped in silence, so a path outside that grant would leave
# every sandboxed application unfixed and say nothing.
SRC="$DIR/build/stage/usr/share/aquatransport"
LIBDIR="/usr/share/aquatransport"
DYLIB="$LIBDIR/aquatransport.dylib"

# AQ_SECURITY_PATH points the patch and restore paths at a copy of the framework binary, so they
# can be exercised without touching the system one. Leave it unset for a real install.
SEC="${AQ_SECURITY_PATH:-/System/Library/Frameworks/Security.framework/Versions/A/Security}"
TOOLDIR="/Library/AquaTransport"   # insert_dylib and this script, when installed from the package
BACKUP="$SEC.aquatransport-original"
INSERT="${AQ_INSERT_DYLIB:-/usr/local/bin/insert_dylib}"
MODE="${1:-}"

need_root() { [ "$(id -u)" = "0" ] || { echo "must run as root (use sudo)"; exit 1; }; }

# Both slices, and nothing exported: a naive link exports the whole OpenSSL SSL_*/EVP_*
# namespace, which would interpose those names in every host process.
verify_build() {
  [ -f "$SRC/aquatransport.dylib" ] || { echo "no build found at $SRC -- run ./build-macos.sh first"; exit 1; }
  have=$(lipo -info "$SRC/aquatransport.dylib" | sed 's/.*://')
  for a in x86_64 i386; do
    echo "$have" | grep -qw "$a" || {
      echo "REFUSING TO INSTALL: dylib is missing the $a slice."
      echo "$a processes would load Security from disk and get no fix."; exit 1; }
  done
  # nm is an Xcode tool and is absent from a stock 10.6, where an empty count would otherwise
  # read as "exports nothing" and print a verification that never ran. nm lists undefined
  # symbols too, so no output at all means the tool did not work rather than the dylib is clean.
  syms=$(nm -arch x86_64 -g "$SRC/aquatransport.dylib" 2>/dev/null || true)
  if [ -n "$syms" ]; then
    n=$(printf '%s\n' "$syms" | grep -cE " (T|D|B|S) _" || true)
    [ "$n" = "0" ] || { echo "REFUSING TO INSTALL: dylib exports $n symbols"; exit 1; }
    echo "  verified: both slices present, no exported symbols"
  else
    echo "  verified: both slices present (no working nm here; the build already enforces exports)"
  fi
}

# Install one file atomically: write alongside with its final owner and mode, then rename over,
# so a load in progress never sees a partial or wrong-permissioned file.
stage_file() { # src dst mode
  [ -f "$1" ] || { echo "missing $1 -- run ./build-macos.sh first"; exit 1; }
  cp "$1" "$2.new"; chown root:wheel "$2.new"; chmod "$3" "$2.new"; mv -f "$2.new" "$2"
}

# The architectures to patch: the ones Security has AND the dylib can serve. On 10.6 Security
# also carries a ppc slice for Rosetta, which is left alone -- a ppc process cannot load an
# x86-only dylib, so a load command there would buy nothing, and insert_dylib has no reason to
# understand a big-endian header.
target_archs() {
  local sa da d
  d="$DYLIB"; [ -f "$d" ] || d="$SRC/aquatransport.dylib"   # so `check` works before `stage`
  sa=$(lipo -info "$SEC" 2>/dev/null | sed 's/.*: //')
  da=$(lipo -info "$d" 2>/dev/null | sed 's/.*: //')
  for a in $sa; do case " $da " in *" $a "*) echo "$a" ;; esac; done
}

# Byte offset and length of one slice within the fat file, so a patched slice can be written
# back exactly where it came from without rebuilding the fat container around it.
slice_off_size() { # arch -> "offset size"
  lipo -detailed_info "$SEC" | awk -v want="$1" '
    $1 == "architecture" { cur = $2 }
    cur == want && $1 == "offset" { off = $2 }
    cur == want && $1 == "size"   { print off, $2; exit }'
}

# The load commands of one slice. otool's -arch has not behaved the same across releases -- on
# 10.6 it yields nothing here -- so when it comes back empty the slice is separated with lipo
# and read on its own, which needs no -arch at all. Everything that reads a Mach-O goes through
# this, because an otool call that quietly returns nothing reads as "no load commands" and is
# indistinguishable from a real answer.
lc_dump() { # file arch
  local out t
  out=$(otool -arch "$2" -l "$1" 2>/dev/null)
  case "$out" in *"Load command"*) printf '%s\n' "$out"; return 0 ;; esac
  t=$(mktemp "${TMPDIR:-/tmp}/aqslice.XXXXXX") || return 1
  if lipo "$1" -thin "$2" -output "$t" 2>/dev/null; then
    out=$(otool -l "$t" 2>/dev/null)
  else
    out=$(otool -l "$1" 2>/dev/null)      # already thin: -arch was the only thing in the way
  fi
  rm -f "$t"
  printf '%s\n' "$out"
  case "$out" in *"Load command"*) return 0 ;; esac
  return 1
}

# Does this file carry the load command naming the dylib?
#
# The structural read is preferred, but a machine without a working otool must not be told its
# binary is unpatched -- that reads as a Mach-O problem when it is a missing tool. So when no
# Mach-O reader answers, the file's bytes are searched for the path instead: a load command
# stores it as a literal string, so finding it means the command is there. That cannot tell one
# slice from another, which is why it is the fallback and not the method.
has_lc() { # file arch
  local out
  if out=$(lc_dump "$1" "$2"); then
    case "$out" in *"$DYLIB"*) return 0 ;; *) return 1 ;; esac
  fi
  LC_ALL=C grep -q -a -F "$DYLIB" "$1" 2>/dev/null
}

# Unused bytes between the end of a slice's load commands and its first section, reported for
# information: insert_dylib makes room when there is none, so nothing here gates the patch.
#
# Prints "pad header commands first-section", so a caller can show its working. The load
# command sizes are summed rather than read from the header, because otool's -h columns have
# changed between releases and misreading them yields a plausible wrong number rather than an
# error. Prints "?" for the pad, and returns non-zero, when the slice could not be read at all.
slice_pad() { # file arch
  local f="$1" a="$2" hdr cmds first
  case "$a" in *64) hdr=32 ;; *) hdr=28 ;; esac
  set -- $(lc_dump "$f" "$a" | awk '
    /^[ \t]*cmdsize [0-9]+$/ { c += $2 }
    /^[ \t]*offset [0-9]+$/  { v = $2 + 0; if (v > 0 && (m == 0 || v < m)) m = v }
    END { print c + 0, m + 0 }')
  cmds="${1:-0}"; first="${2:-0}"
  [ "$cmds" -gt 0 ] && [ "$first" -gt 0 ] || { echo "? $hdr $cmds $first"; return 1; }
  echo "$(( first - hdr - cmds )) $hdr $cmds $first"
}

# Bytes a dylib_command naming $DYLIB occupies: the 24-byte command, the path, its terminator,
# rounded up to 8.
needed_bytes() { echo $(( (24 + ${#DYLIB} + 1 + 7) / 8 * 8 )); }

# True when every architecture that should carry the load command does. Checked per slice
# because otool reports one at a time, and a file patched in only one would leave the other
# unfixed while looking installed.
is_patched() { # file
  local any=0
  for a in $(target_archs); do
    any=1
    has_lc "$1" "$a" || return 1
  done
  [ "$any" = 1 ]
}

# What a process started right now actually loads. security(1) links Security.framework, so it
# reports the state of the patch rather than of this shell, which mapped Security long ago.
loads_dylib() {
  DYLD_PRINT_LIBRARIES=1 /usr/bin/security list-keychains 2>&1 | grep -q "aquatransport.dylib"
}

restore_security() {
  # Re-link rather than copy: the path ends up pointing at the original inode, with the mtime
  # the shared cache recorded, so dyld goes back to using the cached Security.
  ln "$BACKUP" "$SEC.restore"
  mv -f "$SEC.restore" "$SEC"
}

do_stage() {
  verify_build
  mkdir -p "$LIBDIR"; chown root:wheel "$LIBDIR"; chmod 0755 "$LIBDIR"
  stage_file "$SRC/aquatransport.dylib" "$DYLIB" 0644

  # Seed config files on a fresh install without clobbering existing edits. 0644 is what makes
  # them legible from a sandbox: system.sb's grant carries a (file-mode #o0004) requirement,
  # so a stricter mode leaves them readable to root alone and every rule silently inert.
  for f in headers.txt redirects.txt flags.txt; do
    [ -f "$LIBDIR/$f" ] && continue
    if [ -f "$DIR/examples/$f" ]; then cp "$DIR/examples/$f" "$LIBDIR/$f"; else : > "$LIBDIR/$f"; fi
    chown root:wheel "$LIBDIR/$f"; chmod 0644 "$LIBDIR/$f"
  done
  echo "  installed to $LIBDIR (Security.framework not patched yet)"
}

# A slice's alignment, as the hexadecimal value lipo's -segalign wants, so a rebuilt fat file
# keeps each slice on the boundary the original used.
slice_align() { # arch
  local n
  n=$(lipo -detailed_info "$SEC" | awk -v want="$1" '
        $1 == "architecture" { cur = $2 }
        cur == want && $1 == "align" { print $2; exit }')
  printf '%x' $(( 1 << ${n#2^} ))
}

# Patch one slice at a time, so every slice not being patched -- 10.6's ppc among them --
# is carried through untouched, and insert_dylib only ever sees a thin Mach-O.
#
# insert_dylib makes room in a slice with no header padding to spare, which can leave the
# patched slice longer than the one it replaces. When every patched slice came back the same
# length, each goes back into the exact bytes it came from and the fat container is never
# rebuilt; when one grew, the container is rebuilt with lipo instead, preserving each slice's
# original alignment.
patch_slices() { # src dst
  local src="$1" dst="$2" tmp a off size out grew=0 archs create=()
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/aquatransport.XXXXXX") || return 1

  # A thin Security has no container to preserve: insert_dylib works on the file as it stands.
  if lipo -info "$src" 2>/dev/null | grep -q "^Non-fat"; then
    out=$("$INSERT" --weak --all-yes --no-strip-codesig "$DYLIB" "$src" "$dst" 2>&1) || {
      echo "REFUSING: insert_dylib failed:"; echo "$out" | sed 's/^/    /'; rm -rf "$tmp"; return 1; }
    echo "  patched the single slice"; rm -rf "$tmp"; return 0
  fi

  archs=$(lipo -info "$src" | sed 's/.*: //')
  for a in $archs; do
    lipo "$src" -thin "$a" -output "$tmp/$a" 2>/dev/null || {
      echo "REFUSING: could not separate the $a slice"; rm -rf "$tmp"; return 1; }
  done

  for a in $(target_archs); do
    size=$(stat -f %z "$tmp/$a")
    out=$("$INSERT" --weak --all-yes --no-strip-codesig "$DYLIB" "$tmp/$a" "$tmp/$a.patched" 2>&1) || {
      echo "REFUSING: insert_dylib failed on the $a slice:"; echo "$out" | sed 's/^/    /'
      rm -rf "$tmp"; return 1; }
    has_lc "$tmp/$a.patched" "$a" || {
      echo "REFUSING: the $a slice came back without the load command."
      echo "  insert_dylib said:"; echo "$out" | sed 's/^/    /'
      echo "  neither $(command -v otool || echo otool) nor a search of the file's bytes found"
      echo "  $DYLIB in it."
      rm -rf "$tmp"; return 1; }

    [ "$(stat -f %z "$tmp/$a.patched")" = "$size" ] || grew=1
    mv -f "$tmp/$a.patched" "$tmp/$a"
    echo "  patched the $a slice"
  done

  if [ "$grew" = 0 ]; then
    # Every patched slice is the length of the one it replaces, so each can go straight back
    # into the bytes it came from and the rest of the file stays as it was, to the byte.
    cp "$src" "$dst"
    for a in $(target_archs); do
      set -- $(slice_off_size "$a"); off="${1:-0}"
      if [ $(( off % 4096 )) -eq 0 ]; then
        dd if="$tmp/$a" of="$dst" bs=4096 seek=$(( off / 4096 )) conv=notrunc 2>/dev/null
      else
        dd if="$tmp/$a" of="$dst" bs=1 seek="$off" conv=notrunc 2>/dev/null
      fi
    done
  else
    echo "  a slice grew; rebuilding the fat binary"
    for a in $archs; do create+=("$tmp/$a"); done
    for a in $archs; do create+=(-segalign "$a" "$(slice_align "$a")"); done
    lipo -create "${create[@]}" -output "$dst" || { rm -rf "$tmp"; return 1; }
  fi

  rm -rf "$tmp"
  return 0
}

do_check() {
  echo "  Security: $SEC"
  echo "    slices:       $(lipo -info "$SEC" 2>/dev/null | sed 's/.*: //')"
  echo "    to patch:     $(target_archs | tr '\n' ' ')"
  echo "    command size: $(needed_bytes) bytes for $DYLIB"
  for a in $(target_archs); do
    set -- $(slice_pad "$SEC" "$a")
    case "$1" in
      ''|*[!0-9-]*) echo "    $a: could not read the load commands -- otool output unrecognised"; continue ;;
    esac
    if [ "$1" -ge "$(needed_bytes)" ]; then verdict="fits in the padding"
    else                                    verdict="insert_dylib will have to make room"; fi
    if has_lc "$SEC" "$a"; then verdict="$verdict, already patched"; fi
    echo "    $a: $1 bytes free (header $2 + commands $3, first section at $4) -- $verdict"
  done
}

do_install() {
  [ -x "$INSERT" ] || {
    echo "need insert_dylib at $INSERT (set AQ_INSERT_DYLIB to point elsewhere)."
    echo "It is a single self-contained binary and can be copied from another machine."; exit 1; }
  [ -f "$SEC" ] || { echo "no Security.framework binary at $SEC"; exit 1; }

  if is_patched "$SEC"; then echo "  already patched -- nothing to do"; return; fi
  [ -n "$(target_archs)" ] || {
    echo "REFUSING: could not work out which architectures to patch."
    echo "  lipo reports '$(lipo -info "$SEC" 2>&1 | sed 's/.*: //')' for Security"
    echo "  and '$(lipo -info "$DYLIB" 2>&1 | sed 's/.*: //')' for the dylib."; exit 1; }

  # A backup beside an unpatched Security is a leftover -- the state the recovery instructions
  # at the top of this file leave behind, since they re-link the original without clearing the
  # link. Whatever sits at $SEC now is the pristine original, so the old link is the stale one.
  [ -e "$BACKUP" ] && { echo "  discarding leftover backup"; rm -f "$BACKUP"; }
  ln "$SEC" "$BACKUP"

  patch_slices "$SEC" "$SEC.new" || { rm -f "$SEC.new" "$BACKUP"; exit 1; }
  is_patched "$SEC.new" || { rm -f "$SEC.new" "$BACKUP"; echo "REFUSING: patched file does not carry the load command"; exit 1; }

  chown root:wheel "$SEC.new"; chmod 0755 "$SEC.new"
  mv -f "$SEC.new" "$SEC"

  # Confirm against a process started after the patch, and put the original back if it did not
  # take. Skipped when patching a copy, where security(1) would still load the system one.
  if [ -z "$AQ_SECURITY_PATH" ] && ! loads_dylib; then
    restore_security; rm -f "$BACKUP"
    echo "REFUSING: a new process did not load the dylib; Security.framework restored"; exit 1
  fi

  echo "  patched $SEC"
  echo "  original kept at $BACKUP (a hard link, so it costs no disk)"
  echo "  Processes already running keep the Security they mapped at launch. Reboot for full coverage."
}

do_status() {
  if [ -f "$DYLIB" ]; then echo "  dylib:    $DYLIB ($(lipo -info "$DYLIB" | sed 's/.*: //'))"
  else                     echo "  dylib:    not installed"; fi
  if is_patched "$SEC"; then echo "  Security: patched (loads from disk, not the shared cache)"
  else                       echo "  Security: not patched"; fi
  [ -e "$BACKUP" ] && echo "  backup:   $BACKUP" || echo "  backup:   none"
  if loads_dylib; then echo "  a process started now: loads the dylib"
  else                 echo "  a process started now: does NOT load the dylib"; fi
}

do_uninstall() {
  if is_patched "$SEC"; then
    [ -e "$BACKUP" ] || { echo "Security is patched but $BACKUP is gone."
                          echo "Reinstall Security.framework from a system installer to recover."; exit 1; }
    restore_security
    echo "  restored $SEC from $BACKUP"
  elif [ -e "$BACKUP" ]; then
    # Restored by hand already; only the link is left to clear.
    echo "  Security was already unpatched; clearing the leftover backup"
  fi
  rm -f "$BACKUP"
  rm -rf "$LIBDIR"
  echo "  removed $LIBDIR"
  # Unlinking the directory this script is running from is safe: the open file descriptor
  # outlives the name, so the rest of the script still reads.
  [ -d "$TOOLDIR" ] && { rm -rf "$TOOLDIR"; echo "  removed $TOOLDIR"; }

  if [ -z "$AQ_SECURITY_PATH" ] && loads_dylib; then
    echo "  WARNING: a new process still loads the dylib -- check $SEC by hand"; exit 1
  fi
  # Deleting the dylib does not unload it. A process that already mapped it keeps running with
  # it, because a mapped image survives the file being unlinked; nothing new picks it up once
  # Security is restored. A reboot clears every one.
  echo "  uninstalled. Processes already running keep the library until they restart."
}

case "$MODE" in
  check)     do_check ;;
  stage)     need_root; do_stage ;;
  install)   need_root; do_stage; do_install ;;
  patch)     need_root; do_install ;;
  status)    do_status ;;
  uninstall) need_root; do_uninstall ;;
  *) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
