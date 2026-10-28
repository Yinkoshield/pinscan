#!/usr/bin/env bash
# set-target.sh — point ykzpinscan at the package(s) to scan (writes the on-device
# /data/adb/ykzpinscan/targets). Takes effect at the next app launch (per-fork bind;
# no reboot needed). Usage: ./set-target.sh <package> [<package2> ...]
#
# Each root step is its own `su -c`: a chained `su -c '… && …'` is mangled by
# adb's shell quoting on many devices (see the README).
set -eu
[ $# -ge 1 ] || { echo "usage: $0 <package> [<package2> ...]"; exit 1; }
for p in "$@"; do
  case "$p" in
    *[!A-Za-z0-9._]*|"") echo "invalid package name: $p" >&2; exit 1 ;;
  esac
done
tmp=$(mktemp)
for p in "$@"; do echo "$p" >> "$tmp"; done
adb push "$tmp" /data/local/tmp/ykzpinscan_targets >/dev/null
rm -f "$tmp"
adb shell su -c 'mkdir -p /data/adb/ykzpinscan'
adb shell su -c 'cp /data/local/tmp/ykzpinscan_targets /data/adb/ykzpinscan/targets'
adb shell su -c 'chmod 600 /data/adb/ykzpinscan/targets'
adb shell su -c 'rm -f /data/local/tmp/ykzpinscan_targets'
echo "targets set:"
adb shell su -c 'cat /data/adb/ykzpinscan/targets'
