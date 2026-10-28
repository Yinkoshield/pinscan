#!/usr/bin/env bash
# Build the ykzpinscan Zygisk .so from jni/pinscan.cpp and place it where the
# module loads it (zygisk/<abi>.so). Needs the Android NDK.
#
# Point NDK at your install, or let this find one under $ANDROID_HOME/ndk:
#   ANDROID_NDK_HOME=/path/to/ndk/27.2.12479018 ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

ndk="${ANDROID_NDK_HOME:-}"
if [ -z "$ndk" ]; then
  sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
  ndk="$(ls -d "$sdk"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
fi
[ -n "$ndk" ] && [ -x "$ndk/ndk-build" ] || {
  echo "Android NDK not found. Set ANDROID_NDK_HOME to an NDK directory." >&2
  exit 1
}

"$ndk/ndk-build" NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk NDK_APPLICATION_MK=jni/Application.mk
mkdir -p zygisk
cp libs/arm64-v8a/libykzpinscan.so zygisk/arm64-v8a.so
rm -rf libs obj
echo "built zygisk/arm64-v8a.so"
