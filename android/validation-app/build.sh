#!/usr/bin/env bash
# build.sh — regenerate the pinned Network Security Config from the host's live
# chain, build every posture flavor, and optionally install them all.
#
#   ./build.sh                    # build app/build/outputs/apk/<posture>/debug/*.apk
#   ./build.sh --install          # ... and install each on the connected device
#   ./build.sh --host example.org # pin a different host (default: the one in nsc_pinned.xml)
#   ./build.sh --no-refresh       # keep the committed pins (offline build)
#
# Needs: Android SDK (ANDROID_HOME, or ~/Library/Android/sdk / ~/Android/Sdk),
# JDK 17+, and Gradle 8.13+ on PATH unless a ./gradlew wrapper is present (none
# is committed, to keep binaries out of the repo; `gradle wrapper` creates one).
set -euo pipefail
cd "$(dirname "$0")"

install=0
refresh=1
host=$(sed -n 's/.*<domain[^>]*>\([^<]*\)<\/domain>.*/\1/p' app/src/main/res/xml/nsc_pinned.xml | head -1)
while [ $# -gt 0 ]; do
  case "$1" in
    --install) install=1 ;;
    --no-refresh) refresh=0 ;;
    --host) host=${2:?--host needs a value}; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

if [ "$refresh" -eq 1 ]; then
  echo "pins: reading the live chain of $host"
  pins=$(./pins.sh "$host" 443 --pins)
  today=$(date -u +%Y-%m-%d)
  {
    cat <<EOF
<?xml version="1.0" encoding="utf-8"?>
<!-- Correct pins: every certificate of the host's live chain, so the pin set
     stays valid across a leaf rotation as long as the issuing chain is the same.
     This file is the single source of truth for the host and the pins: the
     okhttp and trustmanager flavors read it too (Pins.java). Regenerate it with
     build.sh (or pins.sh) when the host's chain changes.
     Generated $today from the live chain of $host. -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="false">$host</domain>
        <pin-set>
EOF
    IFS=, read -r -a list <<<"$pins"
    for pin in "${list[@]}"; do
      echo "            <pin digest=\"SHA-256\">$pin</pin>"
    done
    cat <<EOF
        </pin-set>
    </domain-config>
</network-security-config>
EOF
  } >app/src/main/res/xml/nsc_pinned.xml
  sed -i.bak "s#<domain includeSubdomains=\"false\">[^<]*</domain>#<domain includeSubdomains=\"false\">$host</domain>#" app/src/main/res/xml/nsc_wrong.xml
  rm -f app/src/main/res/xml/nsc_wrong.xml.bak
  echo "pins: $(echo "$pins" | tr ',' '\n' | wc -l | tr -d ' ') pin(s) written to app/src/main/res/xml/nsc_pinned.xml"
fi

if [ -z "${ANDROID_HOME:-}" ]; then
  for candidate in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk" "${ANDROID_SDK_ROOT:-}"; do
    if [ -n "$candidate" ] && [ -d "$candidate" ]; then
      export ANDROID_HOME=$candidate
      break
    fi
  done
fi
[ -n "${ANDROID_HOME:-}" ] || { echo "build.sh: set ANDROID_HOME to the Android SDK" >&2; exit 1; }

# Gradle 8.x runs on JDK 17 to 21; a newer default JDK fails with "Unsupported
# class file major version". On macOS pick one automatically when JAVA_HOME is unset.
if [ -z "${JAVA_HOME:-}" ] && [ -x /usr/libexec/java_home ]; then
  for v in 17 21 20 19 18; do
    if JAVA_HOME=$(/usr/libexec/java_home -v "$v" 2>/dev/null); then
      export JAVA_HOME
      break
    fi
  done
fi

if [ -x ./gradlew ]; then
  gradle=./gradlew
elif command -v gradle >/dev/null 2>&1; then
  gradle=gradle
else
  echo "build.sh: no ./gradlew and no gradle on PATH (brew install gradle, or run 'gradle wrapper')" >&2
  exit 1
fi

# assembleDebug builds every flavor; the per-flavor install tasks are named
# install<Flavor>Debug, so installation goes through adb on each APK instead.
"$gradle" --quiet assembleDebug

echo
echo "APKs (SHA-256):"
apks=()
while IFS= read -r apk; do apks+=("$apk"); done < <(find app/build/outputs/apk -name '*.apk' | sort)
for apk in "${apks[@]}"; do
  if command -v sha256sum >/dev/null 2>&1; then
    sum=$(sha256sum "$apk" | cut -d' ' -f1)
  else
    sum=$(shasum -a 256 "$apk" | cut -d' ' -f1)
  fi
  echo "  $sum  $apk"
done

if [ "$install" -eq 1 ]; then
  echo
  for apk in "${apks[@]}"; do
    echo "installing $(basename "$apk")"
    adb install -r "$apk" >/dev/null
  done
  echo "installed: $(adb shell pm list packages | grep -c com.yinkoshield.pinscan.validation) com.yinkoshield.pinscan.validation.* package(s)"
fi
